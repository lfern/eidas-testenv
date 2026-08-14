//! Verifies an incoming OID4VP presentation: parses the SD-JWT VC +
//! Key Binding JWT, checks the issuer signature, the KB-JWT signature
//! against the holder's `cnf.jwk`, and that `nonce`/`aud`/`sd_hash`
//! match the original request. Pure logic, no Axum — testable without
//! a server.
//!
//! Adapted from `openid4vp`'s own reference implementation
//! (`examples/verifier-conformance-adapter/server/handlers.rs
//! ::verify_sd_jwt_vc`) — the library itself only parses the response
//! envelope (`AuthorizationResponse`), not the presentation inside it;
//! this is the part every OID4VP verifier integrating this crate has to
//! bring itself.

use std::collections::HashMap;

use base64::prelude::*;
use openid4vp::core::response::{parameters::VpTokenItem, AuthorizationResponse};
use openid4vp::verifier::session::{Outcome, Session};
use p256::pkcs8::DecodePublicKey as _;
use ssi::claims::jws::{decode_unverified, decode_verify};
use ssi::claims::sd_jwt::{KbJwtPayload, SdAlg, SdJwt};
use ssi::claims::{DateTimeProvider, ValidateClaims};
use ssi::jwk::JWK;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

use crate::request::PID_QUERY_ID;

/// A subset of the presented credential's claims, revealed by the
/// wallet's selective disclosure — exactly what the verifier asked for
/// in its DCQL query (see `request.rs::REQUESTED_CLAIMS`), and nothing
/// else, since that's the entire point of checking this rather than
/// just "some valid SD-JWT arrived".
pub type DisclosedClaims = serde_json::Map<String, serde_json::Value>;

struct Now;

impl DateTimeProvider for Now {
    fn date_time(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

/// Verifies a single presented credential's cryptographic correctness
/// and binding to this transaction, returning the claims it actually
/// disclosed.
///
/// # Errors
///
/// Returns a human-readable rejection reason (not `anyhow::Error`,
/// since this is reported straight back as the presentation's outcome,
/// same as `openid4vp`'s own example does).
pub fn verify_presentation(
    presentation: &str,
    expected_nonce: &str,
    expected_aud: &str,
) -> Result<DisclosedClaims, String> {
    let sd_jwt = SdJwt::new(presentation).map_err(|e| format!("invalid SD-JWT: {e}"))?;
    let issuer_jwt = sd_jwt.jwt().as_str();

    let (header, _) =
        decode_unverified(issuer_jwt).map_err(|e| format!("failed to decode issuer JWT: {e}"))?;
    let issuer_key = issuer_key_from_x5c(&header.x509_certificate_chain)?;
    let (_, payload) = decode_verify(issuer_jwt, &issuer_key)
        .map_err(|e| format!("issuer SD-JWT signature verification failed: {e}"))?;

    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| format!("issuer JWT payload not JSON: {e}"))?;
    let cnf_jwk = claims
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or("issuer JWT has no cnf.jwk (holder key)")?;
    let holder_key: JWK =
        serde_json::from_value(cnf_jwk.clone()).map_err(|e| format!("invalid cnf.jwk: {e}"))?;

    let kb_jwt = sd_jwt.kb().ok_or("Key Binding JWT is missing")?.as_str();
    let (_, kb_payload) = decode_verify(kb_jwt, &holder_key)
        .map_err(|e| format!("Key Binding JWT signature verification failed: {e}"))?;
    let kb: KbJwtPayload = serde_json::from_slice(&kb_payload)
        .map_err(|e| format!("KB-JWT is not a valid Key Binding JWT: {e}"))?;

    if kb.nonce.0 != expected_nonce {
        return Err("KB-JWT nonce does not match the request".into());
    }
    if kb.aud != expected_aud {
        return Err("KB-JWT aud does not match the client_id".into());
    }
    if !kb.sd_hash.verify(SdAlg::Sha256, sd_jwt) {
        return Err("KB-JWT sd_hash does not match the presented SD-JWT".into());
    }
    kb.validate_claims(&Now, &())
        .map_err(|e| format!("KB-JWT time claims are invalid: {e}"))?;

    // Reveal the disclosed claims (merges the wallet's selectively
    // disclosed values into the issuer-signed payload, replacing `_sd`
    // digest references) and hand back only what was actually asked
    // for, so the caller can confirm exactly those came through.
    let revealed = sd_jwt
        .decode_reveal_any()
        .map_err(|e| format!("failed to reveal disclosed claims: {e}"))?;
    let revealed_json = serde_json::to_value(revealed.claims())
        .map_err(|e| format!("failed to serialize revealed claims: {e}"))?;
    let revealed_map = revealed_json
        .as_object()
        .ok_or("revealed claims are not a JSON object")?;

    let mut disclosed = DisclosedClaims::new();
    for claim in crate::request::REQUESTED_CLAIMS {
        if let Some(value) = revealed_map.get(*claim) {
            disclosed.insert((*claim).to_owned(), value.clone());
        }
    }
    Ok(disclosed)
}

/// Build a P-256 JWK from the leaf certificate of a JWS `x5c` header.
fn issuer_key_from_x5c(x5c: &Option<Vec<String>>) -> Result<JWK, String> {
    let leaf_b64 = x5c
        .as_ref()
        .and_then(|chain| chain.first())
        .ok_or("issuer JWT header has no x5c certificate")?;
    let der = BASE64_STANDARD
        .decode(leaf_b64)
        .map_err(|e| format!("invalid base64 in x5c: {e}"))?;
    let cert =
        Certificate::from_der(&der).map_err(|e| format!("invalid x5c certificate DER: {e}"))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("failed to re-encode issuer SPKI: {e}"))?;
    p256::PublicKey::from_public_key_der(&spki)
        .map_err(|e| format!("issuer key is not a valid P-256 public key: {e}"))
        .and_then(|pk| {
            serde_json::from_str(&pk.to_jwk_string())
                .map_err(|e| format!("failed to convert issuer key to JWK: {e}"))
        })
}

/// Verifies the (single, `direct_post.jwt`/JARM-encrypted) presentation
/// this verifier's DCQL query asks for, returning the [`Outcome`] to
/// store on the session. Called from `Verifier::verify_response`'s
/// validator closure — see `serve.rs`. `enc_key` is this verifier's own
/// JARM decryption key (`identity.rs`), needed to open the response
/// before its contents can be checked at all.
pub fn verify_response(
    session: &Session,
    response: &AuthorizationResponse,
    enc_key: &p256::SecretKey,
) -> Outcome {
    let nonce = session.authorization_request_object.nonce().to_string();
    let aud = session
        .authorization_request_object
        .client_id()
        .map(|c| c.0.clone())
        .unwrap_or_default();

    match verify_pid_presentation(response, enc_key, &nonce, &aud) {
        Ok(disclosed) => Outcome::Success {
            info: serde_json::json!({ "disclosed_claims": disclosed }),
        },
        Err(reason) => Outcome::Failure { reason },
    }
}

fn verify_pid_presentation(
    response: &AuthorizationResponse,
    enc_key: &p256::SecretKey,
    expected_nonce: &str,
    expected_aud: &str,
) -> Result<DisclosedClaims, String> {
    // Every request this verifier sends declares an encryption key and
    // asks for `direct_post.jwt` (see `request.rs`), so a well-behaved
    // wallet always JARM-encrypts its response — `wallet::present.rs`
    // does. An `Unencoded` response here means the wallet ignored that
    // and sent `vp_token` in the clear, which this phase no longer
    // accepts (Phase 1 did; see ROADMAP.md).
    let AuthorizationResponse::Jwt(jwt) = response else {
        return Err("expected a JARM-encrypted direct_post.jwt response".into());
    };
    let (vp_token, _state) = crate::jwe::decrypt(&jwt.response, enc_key)
        .map_err(|e| format!("failed to decrypt JARM response: {e:#}"))?;

    let presentations = presentations_for_pid_query(&vp_token.0)?;
    let [presentation] = presentations.as_slice() else {
        return Err(format!(
            "expected exactly one '{PID_QUERY_ID}' presentation, got {}",
            presentations.len()
        ));
    };
    verify_presentation(presentation, expected_nonce, expected_aud)
}

fn presentations_for_pid_query(
    vp_token: &HashMap<String, Vec<VpTokenItem>>,
) -> Result<Vec<String>, String> {
    let items = vp_token
        .get(PID_QUERY_ID)
        .ok_or_else(|| format!("vp_token has no '{PID_QUERY_ID}' entry"))?;
    items
        .iter()
        .map(|item| match item {
            VpTokenItem::String(s) => Ok(s.clone()),
            _ => Err(format!(
                "query '{PID_QUERY_ID}': unsupported presentation format"
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;
    use ssi::claims::jwt::{AnyClaims, JWTClaims};
    use ssi::claims::sd_jwt::{
        json_pointer, ConcealJwtClaims as _, JsonPointer, KbJwtPayload, SdAlg, SdJwtBuf,
    };
    use ssi::claims::JwsPayload as _;
    use ssi::JWK;

    const NONCE: &str = "test-nonce";
    const AUD: &str = "https://verifier.example.org";
    const DISCLOSED_POINTERS: &[&JsonPointer] = &[
        json_pointer!("/given_name"),
        json_pointer!("/family_name"),
        json_pointer!("/birthdate"),
    ];

    /// Builds a synthetic issuer identity: a self-signed cert (embedded
    /// as `x5c` in the issuer JWK, same as `verify_presentation` expects
    /// to find in the real presentation's JWS header) plus its private
    /// JWK form, usable as a `ConcealJwtClaims` signer.
    fn issuer_identity() -> JWK {
        let signing_key = SigningKey::random(&mut OsRng);
        let cert = crate::identity::self_signed_cert(&signing_key, "Test Issuer").unwrap();
        let cert_der = cert.to_der().unwrap();

        let secret = p256::SecretKey::from(signing_key);
        let mut jwk: JWK = secret.to_jwk_string().parse().unwrap();
        jwk.x509_certificate_chain = Some(vec![base64::prelude::BASE64_STANDARD.encode(cert_der)]);
        jwk
    }

    /// Signs a synthetic PID-shaped SD-JWT (issuer JWT + disclosures +
    /// KB-JWT) for `holder_key`, with [`DISCLOSED_POINTERS`] revealed —
    /// exactly the claims `response.rs::REQUESTED_CLAIMS` asks for.
    async fn synthetic_presentation(
        issuer_key: &JWK,
        holder_key: &JWK,
        nonce: &str,
        aud: &str,
    ) -> String {
        let claims = JWTClaims::builder()
            .iss("https://issuer.example.org".to_owned())
            .iat(1_700_000_000)
            .with_private_claims(AnyClaims::from_iter([
                ("vct".to_owned(), json!("urn:eudi:pid:1")),
                ("cnf".to_owned(), json!({ "jwk": holder_key.to_public() })),
                ("given_name".to_owned(), json!("Erika")),
                ("family_name".to_owned(), json!("Mustermann")),
                ("birthdate".to_owned(), json!("1964-08-12")),
            ]))
            .unwrap();

        let sd_jwt = claims
            .conceal_and_sign(SdAlg::Sha256, DISCLOSED_POINTERS, issuer_key)
            .await
            .unwrap();

        let kb_jwt = KbJwtPayload::new(
            aud.to_owned(),
            nonce.to_owned(),
            SdAlg::Sha256,
            sd_jwt.as_sd_jwt(),
        )
        .sign(holder_key)
        .await
        .unwrap();
        let mut sd_jwt_buf: SdJwtBuf = sd_jwt.as_str().parse().unwrap();
        sd_jwt_buf.set_kb(&kb_jwt);
        sd_jwt_buf.into_string()
    }

    #[tokio::test]
    async fn accepts_a_well_formed_presentation_and_returns_exactly_the_disclosed_claims() {
        let issuer_key = issuer_identity();
        let holder_key = JWK::generate_p256();
        let presentation = synthetic_presentation(&issuer_key, &holder_key, NONCE, AUD).await;

        let disclosed = verify_presentation(&presentation, NONCE, AUD).unwrap();

        assert_eq!(disclosed.len(), 3);
        assert_eq!(disclosed.get("given_name").unwrap(), "Erika");
        assert_eq!(disclosed.get("family_name").unwrap(), "Mustermann");
        assert_eq!(disclosed.get("birthdate").unwrap(), "1964-08-12");
    }

    #[tokio::test]
    async fn rejects_a_nonce_mismatch() {
        let issuer_key = issuer_identity();
        let holder_key = JWK::generate_p256();
        let presentation = synthetic_presentation(&issuer_key, &holder_key, NONCE, AUD).await;

        assert!(verify_presentation(&presentation, "a-different-nonce", AUD).is_err());
    }

    #[tokio::test]
    async fn rejects_an_audience_mismatch() {
        let issuer_key = issuer_identity();
        let holder_key = JWK::generate_p256();
        let presentation = synthetic_presentation(&issuer_key, &holder_key, NONCE, AUD).await;

        assert!(
            verify_presentation(&presentation, NONCE, "https://someone-else.example.org").is_err()
        );
    }

    #[tokio::test]
    async fn rejects_a_key_binding_signed_by_the_wrong_holder_key() {
        let issuer_key = issuer_identity();
        let holder_key = JWK::generate_p256();
        let wrong_holder_key = JWK::generate_p256();

        // Sign the KB-JWT with a key that doesn't match `cnf.jwk` in the
        // issuer-signed payload.
        let claims = JWTClaims::builder()
            .iss("https://issuer.example.org".to_owned())
            .iat(1_700_000_000)
            .with_private_claims(AnyClaims::from_iter([(
                "cnf".to_owned(),
                json!({ "jwk": holder_key.to_public() }),
            )]))
            .unwrap();
        let sd_jwt = claims
            .conceal_and_sign(SdAlg::Sha256, &[] as &[&JsonPointer], &issuer_key)
            .await
            .unwrap();
        let kb_jwt = KbJwtPayload::new(
            AUD.to_owned(),
            NONCE.to_owned(),
            SdAlg::Sha256,
            sd_jwt.as_sd_jwt(),
        )
        .sign(&wrong_holder_key)
        .await
        .unwrap();
        let mut sd_jwt_buf: SdJwtBuf = sd_jwt.as_str().parse().unwrap();
        sd_jwt_buf.set_kb(&kb_jwt);

        assert!(verify_presentation(&sd_jwt_buf.into_string(), NONCE, AUD).is_err());
    }
}

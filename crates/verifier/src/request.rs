//! Builds a presentation request: a signed OID4VP Authorization Request
//! (JAR) asking for a subset of PID claims, via `openid4vp::verifier`.
//! Pure logic, no Axum — testable without a server.

use anyhow::{Context, Result};
use openid4vp::core::authorization_request::parameters::{
    ClientIdScheme, Nonce, ResponseMode, ResponseType,
};
use openid4vp::core::credential_format::{
    ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload,
};
use openid4vp::core::dcql_query::{
    DcqlCredentialClaimsQuery, DcqlCredentialClaimsQueryPath, DcqlCredentialQuery, DcqlQuery,
};
use openid4vp::core::metadata::{parameters::wallet::VpFormatsSupported, WalletMetadata};
use openid4vp::utils::NonEmptyVec;
use openid4vp::verifier::Verifier;
use url::Url;
use uuid::Uuid;

/// Signing algorithm this verifier's requests are signed with, and the
/// only one it accepts from a wallet's key-binding — matches `wallet`'s
/// own holder key (ES256 / P-256).
const SIGNING_ALG: &str = "ES256";

/// The only credential type this phase asks for — the PID `wallet issue`
/// already knows how to obtain from `issuer.eudiw.dev`.
const PID_VCT: &str = "urn:eudi:pid:1";

/// Deliberately a *subset* of PID claims, not "everything available" —
/// asking for specific claims and checking exactly those (and no others)
/// come back disclosed is what actually demonstrates selective
/// disclosure working, rather than just "some valid SD-JWT arrived".
pub const REQUESTED_CLAIMS: &[&str] = &["given_name", "family_name", "birthdate"];

/// The DCQL credential-query id used for the (single) PID request —
/// echoed back as a key in the wallet's `vp_token` map.
pub const PID_QUERY_ID: &str = "pid";

/// Builds the `WalletMetadata` this verifier targets: **not**
/// `WalletMetadata::openid4vp_scheme_static()` as-is (that default
/// declares `jwt_vc_json`, not `dc+sd-jwt`, and no
/// `ClientIdPrefixesSupported` at all — `request_builder.rs` would
/// reject `x509_hash` outright). Since we know exactly what our own
/// `wallet` declares (`wallet::present.rs::wallet_metadata()`), this
/// mirrors that shape from the other side.
fn target_wallet_metadata() -> Result<WalletMetadata> {
    let mut metadata = WalletMetadata::openid4vp_scheme_static();

    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::DcSdJwt,
        ClaimFormatPayload::Other(serde_json::json!({
            "sd-jwt_alg_values": [SIGNING_ALG],
            "kb-jwt_alg_values": [SIGNING_ALG],
        })),
    );
    *metadata.vp_formats_supported_mut() = VpFormatsSupported(vp_formats);

    metadata.add_client_id_prefixes_supported(&[ClientIdScheme(
        ClientIdScheme::X509_HASH.to_owned(),
    )])?;

    Ok(metadata)
}

/// Builds the DCQL query for a PID presentation with only
/// [`REQUESTED_CLAIMS`] revealed.
fn pid_dcql_query() -> Result<DcqlQuery> {
    let mut credential =
        DcqlCredentialQuery::new(PID_QUERY_ID.to_owned(), ClaimFormatDesignation::DcSdJwt);
    credential
        .meta_mut()
        .insert("vct_values".to_owned(), serde_json::json!([PID_VCT]));

    let mut claims: NonEmptyVec<DcqlCredentialClaimsQuery> = NonEmptyVec::new(claim_query(
        REQUESTED_CLAIMS
            .first()
            .context("REQUESTED_CLAIMS is empty")?,
    ));
    for claim in &REQUESTED_CLAIMS[1..] {
        claims.push(claim_query(claim));
    }
    credential.set_claims(Some(claims));

    Ok(DcqlQuery::new(NonEmptyVec::new(credential)))
}

fn claim_query(name: &str) -> DcqlCredentialClaimsQuery {
    DcqlCredentialClaimsQuery::new(NonEmptyVec::new(DcqlCredentialClaimsQueryPath::String(
        name.to_owned(),
    )))
}

/// Starts a new presentation session and returns the `(session id,
/// request URL)` a wallet should be pointed at.
pub async fn build_presentation_request(verifier: &Verifier) -> Result<(Uuid, Url)> {
    let dcql_query = pid_dcql_query().context("building the DCQL query")?;
    // A fresh nonce per request: what binds the wallet's KB-JWT to this
    // specific transaction (checked in `response.rs::verify_presentation`
    // against `session.authorization_request_object.nonce()`) — required
    // by OID4VP, not optional.
    let nonce = Nonce::from(Uuid::new_v4().to_string());
    verifier
        .build_authorization_request()
        .with_dcql_query(dcql_query)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(ResponseMode::DirectPost)
        .with_request_parameter(nonce)
        .build(target_wallet_metadata().context("building target wallet metadata")?)
        .await
        .context("building the authorization request")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use openid4vp::verifier::client::X509HashClient;
    use openid4vp::verifier::request_signer::P256Signer;
    use openid4vp::verifier::session::MemoryStore;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    /// A throwaway `Verifier` — same construction `serve.rs::build_verifier`
    /// uses, but with an in-memory identity instead of one loaded from disk.
    async fn throwaway_verifier() -> Verifier {
        let key = SigningKey::random(&mut OsRng);
        let cert = crate::identity::self_signed_cert(&key, "Test Verifier").unwrap();
        let signer = Arc::new(P256Signer::new(key).unwrap());
        let client = X509HashClient::new(vec![cert], signer).unwrap();

        Verifier::builder()
            .with_client(Arc::new(client))
            .with_session_store(Arc::new(MemoryStore::default()))
            .with_submission_endpoint("https://verifier.example.org/response".parse().unwrap())
            .by_reference("https://verifier.example.org/request".parse().unwrap())
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn builds_a_by_reference_request_url_for_the_stored_session() {
        let verifier = throwaway_verifier().await;

        let (uuid, url) = build_presentation_request(&verifier).await.unwrap();

        // Passed by reference (see `serve::build_verifier`'s `.by_reference`),
        // so the URL only carries a `request_uri` pointer, not the JWT itself.
        let request_uri = url
            .query_pairs()
            .find(|(k, _)| k == "request_uri")
            .map(|(_, v)| v.into_owned())
            .expect("request URL has no request_uri parameter");
        assert!(request_uri.starts_with("https://verifier.example.org/request/"));
        assert!(request_uri.ends_with(&uuid.to_string()));

        // The session this stored is retrievable and carries the JWT the
        // wallet will actually GET from that request_uri.
        let jwt = verifier.retrieve_authorization_request(uuid).await.unwrap();
        assert_eq!(
            jwt.split('.').count(),
            3,
            "expected a compact JWS (header.payload.signature)"
        );
    }

    #[test]
    fn dcql_query_asks_for_exactly_the_requested_pid_claims() {
        let dcql = pid_dcql_query().unwrap();

        assert_eq!(dcql.credentials().len(), 1);
        let credential = &dcql.credentials()[0];
        assert_eq!(*credential.format(), ClaimFormatDesignation::DcSdJwt);
        assert_eq!(
            credential.meta().get("vct_values"),
            Some(&serde_json::json!([PID_VCT]))
        );

        let claims = credential.claims().expect("claims should be set");
        assert_eq!(claims.len(), REQUESTED_CLAIMS.len());
        for (claim, expected_name) in claims.iter().zip(REQUESTED_CLAIMS) {
            assert_eq!(
                claim.path(),
                &[DcqlCredentialClaimsQueryPath::String(
                    (*expected_name).to_owned()
                )]
            );
        }
    }
}

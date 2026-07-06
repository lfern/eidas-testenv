use anyhow::{Context, Result};
use ssi::claims::sd_jwt::{KbJwtPayload, SdJwt, SdJwtBuf};
use ssi::claims::JwsPayload;
use ssi::JWK;

/// Appends a fresh key-binding JWT (KB-JWT) to a stored compact SD-JWT,
/// producing the string to send as an OID4VP `vp_token` entry.
///
/// This is a thin wrapper around `ssi::claims::sd_jwt` (the `ssi-sd-jwt`
/// crate, already in the dependency tree transitively via `ssi`) rather than
/// a hand-rolled SD-JWT parser/builder: it already implements compact
/// SD-JWT parsing and KB-JWT construction/signing correctly, so there's no
/// reason to reimplement it.
pub async fn append_key_binding(
    stored_sd_jwt: &str,
    audience: &str,
    nonce: &str,
    holder_key: &JWK,
) -> Result<String> {
    let sd_jwt = SdJwt::new(stored_sd_jwt)
        .map_err(|e| anyhow::anyhow!("stored credential is not a valid SD-JWT: {e}"))?;

    // The issuer's hashing algorithm choice (`_sd_alg`) is read back from the
    // stored credential itself rather than assumed, so this keeps working if
    // a future issuer picks something other than the near-universal
    // SHA-256.
    let decoded = sd_jwt.decode().context("decoding stored SD-JWT")?;
    let sd_alg = decoded.jwt.signing_bytes.payload.sd_alg;

    let kb_jwt = KbJwtPayload::new(audience.to_owned(), nonce.to_owned(), sd_alg, sd_jwt)
        .sign(holder_key)
        .await
        .map_err(|e| anyhow::anyhow!("signing key-binding JWT: {e}"))?;

    let mut sd_jwt_buf: SdJwtBuf = stored_sd_jwt
        .parse()
        .map_err(|e| anyhow::anyhow!("stored credential is not a valid SD-JWT: {e}"))?;
    sd_jwt_buf.set_kb(&kb_jwt);

    Ok(sd_jwt_buf.into_string())
}

#[cfg(test)]
mod tests {
    use ssi::claims::jwt::JWTClaims;
    use ssi::claims::sd_jwt::SdAlg;
    use ssi::claims::VerificationParameters;

    use super::*;

    #[tokio::test]
    async fn appends_a_key_binding_jwt_verifiable_with_the_holder_key() {
        let issuer_key = JWK::generate_p256();
        let holder_key = JWK::generate_p256();

        let claims = JWTClaims::builder()
            .iss("https://issuer.example.org".to_owned())
            .iat(1_700_000_000)
            .build()
            .unwrap();

        let no_concealed_claims: &[ssi::claims::sd_jwt::JsonPointerBuf] = &[];
        let sd_jwt =
            SdJwtBuf::conceal_and_sign(&claims, SdAlg::Sha256, no_concealed_claims, &issuer_key)
                .await
                .unwrap();

        let presented = append_key_binding(
            sd_jwt.as_str(),
            "https://verifier.example.org",
            "test-nonce",
            &holder_key,
        )
        .await
        .unwrap();

        // The presented credential is the stored one with a KB-JWT appended,
        // not a different or truncated string.
        assert!(presented.starts_with(sd_jwt.as_str()));

        let presented_sd_jwt = SdJwt::new(&presented).unwrap();
        let kb = presented_sd_jwt
            .decode_kb()
            .unwrap()
            .expect("a key-binding JWT was appended");

        assert_eq!(kb.signing_bytes.payload.aud, "https://verifier.example.org");
        assert!(kb
            .signing_bytes
            .payload
            .sd_hash
            .verify(SdAlg::Sha256, presented_sd_jwt));

        // The KB-JWT must actually verify against the holder's key — proof
        // that it was signed with the key this wallet controls, not some
        // other key.
        let params = VerificationParameters::from_resolver(&holder_key);
        kb.verify(&params)
            .await
            .expect("key-binding JWT verification failed")
            .expect("key-binding JWT signature is invalid");
    }
}

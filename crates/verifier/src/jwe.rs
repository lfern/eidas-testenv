//! Decrypts an incoming JARM (`response_mode=direct_post.jwt`) response
//! back into its `vp_token`/`state` payload, using this verifier's own
//! encryption keypair (see `identity.rs::enc_public_jwk`).
//!
//! `openid4vp::core::jwe` only builds the *encrypting* side
//! (`build_encrypted_response`, used by a wallet responding to a request
//! that declared an encryption key) — decrypting the response that comes
//! back is left to the verifier to implement. This uses the same
//! underlying `josekit` crate (same git rev `openid4vp` itself pins, see
//! `Cargo.toml`) that `build_encrypted_response` uses on the other side.

use anyhow::{Context, Result};
use openid4vp::core::response::parameters::VpToken;

/// Decrypts a compact JWE produced by a wallet's `build_encrypted_response`
/// and pulls out the `vp_token`/`state` claims it carries.
pub fn decrypt(jwe_compact: &str, enc_key: &p256::SecretKey) -> Result<(VpToken, Option<String>)> {
    // The private JWK (includes `d`) `josekit` needs to derive the shared
    // secret — same "EC" `x`/`y`/`d`/`crv` shape as the public form
    // `identity::enc_public_jwk` builds, just not stripped down to the
    // public half.
    let jwk_str = enc_key.to_jwk_string();
    let jwk = josekit::jwk::Jwk::from_bytes(jwk_str.as_bytes())
        .context("building a josekit JWK from the verifier's encryption key")?;
    let decrypter: josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter<p256::NistP256> =
        josekit::jwe::ECDH_ES
            .decrypter_from_jwk(&jwk)
            .context("building the ECDH-ES decrypter")?;

    let (payload, _header) = josekit::jwt::decode_with_decrypter(jwe_compact, &decrypter)
        .context("decrypting the JARM response")?;

    let vp_token_value = payload
        .claim("vp_token")
        .context("decrypted JARM payload has no vp_token")?
        .clone();
    let vp_token: VpToken =
        serde_json::from_value(vp_token_value).context("invalid vp_token in JARM payload")?;
    let state = payload
        .claim("state")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    Ok((vp_token, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    use openid4vp::core::response::parameters::VpTokenItem;
    use rand_core::OsRng;
    use serde_json::json;

    /// Round-trip against `openid4vp`'s own encrypting side
    /// (`core::jwe::JweBuilder`), so this test would fail if this
    /// module's understanding of the JWE shape ever drifted from what a
    /// real wallet actually sends.
    #[test]
    fn decrypts_a_jwe_built_by_josekits_own_encrypter_for_our_public_key() {
        let enc_key = p256::SecretKey::random(&mut OsRng);
        let public_jwk = crate::identity::enc_public_jwk(&enc_key).unwrap();

        let payload = json!({
            "vp_token": { "pid": ["some-presentation"] },
            "state": "abc123"
        });
        let jwe = openid4vp::core::jwe::JweBuilder::new()
            .payload(payload)
            .recipient_key_json(&serde_json::Value::Object(public_jwk))
            .unwrap()
            .alg("ECDH-ES")
            .build()
            .unwrap();

        let (vp_token, state) = decrypt(&jwe, &enc_key).unwrap();

        assert_eq!(state.as_deref(), Some("abc123"));
        let items = vp_token.0.get("pid").unwrap();
        assert_eq!(
            items,
            &vec![VpTokenItem::String("some-presentation".into())]
        );
    }

    #[test]
    fn rejects_a_jwe_encrypted_for_a_different_key() {
        let enc_key = p256::SecretKey::random(&mut OsRng);
        let someone_elses_key = p256::SecretKey::random(&mut OsRng);
        let public_jwk = crate::identity::enc_public_jwk(&someone_elses_key).unwrap();

        let jwe = openid4vp::core::jwe::JweBuilder::new()
            .payload(json!({ "vp_token": { "pid": ["x"] } }))
            .recipient_key_json(&serde_json::Value::Object(public_jwk))
            .unwrap()
            .alg("ECDH-ES")
            .build()
            .unwrap();

        assert!(decrypt(&jwe, &enc_key).is_err());
    }
}

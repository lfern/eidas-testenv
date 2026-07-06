use std::path::Path;

use anyhow::{Context, Result};
use ssi::JWK;

/// The holder's ES256 keypair, persisted as a JWK.
///
/// This is a test tool, not a real HSM-backed wallet: the private key is
/// stored in plaintext on disk (see storage module docs / README).
///
/// Represented as `ssi::JWK` (rather than a raw `p256` key) because both
/// `oid4vci` (issuance proofs) and `openid4vp` (presentation key-binding)
/// pin the same `ssi` version and expect this type directly.
pub struct HolderKey {
    pub jwk: JWK,
}

impl HolderKey {
    // Not used by the hand-rolled issuance flow (issue.rs skips
    // SimpleOid4vciClient/DPoP entirely); needed once present (Phase 3)
    // advertises the holder's public key to a verifier.
    #[allow(dead_code)]
    pub fn public_jwk(&self) -> JWK {
        self.jwk.to_public()
    }
}

/// Load the holder key from `path`, generating and persisting a new one if
/// it doesn't exist yet.
pub fn load_or_generate(path: &Path) -> Result<HolderKey> {
    // Reuse the same key across every issuance/presentation instead of
    // minting a fresh one each run: this key is what a credential's
    // `cnf.jwk` claim gets bound to, so it needs to stay stable for that
    // binding to mean anything over time.
    if path.exists() {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading holder key from {path:?}"))?;
        let jwk: JWK = contents
            .parse()
            .with_context(|| format!("parsing holder key JWK at {path:?}"))?;
        return Ok(HolderKey { jwk });
    }

    let jwk = JWK::generate_p256();
    let contents = serde_json::to_string_pretty(&jwk).context("serializing holder key JWK")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {parent:?}"))?;
    }
    std::fs::write(path, contents).with_context(|| format!("writing holder key to {path:?}"))?;
    Ok(HolderKey { jwk })
}

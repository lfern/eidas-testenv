use std::path::Path;

use anyhow::{Context, Result};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::JwkEcKey;
use p256::SecretKey;
use serde::{Deserialize, Serialize};

/// The holder's ES256 keypair, persisted as a JWK.
///
/// This is a test tool, not a real HSM-backed wallet: the private key is
/// stored in plaintext on disk (see storage module docs / README).
// signing_key()/public_jwk() are consumed by the issue (Phase 2) and
// present (Phase 3) flows, not yet wired up in Phase 1.
#[allow(dead_code)]
pub struct HolderKey {
    pub secret: SecretKey,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    jwk: JwkEcKey,
}

#[allow(dead_code)]
impl HolderKey {
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from(&self.secret)
    }

    pub fn public_jwk(&self) -> JwkEcKey {
        self.secret.public_key().to_jwk()
    }
}

/// Load the holder key from `path`, generating and persisting a new one if
/// it doesn't exist yet.
pub fn load_or_generate(path: &Path) -> Result<HolderKey> {
    if path.exists() {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading holder key from {path:?}"))?;
        let stored: StoredKey = serde_json::from_str(&contents)
            .with_context(|| format!("parsing holder key JWK at {path:?}"))?;
        let secret = SecretKey::from_jwk(&stored.jwk).context("decoding holder key JWK")?;
        return Ok(HolderKey { secret });
    }

    let secret = SecretKey::random(&mut rand_core::OsRng);
    let stored = StoredKey {
        jwk: secret.to_jwk(),
    };
    let contents = serde_json::to_string_pretty(&stored).context("serializing holder key JWK")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {parent:?}"))?;
    }
    std::fs::write(path, contents).with_context(|| format!("writing holder key to {path:?}"))?;
    Ok(HolderKey { secret })
}

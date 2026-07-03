use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::holder_key::{self, HolderKey};

// `key` and the save/lookup methods below are consumed by the issue
// (Phase 2) and present (Phase 3) flows, not yet wired up in Phase 1.
#[allow(dead_code)]
pub struct Wallet {
    pub root: PathBuf,
    pub key: HolderKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredCredential {
    pub id: String,
    pub credential_configuration_id: String,
    pub vct: String,
    pub issuer: String,
    pub received_at: String,
    pub sd_jwt: String,
}

#[allow(dead_code)]
impl Wallet {
    /// Resolve `~/.eidas-testenv/wallet/`, creating it (and loading or
    /// generating the holder key) if needed.
    pub fn open() -> Result<Self> {
        let home = directories::BaseDirs::new()
            .context("resolving home directory")?
            .home_dir()
            .to_path_buf();
        let root = home.join(".eidas-testenv").join("wallet");
        std::fs::create_dir_all(root.join("credentials"))
            .with_context(|| format!("creating wallet directory {root:?}"))?;
        let key = holder_key::load_or_generate(&root.join("key.json"))?;
        Ok(Wallet { root, key })
    }

    fn credentials_dir(&self) -> PathBuf {
        self.root.join("credentials")
    }

    pub fn save_credential(&self, cred: &StoredCredential) -> Result<()> {
        let path = self.credentials_dir().join(format!("{}.json", cred.id));
        let contents = serde_json::to_string_pretty(cred).context("serializing credential")?;
        std::fs::write(&path, contents).with_context(|| format!("writing credential to {path:?}"))
    }

    pub fn list_credentials(&self) -> Result<Vec<StoredCredential>> {
        let dir = self.credentials_dir();
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).with_context(|| format!("reading {dir:?}"))? {
            let entry = entry.with_context(|| format!("reading entry in {dir:?}"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading credential {path:?}"))?;
            let cred: StoredCredential = serde_json::from_str(&contents)
                .with_context(|| format!("parsing credential {path:?}"))?;
            out.push(cred);
        }
        out.sort_by(|a, b| a.received_at.cmp(&b.received_at));
        Ok(out)
    }

    /// Find a stored credential matching the given verifiable credential
    /// type (`vct`), for use in the OID4VP presentation flow.
    pub fn find_credential_by_vct(&self, vct: &str) -> Result<Option<StoredCredential>> {
        Ok(self.list_credentials()?.into_iter().find(|c| c.vct == vct))
    }
}

pub fn list_and_print() -> Result<()> {
    let wallet = Wallet::open()?;
    let creds = wallet.list_credentials()?;
    if creds.is_empty() {
        println!("No credentials stored in {:?}", wallet.credentials_dir());
        return Ok(());
    }
    for cred in creds {
        println!(
            "{}  vct={}  issuer={}  received_at={}",
            cred.id, cred.vct, cred.issuer, cred.received_at
        );
    }
    Ok(())
}

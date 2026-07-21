use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::holder_key::{self, HolderKey};

/// The local wallet state: its root directory on disk and its holder key.
pub struct Wallet {
    pub root: PathBuf,
    pub key: HolderKey,
}

/// A credential received from an issuer (Phase 2), persisted as-is.
///
/// The wallet never parses or verifies `sd_jwt` — it's stored opaque and
/// only read back to be handed to a verifier (Phase 3).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredCredential {
    pub id: String,
    pub credential_configuration_id: String,
    pub vct: String,
    pub issuer: String,
    pub received_at: String,
    pub sd_jwt: String,
}

impl Wallet {
    /// Resolve `~/.eidas-testenv/wallet/`, creating it (and loading or
    /// generating the holder key) if needed.
    pub fn open() -> Result<Self> {
        let home = directories::BaseDirs::new()
            .context("resolving home directory")?
            .home_dir()
            .to_path_buf();
        Self::open_at(home.join(".eidas-testenv").join("wallet"))
    }

    /// Same as [`Wallet::open`], but at an arbitrary root — split out so
    /// tests can point it at a temporary directory instead of the real
    /// `~/.eidas-testenv`.
    fn open_at(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(root.join("credentials"))
            .with_context(|| format!("creating wallet directory {root:?}"))?;
        let key = holder_key::load_or_generate(&root.join("key.json"))?;
        Ok(Wallet { root, key })
    }

    fn credentials_dir(&self) -> PathBuf {
        self.root.join("credentials")
    }

    /// Writes one credential as `credentials/<id>.json`.
    pub fn save_credential(&self, cred: &StoredCredential) -> Result<()> {
        let path = self.credentials_dir().join(format!("{}.json", cred.id));
        let contents = serde_json::to_string_pretty(cred).context("serializing credential")?;
        std::fs::write(&path, contents).with_context(|| format!("writing credential to {path:?}"))
    }

    /// Reads every `credentials/*.json` file, oldest first.
    pub fn list_credentials(&self) -> Result<Vec<StoredCredential>> {
        let dir = self.credentials_dir();
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).with_context(|| format!("reading {dir:?}"))? {
            let entry = entry.with_context(|| format!("reading entry in {dir:?}"))?;
            let path = entry.path();
            // Skip anything that isn't a credential file we wrote
            // ourselves (e.g. stray files a user might drop in there).
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading credential {path:?}"))?;
            let cred: StoredCredential = serde_json::from_str(&contents)
                .with_context(|| format!("parsing credential {path:?}"))?;
            out.push(cred);
        }
        // received_at is an RFC 3339 string, so lexicographic order is
        // chronological order.
        out.sort_by(|a, b| a.received_at.cmp(&b.received_at));
        Ok(out)
    }

    /// Find the most recently received stored credential matching the given
    /// verifiable credential type (`vct`), for use in the OID4VP
    /// presentation flow.
    pub fn find_credential_by_vct(&self, vct: &str) -> Result<Option<StoredCredential>> {
        Ok(self
            .list_credentials()?
            .into_iter()
            .filter(|c| c.vct == vct)
            .max_by_key(|c| c.received_at.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Wallet` rooted in a scratch directory under the OS temp dir,
    /// cleaned up when dropped — no `~/.eidas-testenv` involved.
    struct TempWallet {
        wallet: Wallet,
        root: PathBuf,
    }

    impl Drop for TempWallet {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn temp_wallet() -> TempWallet {
        let root = std::env::temp_dir().join(format!(
            "eidas-testenv-wallet-test-{}",
            uuid::Uuid::new_v4()
        ));
        let wallet = Wallet::open_at(root.clone()).unwrap();
        TempWallet { wallet, root }
    }

    fn sample_credential(id: &str, vct: &str, received_at: &str) -> StoredCredential {
        StoredCredential {
            id: id.to_owned(),
            credential_configuration_id: "eu.europa.ec.eudi.pid_vc_sd_jwt".to_owned(),
            vct: vct.to_owned(),
            issuer: "https://issuer.example.org".to_owned(),
            received_at: received_at.to_owned(),
            sd_jwt: "header.payload.sig~".to_owned(),
        }
    }

    #[test]
    fn starts_empty_and_round_trips_a_saved_credential() {
        let temp = temp_wallet();

        assert!(temp.wallet.list_credentials().unwrap().is_empty());

        let cred = sample_credential("cred-1", "urn:eudi:pid:1", "2026-01-01T00:00:00Z");
        temp.wallet.save_credential(&cred).unwrap();

        let listed = temp.wallet.list_credentials().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "cred-1");
        assert_eq!(listed[0].vct, "urn:eudi:pid:1");
    }

    #[test]
    fn lists_credentials_oldest_first() {
        let temp = temp_wallet();

        temp.wallet
            .save_credential(&sample_credential(
                "newer",
                "urn:eudi:pid:1",
                "2026-06-01T00:00:00Z",
            ))
            .unwrap();
        temp.wallet
            .save_credential(&sample_credential(
                "older",
                "urn:eudi:pid:1",
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();

        let listed = temp.wallet.list_credentials().unwrap();
        assert_eq!(listed[0].id, "older");
        assert_eq!(listed[1].id, "newer");
    }

    #[test]
    fn find_credential_by_vct_matches_and_misses() {
        let temp = temp_wallet();

        temp.wallet
            .save_credential(&sample_credential(
                "cred-1",
                "urn:eudi:pid:1",
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();

        assert!(temp
            .wallet
            .find_credential_by_vct("urn:eudi:pid:1")
            .unwrap()
            .is_some());
        assert!(temp
            .wallet
            .find_credential_by_vct("urn:eudi:other:1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn find_credential_by_vct_picks_the_most_recent_match() {
        let temp = temp_wallet();

        temp.wallet
            .save_credential(&sample_credential(
                "older",
                "urn:eudi:pid:1",
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();
        temp.wallet
            .save_credential(&sample_credential(
                "newer",
                "urn:eudi:pid:1",
                "2026-06-01T00:00:00Z",
            ))
            .unwrap();

        let found = temp
            .wallet
            .find_credential_by_vct("urn:eudi:pid:1")
            .unwrap()
            .unwrap();
        assert_eq!(found.id, "newer");
    }
}

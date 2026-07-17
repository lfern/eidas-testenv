//! Disk layout for the generated test PKI: one directory per role under
//! the chosen output directory, each holding a `cert.pem`/`key.pem` pair.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Every certificate role `ca bootstrap` produces, in issuance order.
pub const ROLES: &[&str] = &["root", "sub-ca", "tsa", "ocsp", "user-p256", "user-rsa2048"];

/// Directory holding a given role's `cert.pem`/`key.pem`.
pub fn role_dir(out_dir: &Path, role: &str) -> PathBuf {
    out_dir.join(role)
}

/// Writes a role's certificate and private key, both already PEM-encoded.
pub fn write_pair(out_dir: &Path, role: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
    let dir = role_dir(out_dir, role);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::write(dir.join("cert.pem"), cert_pem)
        .with_context(|| format!("writing {}/cert.pem", dir.display()))?;
    fs::write(dir.join("key.pem"), key_pem)
        .with_context(|| format!("writing {}/key.pem", dir.display()))?;
    Ok(())
}

/// Reads back a role's `cert.pem` contents, for `ca list`.
pub fn read_cert_pem(out_dir: &Path, role: &str) -> Result<String> {
    let path = role_dir(out_dir, role).join("cert.pem");
    fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// True if `out_dir` doesn't exist yet, or exists but is empty.
pub fn is_empty_or_absent(out_dir: &Path) -> Result<bool> {
    match fs::read_dir(out_dir) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err).with_context(|| format!("reading {}", out_dir.display())),
    }
}

/// Removes `out_dir` and everything under it, for `--force`.
pub fn clear(out_dir: &Path) -> Result<()> {
    match fs::remove_dir_all(out_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing {}", out_dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("eidas-testenv-ca-test-{name}-{}", uuid_like()))
    }

    // Avoids pulling in the `uuid` crate just for test scratch dirs.
    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn is_empty_or_absent_true_for_missing_dir() {
        let dir = temp_dir("missing");
        assert!(is_empty_or_absent(&dir).unwrap());
    }

    #[test]
    fn write_pair_then_read_back_round_trips() {
        let dir = temp_dir("roundtrip");
        assert!(is_empty_or_absent(&dir).unwrap());

        write_pair(&dir, "root", "CERT-CONTENTS", "KEY-CONTENTS").unwrap();
        assert!(!is_empty_or_absent(&dir).unwrap());
        assert_eq!(read_cert_pem(&dir, "root").unwrap(), "CERT-CONTENTS");

        clear(&dir).unwrap();
        assert!(is_empty_or_absent(&dir).unwrap());
    }
}

//! Core CAdES B-B signing logic, independent of Axum so it's testable
//! without a server: load a `ca bootstrap`-issued cert+key pair from disk
//! and sign arbitrary bytes with it via `ades-rs`.

use std::fs;
use std::path::Path;

use ades::{cades, signer::SoftSigner, DigestAlgorithm};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::pkcs8::DecodePrivateKey as _;
use serde::Serialize;
use x509_cert::der::{DecodePem, Encode};

/// Certificate roles `ca bootstrap` produces that are usable as signing
/// identities here (`root`/`sub-ca`/`tsa`/`ocsp` are plumbing, not meant to
/// sign arbitrary documents).
const SIGNING_ROLES: &[&str] = &["user-p256", "user-rsa2048"];

/// Result of one [`sign`] call.
#[derive(Serialize)]
pub struct SignOutcome {
    /// Base64 of the DER-encoded CMS `ContentInfo` (detached CAdES B-B).
    pub signature_der_base64: String,
    pub cert_role: String,
    pub digest_algorithm: String,
}

/// Reads `<ca_dir>/<role>/{cert.pem,key.pem}` and builds the matching
/// `SoftSigner` (RSA for `user-rsa2048`, ECDSA P-256 for `user-p256`).
fn load_signer(ca_dir: &Path, role: &str) -> Result<SoftSigner> {
    let dir = ca_dir.join(role);
    let cert_pem = fs::read_to_string(dir.join("cert.pem"))
        .with_context(|| format!("reading {}/cert.pem", dir.display()))?;
    let key_pem = fs::read_to_string(dir.join("key.pem"))
        .with_context(|| format!("reading {}/key.pem", dir.display()))?;

    let cert_der = x509_cert::Certificate::from_pem(cert_pem.as_bytes())
        .with_context(|| format!("parsing {}/cert.pem", dir.display()))?
        .to_der()
        .with_context(|| format!("re-encoding {}/cert.pem as DER", dir.display()))?;

    match role {
        "user-rsa2048" => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem)
                .with_context(|| format!("parsing {}/key.pem", dir.display()))?;
            SoftSigner::from_parts(key, &cert_der, DigestAlgorithm::Sha256)
                .context("building RSA signer")
        }
        "user-p256" => {
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem)
                .with_context(|| format!("parsing {}/key.pem", dir.display()))?;
            SoftSigner::from_ec_parts(key, &cert_der, DigestAlgorithm::Sha256)
                .context("building EC signer")
        }
        other => bail!("unsupported cert_role {other:?} (expected one of {SIGNING_ROLES:?})"),
    }
}

/// Signs `data` with the identity at `<ca_dir>/<cert_role>/`, producing a
/// detached CAdES B-B (CMS/PKCS#7) signature.
pub fn sign(ca_dir: &Path, cert_role: &str, data: &[u8]) -> Result<SignOutcome> {
    if !SIGNING_ROLES.contains(&cert_role) {
        bail!("unsupported cert_role {cert_role:?} (expected one of {SIGNING_ROLES:?})");
    }
    let signer = load_signer(ca_dir, cert_role)?;
    let signature_der = cades::sign(data, &signer).context("CAdES B-B signing failed")?;
    Ok(SignOutcome {
        signature_der_base64: STANDARD.encode(signature_der),
        cert_role: cert_role.to_owned(),
        digest_algorithm: "Sha256".to_owned(),
    })
}

/// The signing roles that actually have a `cert.pem` under `ca_dir`, for
/// the UI to only offer certs that exist.
pub fn available_cert_roles(ca_dir: &Path) -> Vec<String> {
    SIGNING_ROLES
        .iter()
        .filter(|role| ca_dir.join(role).join("cert.pem").is_file())
        .map(|role| (*role).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ades::signer::Signer as _;
    use p256::pkcs8::EncodePrivateKey as _;
    use rsa::rand_core::OsRng;
    use x509_cert::der::pem::LineEnding;
    use x509_cert::der::{Decode as _, EncodePem as _};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eidas-testenv-portal-test-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Writes a freshly generated P-256 identity as `<ca_dir>/user-p256/`,
    /// mirroring what `ca bootstrap` would have written.
    fn write_p256_identity(ca_dir: &Path) {
        let signer = SoftSigner::generate_ec().unwrap();
        let dir = ca_dir.join("user-p256");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("cert.pem"),
            x509_cert::Certificate::from_der(signer.certificate().to_der())
                .unwrap()
                .to_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        // `SoftSigner` doesn't expose the private key it generated, so
        // `key.pem` here is a freshly generated, unrelated key rather than
        // the one embedded in `cert.pem` above. That's fine for this test:
        // it only exercises the PEM-loading -> `cades::sign` plumbing, not
        // cryptographic correctness (cert/key correspondence is guaranteed
        // in production by `ca bootstrap` writing both from the same key
        // pair, and checked end-to-end by the external verification in
        // ROADMAP.md, not by this unit test).
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        fs::write(
            dir.join("key.pem"),
            key.to_pkcs8_pem(LineEnding::LF).unwrap(),
        )
        .unwrap();
    }

    /// Writes a freshly generated RSA-2048 identity as
    /// `<ca_dir>/user-rsa2048/`, mirroring what `ca bootstrap` would have
    /// written.
    fn write_rsa_identity(ca_dir: &Path) {
        let signer = SoftSigner::generate(2048).unwrap();
        let dir = ca_dir.join("user-rsa2048");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("cert.pem"),
            x509_cert::Certificate::from_der(signer.certificate().to_der())
                .unwrap()
                .to_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        // See the comment in `write_p256_identity`: an unrelated key is
        // fine here too, for the same reason.
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        fs::write(
            dir.join("key.pem"),
            key.to_pkcs8_pem(LineEnding::LF).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn signs_with_p256_identity() {
        let ca_dir = temp_dir("p256");
        write_p256_identity(&ca_dir);

        let outcome = sign(&ca_dir, "user-p256", b"hello world").unwrap();
        assert_eq!(outcome.cert_role, "user-p256");
        let der = STANDARD.decode(outcome.signature_der_base64).unwrap();
        assert_eq!(der[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

        fs::remove_dir_all(&ca_dir).unwrap();
    }

    #[test]
    fn signs_with_rsa_identity() {
        let ca_dir = temp_dir("rsa");
        write_rsa_identity(&ca_dir);

        let outcome = sign(&ca_dir, "user-rsa2048", b"hello world").unwrap();
        assert_eq!(outcome.cert_role, "user-rsa2048");
        let der = STANDARD.decode(outcome.signature_der_base64).unwrap();
        assert_eq!(der[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

        fs::remove_dir_all(&ca_dir).unwrap();
    }

    #[test]
    fn rejects_unknown_cert_role() {
        let ca_dir = temp_dir("unknown-role");
        assert!(sign(&ca_dir, "root", b"data").is_err());
    }

    #[test]
    fn available_cert_roles_lists_only_existing_certs() {
        let ca_dir = temp_dir("available-roles");
        write_p256_identity(&ca_dir);

        assert_eq!(available_cert_roles(&ca_dir), vec!["user-p256"]);

        fs::remove_dir_all(&ca_dir).unwrap();
    }
}

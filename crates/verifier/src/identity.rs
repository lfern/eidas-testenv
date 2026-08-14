//! The verifier's own signing identity: a self-signed P-256 certificate
//! used to sign presentation requests (JAR, `x509_hash` client_id_scheme).
//!
//! Generated once and persisted (same "generate-or-load, keep stable
//! across runs" pattern as `wallet::holder_key`) rather than minted fresh
//! per run. **Not** issued by `ca bootstrap`: `ca` is a closed crate
//! scoped to AdES signing identities (TSA/OCSP/user), and `wallet`'s
//! `x509_hash` validation (see `wallet::present.rs`) never checks a
//! chain up to a root anyway — a self-signed leaf is exactly as trusted
//! as a `ca`-issued one from the wallet's point of view, so depending on
//! `ca` here would add a dependency for no functional gain.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use anyhow::{Context, Result};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::OsRng;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{DecodePem, EncodePem};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

/// This verifier's signing identity: a self-signed P-256 certificate and
/// the key that signs with it. Also carries a second, unrelated P-256
/// keypair (`enc_key`) used only for JARM (`response_mode=direct_post.jwt`)
/// response encryption — a distinct key by design, since `openid4vp`'s own
/// `find_encryption_jwk` (`core::jwe.rs`) requires the JWKS entry to carry
/// `alg=ECDH-ES`/`use=enc`, which is a different key *usage* than the
/// `key`/`cert` pair's ECDSA request-signing role, even though both
/// happen to sit on the same curve.
pub struct Identity {
    pub cert: Certificate,
    pub key: SigningKey,
    pub enc_key: p256::SecretKey,
}

/// Random 20-byte serial number, same RFC 5280-style convention
/// `ca::bootstrap` already uses (top bit cleared, no extra DER sign byte).
fn random_serial() -> Result<SerialNumber> {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    SerialNumber::new(&bytes).context("building serial number")
}

/// Builds a self-signed certificate for `key` — split out from
/// [`generate`] so tests (`response.rs`) can build a synthetic issuer
/// identity with a specific, known key instead of a freshly random one.
pub(crate) fn self_signed_cert(key: &SigningKey, common_name: &str) -> Result<Certificate> {
    let pub_key =
        SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).context("encoding public key")?;
    let subject = Name::from_str(&format!("CN={common_name},O=eidas-testenv"))
        .context("parsing subject name")?;
    let validity = Validity::from_now(std::time::Duration::from_secs(10 * 365 * 86_400)) // 10 years
        .context("building validity")?;
    let builder = CertificateBuilder::new(
        Profile::Root,
        random_serial()?,
        validity,
        subject,
        pub_key,
        key,
    )
    .context("building certificate")?;
    builder
        .build::<DerSignature>()
        .context("signing certificate")
}

fn generate() -> Result<Identity> {
    let key = SigningKey::random(&mut OsRng);
    let cert = self_signed_cert(&key, "eidas-testenv Test Verifier")?;
    let enc_key = p256::SecretKey::random(&mut OsRng);
    Ok(Identity { cert, key, enc_key })
}

/// Loads the verifier's identity from `<dir>/{cert.pem,key.pem,enc_key.pem}`,
/// generating and persisting a new one if it doesn't exist yet.
pub fn load_or_generate(dir: &Path) -> Result<Identity> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let enc_key_path = dir.join("enc_key.pem");

    if cert_path.exists() && key_path.exists() && enc_key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading {}", key_path.display()))?;
        let enc_key_pem = std::fs::read_to_string(&enc_key_path)
            .with_context(|| format!("reading {}", enc_key_path.display()))?;
        let cert = Certificate::from_pem(cert_pem.as_bytes())
            .with_context(|| format!("parsing {}", cert_path.display()))?;
        let key = SigningKey::from_pkcs8_pem(&key_pem)
            .with_context(|| format!("parsing {}", key_path.display()))?;
        let enc_key = p256::SecretKey::from_pkcs8_pem(&enc_key_pem)
            .with_context(|| format!("parsing {}", enc_key_path.display()))?;
        return Ok(Identity { cert, key, enc_key });
    }

    let identity = generate()?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating directory {}", dir.display()))?;
    std::fs::write(
        &cert_path,
        identity
            .cert
            .to_pem(LineEnding::LF)
            .context("encoding verifier certificate as PEM")?,
    )
    .with_context(|| format!("writing {}", cert_path.display()))?;
    std::fs::write(
        &key_path,
        identity
            .key
            .to_pkcs8_pem(LineEnding::LF)
            .context("encoding verifier key as PEM")?,
    )
    .with_context(|| format!("writing {}", key_path.display()))?;
    std::fs::write(
        &enc_key_path,
        identity
            .enc_key
            .to_pkcs8_pem(LineEnding::LF)
            .context("encoding verifier encryption key as PEM")?,
    )
    .with_context(|| format!("writing {}", enc_key_path.display()))?;
    Ok(identity)
}

/// This verifier's JARM encryption key, as a public JWK with the
/// `use`/`alg` parameters `openid4vp::core::jwe::find_encryption_jwk`
/// requires (`use=enc`, `alg=ECDH-ES`) — neither is part of the bare JWK
/// `p256::PublicKey::to_jwk_string()` produces, so they're added here.
/// Meant to go straight into the `jwks` entry of the `client_metadata`
/// this verifier's presentation requests carry (see `request.rs`).
pub fn enc_public_jwk(
    enc_key: &p256::SecretKey,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let jwk_str = enc_key.public_key().to_jwk_string();
    let mut jwk: serde_json::Value =
        serde_json::from_str(&jwk_str).context("serializing verifier encryption public key")?;
    let map = jwk
        .as_object_mut()
        .context("expected the encryption public key's JWK to be a JSON object")?;
    map.insert("use".to_owned(), serde_json::json!("enc"));
    map.insert("alg".to_owned(), serde_json::json!("ECDH-ES"));
    map.insert("kid".to_owned(), serde_json::json!("verifier-enc-1"));
    Ok(map.clone())
}

/// Resolves `~/.eidas-testenv/verifier/`, same base directory convention
/// as `wallet` (`~/.eidas-testenv/wallet/`).
pub fn default_dir() -> Result<PathBuf> {
    let home = directories::BaseDirs::new()
        .context("resolving home directory")?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".eidas-testenv").join("verifier"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Encode as _;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "eidas-testenv-verifier-test-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn generates_and_persists_a_new_identity() {
        let dir = temp_dir("generate");
        assert!(!dir.join("cert.pem").exists());

        let identity = load_or_generate(&dir).unwrap();
        assert!(dir.join("cert.pem").is_file());
        assert!(dir.join("key.pem").is_file());
        assert!(dir.join("enc_key.pem").is_file());
        // Self-signed: the cert's own key must verify its own signature,
        // i.e. it was signed by `identity.key`, not some other key.
        assert_eq!(
            identity
                .cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key,
            der::asn1::BitString::from_bytes(
                identity
                    .key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
            )
            .unwrap()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reuses_a_persisted_identity_instead_of_generating_a_new_one() {
        let dir = temp_dir("reuse");
        let first = load_or_generate(&dir).unwrap();
        let second = load_or_generate(&dir).unwrap();

        assert_eq!(first.key.to_bytes(), second.key.to_bytes());
        assert_eq!(first.cert.to_der().unwrap(), second.cert.to_der().unwrap());
        assert_eq!(
            first.enc_key.to_bytes(),
            second.enc_key.to_bytes(),
            "encryption key should also be reused, not regenerated"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn enc_public_jwk_carries_the_parameters_josekit_requires() {
        let dir = temp_dir("enc-jwk");
        let identity = load_or_generate(&dir).unwrap();
        let jwk = enc_public_jwk(&identity.enc_key).unwrap();

        assert_eq!(jwk.get("kty").unwrap(), "EC");
        assert_eq!(jwk.get("crv").unwrap(), "P-256");
        assert_eq!(jwk.get("use").unwrap(), "enc");
        assert_eq!(jwk.get("alg").unwrap(), "ECDH-ES");
        assert!(jwk.get("d").is_none(), "must be the public key only");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

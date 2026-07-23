//! Builds the full test PKI chain: a self-signed root CA, an intermediate
//! sub-CA, and four leaf certificates signed by the sub-CA — a TSA
//! responder cert, an OCSP responder cert, and two user/signing certs (one
//! P-256, one RSA-2048, so `ades-rs` can be exercised against both
//! algorithms).

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use const_oid::db::rfc5280::{ID_KP_OCSP_SIGNING, ID_KP_TIME_STAMPING};
use p256::ecdsa::{DerSignature, SigningKey as P256SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use signature::Keypair;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::EncodePem;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use crate::storage;

const ORG: &str = "eidas-testenv";

fn years(n: u64) -> Duration {
    Duration::from_secs(n * 365 * 86_400)
}

/// A random 20-byte serial number, RFC 5280-style (unpredictable, unique
/// per certificate). The top bit of the first byte is cleared so the DER
/// INTEGER encoding never needs an extra sign-preserving byte.
fn random_serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 20];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    bytes[0] &= 0x7f;
    SerialNumber::new(&bytes).context("building serial number")
}

fn subject(cn: &str) -> Result<Name> {
    Name::from_str(&format!("CN={cn},O={ORG}")).context("parsing subject name")
}

/// A freshly issued P-256 certificate plus the key that signs its
/// children — root/sub-ca/tsa/ocsp/user-p256 all share this shape.
struct IssuedP256 {
    cert: Certificate,
    key: P256SigningKey,
}

fn issue_root() -> Result<IssuedP256> {
    let key = P256SigningKey::random(&mut OsRng);
    let pub_key = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())
        .context("encoding root public key")?;
    let builder = CertificateBuilder::new(
        Profile::Root,
        random_serial()?,
        Validity::from_now(years(20)).context("root validity")?,
        subject("eidas-testenv Test Root CA")?,
        pub_key,
        &key,
    )
    .context("building root certificate")?;
    let cert = builder
        .build::<DerSignature>()
        .context("signing root certificate")?;
    Ok(IssuedP256 { cert, key })
}

fn issue_sub_ca(root: &IssuedP256) -> Result<IssuedP256> {
    let key = P256SigningKey::random(&mut OsRng);
    let pub_key = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())
        .context("encoding sub-ca public key")?;
    let profile = Profile::SubCA {
        issuer: root.cert.tbs_certificate.subject.clone(),
        path_len_constraint: Some(0),
    };
    let builder = CertificateBuilder::new(
        profile,
        random_serial()?,
        Validity::from_now(years(10)).context("sub-ca validity")?,
        subject("eidas-testenv Test Sub-CA")?,
        pub_key,
        &root.key,
    )
    .context("building sub-ca certificate")?;
    let cert = builder
        .build::<DerSignature>()
        .context("signing sub-ca certificate")?;
    Ok(IssuedP256 { cert, key })
}

/// Issues a P-256 leaf certificate signed by `sub_ca`, optionally adding an
/// extended key usage restriction (TSA/OCSP need one, the user cert doesn't).
fn issue_p256_leaf(
    sub_ca: &IssuedP256,
    cn: &str,
    validity_years: u64,
    eku: Option<&ExtendedKeyUsage>,
) -> Result<IssuedP256> {
    let key = P256SigningKey::random(&mut OsRng);
    let pub_key = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())
        .context("encoding leaf public key")?;
    let profile = Profile::Leaf {
        issuer: sub_ca.cert.tbs_certificate.subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
        // `true` keeps the SubjectKeyIdentifier extension that was always
        // emitted before "hazmat" made this field exist — dropping it
        // would silently regress the AKI/SKI chain check `ca list`'s
        // `openssl verify` round already relies on.
        include_subject_key_identifier: true,
    };
    let mut builder = CertificateBuilder::new(
        profile,
        random_serial()?,
        Validity::from_now(years(validity_years)).context("leaf validity")?,
        subject(cn)?,
        pub_key,
        &sub_ca.key,
    )
    .context("building leaf certificate")?;
    if let Some(eku) = eku {
        builder
            .add_extension(eku)
            .context("adding extended key usage extension")?;
    }
    let cert = builder
        .build::<DerSignature>()
        .context("signing leaf certificate")?;
    Ok(IssuedP256 { cert, key })
}

fn issue_rsa_leaf(
    sub_ca: &IssuedP256,
    cn: &str,
    validity_years: u64,
) -> Result<(Certificate, RsaPrivateKey)> {
    let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).context("generating RSA-2048 key")?;
    let signing_key = RsaSigningKey::<Sha256>::new(priv_key.clone());
    let pub_key = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
        .context("encoding leaf public key")?;
    let profile = Profile::Leaf {
        issuer: sub_ca.cert.tbs_certificate.subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
        // `true` keeps the SubjectKeyIdentifier extension that was always
        // emitted before "hazmat" made this field exist — dropping it
        // would silently regress the AKI/SKI chain check `ca list`'s
        // `openssl verify` round already relies on.
        include_subject_key_identifier: true,
    };
    // The leaf's own key (RSA-2048) only backs its subject public key —
    // the certificate itself is signed by the sub-CA's (P-256) key, same
    // as every other leaf in the chain.
    let builder = CertificateBuilder::new(
        profile,
        random_serial()?,
        Validity::from_now(years(validity_years)).context("leaf validity")?,
        subject(cn)?,
        pub_key,
        &sub_ca.key,
    )
    .context("building leaf certificate")?;
    let cert = builder
        .build::<DerSignature>()
        .context("signing leaf certificate")?;
    Ok((cert, priv_key))
}

/// Generates the entire test PKI chain and writes it to `out_dir`. Refuses
/// to touch a non-empty `out_dir` unless `force` is set.
pub fn run(out_dir: &Path, force: bool) -> Result<()> {
    if !storage::is_empty_or_absent(out_dir)? {
        if !force {
            anyhow::bail!(
                "{} already has certificates in it — pass --force to regenerate",
                out_dir.display()
            );
        }
        storage::clear(out_dir)?;
    }

    let root = issue_root()?;
    storage::write_pair(
        out_dir,
        "root",
        &root.cert.to_pem(LineEnding::LF)?,
        &root.key.to_pkcs8_pem(LineEnding::LF)?,
    )?;

    let sub_ca = issue_sub_ca(&root)?;
    storage::write_pair(
        out_dir,
        "sub-ca",
        &sub_ca.cert.to_pem(LineEnding::LF)?,
        &sub_ca.key.to_pkcs8_pem(LineEnding::LF)?,
    )?;

    let tsa_eku = ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]);
    let tsa = issue_p256_leaf(&sub_ca, "eidas-testenv Test TSA", 3, Some(&tsa_eku))?;
    storage::write_pair(
        out_dir,
        "tsa",
        &tsa.cert.to_pem(LineEnding::LF)?,
        &tsa.key.to_pkcs8_pem(LineEnding::LF)?,
    )?;

    let ocsp_eku = ExtendedKeyUsage(vec![ID_KP_OCSP_SIGNING]);
    let ocsp = issue_p256_leaf(
        &sub_ca,
        "eidas-testenv Test OCSP Responder",
        3,
        Some(&ocsp_eku),
    )?;
    storage::write_pair(
        out_dir,
        "ocsp",
        &ocsp.cert.to_pem(LineEnding::LF)?,
        &ocsp.key.to_pkcs8_pem(LineEnding::LF)?,
    )?;

    let user_p256 = issue_p256_leaf(&sub_ca, "eidas-testenv Test Signer (P-256)", 1, None)?;
    storage::write_pair(
        out_dir,
        "user-p256",
        &user_p256.cert.to_pem(LineEnding::LF)?,
        &user_p256.key.to_pkcs8_pem(LineEnding::LF)?,
    )?;

    let (user_rsa_cert, user_rsa_key) =
        issue_rsa_leaf(&sub_ca, "eidas-testenv Test Signer (RSA-2048)", 1)?;
    storage::write_pair(
        out_dir,
        "user-rsa2048",
        &user_rsa_cert.to_pem(LineEnding::LF)?,
        &user_rsa_key.to_pkcs8_pem(LineEnding::LF)?,
    )?;

    println!("Wrote test PKI chain to {}:", out_dir.display());
    for role in storage::ROLES {
        println!("  {role}");
    }
    Ok(())
}

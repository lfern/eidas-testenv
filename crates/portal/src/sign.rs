//! Core CAdES B-B/B-T/B-LT signing logic, independent of Axum so it's
//! testable without a server: load a `ca bootstrap`-issued cert+key pair
//! from disk and sign arbitrary bytes with it via `ades-rs`.

use std::fs;
use std::path::Path;

use ades::{
    cades,
    ocsp::OcspClient,
    signer::{Signer as _, SoftSigner},
    tsp::TspClient,
    DigestAlgorithm,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::FixedTag as _;
use p256::pkcs8::DecodePrivateKey as _;
use serde::{Deserialize, Serialize};
use x509_cert::der::{Decode, DecodePem, Encode};

/// Certificate roles `ca bootstrap` produces that are usable as signing
/// identities here (`root`/`sub-ca`/`tsa`/`ocsp` are plumbing, not meant to
/// sign arbitrary documents).
const SIGNING_ROLES: &[&str] = &["user-p256", "user-rsa2048"];

/// AdES signature level to produce. Closed set (per `CLAUDE.md`: an enum,
/// not a trait, for closed variants).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureLevel {
    /// CAdES-B-B: signed, no timestamp.
    #[serde(rename = "BB")]
    #[default]
    Bb,
    /// CAdES-B-T: B-B plus a signature timestamp from a TSA
    /// (`id-aa-signatureTimeStampToken`, ETSI EN 319 122-1 §5.2.7).
    #[serde(rename = "BT")]
    Bt,
    /// CAdES-B-LT: B-T plus revocation data proving the signing
    /// certificate wasn't revoked (`id-aa-ets-revocationValues`, ETSI
    /// EN 319 122-1 §5.2.8) — built on top of B-T, not directly on B-B,
    /// so the embedded timestamp establishes the time the revocation
    /// data is checked against.
    #[serde(rename = "BLT")]
    Blt,
}

/// Result of one [`sign`] call.
#[derive(Serialize)]
pub struct SignOutcome {
    /// Base64 of the DER-encoded CMS `ContentInfo` (detached CAdES).
    pub signature_der_base64: String,
    pub cert_role: String,
    pub digest_algorithm: String,
    pub level: SignatureLevel,
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
/// detached CAdES signature at the requested `level`. `tsa_url`/`ocsp_url`
/// are only contacted for [`SignatureLevel::Bt`]/[`SignatureLevel::Blt`]
/// respectively (expected to point at a running `tsa serve`/`ocsp serve`).
pub fn sign(
    ca_dir: &Path,
    cert_role: &str,
    data: &[u8],
    level: SignatureLevel,
    tsa_url: &str,
    ocsp_url: &str,
) -> Result<SignOutcome> {
    if !SIGNING_ROLES.contains(&cert_role) {
        bail!("unsupported cert_role {cert_role:?} (expected one of {SIGNING_ROLES:?})");
    }
    let signer = load_signer(ca_dir, cert_role)?;
    let bb_der = cades::sign(data, &signer).context("CAdES B-B signing failed")?;
    let signature_der = match level {
        SignatureLevel::Bb => bb_der,
        SignatureLevel::Bt => {
            upgrade_to_bt(&bb_der, tsa_url).context("CAdES B-T upgrade failed")?
        }
        SignatureLevel::Blt => {
            let bt_der = upgrade_to_bt(&bb_der, tsa_url).context("CAdES B-T upgrade failed")?;
            upgrade_to_blt(&bt_der, &signer, ca_dir, ocsp_url)
                .context("CAdES B-LT upgrade failed")?
        }
    };
    Ok(SignOutcome {
        signature_der_base64: STANDARD.encode(signature_der),
        cert_role: cert_role.to_owned(),
        digest_algorithm: "Sha256".to_owned(),
        level,
    })
}

/// Upgrades a CAdES B-B CMS to B-T: fetches a timestamp over the
/// signature value from `tsa_url` and embeds it as an unsigned attribute.
fn upgrade_to_bt(bb_der: &[u8], tsa_url: &str) -> Result<Vec<u8>> {
    let signature_value = extract_signature_value(bb_der)?;
    let hash = DigestAlgorithm::Sha256.hash(&signature_value);
    let tst_der = TspClient::new(tsa_url)
        .timestamp(&hash, DigestAlgorithm::Sha256)
        .map_err(|e| anyhow::anyhow!("requesting a timestamp from {tsa_url}: {e}"))?;
    ades::levels::add_signature_timestamp(bb_der, &tst_der)
        .map_err(|e| anyhow::anyhow!("embedding the timestamp token: {e}"))
}

/// Extracts the raw `SignerInfo.signature` bytes from a CAdES CMS
/// `ContentInfo` — what RFC 3161 §2.4.1 requires the TSA's
/// `messageImprint` to hash for a signature timestamp (not the original
/// document). `ades::cades::sign` doesn't hand this back separately, so
/// it's re-extracted here by parsing the CMS it just produced.
fn extract_signature_value(cms_der: &[u8]) -> Result<Vec<u8>> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    let ci = ContentInfo::from_der(cms_der).context("parsing CMS ContentInfo")?;
    let sd_der = ci.content.to_der().context("re-encoding SignedData")?;
    let sd = SignedData::from_der(&sd_der).context("parsing SignedData")?;
    let signer_info = sd
        .signer_infos
        .0
        .as_ref()
        .first()
        .context("CMS has no signer infos")?;
    Ok(signer_info.signature.as_bytes().to_vec())
}

/// Upgrades a CAdES B-T CMS to B-LT: queries the `ocsp` responder for the
/// status of `signer`'s own certificate (issued by `sub-ca`, same as
/// every signing identity `ca bootstrap` produces) and embeds the
/// resulting `BasicOCSPResponse` as revocation data.
fn upgrade_to_blt(
    bt_der: &[u8],
    signer: &SoftSigner,
    ca_dir: &Path,
    ocsp_url: &str,
) -> Result<Vec<u8>> {
    let issuer_pem = fs::read_to_string(ca_dir.join("sub-ca").join("cert.pem"))
        .context("reading sub-ca/cert.pem (the issuer of every signing identity)")?;
    let issuer_der = x509_cert::Certificate::from_pem(issuer_pem.as_bytes())
        .context("parsing sub-ca/cert.pem")?
        .to_der()
        .context("re-encoding sub-ca/cert.pem as DER")?;
    let issuer = ades::Certificate::from_der(&issuer_der).context("building issuer Certificate")?;

    let envelope_der = OcspClient::with_url(ocsp_url)
        .raw_response(signer.certificate(), &issuer)
        .map_err(|e| anyhow::anyhow!("querying the OCSP responder at {ocsp_url}: {e}"))?;
    let basic_response_der = extract_basic_ocsp_response(&envelope_der)?;

    ades::levels::add_revocation_values(bt_der, &basic_response_der)
        .map_err(|e| anyhow::anyhow!("embedding revocation values: {e}"))
}

/// `der` 0.7.10 has no built-in `ENUMERATED` type — same gap `crates/ocsp`
/// hit and worked around the same way (`impl DecodeValue/EncodeValue/
/// FixedTag` by hand, mirroring `der`'s own `impl ... for bool`).
struct OcspEnumeratedStatus(u8);

impl<'a> der::DecodeValue<'a> for OcspEnumeratedStatus {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        if header.length != der::Length::ONE {
            return Err(reader.error(der::ErrorKind::Length { tag: Self::TAG }));
        }
        Ok(OcspEnumeratedStatus(reader.read_byte()?))
    }
}

impl der::EncodeValue for OcspEnumeratedStatus {
    fn value_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::ONE)
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        writer.write_byte(self.0)
    }
}

impl der::FixedTag for OcspEnumeratedStatus {
    const TAG: der::Tag = der::Tag::Enumerated;
}

/// `ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }`
/// (RFC 6960 §4.2.1).
#[derive(der::Sequence)]
struct OcspResponseBytes {
    response_type: der::asn1::ObjectIdentifier,
    response: der::asn1::OctetString,
}

/// `OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus, responseBytes [0]
/// EXPLICIT ResponseBytes OPTIONAL }` (RFC 6960 §4.2.1) — the envelope
/// `ades::ocsp::OcspClient::raw_response` returns as-is.
#[derive(der::Sequence)]
struct OcspResponseEnvelope {
    response_status: OcspEnumeratedStatus,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    response_bytes: Option<OcspResponseBytes>,
}

/// Unwraps an `OCSPResponse` envelope down to the `BasicOCSPResponse` DER
/// bytes inside its `responseBytes.response` OCTET STRING —
/// `ades::levels::add_revocation_values` wants only those, not the
/// envelope `OcspClient::raw_response` actually returns.
fn extract_basic_ocsp_response(envelope_der: &[u8]) -> Result<Vec<u8>> {
    let envelope =
        OcspResponseEnvelope::from_der(envelope_der).context("parsing OCSPResponse envelope")?;
    if envelope.response_status.0 != 0 {
        bail!(
            "OCSP responder returned a non-successful status ({})",
            envelope.response_status.0
        );
    }
    let bytes = envelope
        .response_bytes
        .context("OCSPResponse has no responseBytes")?;
    Ok(bytes.response.as_bytes().to_vec())
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

    use p256::pkcs8::EncodePrivateKey as _;
    use rsa::rand_core::OsRng;
    use x509_cert::der::pem::LineEnding;
    use x509_cert::der::EncodePem as _;

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

    // Unreachable on purpose: only `Bt`/`Blt` ever touch `tsa_url`/
    // `ocsp_url`, and every test below signs at `Bb`.
    const UNUSED_TSA_URL: &str = "http://127.0.0.1:0/";
    const UNUSED_OCSP_URL: &str = "http://127.0.0.1:0/";

    #[test]
    fn signs_with_p256_identity() {
        let ca_dir = temp_dir("p256");
        write_p256_identity(&ca_dir);

        let outcome = sign(
            &ca_dir,
            "user-p256",
            b"hello world",
            SignatureLevel::Bb,
            UNUSED_TSA_URL,
            UNUSED_OCSP_URL,
        )
        .unwrap();
        assert_eq!(outcome.cert_role, "user-p256");
        let der = STANDARD.decode(outcome.signature_der_base64).unwrap();
        assert_eq!(der[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

        fs::remove_dir_all(&ca_dir).unwrap();
    }

    #[test]
    fn signs_with_rsa_identity() {
        let ca_dir = temp_dir("rsa");
        write_rsa_identity(&ca_dir);

        let outcome = sign(
            &ca_dir,
            "user-rsa2048",
            b"hello world",
            SignatureLevel::Bb,
            UNUSED_TSA_URL,
            UNUSED_OCSP_URL,
        )
        .unwrap();
        assert_eq!(outcome.cert_role, "user-rsa2048");
        let der = STANDARD.decode(outcome.signature_der_base64).unwrap();
        assert_eq!(der[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

        fs::remove_dir_all(&ca_dir).unwrap();
    }

    #[test]
    fn rejects_unknown_cert_role() {
        let ca_dir = temp_dir("unknown-role");
        assert!(sign(
            &ca_dir,
            "root",
            b"data",
            SignatureLevel::Bb,
            UNUSED_TSA_URL,
            UNUSED_OCSP_URL
        )
        .is_err());
    }

    #[test]
    fn extracts_a_plausible_ecdsa_signature_value() {
        let ca_dir = temp_dir("extract-sig-value");
        write_p256_identity(&ca_dir);

        let outcome = sign(
            &ca_dir,
            "user-p256",
            b"hello world",
            SignatureLevel::Bb,
            UNUSED_TSA_URL,
            UNUSED_OCSP_URL,
        )
        .unwrap();
        let der = STANDARD.decode(outcome.signature_der_base64).unwrap();
        let signature_value = extract_signature_value(&der).unwrap();
        // A DER ECDSA-Sig-Value (SEQUENCE of two ~32-byte INTEGERs) is
        // comfortably longer than a bare 32-byte digest would be, and
        // starts with a SEQUENCE tag — cheap signals that this is the
        // signature bytes, not e.g. an empty or truncated value.
        assert!(signature_value.len() > 32);
        assert_eq!(signature_value[0], 0x30);

        fs::remove_dir_all(&ca_dir).unwrap();
    }

    #[test]
    fn extracts_the_basic_response_from_an_ocsp_envelope() {
        // Builds a minimal but well-formed OCSPResponse envelope
        // (RFC 6960 §4.2.1) by hand, the same shape `crates/ocsp`
        // produces for real, to check the unwrap logic without needing
        // a running responder.
        let basic_response_der = b"pretend-this-is-a-BasicOCSPResponse".to_vec();
        let envelope = OcspResponseEnvelope {
            response_status: OcspEnumeratedStatus(0),
            response_bytes: Some(OcspResponseBytes {
                response_type: der::asn1::ObjectIdentifier::new("1.3.6.1.5.5.7.48.1.1").unwrap(),
                response: der::asn1::OctetString::new(basic_response_der.clone()).unwrap(),
            }),
        };
        let envelope_der = envelope.to_der().unwrap();

        let extracted = extract_basic_ocsp_response(&envelope_der).unwrap();
        assert_eq!(extracted, basic_response_der);
    }

    #[test]
    fn rejects_a_non_successful_ocsp_envelope() {
        let envelope = OcspResponseEnvelope {
            response_status: OcspEnumeratedStatus(1), // malformedRequest
            response_bytes: None,
        };
        let envelope_der = envelope.to_der().unwrap();

        assert!(extract_basic_ocsp_response(&envelope_der).is_err());
    }

    #[test]
    fn available_cert_roles_lists_only_existing_certs() {
        let ca_dir = temp_dir("available-roles");
        write_p256_identity(&ca_dir);

        assert_eq!(available_cert_roles(&ca_dir), vec!["user-p256"]);

        fs::remove_dir_all(&ca_dir).unwrap();
    }
}

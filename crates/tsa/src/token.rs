//! Builds a signed `TimeStampResp` for a given `TimeStampReq`, using an
//! `ades::signer::SoftSigner` loaded from a `ca bootstrap`-issued `tsa`
//! identity. Pure logic, no Axum — testable without a server.

use ades::signer::{Signer as _, SoftSigner};
use ades::DigestAlgorithm;
use anyhow::{Context, Result};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, Int, OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use rand_core::{OsRng, RngCore as _};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;

use crate::asn1::{
    PkiStatusInfo, TimeStampReq, TimeStampResp, TstInfo, PKI_STATUS_GRANTED, PKI_STATUS_REJECTION,
};

const ID_CT_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

// Not an IANA-registered TSA policy OID — this is a test environment
// with no real policy authority behind it (same spirit as `tl`'s
// `SchemeTerritory = "XX"` placeholder). Under the IANA Private
// Enterprise arc, unassigned per https://www.iana.org/assignments/enterprise-numbers.
const TEST_POLICY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1");

/// Builds a `TimeStampResp` DER for the given `TimeStampReq` DER, signed
/// by `signer` (expected to be the `tsa` identity from `ca bootstrap`).
///
/// On a malformed request, returns a well-formed `TimeStampResp` carrying
/// a `rejection` status rather than an HTTP-level error — matching how a
/// real TSA behaves (RFC 3161 §2.4.2).
///
/// # Errors
///
/// Returns an error only if signing or DER re-encoding of a well-formed
/// request fails (not on malformed input, which is handled as a protocol
/// rejection instead).
pub fn build_timestamp_response(req_der: &[u8], signer: &SoftSigner) -> Result<Vec<u8>> {
    let Ok(req) = TimeStampReq::from_der(req_der) else {
        return rejection_response();
    };
    build_granted_response(&req, signer)
}

fn rejection_response() -> Result<Vec<u8>> {
    let resp = TimeStampResp {
        status: PkiStatusInfo {
            status: Int::new(&[PKI_STATUS_REJECTION as u8])?,
        },
        time_stamp_token: None,
    };
    Ok(resp.to_der()?)
}

fn build_granted_response(req: &TimeStampReq, signer: &SoftSigner) -> Result<Vec<u8>> {
    let tst_info = TstInfo {
        version: Int::new(&[1])?,
        policy: TEST_POLICY_OID,
        message_imprint: req.message_imprint.clone(),
        serial_number: random_serial()?,
        gen_time: GeneralizedTime::from_unix_duration(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system time before unix epoch")?,
        )?,
    };
    let tst_info_der = tst_info.to_der().context("encoding TSTInfo")?;

    let content_info_der = sign_tst_info(&tst_info_der, signer)?;
    let content_info =
        ContentInfo::from_der(&content_info_der).context("re-parsing signed TimeStampToken")?;

    let resp = TimeStampResp {
        status: PkiStatusInfo {
            status: Int::new(&[PKI_STATUS_GRANTED as u8])?,
        },
        time_stamp_token: Some(content_info),
    };
    Ok(resp.to_der()?)
}

/// Wraps `tst_info_der` in a CMS `SignedData` `TimeStampToken`, attached
/// (`eContent` present — unlike `ades::cades::sign`'s detached CAdES-BES,
/// a `TimeStampToken` always carries its `TSTInfo` inline).
fn sign_tst_info(tst_info_der: &[u8], signer: &SoftSigner) -> Result<Vec<u8>> {
    let digest_algo = signer.digest_algorithm();
    let cert = signer.certificate();

    let content_digest = digest_algo.hash(tst_info_der);

    let content_type_attr = Attribute {
        oid: ID_CONTENT_TYPE,
        values: {
            let mut set = SetOfVec::<Any>::new();
            set.insert(Any::encode_from(&ID_CT_TSTINFO)?)?;
            set
        },
    };
    let message_digest_attr = Attribute {
        oid: ID_MESSAGE_DIGEST,
        values: {
            let mut set = SetOfVec::<Any>::new();
            let octet = OctetString::new(content_digest.as_slice())?;
            set.insert(Any::encode_from(&octet)?)?;
            set
        },
    };
    let signing_cert_v2_attr = {
        let sc_v2_der = build_signing_cert_v2_der(cert.to_der());
        Attribute {
            oid: ID_AA_SIGNING_CERTIFICATE_V2,
            values: {
                let mut set = SetOfVec::<Any>::new();
                set.insert(Any::from_der(&sc_v2_der)?)?;
                set
            },
        }
    };

    let mut signed_attrs = SetOfVec::<Attribute>::new();
    signed_attrs.insert(content_type_attr)?;
    signed_attrs.insert(message_digest_attr)?;
    signed_attrs.insert(signing_cert_v2_attr)?;

    let signed_attrs_der = signed_attrs.to_der()?;
    let signing_digest = digest_algo.hash(&signed_attrs_der);
    let signature_bytes = signer
        .sign_digest(&signing_digest)
        .map_err(|e| anyhow::anyhow!("signing TimeStampToken: {e}"))?;

    let x509 = cert.inner();
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: x509.tbs_certificate.issuer.clone(),
        serial_number: x509.tbs_certificate.serial_number.clone(),
    });

    let digest_alg_id = AlgorithmIdentifierOwned {
        oid: digest_algo.oid(),
        parameters: None,
    };
    let key_alg_oid = x509.tbs_certificate.subject_public_key_info.algorithm.oid;
    let sig_alg_id = signature_algorithm_id(key_alg_oid, digest_algo)?;

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: digest_alg_id.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: sig_alg_id,
        signature: OctetString::new(signature_bytes.as_slice())?,
        unsigned_attrs: None,
    };

    let mut digest_algorithms = DigestAlgorithmIdentifiers::new();
    digest_algorithms.insert(digest_alg_id)?;

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_CT_TSTINFO,
        econtent: Some(Any::from_der(&OctetString::new(tst_info_der)?.to_der()?)?),
    };

    let cert_choice =
        CertificateChoices::Certificate(x509_cert::Certificate::from_der(cert.to_der())?);
    let mut certificates = CertificateSet(Default::default());
    certificates.0.insert(cert_choice)?;

    let mut signer_infos = SignerInfos(Default::default());
    signer_infos.0.insert(signer_info)?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info,
        certificates: Some(certificates),
        crls: None,
        signer_infos,
    };

    let signed_data_der = signed_data.to_der()?;
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)?,
    };
    Ok(content_info.to_der()?)
}

/// Random 8-byte positive `TSTInfo.serialNumber` (top bit cleared so the
/// DER INTEGER encoding never needs an extra sign byte, same convention
/// `ca`'s certificate serial numbers already use).
fn random_serial() -> Result<Int> {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    Ok(Int::new(&bytes)?)
}

/// Derives the CMS `signatureAlgorithm` identifier from the certificate's
/// public key OID and the chosen digest algorithm. Reimplemented here
/// because `ades-rs`'s equivalent (`ades::cms::signature_algorithm_id`)
/// is `pub(crate)`, not exported.
fn signature_algorithm_id(
    key_alg_oid: ObjectIdentifier,
    digest: DigestAlgorithm,
) -> Result<AlgorithmIdentifierOwned> {
    const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    if key_alg_oid != EC_PUBLIC_KEY || !matches!(digest, DigestAlgorithm::Sha256) {
        anyhow::bail!(
            "unsupported key/digest combination for the tsa identity: {key_alg_oid} / {digest:?}"
        );
    }
    Ok(AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA256,
        parameters: None,
    })
}

/// Builds the DER encoding of `SigningCertificateV2` (RFC 5035) for the
/// given cert DER, same structure `ades::cades::sign` embeds.
fn build_signing_cert_v2_der(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let hash: [u8; 32] = Sha256::digest(cert_der).into();

    let tlv = |tag: u8, value: &[u8]| -> Vec<u8> {
        let len = value.len();
        let mut out = vec![tag];
        if len < 128 {
            out.push(len as u8);
        } else {
            out.extend_from_slice(&[0x81, len as u8]);
        }
        out.extend_from_slice(value);
        out
    };

    let hash_os = tlv(0x04, hash.as_slice());
    let ess_cert_id = tlv(0x30, &hash_os);
    let certs_seq = tlv(0x30, &ess_cert_id);
    tlv(0x30, &certs_seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ades::signer::SoftSigner;

    fn sample_request() -> Vec<u8> {
        use crate::asn1::MessageImprint;

        let req = TimeStampReq {
            version: Int::new(&[1]).unwrap(),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"), // sha256
                    parameters: None,
                },
                hashed_message: OctetString::new([0x11u8; 32].as_slice()).unwrap(),
            },
            req_policy: None,
            nonce: None,
            cert_req: true,
        };
        req.to_der().unwrap()
    }

    #[test]
    fn grants_a_well_formed_request() {
        let signer = SoftSigner::generate_ec().unwrap();
        let resp_der = build_timestamp_response(&sample_request(), &signer).unwrap();

        let resp = TimeStampResp::from_der(&resp_der).unwrap();
        assert_eq!(
            resp.status.status,
            Int::new(&[PKI_STATUS_GRANTED as u8]).unwrap()
        );
        assert!(resp.time_stamp_token.is_some());
    }

    #[test]
    fn rejects_garbage_input() {
        let signer = SoftSigner::generate_ec().unwrap();
        let resp_der = build_timestamp_response(b"not a TimeStampReq", &signer).unwrap();

        let resp = TimeStampResp::from_der(&resp_der).unwrap();
        assert_eq!(
            resp.status.status,
            Int::new(&[PKI_STATUS_REJECTION as u8]).unwrap()
        );
        assert!(resp.time_stamp_token.is_none());
    }
}

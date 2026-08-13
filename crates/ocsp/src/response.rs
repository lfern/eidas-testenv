//! Builds a signed `OCSPResponse` for a given `OCSPRequest`, using an
//! `ades::signer::SoftSigner` loaded from a `ca bootstrap`-issued `ocsp`
//! identity. Pure logic, no Axum — testable without a server.
//!
//! `ca` has no revocation state at all (no CRL, no revoked-cert list —
//! confirmed by grepping its source, see ROADMAP.md), so this responder
//! always answers `good` for whatever `CertID` it's asked about. That's
//! a documented test-environment simplification, not a bug: it's enough
//! to exercise `portal`'s future B-T/B-LT signing paths, just not to
//! test actual revocation scenarios.

use ades::signer::{Signer as _, SoftSigner};
use ades::DigestAlgorithm;
use anyhow::{Context, Result};
use const_oid::ObjectIdentifier;
use der::asn1::{BitString, GeneralizedTime, Null};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;

use crate::asn1::{
    BasicOcspResponse, CertStatus, OcspRequest, OcspResponse, ResponderId, ResponseBytes,
    ResponseData, SingleResponse, ID_PKIX_OCSP_BASIC, RESPONSE_STATUS_MALFORMED_REQUEST,
    RESPONSE_STATUS_SUCCESSFUL,
};

/// Builds an `OCSPResponse` DER for the given `OCSPRequest` DER, signed
/// by `signer` (expected to be the `ocsp` identity from `ca bootstrap`).
///
/// On a malformed request, or a request with no `Request` entries,
/// returns a well-formed `OCSPResponse` carrying a `malformedRequest`
/// status rather than an HTTP-level error — matching how a real OCSP
/// responder behaves (RFC 6960 §4.2.1).
///
/// # Errors
///
/// Returns an error only if signing or DER re-encoding of a well-formed
/// request fails (not on malformed input, which is handled as a protocol
/// rejection instead).
pub fn build_ocsp_response(req_der: &[u8], signer: &SoftSigner) -> Result<Vec<u8>> {
    let Ok(req) = OcspRequest::from_der(req_der) else {
        return malformed_response();
    };
    let Some(request) = req.tbs_request.request_list.first() else {
        return malformed_response();
    };
    build_good_response(&request.req_cert, signer)
}

fn malformed_response() -> Result<Vec<u8>> {
    let resp = OcspResponse {
        response_status: crate::asn1::Enumerated(RESPONSE_STATUS_MALFORMED_REQUEST),
        response_bytes: None,
    };
    Ok(resp.to_der()?)
}

fn build_good_response(cert_id: &crate::asn1::CertId, signer: &SoftSigner) -> Result<Vec<u8>> {
    let now = GeneralizedTime::from_unix_duration(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system time before unix epoch")?,
    )?;

    let single_response = SingleResponse {
        cert_id: cert_id.clone(),
        cert_status: CertStatus::Good(Null),
        this_update: now,
    };

    let cert = signer.certificate();
    let response_data = ResponseData {
        responder_id: ResponderId::ByName(cert.inner().tbs_certificate.subject.clone()),
        produced_at: now,
        responses: vec![single_response],
    };

    let basic_response_der = sign_response_data(&response_data, signer)?;

    let response_bytes = ResponseBytes {
        response_type: ID_PKIX_OCSP_BASIC,
        response: der::asn1::OctetString::new(basic_response_der)?,
    };
    let resp = OcspResponse {
        response_status: crate::asn1::Enumerated(RESPONSE_STATUS_SUCCESSFUL),
        response_bytes: Some(response_bytes),
    };
    Ok(resp.to_der()?)
}

/// Signs `response_data` and wraps it in a `BasicOCSPResponse` DER.
///
/// Unlike CMS-based CAdES/TSP signing, OCSP signs the DER encoding of
/// `tbsResponseData` directly (RFC 6960 §4.2.1) — there are no CMS
/// signed attributes here.
fn sign_response_data(response_data: &ResponseData, signer: &SoftSigner) -> Result<Vec<u8>> {
    let digest_algo = signer.digest_algorithm();
    let cert = signer.certificate();

    let tbs_der = response_data.to_der().context("encoding ResponseData")?;
    let digest = digest_algo.hash(&tbs_der);
    let signature_bytes = signer
        .sign_digest(&digest)
        .map_err(|e| anyhow::anyhow!("signing BasicOCSPResponse: {e}"))?;

    let key_alg_oid = cert
        .inner()
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid;
    let signature_algorithm = signature_algorithm_id(key_alg_oid, digest_algo)?;

    let basic_response = BasicOcspResponse {
        tbs_response_data: response_data.clone(),
        signature_algorithm,
        signature: BitString::from_bytes(&signature_bytes)?,
        certs: Some(vec![x509_cert::Certificate::from_der(cert.to_der())?]),
    };
    Ok(basic_response.to_der()?)
}

/// Derives the CMS-style `signatureAlgorithm` identifier from the
/// certificate's public key OID and the chosen digest algorithm.
/// Reimplemented here because `ades-rs`'s equivalent
/// (`ades::cms::signature_algorithm_id`) is `pub(crate)`, not exported —
/// same duplication `tsa` already carries for the same reason.
fn signature_algorithm_id(
    key_alg_oid: ObjectIdentifier,
    digest: DigestAlgorithm,
) -> Result<AlgorithmIdentifierOwned> {
    const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    if key_alg_oid != EC_PUBLIC_KEY || !matches!(digest, DigestAlgorithm::Sha256) {
        anyhow::bail!(
            "unsupported key/digest combination for the ocsp identity: {key_alg_oid} / {digest:?}"
        );
    }
    Ok(AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA256,
        parameters: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::{CertId, Request, TbsRequest};
    use der::asn1::{Int, OctetString};

    fn sample_request() -> Vec<u8> {
        let req = OcspRequest {
            tbs_request: TbsRequest {
                version: None,
                requestor_name: None,
                request_list: vec![Request {
                    req_cert: CertId {
                        hash_algorithm: AlgorithmIdentifierOwned {
                            oid: ObjectIdentifier::new_unwrap("1.3.14.3.2.26"), // sha1
                            parameters: None,
                        },
                        issuer_name_hash: OctetString::new([0x11u8; 20].as_slice()).unwrap(),
                        issuer_key_hash: OctetString::new([0x22u8; 20].as_slice()).unwrap(),
                        serial_number: Int::new(&[0x01, 0x02, 0x03]).unwrap(),
                    },
                    single_request_extensions: None,
                }],
                request_extensions: None,
            },
        };
        req.to_der().unwrap()
    }

    #[test]
    fn answers_good_for_a_well_formed_request() {
        let signer = SoftSigner::generate_ec().unwrap();
        let resp_der = build_ocsp_response(&sample_request(), &signer).unwrap();

        let resp = OcspResponse::from_der(&resp_der).unwrap();
        assert_eq!(resp.response_status.0, RESPONSE_STATUS_SUCCESSFUL);
        let bytes = resp.response_bytes.unwrap();
        assert_eq!(bytes.response_type, ID_PKIX_OCSP_BASIC);

        let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).unwrap();
        assert_eq!(basic.tbs_response_data.responses.len(), 1);
        assert!(matches!(
            basic.tbs_response_data.responses[0].cert_status,
            CertStatus::Good(_)
        ));
    }

    #[test]
    fn rejects_garbage_input_as_malformed() {
        let signer = SoftSigner::generate_ec().unwrap();
        let resp_der = build_ocsp_response(b"not an OCSPRequest", &signer).unwrap();

        let resp = OcspResponse::from_der(&resp_der).unwrap();
        assert_eq!(resp.response_status.0, RESPONSE_STATUS_MALFORMED_REQUEST);
        assert!(resp.response_bytes.is_none());
    }
}

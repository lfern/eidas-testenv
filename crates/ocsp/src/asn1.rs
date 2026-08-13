//! RFC 6960 ASN.1 types, typed via `der`'s `Sequence`/`Choice` derives
//! (not hand-rolled TLV) — this crate both parses and encodes these
//! structures, unlike `ades-rs`'s own OCSP client, which only ever
//! parses/emits flat messages and hand-rolled its own minimal DER for
//! that.
//!
//! Optional/DEFAULT fields this responder never sets (`version`,
//! `requestorName`, `*Extensions`, `optionalSignature`, `nextUpdate`) are
//! omitted from these structs entirely rather than modeled as
//! always-`None`/always-default — DER encodes an absent OPTIONAL/DEFAULT
//! field identically either way.

use der::asn1::{BitString, GeneralizedTime, Int, ObjectIdentifier, OctetString};
use der::{Choice, FixedTag, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::Certificate;

/// `der` 0.7.10 has no built-in `ENUMERATED` type (added in later `der`
/// releases, which the `x509-cert 0.2.5`/`cms 0.2.3` pin in this
/// workspace can't take). `OCSPResponseStatus` is a single-byte
/// `ENUMERATED` (RFC 6960 §4.2.1), so this wraps a `u8` the same way
/// `der`'s own `impl DecodeValue/EncodeValue/FixedTag for bool` wraps a
/// single byte for `BOOLEAN` — same trait pattern, different fixed tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Enumerated(pub u8);

impl<'a> der::DecodeValue<'a> for Enumerated {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        if header.length != der::Length::ONE {
            return Err(reader.error(der::ErrorKind::Length { tag: Self::TAG }));
        }
        Ok(Enumerated(reader.read_byte()?))
    }
}

impl der::EncodeValue for Enumerated {
    fn value_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::ONE)
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        writer.write_byte(self.0)
    }
}

impl der::FixedTag for Enumerated {
    const TAG: der::Tag = der::Tag::Enumerated;
}

/// OCSPResponseStatus `successful` (RFC 6960 §4.2.1).
pub const RESPONSE_STATUS_SUCCESSFUL: u8 = 0;
/// OCSPResponseStatus `malformedRequest`.
pub const RESPONSE_STATUS_MALFORMED_REQUEST: u8 = 1;

// ---------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------

/// `CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, issuerNameHash OCTET STRING,
/// issuerKeyHash OCTET STRING, serialNumber CertificateSerialNumber }` (RFC 6960 §4.1.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: Int,
}

/// `Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT
/// Extensions OPTIONAL }` (RFC 6960 §4.1.1). This responder never reads
/// `singleRequestExtensions`, but real clients may still send one (e.g. a
/// per-cert nonce) — modeled so decoding a real request doesn't fail on it.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Request {
    pub req_cert: CertId,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub single_request_extensions: Option<Extensions>,
}

/// `TBSRequest ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, requestorName
/// [1] EXPLICIT GeneralName OPTIONAL, requestList SEQUENCE OF Request, requestExtensions
/// [2] EXPLICIT Extensions OPTIONAL }` (RFC 6960 §4.1.1). `version`/`requestorName`/
/// `requestExtensions` are never read by this responder, but real clients commonly send
/// `requestExtensions` (e.g. `openssl ocsp`'s nonce) — modeled so decoding doesn't fail on
/// them, unlike the trailing fields other structs in this module genuinely omit.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsRequest {
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub version: Option<Int>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub requestor_name: Option<GeneralName>,
    pub request_list: alloc::vec::Vec<Request>,
    #[asn1(
        context_specific = "2",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub request_extensions: Option<Extensions>,
}

/// `OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] EXPLICIT
/// Signature OPTIONAL }` (RFC 6960 §4.1.1). `optionalSignature` omitted (never sent by
/// `ades-rs`'s client, and this responder never requires request signing).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspRequest {
    pub tbs_request: TbsRequest,
}

// ---------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------

/// `RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0]
/// EXPLICIT CRLReason OPTIONAL }` (RFC 6960 §4.2.1). Modeled for completeness (`CertStatus`
/// is a proper 3-way CHOICE per the RFC) even though this responder only ever emits `Good`
/// — see the crate-level "always good" decision in `response.rs`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedInfo {
    pub revocation_time: GeneralizedTime,
}

/// `CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
/// unknown [2] IMPLICIT UnknownInfo }` (RFC 6960 §4.2.1).
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(der::asn1::Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(der::asn1::Null),
}

/// `SingleResponse ::= SEQUENCE { certID CertID, certStatus CertStatus, thisUpdate
/// GeneralizedTime, nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, singleExtensions
/// [1] EXPLICIT Extensions OPTIONAL }` (RFC 6960 §4.2.1). `nextUpdate`/extensions omitted.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,
}

/// `ResponderID ::= CHOICE { byName [1] EXPLICIT Name, byKey [2] EXPLICIT KeyHash }`
/// (RFC 6960 §4.2.1). This responder always identifies itself `byName` (its own
/// certificate's subject) — `byKey` is modeled for completeness but never constructed.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}

/// `ResponseData ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, responderID
/// ResponderID, producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse,
/// responseExtensions [1] EXPLICIT Extensions OPTIONAL }` (RFC 6960 §4.2.1).
/// `version`/extensions omitted.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseData {
    pub responder_id: ResponderId,
    pub produced_at: GeneralizedTime,
    pub responses: alloc::vec::Vec<SingleResponse>,
}

/// `BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, signatureAlgorithm
/// AlgorithmIdentifier, signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate
/// OPTIONAL }` (RFC 6960 §4.2.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub certs: Option<alloc::vec::Vec<Certificate>>,
}

/// `id-pkix-ocsp-basic` (RFC 6960 §4.2.1) — the only `responseType` this
/// responder ever produces.
pub const ID_PKIX_OCSP_BASIC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// `ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }`
/// (RFC 6960 §4.2.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseBytes {
    pub response_type: ObjectIdentifier,
    pub response: OctetString,
}

/// `OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus, responseBytes [0]
/// EXPLICIT ResponseBytes OPTIONAL }` (RFC 6960 §4.2.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspResponse {
    pub response_status: Enumerated,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub response_bytes: Option<ResponseBytes>,
}

// `der`'s `alloc` feature re-exports `alloc::vec::Vec` at the crate root
// for `no_std` compatibility; this crate is `std`-only, so a plain
// `extern crate alloc` alias keeps the RFC-shaped field types above
// terse without importing `std::vec::Vec` under a different name.
extern crate alloc;

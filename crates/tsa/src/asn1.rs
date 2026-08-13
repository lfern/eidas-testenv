//! RFC 3161 ASN.1 types, typed via `der`'s `Sequence` derive (not
//! hand-rolled TLV) — this crate both parses and encodes these
//! structures, unlike `ades-rs`'s own TSP client, which only ever
//! parses/emits two flat messages and hand-rolled its own minimal DER
//! for that.
//!
//! Optional/DEFAULT trailing fields that this responder never sets
//! (`reqPolicy`, `nonce`, `accuracy`, `ordering`, `tsa`, `extensions`,
//! `statusString`, `failInfo`) are omitted from these structs entirely
//! rather than modeled as always-`None`/always-default — DER encodes an
//! absent OPTIONAL/DEFAULT field identically either way.

use cms::content_info::ContentInfo;
use der::asn1::{GeneralizedTime, Int, OctetString};
use der::Sequence;
use spki::AlgorithmIdentifierOwned;

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}

/// `TimeStampReq ::= SEQUENCE { version INTEGER, messageImprint MessageImprint,
/// reqPolicy TSAPolicyId OPTIONAL, nonce INTEGER OPTIONAL, certReq BOOLEAN DEFAULT FALSE,
/// extensions [0] IMPLICIT Extensions OPTIONAL }` (RFC 3161 §2.4.1).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampReq {
    pub version: Int,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<der::asn1::ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(default = "Default::default")]
    pub cert_req: bool,
}

/// `TSTInfo ::= SEQUENCE { version INTEGER, policy TSAPolicyId,
/// messageImprint MessageImprint, serialNumber INTEGER, genTime GeneralizedTime, ... }`
/// (RFC 3161 §2.4.2). Trailing OPTIONAL/DEFAULT fields omitted, see module docs.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    pub version: Int,
    pub policy: der::asn1::ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: Int,
    pub gen_time: GeneralizedTime,
}

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL,
/// failInfo PKIFailureInfo OPTIONAL }` (RFC 3161 §2.4.2). `statusString`/`failInfo`
/// omitted — this responder either grants (status 0) or rejects with no extra detail.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    pub status: Int,
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }`
/// (RFC 3161 §2.4.2). `TimeStampToken` is a CMS `ContentInfo`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    pub status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<ContentInfo>,
}

/// PKIStatus `granted` (RFC 3161 §2.4.2): the TSA has approved the request.
pub const PKI_STATUS_GRANTED: i8 = 0;
/// PKIStatus `rejection`: the TSA rejected the request.
pub const PKI_STATUS_REJECTION: i8 = 2;

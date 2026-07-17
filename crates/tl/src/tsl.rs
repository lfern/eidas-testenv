//! Builds the Trusted List XML itself (ETSI TS 119 612), given the DER
//! bytes of the Root CA certificate `ca bootstrap` already produced.
//!
//! Scope of this first phase: a single `TrustServiceProvider` with a
//! single `TSPService` pointing at the Root CA, service type `CA/QC`,
//! status `granted`. No `ds:Signature` — signing is deferred (see
//! `ROADMAP.md`). Every scheme-operator/TSP identity field below is a
//! placeholder for a test environment, not a real trust scheme.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const TSL_NAMESPACE: &str = "http://uri.etsi.org/02231/v2#";
const TSL_TAG: &str = "http://uri.etsi.org/02231/TSLTag";
const TSL_TYPE_GENERIC: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/generic";
const STATUS_DETERMINATION_APPROACH: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate";
const SERVICE_TYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
const SERVICE_STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
/// Placeholder from the ISO 3166-1 "user-assigned" code range — there is
/// no real scheme operator or country behind this test Trusted List.
const SCHEME_TERRITORY: &str = "XX";
const PROJECT_URL: &str = "https://github.com/lfern/eidas-testenv";

/// Builds the full Trusted List XML for a single Root CA, as UTF-8 text.
pub fn build(root_cn: &str, root_cert_der: &[u8]) -> Result<String> {
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .context("writing XML declaration")?;

    let now = OffsetDateTime::now_utc();
    let issued = now
        .format(&Rfc3339)
        .context("formatting ListIssueDateTime")?;
    let next_update = (now + Duration::days(365))
        .format(&Rfc3339)
        .context("formatting NextUpdate")?;

    let mut root = BytesStart::new("TrustServiceStatusList");
    root.push_attribute(("xmlns", TSL_NAMESPACE));
    root.push_attribute(("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"));
    root.push_attribute(("TSLTag", TSL_TAG));
    writer
        .write_event(Event::Start(root))
        .context("writing TrustServiceStatusList")?;

    write_scheme_information(&mut writer, &issued, &next_update)?;
    write_tsp_list(&mut writer, root_cn, root_cert_der, &issued)?;

    writer
        .write_event(Event::End(BytesEnd::new("TrustServiceStatusList")))
        .context("closing TrustServiceStatusList")?;

    let bytes = writer.into_inner();
    String::from_utf8(bytes).context("TSL XML is not valid UTF-8")
}

fn write_scheme_information(
    writer: &mut Writer<Vec<u8>>,
    issued: &str,
    next_update: &str,
) -> Result<()> {
    open(writer, "SchemeInformation")?;
    text_elem(writer, "TSLVersionIdentifier", "5")?;
    text_elem(writer, "TSLSequenceNumber", "1")?;
    text_elem(writer, "TSLType", TSL_TYPE_GENERIC)?;

    open(writer, "SchemeOperatorName")?;
    lang_text_elem(
        writer,
        "Name",
        "en",
        "eidas-testenv (test environment, no legal value)",
    )?;
    close(writer, "SchemeOperatorName")?;

    write_address(writer, "SchemeOperatorAddress")?;

    open(writer, "SchemeName")?;
    lang_text_elem(
        writer,
        "Name",
        "en",
        "eidas-testenv Test Trusted List (no legal value)",
    )?;
    close(writer, "SchemeName")?;

    open(writer, "SchemeInformationURI")?;
    lang_text_elem(writer, "URI", "en", PROJECT_URL)?;
    close(writer, "SchemeInformationURI")?;

    text_elem(
        writer,
        "StatusDeterminationApproach",
        STATUS_DETERMINATION_APPROACH,
    )?;
    text_elem(writer, "SchemeTerritory", SCHEME_TERRITORY)?;
    text_elem(writer, "HistoricalInformationPeriod", "0")?;
    text_elem(writer, "ListIssueDateTime", issued)?;

    open(writer, "NextUpdate")?;
    text_elem(writer, "dateTime", next_update)?;
    close(writer, "NextUpdate")?;

    close(writer, "SchemeInformation")
}

fn write_tsp_list(
    writer: &mut Writer<Vec<u8>>,
    root_cn: &str,
    root_cert_der: &[u8],
    status_starting_time: &str,
) -> Result<()> {
    open(writer, "TrustServiceProviderList")?;
    open(writer, "TrustServiceProvider")?;

    open(writer, "TSPInformation")?;
    open(writer, "TSPName")?;
    lang_text_elem(writer, "Name", "en", "eidas-testenv")?;
    close(writer, "TSPName")?;
    write_address(writer, "TSPAddress")?;
    open(writer, "TSPInformationURI")?;
    lang_text_elem(writer, "URI", "en", PROJECT_URL)?;
    close(writer, "TSPInformationURI")?;
    close(writer, "TSPInformation")?;

    open(writer, "TSPServices")?;
    open(writer, "TSPService")?;
    open(writer, "ServiceInformation")?;
    text_elem(writer, "ServiceTypeIdentifier", SERVICE_TYPE_CA_QC)?;
    open(writer, "ServiceName")?;
    lang_text_elem(writer, "Name", "en", root_cn)?;
    close(writer, "ServiceName")?;
    open(writer, "ServiceDigitalIdentity")?;
    open(writer, "DigitalId")?;
    text_elem(writer, "X509Certificate", &BASE64.encode(root_cert_der))?;
    close(writer, "DigitalId")?;
    close(writer, "ServiceDigitalIdentity")?;
    text_elem(writer, "ServiceStatus", SERVICE_STATUS_GRANTED)?;
    text_elem(writer, "StatusStartingTime", status_starting_time)?;
    close(writer, "ServiceInformation")?;
    close(writer, "TSPService")?;
    close(writer, "TSPServices")?;

    close(writer, "TrustServiceProvider")?;
    close(writer, "TrustServiceProviderList")
}

/// `AddressType`: a placeholder postal + electronic address — the XSD
/// requires both, but nothing about their content is meaningful for a
/// test environment with no real scheme operator.
fn write_address(writer: &mut Writer<Vec<u8>>, wrapper: &str) -> Result<()> {
    open(writer, wrapper)?;
    open(writer, "PostalAddresses")?;
    let mut postal = BytesStart::new("PostalAddress");
    postal.push_attribute(("xml:lang", "en"));
    writer
        .write_event(Event::Start(postal))
        .context("writing PostalAddress")?;
    text_elem(writer, "StreetAddress", "N/A")?;
    text_elem(writer, "Locality", "N/A")?;
    text_elem(writer, "CountryName", "N/A (test environment)")?;
    close(writer, "PostalAddress")?;
    close(writer, "PostalAddresses")?;

    open(writer, "ElectronicAddress")?;
    lang_text_elem(writer, "URI", "en", "mailto:noreply@example.invalid")?;
    close(writer, "ElectronicAddress")?;
    close(writer, wrapper)
}

fn open(writer: &mut Writer<Vec<u8>>, name: &str) -> Result<()> {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .with_context(|| format!("opening <{name}>"))
}

fn close(writer: &mut Writer<Vec<u8>>, name: &str) -> Result<()> {
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .with_context(|| format!("closing </{name}>"))
}

fn text_elem(writer: &mut Writer<Vec<u8>>, name: &str, text: &str) -> Result<()> {
    open(writer, name)?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .with_context(|| format!("writing text of <{name}>"))?;
    close(writer, name)
}

fn lang_text_elem(writer: &mut Writer<Vec<u8>>, name: &str, lang: &str, text: &str) -> Result<()> {
    let mut start = BytesStart::new(name);
    start.push_attribute(("xml:lang", lang));
    writer
        .write_event(Event::Start(start))
        .with_context(|| format!("opening <{name}>"))?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .with_context(|| format!("writing text of <{name}>"))?;
    close(writer, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event as XmlEvent;
    use quick_xml::Reader;

    #[test]
    fn build_produces_well_formed_xml() {
        let der = b"not a real certificate, just test bytes";
        let xml = build("Test Root CA", der).unwrap();

        // Well-formedness: the whole document must parse without error.
        let mut reader = Reader::from_str(&xml);
        loop {
            match reader.read_event().unwrap() {
                XmlEvent::Eof => break,
                _ => continue,
            }
        }
    }

    #[test]
    fn embedded_certificate_round_trips() {
        let der = b"another set of test bytes standing in for a DER certificate";
        let xml = build("Test Root CA", der).unwrap();

        let start = xml.find("<X509Certificate>").unwrap() + "<X509Certificate>".len();
        let end = xml[start..].find("</X509Certificate>").unwrap() + start;
        let decoded = BASE64.decode(&xml[start..end]).unwrap();

        assert_eq!(decoded, der);
    }
}

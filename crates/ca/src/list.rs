//! `ca list`: reads back the certificates `ca bootstrap` wrote and prints
//! a short summary of each.

use std::path::Path;

use anyhow::{Context, Result};
use const_oid::db::rfc5280::{ID_KP_OCSP_SIGNING, ID_KP_TIME_STAMPING};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, DecodePem};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

use crate::storage;

const OID_P256: &str = "1.2.840.10045.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

pub fn run(out_dir: &Path) -> Result<()> {
    let mut any_found = false;
    for role in storage::ROLES {
        let pem = match storage::read_cert_pem(out_dir, role) {
            Ok(pem) => pem,
            Err(_) => {
                println!("{role}: (not generated yet)");
                continue;
            }
        };
        any_found = true;
        let cert = Certificate::from_pem(pem.as_bytes())
            .with_context(|| format!("parsing {role}/cert.pem"))?;
        print_summary(role, &cert);
    }
    if !any_found {
        println!(
            "No certificates found in {} — run `ca bootstrap` first.",
            out_dir.display()
        );
    }
    Ok(())
}

fn key_algorithm(cert: &Certificate) -> String {
    let oid = cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();
    match oid.as_str() {
        OID_P256 => "P-256".to_owned(),
        OID_RSA_ENCRYPTION => "RSA-2048".to_owned(),
        other => other.to_owned(),
    }
}

fn extended_key_usage(cert: &Certificate) -> Option<String> {
    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == ExtendedKeyUsage::OID)?;
    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(
        eku.0
            .iter()
            .map(|oid| {
                if *oid == ID_KP_TIME_STAMPING {
                    "timeStamping".to_owned()
                } else if *oid == ID_KP_OCSP_SIGNING {
                    "OCSPSigning".to_owned()
                } else {
                    oid.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn print_summary(role: &str, cert: &Certificate) {
    let tbs = &cert.tbs_certificate;
    let serial = tbs
        .serial_number
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    println!("{role}:");
    println!("  subject:  {}", tbs.subject);
    println!("  issuer:   {}", tbs.issuer);
    println!("  serial:   {serial}");
    println!(
        "  validity: {} .. {}",
        tbs.validity.not_before, tbs.validity.not_after
    );
    println!("  key:      {}", key_algorithm(cert));
    if let Some(eku) = extended_key_usage(cert) {
        println!("  eku:      {eku}");
    }
}

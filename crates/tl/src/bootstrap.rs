//! `tl bootstrap`: reads the Root CA certificate `ca bootstrap` already
//! wrote to disk and generates the Trusted List XML that lists it.

use std::path::Path;

use anyhow::{Context, Result};
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

use crate::tsl;

const OUT_FILE: &str = "tl.xml";

/// Generates `<out_dir>/tl.xml` from `<ca_dir>/root/cert.pem`. Refuses to
/// overwrite an existing file unless `force` is set.
pub fn run(ca_dir: &Path, out_dir: &Path, force: bool) -> Result<()> {
    let out_path = out_dir.join(OUT_FILE);
    if out_path.exists() && !force {
        anyhow::bail!(
            "{} already exists — pass --force to regenerate",
            out_path.display()
        );
    }

    let root_cert_path = ca_dir.join("root").join("cert.pem");
    let pem = std::fs::read_to_string(&root_cert_path)
        .with_context(|| format!("reading {}", root_cert_path.display()))?;
    let cert = Certificate::from_pem(pem.as_bytes())
        .with_context(|| format!("parsing {}", root_cert_path.display()))?;
    let der = cert
        .to_der()
        .context("re-encoding root certificate as DER")?;

    let root_cn = cert.tbs_certificate.subject.to_string();
    let xml = tsl::build(&root_cn, &der)?;

    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    std::fs::write(&out_path, xml).with_context(|| format!("writing {}", out_path.display()))?;

    println!("Wrote Trusted List to {}", out_path.display());
    Ok(())
}

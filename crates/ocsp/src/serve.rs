//! Axum HTTP wiring for the OCSP responder: `POST /` takes a raw DER
//! `OCSPRequest` body and returns a raw DER `OCSPResponse` body, per
//! RFC 6960's HTTP binding (`Content-Type: application/ocsp-request` /
//! `application/ocsp-response`).

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ades::signer::SoftSigner;
use ades::DigestAlgorithm;
use anyhow::Context;
use axum::extract::State;
use axum::{
    body::Bytes,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use p256::pkcs8::DecodePrivateKey as _;
use x509_cert::der::{DecodePem, Encode};

use crate::response::build_ocsp_response;

#[derive(Clone)]
struct AppState {
    ca_dir: PathBuf,
}

/// Reads `<ca_dir>/ocsp/{cert.pem,key.pem}` and builds the matching
/// `SoftSigner` — same pattern `portal::sign::load_signer`/`tsa::load_signer`
/// use, minus the RSA branch: `ca bootstrap` always issues the `ocsp`
/// identity in P-256.
fn load_signer(ca_dir: &Path) -> anyhow::Result<SoftSigner> {
    let dir = ca_dir.join("ocsp");
    let cert_pem = fs::read_to_string(dir.join("cert.pem"))
        .with_context(|| format!("reading {}/cert.pem", dir.display()))?;
    let key_pem = fs::read_to_string(dir.join("key.pem"))
        .with_context(|| format!("reading {}/key.pem", dir.display()))?;

    let cert_der = x509_cert::Certificate::from_pem(cert_pem.as_bytes())
        .with_context(|| format!("parsing {}/cert.pem", dir.display()))?
        .to_der()
        .with_context(|| format!("re-encoding {}/cert.pem as DER", dir.display()))?;
    let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem)
        .with_context(|| format!("parsing {}/key.pem", dir.display()))?;
    SoftSigner::from_ec_parts(key, &cert_der, DigestAlgorithm::Sha256)
        .context("building the ocsp signer")
}

async fn check(State(state): State<AppState>, body: Bytes) -> Response {
    let signer = match load_signer(&state.ca_dir) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("loading ocsp identity: {e:#}"),
            )
                .into_response()
        }
    };

    match build_ocsp_response(&body, &signer) {
        Ok(resp_der) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ocsp-response")],
            resp_der,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("building OCSPResponse: {e:#}"),
        )
            .into_response(),
    }
}

fn router(ca_dir: PathBuf) -> Router {
    let state = AppState { ca_dir };
    Router::new().route("/", post(check)).with_state(state)
}

/// Starts the OCSP responder on `<host>:<port>`.
///
/// Unlike `wallet`/`portal serve` (always `127.0.0.1`, since those hold a
/// local user's own secrets), `host` here defaults to `127.0.0.1` but is
/// meant to be overridden to `0.0.0.0` when run in Docker: an OCSP
/// responder is, by protocol design, a service other processes are
/// meant to reach over the network, not a holder of private material for
/// one local user.
pub async fn run(host: std::net::IpAddr, port: u16, ca_dir: PathBuf) -> anyhow::Result<()> {
    let app = router(ca_dir);
    let addr = SocketAddr::from((host, port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;

    println!("ocsp responder listening on http://{addr}");
    axum::serve(listener, app).await.context("serving ocsp")
}

#[cfg(test)]
mod tests {
    //! Integration test: drives this responder with `ades-rs`'s own
    //! `OcspClient` (the real, only consumer this crate needs to
    //! satisfy), not a hand-rolled test client. `ades-rs`'s `ocsp`
    //! feature is a dev-dependency only — never shipped in the release
    //! binary.
    use super::*;
    use ades::ocsp::{OcspClient, OcspStatus};
    use ades::signer::Signer as _;
    use p256::pkcs8::EncodePrivateKey as _;
    use rand_core::OsRng;
    use x509_cert::der::pem::LineEnding;
    use x509_cert::der::{Decode as _, EncodePem as _};

    fn temp_ca_dir_with_ocsp_identity() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "eidas-testenv-ocsp-itest-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ocsp_dir = dir.join("ocsp");
        std::fs::create_dir_all(&ocsp_dir).unwrap();

        let signer = SoftSigner::generate_ec().unwrap();
        std::fs::write(
            ocsp_dir.join("cert.pem"),
            x509_cert::Certificate::from_der(signer.certificate().to_der())
                .unwrap()
                .to_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        // SoftSigner doesn't expose the key it generated; an unrelated
        // fresh key is fine here (see the equivalent comment in
        // portal/src/sign.rs's own tests / tsa/src/serve.rs's own test)
        // — this test only checks that ades-rs's real OcspClient can
        // parse our response, not cert/key correspondence.
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        std::fs::write(
            ocsp_dir.join("key.pem"),
            key.to_pkcs8_pem(LineEnding::LF).unwrap(),
        )
        .unwrap();

        dir
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ades_rs_ocsp_client_accepts_our_response() {
        let ca_dir = temp_ca_dir_with_ocsp_identity();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = router(ca_dir.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Arbitrary cert/issuer pair — `OcspClient::check` only uses them
        // to build the `CertID` hash fields; this responder never
        // validates the relationship (it always answers `good`, see
        // response.rs), so unrelated certs are enough to exercise the
        // wire format.
        let cert_signer = SoftSigner::generate_ec().unwrap();
        let issuer_signer = SoftSigner::generate_ec().unwrap();
        let cert = ades::Certificate::from_der(cert_signer.certificate().to_der()).unwrap();
        let issuer = ades::Certificate::from_der(issuer_signer.certificate().to_der()).unwrap();

        let url = format!("http://{addr}/");
        let status =
            tokio::task::spawn_blocking(move || OcspClient::with_url(&url).check(&cert, &issuer))
                .await
                .unwrap()
                .expect("ades-rs's OcspClient should accept our OCSPResponse");

        assert_eq!(status, OcspStatus::Good);

        std::fs::remove_dir_all(&ca_dir).unwrap();
    }
}

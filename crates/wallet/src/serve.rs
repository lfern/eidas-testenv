//! Local browser UI for `wallet serve`: an axum HTTP server exposing the
//! same issue/present/list flows as the CLI subcommands, plus server-side
//! decoding of pasted/dropped QR screenshots, so offer/request URLs never
//! need hand-copying from the issuer/verifier web UIs.

use std::net::SocketAddr;

use anyhow::Context;
use axum::{
    body::Bytes,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::{issue, present, storage};

/// Adapts `anyhow::Error` to axum's `IntoResponse` (500 + JSON
/// `{"error": ...}`), since every fallible operation in this crate returns
/// `anyhow::Result` rather than a custom error enum (see CLAUDE.md). This
/// implements a trait axum's own handler-signature machinery requires, the
/// same class of externally-imposed exception already accepted for
/// `openid4vp`'s/`oid4vci`'s traits — not one invented for our own
/// extensibility.
struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": format!("{:#}", self.0) }));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(err: E) -> Self {
        ApiError(err.into())
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

#[derive(serde::Serialize)]
struct DecodeQrResponse {
    text: String,
}

/// Decodes a QR code out of a pasted/dropped image, so the browser side
/// never needs its own QR-decoding logic.
async fn decode_qr(body: Bytes) -> Result<Json<DecodeQrResponse>, ApiError> {
    let luma = image::load_from_memory(&body)
        .context("decoding pasted image (expected PNG or JPEG)")?
        .to_luma8();

    let mut prepared = rqrr::PreparedImage::prepare(luma);
    let grids = prepared.detect_grids();
    let grid = grids
        .first()
        .context("no QR code detected in the pasted image")?;
    let (_meta, text) = grid.decode().context("decoding QR code")?;

    Ok(Json(DecodeQrResponse { text }))
}

#[derive(Deserialize)]
struct IssueRequest {
    url: String,
    tx_code: Option<String>,
}

async fn api_issue(Json(req): Json<IssueRequest>) -> Result<Json<issue::IssueOutcome>, ApiError> {
    Ok(Json(issue::run_inner(&req.url, req.tx_code).await?))
}

#[derive(Deserialize)]
struct PresentRequest {
    url: String,
}

async fn api_present(
    Json(req): Json<PresentRequest>,
) -> Result<Json<present::PresentOutcome>, ApiError> {
    Ok(Json(present::run_inner(&req.url).await?))
}

async fn api_credentials() -> Result<Json<Vec<storage::StoredCredential>>, ApiError> {
    Ok(Json(storage::Wallet::open()?.list_credentials()?))
}

/// Starts the local browser UI on `127.0.0.1:<port>` — never `0.0.0.0`,
/// since this tool operates on a plaintext-stored holder private key
/// (`~/.eidas-testenv/wallet/key.json`) and must never be LAN-reachable.
pub async fn run(port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/decode-qr", post(decode_qr))
        .route("/api/issue", post(api_issue))
        .route("/api/present", post(api_present))
        .route("/api/credentials", get(api_credentials));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;

    println!("wallet UI listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .context("serving wallet UI")
}

//! Local browser UI for `portal serve`: an axum HTTP server exposing the
//! CAdES B-B signing flow — pick one of the certs `ca bootstrap` produced,
//! upload a file, download the resulting detached signature.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::extract::State;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

use crate::sign;

/// Adapts `anyhow::Error` to axum's `IntoResponse` (500 + JSON
/// `{"error": ...}`), same pattern as `wallet`'s `serve.rs` — every
/// fallible operation in this crate returns `anyhow::Result` rather than a
/// custom error enum (see CLAUDE.md).
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

#[derive(Clone)]
struct AppState {
    ca_dir: PathBuf,
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

async fn api_certs(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(sign::available_cert_roles(&state.ca_dir))
}

#[derive(Deserialize)]
struct SignRequest {
    cert_role: String,
    data_base64: String,
}

async fn api_sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<sign::SignOutcome>, ApiError> {
    let data = STANDARD
        .decode(&req.data_base64)
        .context("decoding uploaded file (expected base64)")?;
    Ok(Json(sign::sign(&state.ca_dir, &req.cert_role, &data)?))
}

/// Starts the local browser UI on `127.0.0.1:<port>` — never `0.0.0.0`,
/// since this tool reads private signing keys from `<ca_dir>/*/key.pem`
/// and must never be LAN-reachable.
pub async fn run(port: u16, ca_dir: PathBuf) -> anyhow::Result<()> {
    let state = AppState { ca_dir };
    let app = Router::new()
        .route("/", get(index))
        .route("/api/certs", get(api_certs))
        .route("/api/sign", post(api_sign))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;

    println!("portal UI listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .context("serving portal UI")
}

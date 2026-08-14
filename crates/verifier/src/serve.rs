//! Axum HTTP wiring for the verifier: starts a presentation session,
//! serves the signed request by reference, receives the wallet's
//! `direct_post` response, and reports the outcome.

use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Path, State};
use axum::{
    body::Bytes,
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use openid4vp::core::response::AuthorizationResponse;
use openid4vp::verifier::client::X509HashClient;
use openid4vp::verifier::request_signer::P256Signer;
use openid4vp::verifier::session::MemoryStore;
use openid4vp::verifier::Verifier;
use uuid::Uuid;

use crate::{identity, request, response};

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

/// Everything a request handler needs: the `Verifier` itself plus this
/// verifier's own JARM decryption key, kept alongside it since it isn't
/// part of `Verifier`'s state (`identity.rs`'s signing identity is,
/// via `X509HashClient`; the encryption keypair is a separate, unrelated
/// key — see `identity::Identity`'s doc comment).
struct AppState {
    verifier: Verifier,
    enc_key: p256::SecretKey,
}

/// Builds the [`AppState`] used for the whole server lifetime: a self-
/// signed `x509_hash` identity (see `identity.rs`), an in-memory session
/// store (fine for a test/demo tool — not for production, per
/// `openid4vp`'s own `MemoryStore` doc comment), and `external_url` as
/// the base both the by-reference request and the response submission
/// endpoint are built against.
async fn build_verifier(
    identity_dir: &std::path::Path,
    external_url: &url::Url,
) -> anyhow::Result<AppState> {
    let identity = identity::load_or_generate(identity_dir)?;
    let signer = Arc::new(P256Signer::new(identity.key)?);
    let client = X509HashClient::new(vec![identity.cert], signer)?;

    let request_base = external_url
        .join("request")
        .context("building the by-reference request base URL")?;
    let submission_endpoint = external_url
        .join("response")
        .context("building the submission endpoint URL")?;

    let verifier = Verifier::builder()
        .with_client(Arc::new(client))
        .with_session_store(Arc::new(MemoryStore::default()))
        .with_submission_endpoint(submission_endpoint)
        .by_reference(request_base)
        .build()
        .await
        .context("building the Verifier")?;

    Ok(AppState {
        verifier,
        enc_key: identity.enc_key,
    })
}

#[derive(serde::Serialize)]
struct NewRequestResponse {
    uuid: Uuid,
    request_url: String,
}

async fn api_new_request(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NewRequestResponse>, ApiError> {
    let (uuid, request_url) =
        request::build_presentation_request(&state.verifier, &state.enc_key).await?;
    Ok(Json(NewRequestResponse {
        uuid,
        request_url: request_url.to_string(),
    }))
}

/// Serves the signed request JWT for a by-reference presentation
/// request — what a wallet's `request_uri` GET fetches.
async fn get_request(
    State(state): State<Arc<AppState>>,
    Path(uuid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let jwt = state.verifier.retrieve_authorization_request(uuid).await?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/oauth-authz-req+jwt")],
        jwt,
    )
        .into_response())
}

/// Receives the wallet's `direct_post` response and records the
/// verification outcome (see `response.rs`). Always answers `200` with
/// an empty JSON body once the session itself is found and updated —
/// the actual accept/reject verdict is read back via `GET
/// /api/status/:uuid`, not this response's HTTP status. (OID4VP §8.2
/// allows a verifier to answer 4xx on rejection instead; skipped here —
/// this is a test/demo tool, not a conformance target, and polling
/// status is simpler than threading the rejection reason back out of
/// `verify_response`'s validator closure.)
async fn post_response(
    State(state): State<Arc<AppState>>,
    Path(uuid): Path<Uuid>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let authorization_response = AuthorizationResponse::from_x_www_form_urlencoded(&body)
        .context("parsing the authorization response")?;
    let enc_key = state.enc_key.clone();
    state
        .verifier
        .verify_response(uuid, authorization_response, move |session, resp| {
            Box::pin(async move { response::verify_response(&session, &resp, &enc_key) })
        })
        .await?;
    Ok(Json(serde_json::json!({})))
}

async fn api_status(
    State(state): State<Arc<AppState>>,
    Path(uuid): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let status = state.verifier.poll_status(uuid).await?;
    Ok(Json(serde_json::to_value(status)?))
}

/// Starts the verifier on `<host>:<port>`. `external_url` is the base
/// other processes (the wallet) reach this server at — used to build
/// absolute `request_uri`/response submission URLs, so it generally
/// needs to differ from `127.0.0.1` only when the wallet runs somewhere
/// this box's loopback address doesn't resolve to (e.g. a container).
pub async fn run(
    host: std::net::IpAddr,
    port: u16,
    identity_dir: std::path::PathBuf,
    external_url: url::Url,
) -> anyhow::Result<()> {
    let state = build_verifier(&identity_dir, &external_url).await?;
    let app = Router::new()
        .route("/api/request", post(api_new_request))
        .route("/request/{uuid}", get(get_request))
        .route("/response/{uuid}", post(post_response))
        .route("/api/status/{uuid}", get(api_status))
        .with_state(Arc::new(state));

    let addr = std::net::SocketAddr::from((host, port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;

    println!("verifier listening on http://{addr} (external: {external_url})");
    axum::serve(listener, app).await.context("serving verifier")
}

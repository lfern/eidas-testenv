use std::io::{self, Write as _};

use anyhow::{bail, Context, Result};
use oid4vci::{
    credential::CredentialOrConfigurationId,
    endpoints::credential::{AnyCredentialRequestParams, CredentialRequest, CredentialResponse},
    iref::{Uri, UriBuf},
    issuer::metadata::CredentialIssuerMetadata,
    open_auth2::util::Discoverable,
    profile::StandardCredentialFormatMetadata,
    proof::{
        jwt::{create_jwt_proof, JwkProofSigner},
        Proofs,
    },
    CredentialOffer,
};
use serde::Deserialize;

use crate::storage::{StoredCredential, Wallet};

/// `oid4vci`'s own vendored `reqwest` (re-exported), reused here because
/// `CredentialOffer::resolve`/`CredentialIssuerMetadata::discover` require
/// its `HttpClient` trait impl.
type HttpClient = oid4vci::open_auth2::reqwest::Client;

/// RFC 8414 well-known path for OAuth 2.0 Authorization Server Metadata.
const AUTHORIZATION_SERVER_WELL_KNOWN_PATH: &str = ".well-known/oauth-authorization-server";

/// Runs the OID4VCI pre-authorized_code flow against a credential offer
/// URL, saving any issued credential(s) to local storage.
///
/// This hand-rolls the post-offer-resolution steps (authorization server
/// metadata, token exchange, nonce, credential request) instead of using
/// `oid4vci`'s own `Oid4vciClient`/`SimpleOid4vciClient`: that client's
/// `accept_offer` unconditionally parses the full Authorization Server
/// Metadata document through a strictly-typed `Vec<ssi::jwk::Algorithm>`
/// (for DPoP/client-attestation fields this wallet never uses), and real
/// issuers — `issuer.eudiw.dev` included — advertise `ES512`, which that
/// enum doesn't have (confirmed: both `ssi` and `ssi-jwk` are already at
/// their latest published version). Everything else here (offer parsing,
/// issuer metadata, credential/proof types) still comes straight from
/// `oid4vci`.
pub async fn run(url: &str) -> Result<()> {
    // The holder key was already generated (or loaded) in Phase 1 and is
    // reused across every issuance and, later, every presentation.
    let wallet = Wallet::open()?;
    let http_client = HttpClient::new();

    // Step 1: parse the offer URL. This is pure local decoding (the
    // `credential_offer` query parameter is percent-encoded JSON) — no
    // network call yet.
    let offer_uri =
        Uri::new(url).map_err(|e| anyhow::anyhow!("invalid credential offer URL: {e}"))?;
    let credential_offer =
        CredentialOffer::from_uri(offer_uri).context("parsing credential offer")?;

    // Step 2: resolve the offer. For a `credential_offer_uri` reference this
    // dereferences it over HTTP; for an inline `credential_offer` value (our
    // case) it's a no-op and just returns the already-parsed parameters.
    let offer_params = credential_offer
        .resolve(&http_client)
        .await
        .context("resolving credential offer")?;

    // Step 3: GET /.well-known/openid-credential-issuer — ask the issuer
    // where its credential/nonce endpoints are and which credential
    // formats/configurations it supports. This call works fine as-is
    // against real issuers (unlike the authorization server metadata
    // below), so we keep using oid4vci's own discovery here.
    let issuer_metadata = CredentialIssuerMetadata::<StandardCredentialFormatMetadata>::discover(
        &http_client,
        &offer_params.credential_issuer,
    )
    .await
    .context("discovering issuer metadata")?;

    // We only support the pre-authorized_code grant (see module doc comment
    // for why authorization_code is out of scope). Bail out immediately,
    // before any authorization-server call, if the offer doesn't have it.
    let Some(grant) = &offer_params.grants.pre_authorized_code else {
        bail!(
            "this credential offer requires the authorization_code flow, which this wallet \
             doesn't support — paste a pre-authorized offer instead"
        );
    };

    // Step 4: GET /.well-known/oauth-authorization-server — find the token
    // endpoint. Hand-rolled (see module doc comment): oid4vci's own
    // discovery for this document fails against real issuers.
    let authorization_server = select_authorization_server(
        grant.authorization_server.as_deref(),
        &offer_params.credential_issuer,
        &issuer_metadata.authorization_servers,
    )?;
    let token_endpoint = discover_token_endpoint(&http_client, authorization_server).await?;

    // If the offer requires a transaction code (a short PIN the issuer's
    // web UI displayed to the person who created the offer), ask for it on
    // stdin. Otherwise there's nothing more to collect before the token
    // exchange.
    let tx_code = match &grant.tx_code {
        Some(definition) => {
            if let Some(description) = &definition.description {
                println!("{description}");
            }
            print!("Enter transaction code: ");
            io::stdout().flush().ok();
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .context("reading transaction code from stdin")?;
            Some(input.trim().to_owned())
        }
        None => None,
    };

    // Step 5: POST to the token endpoint. This is the point where the
    // pre-authorized_code (plus tx_code, if any) is actually consumed —
    // the offer URL is single-use and stops working after this succeeds.
    // In exchange we get a short-lived access token.
    let access_token = exchange_pre_authorized_code(
        &http_client,
        &token_endpoint,
        &grant.pre_authorized_code,
        tx_code.as_deref(),
    )
    .await?;

    // This wallet only requests a single credential per offer (no
    // scope/authorization_details negotiation), so an offer listing more
    // than one configuration id would be ambiguous for us.
    if offer_params.credential_configuration_ids.len() != 1 {
        bail!(
            "credential offer must request exactly one credential configuration, this wallet \
             doesn't support selecting among several yet"
        );
    }
    let credential_configuration_id = offer_params.credential_configuration_ids[0].clone();

    // Look up the offered configuration in the issuer metadata (step 3) to
    // read its `vct` — we only understand the dc+sd-jwt format.
    let configuration = issuer_metadata
        .credential_configurations_supported
        .get(&credential_configuration_id)
        .context("issuer metadata is missing the requested credential configuration")?;
    let vct = match &configuration.format {
        StandardCredentialFormatMetadata::DcSdJwt(meta) => meta.vct.clone(),
        _ => bail!("credential configuration is not in dc+sd-jwt format"),
    };

    // Step 6: POST to the nonce endpoint (if the issuer publishes one) for
    // a fresh, single-use c_nonce. This nonce goes into the key-binding
    // proof below so it can't be replayed against a different request.
    let nonce = match &issuer_metadata.nonce_endpoint {
        Some(nonce_endpoint) => Some(fetch_nonce(&http_client, nonce_endpoint).await?),
        None => None,
    };

    // Step 7: build and sign the key-binding proof — a JWT, signed with the
    // holder's private key, whose header carries the matching public JWK.
    // This is how the wallet proves "I control this specific key" to the
    // issuer, so the credential it issues can be bound to it.
    let proof = create_jwt_proof(
        None,
        offer_params.credential_issuer.clone(),
        None,
        nonce,
        JwkProofSigner(&wallet.key.jwk),
    )
    .await
    .map_err(|e| anyhow::anyhow!("signing key-binding proof: {e}"))?;

    // Step 8: POST to the credential endpoint with the access token (proves
    // we're authorized to ask) and the key-binding proof (proves which key
    // to bind the credential to). A successful response embeds our public
    // key in the credential's `cnf.jwk` claim.
    let mut request = CredentialRequest::<AnyCredentialRequestParams>::new(
        CredentialOrConfigurationId::Configuration(credential_configuration_id.clone()),
    );
    request.proofs = Some(Proofs::Jwt(vec![proof]));

    let response: CredentialResponse<serde_json::Value> = http_client
        .post(issuer_metadata.credential_endpoint.as_str())
        .bearer_auth(&access_token)
        .header("accept", "application/json")
        .json(&request)
        .send()
        .await
        .context("sending credential request")?
        .error_for_status()
        .context("issuer rejected credential request")?
        .json()
        .await
        .context("parsing credential response")?;

    // Deferred issuance (poll-until-ready) isn't implemented — out of
    // scope for this wallet, see CLAUDE.md/ROADMAP.md.
    let credentials = match response {
        CredentialResponse::Immediate(response) => response.credentials,
        CredentialResponse::Deferred(_) => {
            bail!("issuer deferred credential issuance, which this wallet doesn't support yet")
        }
    };

    if credentials.is_empty() {
        bail!("issuer returned no credentials");
    }

    let issuer = offer_params.credential_issuer.to_string();
    let received_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("formatting timestamp")?;

    // Step 9: persist the compact SD-JWT as-is. The wallet doesn't parse or
    // verify it — it's opaque storage until a future `present` (Phase 3)
    // needs to read it back out.
    for credential in credentials {
        let sd_jwt = credential
            .value
            .as_str()
            .context("credential value is not a string")?
            .to_owned();

        let stored = StoredCredential {
            id: uuid::Uuid::new_v4().to_string(),
            credential_configuration_id: credential_configuration_id.clone(),
            vct: vct.clone(),
            issuer: issuer.clone(),
            received_at: received_at.clone(),
            sd_jwt,
        };
        wallet.save_credential(&stored)?;
        println!(
            "Saved credential {} (vct={}, issuer={})",
            stored.id, stored.vct, stored.issuer
        );
    }

    Ok(())
}

/// Picks the authorization server for a grant, mirroring
/// `oid4vci::client::select_authorization_server` (private to that crate).
fn select_authorization_server<'a>(
    grant_authorization_server: Option<&'a Uri>,
    issuer: &'a Uri,
    issuer_authorization_servers: &'a [UriBuf],
) -> Result<&'a Uri> {
    match grant_authorization_server {
        // The grant names an explicit authorization server: use it.
        Some(url) => Ok(url),
        None => match issuer_authorization_servers {
            // Issuer publishes no separate authorization server: it acts
            // as its own (the common case for issuer.eudiw.dev).
            [] => Ok(issuer),
            // Exactly one candidate: unambiguous.
            [url] => Ok(url),
            // More than one, and the grant didn't pick: we don't implement
            // the tie-breaking rules for this edge case.
            _ => bail!("credential offer's authorization server is ambiguous"),
        },
    }
}

/// Fetches just the `token_endpoint` out of the Authorization Server
/// Metadata document, instead of `oid4vci`'s
/// `Oid4vciAuthorizationServerMetadata::discover` (see [`run`] doc comment
/// for why). Only handles authorization servers with no path component,
/// which covers the real issuers this wallet has been tested against.
async fn discover_token_endpoint(
    http_client: &HttpClient,
    authorization_server: &Uri,
) -> Result<String> {
    // Deliberately loose: only the one field we actually need. A struct
    // matching oid4vci's full Authorization Server Metadata would fail to
    // deserialize real responses that advertise `ES512` (see module doc
    // comment) — unknown/unused fields here are simply never looked at,
    // so new algorithms or capabilities an issuer adds later can't break
    // this wallet.
    #[derive(Deserialize)]
    struct MinimalAuthorizationServerMetadata {
        token_endpoint: String,
    }

    // RFC 8414 well-known URL construction, simplified: only correct for
    // authorization servers with no path component (true for every real
    // issuer this wallet has been tested against so far).
    let base = authorization_server.as_str().trim_end_matches('/');
    let url = format!("{base}/{AUTHORIZATION_SERVER_WELL_KNOWN_PATH}");

    let metadata: MinimalAuthorizationServerMetadata = http_client
        .get(url.as_str())
        .header("accept", "application/json")
        .send()
        .await
        .with_context(|| format!("fetching authorization server metadata from {url}"))?
        .error_for_status()
        .with_context(|| format!("authorization server metadata request to {url} failed"))?
        .json()
        .await
        .with_context(|| format!("parsing authorization server metadata from {url}"))?;

    Ok(metadata.token_endpoint)
}

/// Exchanges a pre-authorized_code (and optional transaction code) for an
/// access token.
async fn exchange_pre_authorized_code(
    http_client: &HttpClient,
    token_endpoint: &str,
    pre_authorized_code: &str,
    tx_code: Option<&str>,
) -> Result<String> {
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    // Standard OAuth 2.0 token request body for the pre-authorized_code
    // grant (RFC 8693-style grant_type URN). Built and encoded by hand
    // (rather than via reqwest's `.form()`) because the reqwest instance
    // re-exported by oid4vci doesn't have its own "form" feature enabled
    // — see the Cargo.toml comment on the `serde_urlencoded` dependency.
    let mut params = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ),
        ("pre-authorized_code", pre_authorized_code),
    ];
    if let Some(tx_code) = tx_code {
        params.push(("tx_code", tx_code));
    }
    let body = serde_urlencoded::to_string(&params).context("encoding token request body")?;

    let response: TokenResponse = http_client
        .post(token_endpoint)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .context("sending pre-authorized_code token request")?
        .error_for_status()
        .context("issuer rejected pre-authorized_code token request")?
        .json()
        .await
        .context("parsing token response")?;

    Ok(response.access_token)
}

/// Fetches a fresh `c_nonce` from the issuer's Nonce Endpoint.
async fn fetch_nonce(http_client: &HttpClient, nonce_endpoint: &Uri) -> Result<String> {
    #[derive(Deserialize)]
    struct NonceResponse {
        c_nonce: String,
    }

    let response: NonceResponse = http_client
        .post(nonce_endpoint.as_str())
        .header("accept", "application/json")
        .send()
        .await
        .context("requesting credential nonce")?
        .error_for_status()
        .context("issuer rejected nonce request")?
        .json()
        .await
        .context("parsing nonce response")?;

    Ok(response.c_nonce)
}

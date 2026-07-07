use anyhow::{Context, Result};
use async_trait::async_trait;
use openid4vp::core::{
    authorization_request::{
        parameters::{ClientIdScheme, ResponseMode},
        verification::{verifier::P256Verifier, x509_hash, x509_san, RequestVerifier},
        AuthorizationRequestObject,
    },
    credential_format::{ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload},
    jwe::build_encrypted_response,
    metadata::{parameters::wallet::VpFormatsSupported, WalletMetadata},
    response::{
        parameters::{VpToken, VpTokenItem},
        AuthorizationResponse, UnencodedAuthorizationResponse,
    },
    util::ReqwestClient,
};
use openid4vp::wallet::Wallet as Oid4vpWallet;
use url::Url;

use serde::Serialize;

use crate::sd_jwt;
use crate::storage::Wallet as StorageWallet;

/// Signing algorithm this wallet's holder key uses (ES256 / P-256), advertised
/// in the wallet metadata below so a verifier knows what to expect.
const SIGNING_ALG: &str = "ES256";

/// Adapter implementing `openid4vp`'s `Wallet`/`RequestVerifier` traits.
///
/// These traits are implemented (rather than following the "structs only"
/// house style) because `openid4vp` requires them for integration — an
/// externally-imposed exception, same as `oid4vci`'s client trait (see
/// CLAUDE.md).
struct EidasTestenvWallet {
    metadata: WalletMetadata,
    http_client: ReqwestClient,
}

#[async_trait]
impl Oid4vpWallet for EidasTestenvWallet {
    type HttpClient = ReqwestClient;

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    fn http_client(&self) -> &Self::HttpClient {
        &self.http_client
    }
}

#[async_trait]
impl RequestVerifier for EidasTestenvWallet {
    // This is a test wallet with no trust anchors configured yet (the `ca`
    // crate is still a stub, see ROADMAP.md) — accept any request signed
    // with the key in its own leaf certificate, without validating the
    // chain up to a root. Consistent with this environment having no legal
    // validity by design (see CLAUDE.md).
    //
    // Both `x509_hash` and `x509_san_dns` are implemented (rather than
    // guessing which one a given verifier uses) since the reference
    // verifier-endpoint image can run with either client-id scheme
    // depending on its configured Spring profile.
    async fn x509_hash(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<()> {
        x509_hash::validate::<P256Verifier>(
            self.metadata(),
            decoded_request,
            request_jwt.context("x509_hash requests must be signed")?,
            None,
        )
    }

    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<()> {
        x509_san::validate::<P256Verifier>(
            self.metadata(),
            decoded_request,
            request_jwt.context("x509_san_dns requests must be signed")?,
            None,
        )
    }
}

/// Builds this wallet's metadata: the `openid4vp:` scheme default, with
/// `dc+sd-jwt` as the only supported presentation format (this wallet only
/// ever holds SD-JWT VC credentials) and both x509-based client
/// identifier schemes registered as supported (see `RequestVerifier` impl
/// above for why both).
fn wallet_metadata() -> Result<WalletMetadata> {
    let mut metadata = WalletMetadata::openid4vp_scheme_static();

    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::DcSdJwt,
        ClaimFormatPayload::Other(serde_json::json!({
            "sd-jwt_alg_values": [SIGNING_ALG],
            "kb-jwt_alg_values": [SIGNING_ALG],
        })),
    );
    *metadata.vp_formats_supported_mut() = VpFormatsSupported(vp_formats);

    metadata.add_client_id_prefixes_supported(&[
        ClientIdScheme(ClientIdScheme::X509_HASH.to_owned()),
        ClientIdScheme(ClientIdScheme::X509_SAN_DNS.to_owned()),
    ])?;

    Ok(metadata)
}

/// Result of a successful presentation.
#[derive(Serialize)]
pub struct PresentOutcome {
    pub vct: String,
    pub audience: String,
    pub redirect: Option<String>,
}

/// Runs the OID4VP presentation flow against a verifier's request URL,
/// printing a confirmation line (and any verifier-requested redirect).
///
/// Thin wrapper around [`run_inner`].
pub async fn run(url: &str) -> Result<()> {
    let outcome = run_inner(url).await?;

    println!(
        "Presented credential (vct={}) to {}",
        outcome.vct, outcome.audience
    );
    if let Some(redirect) = &outcome.redirect {
        println!("Verifier requested redirect: {redirect}");
    }

    Ok(())
}

/// Drives the OID4VP presentation flow against a verifier's request URL,
/// returning the presented credential's `vct`, the verifier's `client_id`,
/// and any redirect it requested.
pub async fn run_inner(url: &str) -> Result<PresentOutcome> {
    let request_url = Url::parse(url).context("invalid presentation request URL")?;

    let storage_wallet = StorageWallet::open()?;

    let wallet = EidasTestenvWallet {
        metadata: wallet_metadata()?,
        http_client: ReqwestClient::new().context("building HTTP client")?,
    };

    let request = wallet
        .validate_request(request_url)
        .await
        .context("validating presentation request")?;

    let dcql_query = request
        .dcql_query()
        .context("presentation request has no dcql_query")?
        .context("parsing dcql_query")?;

    // Find a query entry asking for dc+sd-jwt, and match it against a
    // stored credential whose vct is one of the query's `vct_values`.
    let (credential_query_id, stored) = dcql_query
        .credentials()
        .iter()
        .find_map(|query| {
            if *query.format() != ClaimFormatDesignation::DcSdJwt {
                return None;
            }
            let vct_values = query.meta().get("vct_values")?.as_array()?;
            vct_values.iter().find_map(|value| {
                let vct = value.as_str()?;
                let stored = storage_wallet.find_credential_by_vct(vct).ok()??;
                Some((query.id().to_owned(), stored))
            })
        })
        .context("no stored credential matches the verifier's request")?;

    let audience = request
        .client_id()
        .context("request has no client_id")?
        .0
        .clone();
    let nonce = request.nonce().to_string();

    let vp_token_str =
        sd_jwt::append_key_binding(&stored.sd_jwt, &audience, &nonce, &storage_wallet.key.jwk)
            .await?;

    let vp_token =
        VpToken::with_credential(credential_query_id, vec![VpTokenItem::from(vp_token_str)]);

    // Echo back the request's `state`, if any — the verifier uses it to
    // match our response to the session it created, and rejects responses
    // that omit or mismatch it.
    let state = request.state().transpose().context("parsing state")?;

    // `direct_post.jwt` (JARM) requires the response encrypted with the
    // verifier's key from its client_metadata; plain `direct_post` sends
    // vp_token as-is. openid4vp already provides `build_encrypted_response`
    // for the JARM case, so both response modes are handled explicitly
    // rather than assuming one.
    let response = match request.response_mode() {
        ResponseMode::DirectPost => match state {
            Some(state) => AuthorizationResponse::Unencoded(
                UnencodedAuthorizationResponse::with_state(vp_token, state),
            ),
            None => AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse::new(vp_token)),
        },
        ResponseMode::DirectPostJwt => {
            build_encrypted_response(&request, &vp_token, state.as_ref())
                .context("building JARM-encrypted response")?
        }
        other => anyhow::bail!("unsupported response_mode: {other}"),
    };

    let redirect = wallet
        .submit_response(request, response)
        .await
        .context("submitting presentation")?;

    Ok(PresentOutcome {
        vct: stored.vct,
        audience,
        redirect: redirect.map(|url| url.to_string()),
    })
}

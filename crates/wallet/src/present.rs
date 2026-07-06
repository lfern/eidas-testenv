use anyhow::bail;

/// Runs the OID4VP presentation flow against a verifier's request URL.
///
/// Not implemented yet — this is Phase 3 (see ROADMAP.md): it will use
/// `openid4vp`'s `Wallet`/`RequestVerifier` traits to parse the request,
/// pick a stored credential matching the request's DCQL query by `vct`
/// (via `storage::find_credential_by_vct`), build a fresh key-binding
/// proof with the same holder key used at issuance, and `direct_post` the
/// resulting VP token back to the verifier.
pub async fn run(_url: &str) -> anyhow::Result<()> {
    bail!("not yet implemented — coming in Phase 3")
}

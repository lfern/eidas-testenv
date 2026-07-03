# eidas-testenv — Roadmap

Estado de cada crate y fases del sprint activo. A diferencia de
`CLAUDE.md`, este fichero cambia a menudo — no se carga automáticamente en
cada sesión, se consulta cuando hace falta ver "por dónde íbamos".

## wallet (sprint activo)

Decisiones de diseño ya tomadas (resumen; la regla derivada está en
`CLAUDE.md`):

- **Flujo OID4VCI: solo `pre-authorized_code`.** Comprobado contra la doc
  de `eudi-srv-web-issuing-eudiw-py`: el flujo pre-authorized funciona
  exactamente como "pega la URL, el wallet hace el resto" — sin navegador.
  El flujo `authorization_code` necesitaría simular el login del formulario
  de test "Utopia", frágil y fuera de alcance.
- **Sin ngrok / redirect_uri propio.** Comprobado contra
  `eudi-srv-verifier-endpoint` (el backend real de verifier.eudiw.dev): el
  wallet nunca expone endpoint público; `response_uri` del `direct_post` ya
  es del propio verifier. Reversible si aparece un caso real que lo
  necesite.
- **Formato de credencial: SD-JWT VC** (`dc+sd-jwt`, PID `vct:
  urn:eudi:pid:1`), no `mso_mdoc` — coherente con las dependencias de
  criptografía del crate (sin CBOR/COSE).
- **Librerías**: `openid4vp` (crates.io, SpruceID) para OID4VP, `oid4vci`
  (git, SpruceID) para OID4VCI — ambas inmaduras (0.1.x, git deps, poca
  documentación), se usan en vez de implementar los protocolos a mano.

Fases:

- [x] **Phase 0** — esqueleto del repo: workspace, `docker-compose.yml`,
      `docker/tsa`+`docker/ocsp` (placeholders), stubs `ca`/`tl`/`verifier`/`portal`
- [x] **Phase 1** — scaffolding `wallet`: `storage.rs` + `holder_key.rs`
      (JWK ES256 generado/persistido), CLI con `clap` (`list` funcional,
      `issue`/`present` como stubs)
- [ ] **Phase 2** — flujo OID4VCI `issue` vía `oid4vci-rs`. Pendiente:
      necesito una URL de credential-offer pre-authorized real, copiada a
      mano desde la web de `issuer.eudiw.dev`, para probar el round-trip
- [ ] **Phase 3** — flujo OID4VP `present` vía `openid4vp` +
      `sd_jwt.rs` (parseo SD-JWT + key-binding JWT). Pendiente: URL de
      presentation-request real desde `verifier.eudiw.dev`
- [ ] **Phase 4** — README + pulido final (clippy/fmt en todo el workspace)

## ca / tl / verifier / portal

Solo stubs (`println!("not implemented yet")`). Sin sprint planificado
todavía — se detallará aquí cuando arranque cada uno.

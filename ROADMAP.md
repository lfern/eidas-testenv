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
- [x] **Phase 2** — flujo OID4VCI `issue` implementado en
      `issue.rs`, **parcialmente hand-rolled** en vez de usar
      `Oid4vciClient`/`SimpleOid4vciClient` de `oid4vci-rs` completo.
      Motivo: probando contra el issuer real (`issuer.eudiw.dev`),
      `accept_offer` de `oid4vci-rs` falla siempre (con
      pre-authorized_code o authorization_code) porque parsea
      Authorization Server Metadata con campos tipados como
      `Vec<ssi::jwk::Algorithm>`, y el issuer real anuncia `ES512`, que esa
      versión de `ssi-jwk` (0.4.0, la última publicada) no tiene en su
      enum — deserialización estricta rompe el documento entero aunque
      esos campos (DPoP/client-attestation) no los usamos. En vez de
      forkear `ssi-jwk`/`oid4vci-rs` (parche mínimo pero con
      mantenimiento externo), se reescribió `issue.rs` reutilizando de
      `oid4vci` todo lo que sigue funcionando bien (parseo de offer,
      `CredentialIssuerMetadata::discover`, tipos de formato/`vct`, tipos
      de proof JWT y de credential request/response) y sustituyendo **solo**
      el paso roto (Authorization Server Metadata + intercambio de token +
      nonce) por peticiones HTTP directas con `reqwest`/`serde_urlencoded`,
      leyendo únicamente los campos que necesitamos (p.ej. `token_endpoint`)
      en vez de tipar el documento entero. Nombres/organización siguen el
      estilo de `oid4vci-rs` (`select_authorization_server`,
      `discover_token_endpoint`, etc.) por si algún día compensa proponerlo
      río arriba. `holder_key.rs` migrado de `p256::SecretKey` a `ssi::JWK`
      porque tanto `oid4vci` como `openid4vp` fijan la misma versión de
      `ssi` y esperan ese tipo directamente. Build/clippy/fmt limpios;
      probado en frío (URL inválida, URL inalcanzable, oferta
      `authorization_code` real de `issuer.eudiw.dev` — corta limpio en
      nuestro propio `bail!` sin tocar el endpoint de metadatos roto).
      **Round-trip real confirmado** (2026-07-06): oferta pre-authorized
      con `tx_code` de `issuer.eudiw.dev`, PID (SD-JWT VC) emitido y
      guardado correctamente; `wallet list` lo muestra
      (`vct=urn:eudi:pid:1`, disclosures de nombre/apellidos/fecha de
      nacimiento/etc. legibles en el SD-JWT resultante). Phase 2 cerrada.
- [ ] **Phase 3** — flujo OID4VP `present` vía `openid4vp` +
      `sd_jwt.rs` (parseo SD-JWT + key-binding JWT). Pendiente: URL de
      presentation-request real desde `verifier.eudiw.dev`
- [ ] **Phase 4** — README + pulido final (clippy/fmt en todo el workspace)

## ca / tl / verifier / portal

Solo stubs (`println!("not implemented yet")`). Sin sprint planificado
todavía — se detallará aquí cuando arranque cada uno.

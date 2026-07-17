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

### Alcance actual — recordatorio de lo que NO cubrimos todavía

Probado y verificado solo en un caso concreto, de los varios posibles en
cada punto:

- **Tipo de credencial**: solo **PID**. `issuer.eudiw.dev` ofrece muchas
  más (Diploma, EHIC, Health ID, IBAN, Learning Credential, MSISDN, PDA1,
  Power Of Representation, Tax Residency, Tax Number, mDL, Photo ID,
  Certificate of Residence, Employee ID, Loyalty, Seafarer...) — ninguna
  probada.
- **Formato**: solo **SD-JWT VC** (`dc+sd-jwt`), nunca `mso_mdoc` —
  decisión ya tomada y documentada en `CLAUDE.md` (sin CBOR/COSE), no es
  un olvido.
- **Perfil de presentación**: solo **`openid4vp`** (el genérico). No
  probado contra **`haip`** (HAIP, el perfil más estricto que ofrece
  `verifier.eudiw.dev`) — nuestro `present.rs` no implementa lo que ese
  perfil exigiría de más (DPoP, client attestation, etc.).

No bloquea nada ahora mismo — el `wallet` cumple su criterio de
corrección (`CLAUDE.md`: "el flujo funciona end-to-end") para el caso que
sí hemos probado. Queda anotado por si en el futuro hace falta ampliar a
otro tipo/formato/perfil.

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
- [x] **Phase 3** — flujo OID4VP `present` implementado en
      `present.rs` + `sd_jwt.rs`. Hallazgo: `ssi::claims::sd_jwt`
      (re-exportado desde `ssi-sd-jwt`, ya en el árbol de dependencias vía
      `ssi`) trae parseo de SD-JWT compacto y construcción/firma de KB-JWT
      completos y correctos — `sd_jwt.rs` es una envoltura fina sobre eso
      en vez de un parser hand-rolled desde cero (a diferencia de lo
      previsto en el plan original). `present.rs` implementa los traits
      `Wallet`/`RequestVerifier` de `openid4vp` (excepción a "sin traits
      propios", igual que `oid4vci`): `x509_hash` y `x509_san_dns` ambos
      implementados (delegando en los `validate()` ya provistos por
      `openid4vp` con `P256Verifier`) porque no sabemos aún cuál de los dos
      client-id schemes usa `verifier.eudiw.dev` — sin validar la cadena
      hasta una root de confianza (no tenemos CA propia todavía, `ca` sigue
      stub; coherente con que este entorno no tiene validez legal). Metadata
      del wallet declarada solo con formato `dc+sd-jwt`. El match de
      credencial guardada usa `dcql_query().meta().vct_values` contra
      `storage::find_credential_by_vct`. Nuevas dependencias: `async-trait`
      (exigido por los traits de `openid4vp`) y `url` (tipo que exige
      `Wallet::validate_request`); se quitó `base64` (dependencia añadida
      preventivamente en Phase 1, quedó sin usar tras este descubrimiento).
      Build/clippy/fmt limpios; probado en frío (URL inválida, URL
      sintética bien formada pero con `authorization_endpoint` que no
      cuadra — falla limpio, sin pánicos). Además, 8 tests unitarios
      añadidos sin red: `select_authorization_server` (`issue.rs`,
      4 casos), `sd_jwt::append_key_binding` (genera un SD-JWT sintético
      con `ssi`, comprueba que el KB-JWT resultante verifica con la clave
      del holder), y `storage.rs` (guardado/listado/orden/búsqueda por
      `vct`, con un `Wallet::open_at` interno para poder usar un directorio
      temporal en vez de `~/.eidas-testenv`).

      **Round-trip real contra `verifier.eudiw.dev`** — dos hallazgos
      reales corregidos en el camino, ninguno anticipado por la
      documentación de `openid4vp`:
      1. El verifier pedía `response_mode=direct_post.jwt` (JARM, respuesta
         cifrada), no `direct_post` plano. Arreglado usando
         `openid4vp::core::jwe::build_encrypted_response` (ya provisto por
         la librería) cuando `request.response_mode()` es
         `DirectPostJwt`.
      2. El verifier exige recibir de vuelta el `state` de la petición
         original — lo omitíamos. Arreglado leyendo `request.state()` y
         pasándolo tanto a la respuesta sin cifrar
         (`UnencodedAuthorizationResponse::with_state`) como a
         `build_encrypted_response`.
      3. (No es bug nuestro) Un primer intento con un PID emitido el día
         anterior falló con `IssuerCertificateIsNotTrusted` — el
         certificado de firma de `issuer.eudiw.dev` había rotado desde la
         emisión. Con un PID recién emitido, la presentación se aceptó sin
         problemas.

      **Confirmado (2026-07-07)**: `wallet present --url ...` contra una
      petición real de `verifier.eudiw.dev` (client_id_scheme `x509_hash`)
      completa el flujo entero — validación de la petición firmada,
      emparejamiento DCQL por `vct`, KB-JWT firmado con la clave del
      holder, respuesta JARM cifrada con `state`, aceptada por
      `direct_post`. Phase 3 cerrada.
- [x] **Phase 4** — `README.md` escrito (pitch, tabla de estado de
      componentes, guía rápida de `wallet`, alcance actual, comandos de
      desarrollo, licencia). Pasada final de `cargo build/clippy/fmt/test
      --workspace` limpia. Sprint de `wallet` cerrado.
- [x] **Phase 5** — `wallet serve`: UI web local (`127.0.0.1` únicamente)
      que replica `issue`/`present`/`list` en el navegador, pensada para
      pegar directamente una captura del QR en vez de copiar la URL a
      mano. Decisión de diseño: el QR se decodifica **en Rust, en el
      servidor** (`image` + `rqrr`), no con una librería JS de terceros —
      el frontend (un único `assets/index.html`, vanilla JS, sin CDN ni
      build step) solo manda los bytes de la imagen pegada/soltada y
      pinta el JSON de vuelta. `image` fijado a `=0.25.6` exacto (0.25.7+
      exige rustc 1.85, por encima del `rust-version = "1.80"` del
      workspace). Refactor necesario en `issue.rs`/`present.rs`: el cuerpo
      de `run()` pasó a `run_inner(...) -> Result<IssueOutcome |
      PresentOutcome>` (structs/enum `#[derive(Serialize)]`), con `run()`
      como wrapper fino que conserva exactamente el mismo comportamiento
      de la CLI (incluido el prompt de `tx_code` por stdin) — así la
      lógica de protocolo se comparte entre CLI y web sin duplicarla.
      `serve.rs` expone `GET /`, `POST /api/decode-qr`, `POST /api/issue`,
      `POST /api/present`, `GET /api/credentials`, con un adaptador
      `ApiError` (`anyhow::Error` → `IntoResponse`) — mismo tipo de
      excepción "trait exigido por una librería externa" ya aceptada para
      `openid4vp`/`oid4vci`. La página incluye un cuarto bloque "Firmar"
      visualmente presente pero deshabilitado, señalando que la firma QES
      queda fuera de alcance de `wallet` (ver `CLAUDE.md`). Verificado:
      build/test/fmt/clippy limpios en todo el workspace; `ss -tlnp`
      confirma bind solo a `127.0.0.1`; `/api/decode-qr` probado con un
      QR real generado con `python3-qrcode` (decodifica correctamente) y
      con datos basura (error JSON legible, sin pánico ni 500 vacío);
      `/api/credentials` coincide con la salida de `wallet list`.

### Pendiente, sin prisa (anotado, no bloquea Phase 4)

- **`find_credential_by_vct` coge el más antiguo, no el más reciente.**
  `storage.rs` ordena `list_credentials()` de más antiguo a más nuevo y
  hace `.find()`, que se queda con el primero — o sea, el PID más viejo
  con ese `vct`. Si hay varios guardados con el mismo `vct` (p.ej. tras
  reemitir un PID de prueba), `wallet present` presenta el viejo, no el
  recién emitido — nos pasó durante las pruebas de Phase 3, tocó borrar el
  antiguo a mano. Arreglo barato cuando se retome: invertir el criterio
  para quedarse con el más reciente (`.max_by_key` sobre `received_at`, o
  invertir el orden antes de `.find()`).

## ca (sprint activo)

Decisiones de diseño ya tomadas:

- **Generador estático (CLI), no un servicio de emisión.** Se ejecuta una
  vez (`ca bootstrap`), escribe certificados/claves a disco bajo
  `./data/ca/` (ya referenciado por `docker-compose.yml`) y no queda nada
  corriendo — igual que `tl` será "generador de Trusted List". No hay caso
  de uso real hoy que justifique una API de emisión bajo demanda
  (CSC/ACME-like).
- **Cadena de 3 niveles**: Root CA (autofirmada) → Sub-CA (`pathlen:0`,
  no puede emitir más sub-CAs) → 4 hojas firmadas por la sub-CA (TSA,
  OCSP, dos user/signing certs). Root/Sub-CA/TSA/OCSP fijos en P-256 (son
  plumbing de la cadena); el punto donde de verdad importa poder variar
  el algoritmo es el certificado de firma ("user"), de ahí que
  `bootstrap` genere por defecto uno P-256 y otro RSA-2048 — los dos que
  `ades-rs`/`portal` necesitarán para probar ambos algoritmos.
- **Librería**: `x509-cert` (RustCrypto, `builder` feature) para
  construir los certificados, `p256`/`rsa` para las claves — todo puro
  Rust, sin OpenSSL, coherente con `CLAUDE.md`. Verificado contra el
  código fuente real de `x509-cert` v0.2.5 antes de implementar: el
  perfil `Leaf` ya pone `KeyUsage(DigitalSignature | NonRepudiation)` por
  defecto (sin el feature `hazmat`/`Manual`) y `ExtendedKeyUsage` puede
  añadirse con `add_extension` sin chocar con nada que el perfil ya
  genere — así que ninguno de los 5 tipos de certificado necesitó el
  perfil `Manual`.

Fases:

- [x] **Phase 1** — `ca bootstrap`/`ca list` implementados en
      `bootstrap.rs`/`list.rs`/`storage.rs`. Capa de almacenamiento:
      `./data/ca/<rol>/{cert.pem,key.pem}` para
      `root`/`sub-ca`/`tsa`/`ocsp`/`user-p256`/`user-rsa2048`; `bootstrap`
      rechaza pisar un `out-dir` no vacío salvo `--force`. Números de
      serie: 20 bytes aleatorios (bit alto del primer byte a 0, para que
      la codificación DER INTEGER no necesite byte de signo extra),
      siguiendo RFC 5280.

      **Bug real encontrado y corregido durante la verificación con
      `openssl verify`** (no anticipado por la compilación ni por
      clippy): las funciones `issue_p256_leaf`/`issue_rsa_leaf` firmaban
      cada hoja con la propia clave recién generada del leaf en vez de
      con la clave de la sub-CA emisora — el certificado quedaba
      criptográficamente autofirmado pese a declarar `issuer` = sub-CA en
      el Name. `openssl verify` lo detectó de inmediato como
      `error 30: authority and subject key identifier mismatch` (el AKI
      de la hoja no coincidía con el SKI de la sub-CA). Arreglado pasando
      `&sub_ca.key` como `cert_signer` en ambas funciones — la clave
      propia del leaf sigue usándose para su `subject_public_key_info` (y
      para `user-rsa2048`, `.build::<DerSignature>()` en vez de
      `.build::<RsaSignature>()`, ya que quien firma es siempre la
      sub-CA, en P-256, independientemente del algoritmo de la clave del
      sujeto).

      **Verificado**: `cargo build/clippy/fmt/test --workspace` limpios;
      `cargo run -p ca -- bootstrap` genera los 6 pares cert/key;
      `openssl verify -CAfile root/cert.pem -untrusted sub-ca/cert.pem
      <hoja>/cert.pem` da `OK` en las 4 hojas y en la propia sub-ca;
      `openssl x509 -ext basicConstraints,keyUsage,extendedKeyUsage`
      confirma `CA:TRUE`/`pathlen:0` en root/sub-ca y el EKU correcto
      (`Time Stamping` / `OCSP Signing`, ambos `critical`) en tsa/ocsp;
      comprobado que cada `key.pem` corresponde a su `cert.pem`
      (`openssl x509 -pubkey` vs `openssl pkey -pubout`, mismo hash
      SHA-256). `cargo run -p ca -- list` relee los certificados y
      muestra subject/issuer/serial/validez/algoritmo/EKU. Phase 1
      cerrada.

### Pendiente, sin prisa (anotado, no bloquea Phase 1)

- `ca issue-user --cn ... --key-algo ...` para identidades ad-hoc
  adicionales, si `portal`/`ades-rs` acaban necesitando más de los dos
  user certs por defecto.
- Extensión "OCSP No Check" (`id-pkix-ocsp-nocheck`) en el cert de OCSP,
  si el stub de `docker/ocsp` la acaba necesitando.
- QCStatements (ETSI EN 319 412-5) en el user cert si en algún momento
  hace falta simular explícitamente un "certificado cualificado" en vez
  de un leaf cert genérico.

## tl (sprint activo)

Decisiones de diseño ya tomadas:

- **Generador estático (CLI), no un servicio.** `tl bootstrap` lee
  `<ca-dir>/root/cert.pem` (el Root CA que ya produce `ca bootstrap`) y
  escribe `<out-dir>/tl.xml` — mismo patrón que `ca`: se ejecuta una vez,
  no queda nada corriendo.
- **Alcance de esta primera fase**: un único `TrustServiceProvider` con un
  único `TSPService` apuntando al Root CA, tipo de servicio `CA/QC`,
  estado `granted`. Sin `AdditionalServiceInformation`, sin múltiples
  TSPs/servicios, sin historial — se añaden si `verifier`/`portal` los
  necesitan de verdad.
- **Sin firma XAdES por ahora** (decisión explícita, confirmada con el
  usuario) — se genera el XML en claro, sin `ds:Signature`. Firmar exige
  una identidad de "scheme operator" y dependencias AdES que aún no están
  decididas; queda como pendiente, igual que `ca` dejó pendientes las
  QCStatements.
- **`SchemeTerritory = "XX"`**: placeholder del rango ISO 3166-1
  "user-assigned" (nunca asignado a un país real) — no hay operador de
  esquema real detrás de esta TL de pruebas. El resto de campos de
  identidad (nombre del operador, direcciones postal/electrónica) son
  igualmente placeholders marcados como "no legal value"/"test
  environment" en el propio texto.
- **Librería**: `quick-xml` (escritura, con escapado correcto) en vez de
  concatenar strings a mano; `base64` para el `X509Certificate`
  (base64Binary del XSD); `time` (no `chrono`) para los timestamps
  RFC 3339 que exige `xsd:dateTime`.

Fases:

- [x] **Phase 1** — `tl bootstrap` implementado en
      `tsl.rs` (construcción pura del XML) + `bootstrap.rs` (lectura del
      Root CA + CLI). Estructura verificada elemento por elemento contra
      el XSD real de ETSI TS 119 612 v2.2.1 (namespace
      `http://uri.etsi.org/02231/v2#`, descargado de
      `uri.etsi.org/19612/v2.2.1/...xsd` — requiere un User-Agent de
      navegador, si no devuelve una página HTML de aviso en vez del XSD)
      antes de escribir el generador, no de memoria.

      **Validación**: se había decidido `xmllint --schema` como criterio
      de corrección (igual que `openssl verify` para `ca`), pero
      `xmllint` (paquete `libxml2-utils`) no está instalado y este
      entorno no tiene acceso root para instalarlo. Sustituido por
      `lxml.etree.XMLSchema` (Python), que usa la misma librería
      `libxml2` por debajo — mismo motor de validación, distinta
      interfaz; si en el futuro se dispone de `xmllint`, es intercambiable
      sin cambiar nada del generador. El propio XSD importa
      `http://www.w3.org/2001/xml.xsd` (para `xml:lang`) y el schema de
      XML-DSig (para `ds:Signature`, no usado en esta fase pero declarado
      en el tipo); ambos se descargaron también y se resolvieron con un
      `lxml.etree.Resolver` local en vez de dejar que la validación
      dependa de red en tiempo de ejecución.

      **Verificado**: `cargo build/clippy/fmt/test --workspace` limpios;
      `cargo run -p tl -- bootstrap` genera `./data/tl/tl.xml` a partir de
      `./data/ca/root/cert.pem`; `lxml.etree.XMLSchema(...).validate(...)`
      da `True` contra el XSD oficial; el `<X509Certificate>` embebido
      decodifica (base64) a los mismos bytes DER exactos que
      `data/ca/root/cert.pem`. 2 tests unitarios sin red en `tsl.rs`
      (bien-formado vía `quick_xml::Reader`, round-trip del base64 del
      certificado). Phase 1 cerrada.

### Pendiente, sin prisa (anotado, no bloquea Phase 1)

- Firma XAdES-BES del `tl.xml` con un certificado de "scheme operator" —
  diferida a propósito (ver decisiones arriba).
- `AdditionalServiceInformation` / múltiples TSPs o servicios (p.ej. TSA,
  OCSP como servicios separados en la TL) si `verifier`/`portal` acaban
  necesitando distinguir tipos de servicio más allá del `CA/QC` único.

## verifier / portal

Solo stubs (`println!("not implemented yet")`). Sin sprint planificado
todavía — se detallará aquí cuando arranque cada uno.

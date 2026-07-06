# eidas-testenv — CLAUDE.md

## Contexto del proyecto

Workspace Rust: entorno de pruebas/demo para `ades-rs` (librería AdES del
mismo autor, https://crates.io/crates/ades-rs) y para el ecosistema EUDI
Wallet (OID4VCI/OID4VP). Sustituye el DSS Demo de la Comisión Europea (que
exige certificados de CAs en Trusted Lists oficiales) por un entorno donde
se puede probar wallets/verificadores/firmas AdES sin necesitar
infraestructura o certificados reales de un QTSP.

Crates:
- `wallet` — CLI que obtiene (OID4VCI) y presenta (OID4VP) una credencial
  PID contra los endpoints oficiales de la CE (`issuer.eudiw.dev`,
  `verifier.eudiw.dev`). **En desarrollo.**
- `ca`, `tl`, `verifier`, `portal` — generador de cadena CA, generador de
  Trusted List (ETSI TS 119 612), verifier OID4VP propio, portal de demo
  AdES. **Stubs**, sin implementar todavía.

Ver `ROADMAP.md` para el estado actual de cada crate/fase — este fichero
(`CLAUDE.md`) solo contiene reglas y decisiones estables, no tracking de
progreso.

## Comandos esenciales

```bash
cargo build --workspace                            # compilar todo
cargo test --workspace                              # tests
cargo clippy --workspace --all-targets -- -D warnings  # lint estricto — cero warnings tolerados
cargo fmt --all                                     # formatear
cargo fmt --all -- --check                          # verificar formato sin modificar (CI)
cargo doc --workspace --no-deps --open              # documentación
cargo run -p <crate> -- --help                      # ver comandos de un crate
```

## Arquitectura — decisiones tomadas, NO cambiar sin consultar

- Todos los crates son **binarios**, no librerías — por eso `anyhow` en
  todos, nunca `thiserror` (a diferencia de `eidas-rs`, que sí es una
  librería production-ready con esa regla)
- Workspace mono-repo: un `Cargo.toml` raíz con `[workspace.package]`
  (edition, rust-version, license compartidos), crates en `/crates/`
- Sin `unwrap()` ni `expect()` fuera de `#[cfg(test)]` — propagar con `?`
- `#![forbid(unsafe_code)]` en todo crate nuevo (aplica a nuestro propio
  código; las dependencias externas pueden usar `unsafe` internamente, eso
  no lo controlamos ni lo intentamos prohibir)
- MSRV: Rust 1.80, edition 2021 (**no** edition 2024, que exige rustc 1.85+)
- Licencia: MIT OR Apache-2.0 (dual, estándar del ecosistema Rust)
- `wallet` solo implementa el flujo OID4VCI `pre-authorized_code` (no
  `authorization_code`) y no monta infraestructura propia (sin ngrok, sin
  servidor público) — detalles y motivos en `ROADMAP.md`
- Formato de credencial objetivo en `wallet`: SD-JWT VC (`dc+sd-jwt`), no
  `mso_mdoc` (no hay dependencias CBOR/COSE en el repo)

## Dependencias — política

- Preferir RustCrypto / Rust puro (`p256`, `sha2`, `rsa`, `x509-cert`, `cms`,
  `der`, `spki`, etc.) siempre que sea posible, igual que en `eidas-rs`
- **Evitar OpenSSL siempre que se pueda.** Si en algún caso concreto resulta
  claramente más fácil o mejor usar OpenSSL en vez de RustCrypto puro, **no
  decidirlo unilateralmente** — anotarlo (comentario en el Cargo.toml o
  aviso explícito) y consultarlo antes de añadirlo
- **Excepción ya aceptada y documentada**: `wallet` depende de `openid4vp` y
  `oid4vci` (SpruceID, git deps) cuyos propios `Cargo.toml` no desactivan
  las features por defecto de `reqwest`, así que arrastran `native-tls` /
  `openssl-sys` transitivamente pese a que nuestro propio `reqwest` pide
  `rustls-tls`. Este entorno no tiene `pkg-config`/`libssl-dev` ni acceso
  root, así que se fuerza el feature `vendored` de `openssl` (compila
  OpenSSL desde fuente con `perl`+`make`+`cc`, sin depender del sistema)
  en vez de instalar paquetes del sistema
- Sin dependencias innecesarias — justificar cada dependencia añadida más
  allá de lo obvio con un comentario en el `Cargo.toml` (ver ejemplos ya
  presentes en `crates/wallet/Cargo.toml`)

## Patrones obligatorios

- Toda función y tipo público lleva doc comment
- Errores propagados con `anyhow::Result` + `.context(...)`, nunca
  `Err("string")` ad-hoc
- Cada cambio debe pasar: `cargo fmt --all -- --check` +
  `cargo clippy --workspace --all-targets -- -D warnings`

## Estilo de código — traits vs structs (misma filosofía que eidas-rs)

- Trait **solo** cuando hay de verdad varios backends intercambiables
  dentro de este repo — no por costumbre ni por si acaso
  - Excepción impuesta desde fuera: los traits `Wallet` / `RequestVerifier`
    de `openid4vp`, y el cliente de `oid4vci`, se implementan porque esas
    librerías externas lo exigen para integrarse — no es una decisión de
    diseño nuestra, así que no cuenta como precedente para inventar más
    traits propios
- Para todo lo demás → structs concretas, una sola implementación:
  generador de certificados en `ca`, generador de Trusted List en `tl`,
  handlers de `verifier`/`portal`, storage y holder key del `wallet`
- Enums para variantes cerradas (p.ej. `CredentialTokenState`, que ya viene
  así definido en `oid4vci`), nunca un trait para eso
- No diseñar para extensibilidad imaginaria — YAGNI. Si en el futuro se
  necesita de verdad un segundo backend intercambiable en algún punto,
  entonces se introduce el trait en ese momento

## Criterio de corrección — por componente

No hay un único validador externo como el DSS de `eidas-rs`; cada
componente tiene el suyo:

- `wallet`: el flujo funciona end-to-end contra los servicios oficiales —
  `issuer.eudiw.dev` acepta la petición de credencial, `verifier.eudiw.dev`
  acepta la presentación
- `ca` (futuro): `openssl verify` acepta la cadena generada; los
  certificados son consumibles por `ades-rs`
- `tl` (futuro): XML válido según ETSI TS 119 612
- `verifier` / `portal` (futuro): firmas AdES generadas/validadas por el
  DSS de la CE (mismo criterio que usa `ades-rs`)

## Lo que NO hacer ahora

- No implementar el flujo `authorization_code` de OID4VCI (necesitaría
  simular un login de navegador contra el formulario de test "Utopia" —
  descartado, ver `ROADMAP.md` para el razonamiento)
- No implementar el formato `mso_mdoc` — solo SD-JWT VC
- No montar infraestructura propia (ngrok, servidor público) para el
  wallet — no hace falta contra los endpoints oficiales tal y como
  funcionan hoy
- No trabajar en `ca` / `tl` / `verifier` / `portal` más allá del stub
  hasta que les toque su sprint
- **`wallet` no implementa firma remota cualificada (QES)** — solo
  emisión (OID4VCI) y presentación (OID4VP) de credenciales, tal y como
  dice su descripción arriba. Firmar con un certificado cualificado vía un
  QTSP (típicamente API CSC / flujo "Remote QES" de eIDAS 2.0) es un
  protocolo distinto de OID4VCI/OID4VP, y encaja más naturalmente con la
  otra mitad del proyecto (`ades-rs` + `portal`) que con `wallet`. Si algún
  día se aborda, decidir entonces si es un comando nuevo de `wallet` o un
  módulo aparte — no asumirlo por precedente de este repo

## Licencia

MIT OR Apache-2.0 (dual) — estándar del ecosistema Rust.

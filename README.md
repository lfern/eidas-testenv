# eidas-testenv

Workspace Rust: entorno de pruebas/demo para
[`ades-rs`](https://crates.io/crates/ades-rs) (librería AdES del mismo
autor) y para el ecosistema EUDI Wallet (OID4VCI/OID4VP). Sustituye el DSS
Demo de la Comisión Europea (que exige certificados de CAs en Trusted
Lists oficiales) por un entorno donde se puede probar
wallets/verificadores/firmas AdES sin necesitar infraestructura o
certificados reales de un QTSP.

> ⚠️ **Sin validez legal.** Nada de lo que emite, firma o verifica este
> repositorio tiene validez jurídica. Es un entorno de pruebas contra los
> servicios de demo oficiales de la UE (`issuer.eudiw.dev`,
> `verifier.eudiw.dev`), con datos e identidades sintéticas.

## Estado de los componentes

| Crate | Qué es | Estado |
|-------|--------|--------|
| `wallet` | CLI que obtiene (OID4VCI) y presenta (OID4VP) una credencial PID contra los endpoints oficiales de la CE | En desarrollo — `issue`/`present`/`list` funcionales |
| `ca` | Generador de cadena de certificados | Stub, sin implementar |
| `tl` | Generador de Trusted List (ETSI TS 119 612) | Stub, sin implementar |
| `verifier` | Verifier OID4VP propio | Stub, sin implementar |
| `portal` | Portal de demo AdES | Stub, sin implementar |

Ver [`ROADMAP.md`](ROADMAP.md) para el detalle de fases y decisiones de
diseño del sprint activo, y [`CLAUDE.md`](CLAUDE.md) para las reglas
estables del repo (arquitectura, dependencias, estilo de código).

## `wallet` — guía rápida

### Comandos

```bash
# Obtener un PID a partir de una oferta de credencial pre-authorized
cargo run -p wallet -- issue --url "<credential-offer-url>"

# Presentar un PID guardado contra la petición de un verifier
cargo run -p wallet -- present --url "<presentation-request-url>"

# Listar las credenciales guardadas localmente
cargo run -p wallet -- list
```

Las dos URLs (`issue`/`present`) son de un solo uso y hay que generarlas a
mano desde la web del issuer/verifier — no se pueden scriptear. Ver
[`MANUAL-TESTING.md`](MANUAL-TESTING.md) para el procedimiento paso a
paso contra `issuer.eudiw.dev`/`verifier.eudiw.dev`.

### Dónde se guarda todo

```
~/.eidas-testenv/wallet/
├── key.json                  # clave ES256 del holder (JWK, en claro)
└── credentials/
    └── <uuid>.json           # credenciales SD-JWT VC recibidas
```

La clave del holder se genera una vez y se reutiliza para todas las
emisiones y presentaciones futuras — no se regenera en cada ejecución.

### Alcance actual

- Solo el flujo OID4VCI **pre-authorized_code** (no `authorization_code`)
- Solo formato de credencial **SD-JWT VC** (`dc+sd-jwt`, no `mso_mdoc`)
- Solo tipo de credencial **PID** (no mDL, Diploma, EHIC, etc.)
- Solo perfil de presentación **`openid4vp`** genérico (no `haip`)
- Sin infraestructura propia (sin ngrok, sin servidor público)

Motivos y detalles de cada decisión en [`CLAUDE.md`](CLAUDE.md) y
[`ROADMAP.md`](ROADMAP.md).

## Comandos de desarrollo

```bash
cargo build --workspace                                # compilar todo
cargo test --workspace                                 # tests
cargo clippy --workspace --all-targets -- -D warnings  # lint estricto — cero warnings tolerados
cargo fmt --all                                        # formatear
cargo fmt --all -- --check                              # verificar formato sin modificar (CI)
cargo doc --workspace --no-deps --open                  # documentación
cargo run -p <crate> -- --help                          # ver comandos de un crate
```

## Licencia

MIT OR Apache-2.0 (dual) — estándar del ecosistema Rust.

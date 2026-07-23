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
| `ca` | Generador estático de PKI de pruebas (Root CA, Sub-CA, TSA, OCSP, user certs) | En desarrollo — `bootstrap`/`list` funcionales |
| `tl` | Generador de Trusted List (ETSI TS 119 612) | En desarrollo — `bootstrap` funcional |
| `verifier` | Verifier OID4VP propio | Stub, sin implementar |
| `portal` | Portal de demo AdES (firma CAdES B-B) | En desarrollo — `serve` funcional |

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

# UI web local (127.0.0.1 únicamente): pega una captura del QR o la URL
cargo run -p wallet -- serve --port 7890
```

Las dos URLs (`issue`/`present`) son de un solo uso y hay que generarlas a
mano desde la web del issuer/verifier — no se pueden scriptear. Ver
[`MANUAL-TESTING.md`](MANUAL-TESTING.md) para el procedimiento paso a
paso contra `issuer.eudiw.dev`/`verifier.eudiw.dev`.

`wallet serve` levanta la misma funcionalidad (`issue`/`present`/`list`) en
`http://127.0.0.1:<puerto>` — el QR se decodifica en el propio servidor
(pura Rust, `image`+`rqrr`), sin ninguna librería JS de terceros. Nunca
escucha en `0.0.0.0`: la clave privada del holder se guarda en claro en
disco, así que no debe quedar accesible desde la red local.

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

## `ca` — guía rápida

### Comandos

```bash
# Generar la cadena completa (root, sub-ca, tsa, ocsp, dos user certs)
cargo run -p ca -- bootstrap

# Regenerar desde cero, pisando lo que hubiera en ./data/ca
cargo run -p ca -- bootstrap --force

# Listar los certificados generados (subject/issuer/serial/validez/EKU)
cargo run -p ca -- list
```

Es un **generador estático**, no un servicio: `bootstrap` escribe todo a
disco de una vez y no deja nada corriendo. Cadena de 3 niveles — Root CA
autofirmada → Sub-CA (`pathlen:0`) → 4 hojas firmadas por la sub-CA (TSA,
OCSP, y dos certificados de firma de usuario, uno P-256 y otro RSA-2048,
para poder probar `ades-rs` contra ambos algoritmos).

### Dónde se guarda todo

```
./data/ca/
├── root/{cert.pem,key.pem}
├── sub-ca/{cert.pem,key.pem}
├── tsa/{cert.pem,key.pem}
├── ocsp/{cert.pem,key.pem}
├── user-p256/{cert.pem,key.pem}
└── user-rsa2048/{cert.pem,key.pem}
```

Claves privadas en PKCS#8 PEM sin cifrar (entorno de pruebas, sin validez
legal — ver aviso arriba). `./data/` está en `.gitignore`.

## `portal` — guía rápida

### Comandos

```bash
# UI web local (127.0.0.1 únicamente): sube un archivo, elige un cert de
# `ca bootstrap` (user-p256 / user-rsa2048), firma en CAdES B-B
cargo run -p portal -- serve --port 8090 --ca-dir ./data/ca
```

Firma **detached** (el archivo original no queda embebido en la firma —
hace falta guardarlo aparte para verificar después). Requiere haber
ejecutado antes `ca bootstrap` (u otro `--ca-dir` con la misma estructura
`<role>/{cert.pem,key.pem}`).

```bash
# Verificación local sin depender del DSS de la CE
openssl cms -verify -binary -in firma.p7s -inform DER -content original.txt \
  -CAfile <(cat data/ca/root/cert.pem data/ca/sub-ca/cert.pem)
```

(`-binary` es obligatorio — sin él, `openssl cms -verify` aplica
canonicalización S/MIME al contenido y la verificación falla aunque la
firma sea correcta.)

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

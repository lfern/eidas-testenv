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
| `tsa` | Responder RFC 3161 (timestamp authority) | En desarrollo — `serve` funcional |
| `ocsp` | Responder RFC 6960 (OCSP) | En desarrollo — `serve` funcional |

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
# `ca bootstrap` (user-p256 / user-rsa2048) y un nivel (B-B / B-T / B-LT)
cargo run -p portal -- serve --port 8090 --ca-dir ./data/ca
```

Firma **detached** (el archivo original no queda embebido en la firma —
hace falta guardarlo aparte para verificar después). Requiere haber
ejecutado antes `ca bootstrap` (u otro `--ca-dir` con la misma estructura
`<role>/{cert.pem,key.pem}`). El nivel **B-T** (con sello de tiempo)
requiere tener `tsa serve` corriendo — por defecto `portal` lo busca en
`http://127.0.0.1:2560/` (`--tsa-url` para cambiarlo). **B-LT** (con
prueba de no-revocación, construido sobre B-T) requiere además `ocsp
serve` — por defecto `http://127.0.0.1:2561/` (`--ocsp-url`).

```bash
# Verificación local sin depender del DSS de la CE
openssl cms -verify -binary -in firma.p7s -inform DER -content original.txt \
  -CAfile <(cat data/ca/root/cert.pem data/ca/sub-ca/cert.pem)
```

(`-binary` es obligatorio — sin él, `openssl cms -verify` aplica
canonicalización S/MIME al contenido y la verificación falla aunque la
firma sea correcta.)

### Verificación contra el DSS de la Comisión Europea

Además de `openssl` (verificación local, sin red), la firma se puede
comprobar con el validador de referencia oficial,
[dss.nowina.lu/validation](https://dss.nowina.lu/validation) — el mismo
criterio de corrección que fija `CLAUDE.md` para este crate.

1. `cargo run -p portal -- serve --port 8090 --ca-dir ./data/ca` (requiere
   haber ejecutado antes `ca bootstrap`).
2. Abrir `http://127.0.0.1:8090`, subir cualquier archivo, elegir un cert
   (`user-p256` o `user-rsa2048`) y pulsar "Firmar".
3. Pulsar "Descargar firma (.p7s)" — es una firma **detached**, así que
   además de ese `.p7s` hace falta el archivo original que se subió en el
   paso 2 (el mismo que ya está en el disco del usuario).
4. En `https://dss.nowina.lu/validation`, subir el `.p7s` en **"Signed
   file"** y el archivo original en **"Original file(s)"**, dejar el resto
   de opciones por defecto y pulsar **Validate**.

**Resultado esperado**: `Signature format: CAdES-BASELINE-B`,
`Signature scope: <archivo> (FULL)` (documento y firma correctamente
emparejados) y `Indication: INDETERMINATE` /
`Sub indication: NO_CERTIFICATE_CHAIN_FOUND` ("The certificate chain for
signature is not trusted, it does not contain a trust anchor."). Ese
`INDETERMINATE` es correcto, no un fallo: la política de validación del
DSS comprueba la cadena contra las Trusted Lists reales de la UE, y la CA
de `ca bootstrap` es de pruebas — no está en ninguna TL real (ver aviso de
"Sin validez legal" al principio de este documento). Un `TOTAL_FAILED` o
un error de integridad de la firma sí indicaría un problema real.

No existe (todavía) un script que automatice la subida al DSS — su
formulario web no es una API pública pensada para *scripting* — así que
este paso se hace a mano, en el navegador.

## `tsa` / `ocsp` — guía rápida

Responder RFC 3161 (timestamp authority) y responder RFC 6960 (OCSP),
firmando con las identidades `tsa`/`ocsp` que `ca bootstrap` ya genera.
`portal` ya los usa para los niveles B-T/B-LT (ver arriba); también se
pueden probar de forma independiente:

```bash
# Requiere haber ejecutado antes `ca bootstrap`
cargo run -p tsa -- serve --port 2560 --ca-dir ./data/ca
cargo run -p ocsp -- serve --port 2561 --ca-dir ./data/ca
```

Verificación con `openssl` (sin depender de `ades-rs`):

```bash
# TSA
openssl ts -query -data <archivo> -sha256 -cert -out req.tsq
curl -s -X POST http://127.0.0.1:2560/ -H "Content-Type: application/timestamp-query" \
  --data-binary @req.tsq -o resp.tsr
openssl ts -reply -in resp.tsr -text
openssl ts -verify -in resp.tsr -data <archivo> \
  -CAfile <(cat data/ca/root/cert.pem data/ca/sub-ca/cert.pem) \
  -untrusted <(cat data/ca/tsa/cert.pem data/ca/sub-ca/cert.pem)

# OCSP
openssl ocsp -issuer data/ca/sub-ca/cert.pem -cert data/ca/user-p256/cert.pem \
  -reqout req.der
curl -s -X POST http://127.0.0.1:2561/ -H "Content-Type: application/ocsp-request" \
  --data-binary @req.der -o resp.der
openssl ocsp -respin resp.der -text \
  -issuer data/ca/sub-ca/cert.pem -cert data/ca/user-p256/cert.pem \
  -CAfile <(cat data/ca/root/cert.pem data/ca/sub-ca/cert.pem) \
  -verify_other <(cat data/ca/ocsp/cert.pem data/ca/sub-ca/cert.pem)
```

`--host` por defecto es `127.0.0.1` en ambos, a diferencia de
`wallet`/`portal serve` (que nunca salen de `127.0.0.1`): un TSA/OCSP es,
por diseño de protocolo, un servicio de cara a otros procesos, así que
`docker-compose.yml`/los `Dockerfile` de `docker/tsa`/`docker/ocsp` lo
levantan con `--host 0.0.0.0`:

```bash
docker compose build tsa ocsp
docker compose up tsa ocsp
```

El `ocsp` de esta fase siempre responde `good` — `ca` no tiene
CRL/revocación todavía (ver `ROADMAP.md`), no hay estado de revocación
real que consultar.

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

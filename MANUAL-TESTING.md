# wallet — round-trip manual (issue + present)

El flujo completo de `wallet` no se puede scriptear de punta a punta: tanto
la oferta de credencial (`issuer.eudiw.dev`) como la petición de
presentación (`verifier.eudiw.dev`) son URLs **de un solo uso**, generadas
a mano en la web de cada servicio. Este documento recoge los pasos exactos
que hay que repetir cada vez que se quiera probar el flujo contra los
servicios reales.

## 1. Emisión — obtener un PID (`wallet issue`)

### Pasos en `issuer.eudiw.dev`

1. Abrir `https://issuer.eudiw.dev`.
2. En la lista de credenciales, marcar **"PID (SD-JWT VC)"** — está en el
   grupo **"sd-jwt vc format"**. No marcar la versión de la lista "mdoc
   format" (`PID (MSO Mdoc)` / `PID (MSO Mdoc Deferred)`): este wallet solo
   entiende SD-JWT VC.
3. En **Grants**, elegir **"Pre-Authorization Code Grant"** (nunca
   "Authorization Code Grant" — ese flujo no está soportado, ver
   `CLAUDE.md`).
4. Rellenar el formulario con datos sintéticos (cualquier dato inventado;
   la fecha de nacimiento debe dar mayor de edad).
5. Generar la oferta y copiar el valor de **"Credentials Offer URI"**
   (empieza por `haip-vci://credential_offer?credential_offer=...` o
   similar).

### Comando

```bash
cargo run -p wallet -- issue --url "<URL copiada>"
```

Si la oferta incluye `tx_code` (un código numérico corto que la propia web
muestra al generarla), el comando lo pide interactivamente:

```
Please provide the one-time code.
Enter transaction code: <introducir el código>
```

### Verificar

```bash
cargo run -p wallet -- list
```

Debe aparecer el PID recién guardado (`vct=urn:eudi:pid:1`).

## 2. Presentación — presentar el PID (`wallet present`)

### Pasos en `verifier.eudiw.dev`

1. Abrir `https://verifier.eudiw.dev`.
2. Paso **"select attestation(s)"**: marcar **"Person Identification Data
   (PID)"**.
3. Paso **"Presentation Options"**:
   - **Presentation Profile**: elegir **`openid4vp`** (no `haip` — ese
     perfil exige cosas que este wallet no implementa, como DPoP o client
     attestation).
   - **Authorization Endpoint**: cambiar el valor por defecto
     (`haip-vp://`) por **`openid4vp://`** — tiene que coincidir con el
     esquema que `present.rs` declara soportado
     (`WalletMetadata::openid4vp_scheme_static()`).
   - **Request URI Method**: dejar el valor por defecto.
4. Generar la petición y copiar la URL resultante, con esta forma:
   ```
   openid4vp://?client_id=x509_hash%3A...&request_uri=https%3A%2F%2Fverifier-backend.eudiw.dev%2Fwallet%2Frequest.jwt%2F...&request_uri_method=get
   ```

### Comando

```bash
cargo run -p wallet -- present --url "<URL copiada>"
```

Si todo va bien:

```
Presented credential (vct=urn:eudi:pid:1) to x509_hash:...
```

## 3. Variante web (`wallet serve`)

En vez de copiar la URL a mano y pegarla en `--url`, puedes usar la UI
local:

```bash
cargo run -p wallet -- serve --port 7890
```

Abre `http://127.0.0.1:7890` en el navegador. En las secciones "Emitir" y
"Presentar" puedes:

- Pegar (Ctrl+V) una captura de pantalla del QR que muestra
  `issuer.eudiw.dev`/`verifier.eudiw.dev`, soltarla arrastrándola, o
  seleccionarla con el selector de fichero — se decodifica en el propio
  servidor (no hace falta copiar la URL como texto).
- O pegar directamente la URL como texto en el campo, exactamente igual
  que con `--url`.

El resto del comportamiento es el mismo que la CLI: si el offer requiere
`tx_code`, aparece un campo para introducirlo; la sección "Credenciales
guardadas" refleja lo mismo que `wallet list`. El servidor solo escucha en
`127.0.0.1` — no lo expongas a la red local ni a internet.

## Notas importantes

- **Las dos URLs son de un solo uso** — se consumen aunque el intento
  falle. Cada reintento (por ejemplo, tras arreglar un bug) exige volver a
  generar una URL nueva desde cero.
- **Selección de credencial**: si hay más de un PID guardado en
  `~/.eidas-testenv/wallet/credentials/`, `wallet present` coge el más
  antiguo cuyo `vct` case con lo pedido. Para forzar que use uno concreto
  (por ejemplo, uno recién emitido), borra los demás:
  ```bash
  rm ~/.eidas-testenv/wallet/credentials/<id-a-borrar>.json
  ```
- **Certificados de demo que rotan**: si `present` falla con
  `IssuerCertificateIsNotTrusted`, es porque el certificado de firma de
  `issuer.eudiw.dev` rotó desde que se emitió el PID guardado — no es un
  bug del wallet. Solución: repetir el paso 1 (emitir un PID nuevo) y
  probar la presentación con ese.

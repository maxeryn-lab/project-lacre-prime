# LACRE-WIRE-v1 — Especificación normativa del formato de transporte

Estado: **v1** · Versión de protocolo: **1** · Registro: EXT/E2 de la Etapa 3 (ver `Text/`).
Vectores conocidos: `spec/vectors/wire-v1.json`, producidos por `Tools/gen_vectors.py`
(implementación independiente en Python; no comparte código con el Core en Rust).

## 0. Convenciones

Las palabras **DEBE**, **NO DEBE**, **DEBERÍA** y **PUEDE** se interpretan como en RFC 2119.
Una afirmación marcada **[V]** está cubierta por un vector conocido; **[T]** está cubierta por un
test automatizado que no es un vector; **[I]** es informativa (comportamiento de la implementación de
referencia, no un requisito de interoperabilidad). Las cadenas de bytes se escriben en hexadecimal
minúscula. `∥` es concatenación. `HMAC` es HMAC-SHA256 (RFC 2104/4231) salvo indicación.

## 1. Alcance

Esta especificación fija lo que dos implementaciones independientes deben compartir para que un sello
producido por una sea verificado por la otra: derivación de claves, cadena de estado, sello, recibo,
firma Vault, tokens de capacidad, forma de los mensajes y reglas de versión. **No** especifica
perfiles de reglas (`ruleset`), el motor Toolchain ni la política de recursos del servidor (§10, [I]).

## 2. Identificadores

- `session_id`: 16 bytes. En el cable, 32 caracteres hexadecimales. Cualquier otra longitud o
  carácter no hexadecimal DEBE rechazarse como solicitud mal formada. [T]
- `key_id`: entero sin signo de 8 bits que identifica la clave maestra. Un `key_id` que el verificador
  no posee DEBE producir `UnknownKeyId`; NO DEBE usarse otra clave en su lugar. [V]
- `index`: entero sin signo de 64 bits; el primer fragmento de una sesión tiene índice 0.

## 3. Derivación de la clave de sesión [V]

```
session_key = HKDF-SHA256(ikm = clave_maestra, salt = session_id,
                          info = "lacre-core/v1/session-key", L = 32)
```

`info` es la cadena ASCII, sin terminador. `clave_maestra` es la clave configurada o, tras un
handshake X25519, el secreto compartido de 32 bytes (RFC 7748 §5), usado directamente como `ikm`. La
clave de sesión NO DEBE aparecer en registros ni en mensajes.

## 4. Cadena de estado [V]

```
Es(0)   = HMAC(session_key, session_id ∥ "lacre-core/v1/initial-state")
Es(i+1) = HMAC(session_key, Es(i) ∥ fᵢ)        i ≥ 0
```

`fᵢ` es el payload del fragmento de índice `i` (desde 0) tal como viaja, sin relleno ni cabecera. El
fragmento `i` se sella con `Es(i)`. El estado es secreto de sesión: NO DEBE transmitirse.

## 5. Sello [V]

Sea `S = Es(i)` el estado vigente **antes** de procesar el fragmento `i`.

- Algoritmo `sha256`: `δ = HMAC-SHA256(session_key, fᵢ ∥ S)`
- Algoritmo `blake3`: `δ = BLAKE3-keyed(key = session_key, fᵢ ∥ S)`

`δ` mide siempre 32 bytes. El algoritmo lo fija el perfil y NO viaja en el sello: un verificador que use
el algoritmo equivocado DEBE obtener `SealMismatch`. [V] Tras verificar o sellar, el estado avanza según §4.

La comparación de sellos DEBE hacerse en tiempo constante. [T]

## 6. Recibo [V]

`recibo = SHA-256(δ)` (32 bytes). Se registra al purgar el fragmento (perfil Vault).

## 7. Firma Vault [V]

`firma = Ed25519(semilla, δ)` sobre los 32 bytes del sello, 64 bytes (RFC 8032, determinista). Una sesión
Vault DEBE exigir la firma y rechazar el fragmento si falta o no verifica (`VaultSignatureMismatch`). [T]

## 8. Verificación de una secuencia

Un verificador mantiene `next_index` (inicialmente 0) y el estado de §4. Para cada fragmento recibido,
en este orden:

1. Si `index ≠ next_index` → `OutOfSequence{expected, received}` y NO avanza ni consume nada. [V]
2. Se elige la clave según `key_id`; si no existe → `UnknownKeyId`. [V]
3. Si el sello no coincide → `SealMismatch` y NO avanza; el mismo fragmento correcto puede reenviarse. [V]
4. Perfil Vault: firma ausente o inválida → `VaultSignatureMismatch`. [T]
5. Éxito: estado y `next_index` avanzan en una unidad.

Un fragmento ya verificado no se acepta de nuevo (queda como `OutOfSequence`). [V]
Intercambiar fragmentos, repetirlos u omitirlos DEBE detectarse.

## 9. Mensajes (HTTP/JSON y WebSocket)

Todas las rutas están bajo `/v1/`. Cuerpos en JSON UTF-8. Los campos binarios son hexadecimal.

| Ruta | Método | Petición (campos) | Respuesta (campos) |
|---|---|---|---|
| `/v1/health` | GET | — | estado |
| `/v1/profiles` | GET | — | `version`, `core_touches_payload`, `profiles[]{name, content_access, touches_payload, justification}` |
| `/v1/handshake` | POST | `version?`, `client_public_key_hex` (32 B) | `version`, `server_public_key_hex`, `session_id`, `key_id`, `capabilities{write,verify,ack?}` |
| `/v1/seal` | POST | `version?`, `profile`, `payload_hex`, `session_id?`, `token?`, `ruleset?` | `version`, `session_id`, `frames[]`, `capabilities`, `ruleset_outcome?` |
| `/v1/verify` | POST | `version?`, `profile`, `session_id`, `key_id`, `frames[]`, `token?`, `reassemble?`, `ruleset?` | `version`, `session_id`, `results[]`, `all_verified`, `payload_hex?`, `ruleset_outcome?` |
| `/v1/ack` | POST | `session_id`, `indices[]`, `token?` | `results[]`, `all_acknowledged`, `total_receipts` |
| `/v1/receipts` | POST | `session_id`, `token?` | `entries[]` |
| `/v1/validate` | POST | `ruleset`, `payload_hex` | resultado de reglas |
| `/v1/toolchain/*` | POST | ver código | [I] |

`frames[]` (SealedFrameWire): `session_id`, `index`, `total_fragments` (nulo en streaming), `is_last`,
`payload_hex`, `seal_hex` (32 B), `vault_signature_hex` (64 B, nulo fuera de Vault).

Un `session_id` de nivel superior que no sean 16 bytes hex DEBE rechazarse con 400. [T] Un **frame**
mal formado dentro de `verify` (hex inválido, `seal_hex` ≠ 32 B, `vault_signature_hex` ≠ 64 B, `session_id`
del frame inválido) NO produce 400: la respuesta es 200, el resultado de ese frame lleva `ok: false` con
`error`, el procesamiento de los frames siguientes se detiene y la sesión NO avanza (el mismo frame
corregido puede reenviarse). [T]

Perfiles: `lite`, `core`, `vault`. El perfil fija el algoritmo del sello (§5), el tamaño de fragmento y
si hay firma y recibos. Un perfil desconocido DEBE rechazarse.

### 9.1 Estados de respuesta

| Código | Significado |
|---|---|
| 200 | operación realizada (el veredicto por fragmento va en el cuerpo: `ok`, `error`) |
| 400 | solicitud mal formada (hex, longitudes, perfil, **versión**) |
| 401 | capacidad ausente o inválida (mensaje único para todas las causas; sin oráculo) |
| 404 | recurso inexistente o vencido |
| 422 | solicitud válida que no puede completarse por estado del servidor |
| 429 | tope por sesión alcanzado (no se resuelve reintentando igual) |
| 503 | tope de recursos del servidor; reintentar más tarde PUEDE funcionar |

(413, cuerpo demasiado grande, lo emite la capa HTTP y es [I].)

## 10. Versión del protocolo (A8) [T]

- La versión actual es **1**. Toda petición que inicia una operación (`handshake`, `seal`, `verify`,
  episodio Toolchain) PUEDE llevar `version`; **si se omite, equivale a la versión actual**.
- Una versión desconocida (0, 2, 4294967295, …) o mal formada (negativa, decimal, cadena, booleano,
  lista, fuera de `u32`) DEBE rechazarse con 400 **antes de cualquier otro efecto**: no abre sesión, no
  consume sesión existente. [T]
- Toda respuesta de esas operaciones DEBE incluir `version`.
- La versión **no** está ligada criptográficamente al sello (decisión declarada: cambiar el sello queda
  fuera de alcance). Mientras exista una sola versión, omitirla es válido; cuando exista una segunda, se
  DEBERÁ decidir si `version` pasa a ser obligatorio (pendiente registrado).

## 11. Capacidades [V]

```
token(scope, session_id) = HMAC-SHA256(raíz, "lacre-domain/v1/capability" ∥ 0x00 ∥ scope ∥ 0x00 ∥ session_id)
```

`scope` ∈ {`write`, `verify`, `ack`} en ASCII; `session_id` son los 16 bytes crudos; el token mide
32 bytes y viaja en hexadecimal. Un token DEBE valer solo para su alcance y su sesión, y compararse en
tiempo constante. [V][T] Operaciones y alcance: `seal` sobre sesión existente y `receipts` → `write`;
`verify` → `verify`; `ack` → `ack`; Toolchain: añadir nodo → `write`, verificar salida → `verify`. Un `session_id` sin token DEBE rechazarse con 401.

## 12. Vectores y conformidad

Una implementación es conforme a v1 si reproduce byte a byte todos los valores de
`spec/vectors/wire-v1.json`: derivación (`key_derivation`, `handshake`), cadenas (`chains`: sellos,
estados, recibos), veredictos (`scenarios`), firma (`vault`) y tokens (`capability`). La
implementación de referencia lo comprueba en `lacre-core/tests/wire_vectors.rs` y
`lacre-domain/tests/wire_vectors.rs`; `Tools/gen_vectors.py --check` comprueba que el archivo coincide
con el generador independiente. Si el generador y la implementación discrepan, el generador y las RFC
citadas prevalecen sobre el código hasta que se registre lo contrario.

## 13. Neutralidad del contenido y acceso al payload (Prime 4.2, 4.8, 7.3.1)

Esta sección distingue dos cosas: el **Núcleo** (fragmentación, sello, purga) y los **Profiles de
extensión** (reensamblado, Toolchain, motor de reglas, Guardian, Certifier). Los perfiles de despliegue
`lite`, `core` y `vault` (§9) son parámetros del Núcleo, no Profiles de extensión.

**Niveles de acceso.** Un Profile declara su acceso al contenido como uno de tres niveles:
`none` (solo la cabecera: sesión, índice, indicadores y longitud), `derived` (bytes que por contrato no
son el dato: una prueba, una proyección de metadatos) y `full` (los bytes del dato). `touches_payload`
es verdadero para `derived` y `full`, y falso para `none`. La longitud del fragmento es parte de la
cabecera y no cuenta como contenido: el Núcleo la necesita para dimensionar su memoria.

1. El Núcleo NO DEBE inspeccionar, interpretar ni clasificar el contenido de un fragmento (A1). Una
   implementación conforme DEBE poder mostrar que el Núcleo no depende de ninguna capa que lea contenido
   ni de bibliotecas de análisis de texto, JSON o expresiones regulares. [T]
2. Todo Profile de extensión DEBE declarar su nivel de acceso en su tipo (`type Access`); no existe
   Profile sin declaración. `touches_payload` se deriva de ese tipo y no puede discrepar de él. [T]
3. Un Profile que lee bytes (`derived` o `full`) DEBE acompañar su declaración de una justificación no
   vacía. [T]
4. Un nodo DEBE publicar sus declaraciones en `GET /v1/profiles`: `core_touches_payload` (siempre
   `false`) y la lista de Profiles con su `content_access`, su `touches_payload` y su justificación. La
   respuesta es estática, pública y no requiere sesión ni capacidad; otros métodos sobre la ruta DEBEN
   rechazarse (405). Añadir `content_access` es un cambio aditivo y no cambia la versión de protocolo. [T]
5. La lista publicada DEBE construirse a partir de las declaraciones de los propios tipos, no de
   literales independientes. [T]
6. El acceso a los bytes DEBE pasar por una vista tipada (`ContentView`) cuyo tipo es el nivel declarado.
   Una vista de nivel `none` NO DEBE ofrecer ningún accesor de bytes; una de nivel `derived` solo ofrece
   `derived_bytes`; una de `full` ofrece `content_bytes`. Los niveles están sellados: añadir uno es una
   decisión del Núcleo. [T] (comprobado por el compilador: `lacre-core/tests/ui/*.rs`)
7. Solo el Núcleo puede construir un `VerifiedFrame`, y solo después de verificar el sello y la
   secuencia. Un Profile alimentado desde él ve únicamente bytes que el Núcleo certificó. Una vista
   construida sin pasar por el Núcleo DEBE declarar su procedencia: `caller_supplied` (bytes que nadie
   verificó, por ejemplo las rutas que evalúan un conjunto de reglas sobre un payload recibido) o
   `reassembled` (un payload que un Profile reconstruyó a partir de fragmentos verificados). [T]
8. Un Profile de nivel `none` DEBE dar el mismo resultado para cualquier contenido de la misma
   longitud. El repositorio aporta la comprobación (`assert_content_blind`, con control positivo y
   negativo) y un Profile de ejemplo de cada nivel; hoy los cinco Profiles reales declaran `full`. [T]
9. Cambiar el nivel de acceso de un Profile DEBE ser una decisión revisada: el conjunto de niveles está
   fijado por un test, de modo que alterarlo obliga a editar ese test. [T]
10. Un archivo fuente que llame a `content_bytes` DEBE declarar `FullContent`; uno que llame a
    `derived_bytes` DEBE declarar `DerivedContent`; ningún Profile DEBE fabricar su propia vista. [T]

Límites declarados. El compilador impide que un Profile de nivel `none` alcance bytes por la API que
recibe; no puede impedir que un Profile mantenga por su cuenta otro canal hacia el dato (un búfer
compartido, `unsafe`). La diferencia entre `derived` y `full` es una declaración que un auditor
comprueba leyendo qué accesor se llama (regla 10), no una barrera de tipos: los dos devuelven los
mismos bytes. Ninguna prueba mecánica demuestra que una declaración `none` sea veraz para código
arbitrario fuera de esa API. Una declaración `full` falsa por exceso es conservadora; la peligrosa es
`none` falsa.
Pendiente: los cinco Profiles reales declaran `full`. Queda por decidir si la inspección de metadatos de
un Toolchain y Zero-Knowledge-Bridge pasan a `derived`.

## 14. Fuera de esta versión (declarado)

Ligar `version` y `key_id` al sello; verificación tras pérdida de sesión (checkpoint); límites de recursos como requisito; criptografía post-cuántica.

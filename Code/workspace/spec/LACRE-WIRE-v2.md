# LACRE-WIRE-v2 — contrato observable del cable v2 (E4 y E5)

Estado: implementado en E4. Parte de `LACRE-WIRE-v1.md` (congelado, hash de `vectors/wire-v1.json` fijado) Este archivo describe lo que un cliente observa; no repite la justificación del diseño.

Los anexos del proyecto son especificaciones conceptuales, no evidencia del comportamiento del código. Lo que sigue se comprueba con `lacre-domain/tests/v2_domain.rs`, `lacre-server/tests/v2_http.rs` y el grupo `wire v2` de `Tools/external_suite.py` (re-derivación independiente de los sellos).

## 1. Activación

Un nodo habla v2 solo si el operador le dio una política explícita (`LACRE_SEAL_POLICY=/ruta/politica.json` o `preset:standard`). Sin ella el conjunto aceptado es `{1}` y toda petición con `version: 2` recibe 400. No hay valores por defecto que habiliten algoritmos ni límites.

## 2. Reglas de versión

| Petición | Resultado |
|---|---|
| `version` ausente, sin `suite` | v1 (siempre fue v1), salvo que la política tenga `allow_implicit_version: false` → 400 |
| `version: 1`, sin `suite` | v1 |
| `version: 2` con `suite` | v2 |
| `version: 2` sin `suite` | 400 (no existe suite por defecto) |
| `suite` con `version: 1` o sin `version` | 400 (no se reinterpreta) |
| otra versión, o fuera de `wire_versions` | 400, sin leer perfil ni payload |
| `profile: "vault"` con v2 y `suite.signature` = id de un esquema | v2 firmado (sección 10) |
| `profile: "vault"` con v2 sin esquema de firma | 400 (no degrada a v1 ni infiere un esquema) |
| `suite.signature` no nulo con un perfil que no es `vault` | 400 |

El handshake sigue siendo v1 (no lleva suite). Una sesión de handshake se puede usar con v2: la suite se liga al sellar.

## 3. Cuerpo

`POST /v1/seal`:
```json
{"version": 2, "profile": "core", "payload_hex": "…",
 "suite": {"seal": "blake3-keyed-xof", "tag_len_bytes": 64, "signature": null},
 "session_id": "…opcional…", "token": "…si hay session_id…", "ruleset": "…opcional…"}
```
`suite` rechaza campos desconocidos. `tag_len_bytes` es obligatorio para algoritmos de salida extensible y prohibido para los de longitud fija. `signature` es `null` en todos los perfiles salvo `vault`, donde es obligatorio y nombra un esquema (sección 10).

Respuesta: `version: 2`, `session_id`, `frames[]` con `seal_hex` de longitud variable (1 a 1024 bytes, la de la suite), `capabilities`, `suite` (eco canónico) y `suite_hash_hex`.

`POST /v1/verify`: mismos campos de v1 más `version: 2` y `suite`. La primera petición viva liga la sesión a `(versión, suite_hash)`; otra versión o suite posterior → 400 sin tocar el estado. La respuesta lleva `version`, `suite` y `suite_hash_hex`. Una sesión cuyo cálculo entró en pánico queda cerrada para siempre (no existe operación para reanudarla).

La versión queda atada por consecuencia, no por un MAC propio: el byte de versión es el primero del descriptor cuyo hash entra en la derivación de claves y en `Es(0)`. Quien cambie el campo en tránsito solo consigue un rechazo.

## 4. Derivación (lo que un verificador independiente necesita)

```
descriptor = 0x02 ∥ (1,len,"hkdf-sha256") ∥ (2,len,"hmac-sha256") ∥ (3,len,seal_id) ∥ (4,len,params) ∥ (5,len,signature)
params     = tag_len_bytes en 2 bytes big-endian (XOF) | vacío (longitud fija)
suite_hash = SHA-256("lacre/v2/suite" ∥ descriptor)
k_seal     = HKDF-SHA256(ikm, salt=session_id, info="lacre/v2/seal-key" ∥ suite_hash,  largo=key_len del algoritmo)
k_chain    = HKDF-SHA256(ikm, salt=session_id, info="lacre/v2/chain-key" ∥ suite_hash, largo=32)
Es(0)      = HMAC-SHA256(k_chain, session_id ∥ "lacre/v2/initial-state" ∥ suite_hash)
Es(i+1)    = HMAC-SHA256(k_chain, Es(i) ∥ fragmento_i)
sello_i    = MAC(k_seal, u64be(len(fragmento_i)) ∥ fragmento_i ∥ Es(i))
```
Vectores: `vectors/suite-v2.json` (generador Python independiente). `key_len`: 32 (hmac-sha256, blake3-keyed-xof, aes-cmac), 64 (hmac-sha512, hmac-sha3-512, blake2b-keyed).

## 5. Orden de validación y códigos

1. versión → 400 · 2. perfil → 400 · 3. suite bien formada y conocida por el registro (incluida la regla vault ⇔ esquema) → 400 · 4. política (algoritmo, perfil, rango de `tag_len_bytes`, coste, estado, cuarentena, esquema de firma listado) → **403** · 5. presupuesto de memoria `slot_count × (slot_size + tag_len_bytes) ≤ max_session_memory_bytes`, antes de reservar → 422 · 6. cuerpo y hex → 413 / 400 · 7. reglas → 422 · 8. admisión (solo si el operador la configuró) → 503 + `Retry-After: 1` · 9. cómputo.

Un rechazo en los pasos 1 a 8 no deja estado. 504 solo si el operador configuró `LACRE_REQUEST_DEADLINE_MS`; 500 es genérico, sin texto del pánico. La política se reevalúa en cada `verify`.

## 6. Política

JSON con `wire_versions`, `max_session_memory_bytes` (obligatorio), `allow_implicit_version` (por defecto `true`), `quarantined_at_start` (por defecto vacío), `allow_legacy` (por defecto `false`), `expose_discovery` (por defecto `false`), `quarantine_after_panics` (opcional; sin él no hay cuarentena automática), `on_quarantine` (`close` por defecto | `drain`) `signatures[]` (opcional; sin ella no hay esquemas y `vault` no puede permitirse bajo v2) con `id` y `expect_status`, y `algorithms[]` con `id`, `expect_status`, `profiles`, `tag_len_bytes {min,max}` (obligatorio para XOF, prohibido para longitud fija) y `max_cost`. Cualquier inconsistencia impide arrancar. SHA-1 exige las tres cosas: compilado con `legacy-seals`, nombrado con `expect_status: "legacy"` y `allow_legacy: true`.

Cuarentena: tras `quarantine_after_panics` pánicos de un algoritmo (en `seal` o en `verify`), o por orden del operador (`quarantined_at_start`, solo ids que la política lista), las sesiones nuevas reciben 403; las abiertas se cierran (`close`) o terminan (`drain`). Nunca vuelve a activarse por el paso del tiempo: solo reiniciando con una política que ya no lo ordene en cuarentena. Cada pánico, cada entrada en cuarentena y cada orden del operador se registra en el log del servidor (stderr), sin payloads, claves ni session_id; no se exporta nada.

## 7. Operación (variables de entorno; solo el tope de cuerpo tiene valor por defecto, y está escrito)

`LACRE_SEAL_POLICY`, `LACRE_MAX_INFLIGHT` (operaciones en ejecución), `LACRE_MAX_HEAVY` (operaciones de coste alto), `LACRE_REQUEST_DEADLINE_MS`, `LACRE_MAX_BODY_BYTES` (tamaño máximo del cuerpo de una petición HTTP; por defecto 2 097 152 bytes, que es lo que el adaptador siempre aceptó; una prueba fija el borde al byte; el arranque imprime el valor y si es el predeterminado o el configurado). `LACRE_WS_PING_SECS` (segundos entre pings de WebSocket; por defecto 25, escrito en el código; ver §12). Un valor mal formado o igual a cero impide arrancar. El arranque imprime qué quedó activo y qué «no tiene límite configurado». La admisión cuenta trabajo en ejecución y no puede cancelar un algoritmo ya iniciado.

## 8. Descubrimiento

`GET /v1/seal-algorithms`: 404 salvo `expose_discovery: true`. Lista lo que la política permite; no es negociación y no expone carga ni cuarentena.

## 9. Fuera de E4 y E5

Doble aceptación de versión con expiración, recarga de política en caliente, registro central de compatibilidad, Profile de admisión, exportadores de telemetría.

## 10. Firma y perfil `vault` bajo v2 (E5)

Solo el perfil `vault` firma. `suite.signature` nombra el esquema (`"ed25519"` en el catálogo de este binario) y entra en el descriptor (campo 5), por tanto en `suite_hash`, en la derivación de claves y en `Es(0)`: dos suites que difieren solo en el esquema no comparten ni claves ni sellos.

Cada fragmento viaja con `signature: {"scheme": "ed25519", "sig_hex": "…"}` (rechaza campos desconocidos). `vault_signature_hex` es solo de v1 y `signature` solo de v2: mezclarlos se rechaza, nunca se ignora uno.

```
sign_input = "lacre/v2/vault-sig" ∥ suite_hash(32) ∥ session_id(16) ∥ u64be(index) ∥ u64be(len(tag)) ∥ tag
```

La firma cubre el sello (que ya cubre payload y cadena). El verificador exige la firma, de longitud exactamente la del esquema, la comprueba después del sello y antes de cambiar estado; un rechazo no hace avanzar la sesión. Una firma que nombra otro esquema que el de la suite se rechaza por nombre. Límites del Núcleo: `MAX_SIGNATURE_LEN = MAX_SIGNATURE_KEY_LEN = 8192`.

Recibo v2 (solo sesiones que firman): `SHA-256("lacre/v2/receipt" ∥ suite_hash ∥ u64be(index) ∥ tag)`, registrado antes de purgar. `/v1/ack` y `/v1/receipts` despachan por la versión con que se abrió la sesión.

Política: `signatures[]` con `id` y `expect_status` (si el estado del catálogo difiere, no arranca). `vault` en los `profiles` de un algoritmo exige al menos un esquema listado. La clave de firma es la de `LACRE_VAULT_SIGNING_KEY`; la pública se deriva con el propio esquema.

Vectores independientes: `spec/vectors/signatures-v2.json` (`Tools/gen_sign_vectors.py`, OpenSSL, sin Rust). Rotación de claves, otros esquemas y poscuánticos quedan fuera.

## 11. Despliegue detrás de intermediarios (probado)

Lo que sigue se midió con `Tools/intermediaries.py`: 14 escenarios con intermediario más la línea base (nginx 1.24, haproxy 2.8, mitmproxy 12, dos cadenas) y la suite externa completa (337 casos en la primera medición; 381 con la tolerancia a intermediarios de la sección 12) a través de cada uno. Son configuraciones típicas emuladas en un solo equipo, no productos de terceros en producción; no se probó Cloudflare ni HTTP/3 ni gRPC.

**Qué resultó transparente** (en 13 de los 14 escenarios pasaron los 337 casos igual que sin intermediario, con evidencia de que el intermediario estaba en el camino; el que falla es el de la regla 1): reverse proxy HTTP/1.1 con y sin búfer de la petición (cuerpo en `chunked` hacia Lacre); compresión gzip de las respuestas; cliente HTTP/2 con TLS y Lacre en HTTP/1.1 (nginx y haproxy); cabeceras `X-Forwarded-*`; reserialización del JSON por el intermediario (claves ordenadas, sin espacios: 412 peticiones y 284 respuestas reescritas); WebSocket (`ws` y `wss`) por nginx, haproxy y mitmproxy; dos cadenas, de dos y de tres intermediarios.

**Una alteración se detecta siempre.** Un intermediario que cambia un byte del payload en la respuesta de `/v1/seal` o en la petición de `/v1/verify` fue detectado en 40 de 40 intentos, y el mismo recorrido sin alterar fue aceptado en 10 de 10.

**Requisitos de despliegue** (lo que Lacre no puede arreglar desde dentro):

1. **~~No borrar `Authorization`~~ (ya no hace falta, P1).** La forma de referencia es el token en el campo `token` del cuerpo; `Authorization: Bearer` sigue aceptado como alternativa, pero un intermediario que lo borra hace fallar la operación cerrada (401 «missing or invalid capability token for this operation»). Con el token en el cuerpo pasaron 381 de 381 casos detrás de un haproxy que borra la cabecera; con la cabecera, ese escenario falla a propósito (modo de compatibilidad de la suite, `--token-in-header`).
2. **Tope de cuerpo del intermediario no mayor que el de Lacre.** Lacre rechaza cuerpos de más de `LACRE_MAX_BODY_BYTES` (2 097 152 por defecto) con 413 de texto plano «Failed to buffer the request body: length limit exceeded», y cierra la conexión sin leer el resto. Un nginx que almacena la petición en búfer y tiene un tope mayor (aquí 64 MB) pierde esa respuesta y devuelve 502: con un cuerpo de unos 10 MiB, 10 de 10 intentos dieron 502; con unos 3 MiB, 1 de 10; con haproxy en HTTP/1.1 los 10 de 10 dieron el 413 de Lacre. Con `client_max_body_size 2m` el 413 lo da nginx (6 de 6) y la suite lenta pasa completa. Un `client_max_body_size` por defecto de nginx (1 MB) rechaza antes y con una página HTML; las dos respuestas se distinguen por el tipo de contenido. **Con el sellado por partes (P2, §12) ya no hace falta tocar ese tope:** ningún cuerpo supera unos 0,5 MiB, y 20 MiB pasaron por un nginx con 1 MB y por un haproxy con h2 (peticiones de hasta 446 KiB). El tope sigue valiendo para `/v1/seal` completo.
3. **~~No reintentar `/v1/verify` automáticamente~~ (ya no hace falta, P3).** Repetir idéntica la última petición aceptada de una sesión devuelve el mismo veredicto (200, `all_verified: true`, mismos `results`); una petición distinta sobre la sesión terminada sigue dando 400 «session_id already completed», y una verificación fallida nunca se guarda. `/v1/ack` es idempotente (la segunda llamada da 200 y `total_receipts` no cambia). Un `/v1/seal` repetido crea otra sesión; la primera ocupa un cupo hasta que vence su TTL (el sellado por partes lo evita: cada parte se repite sin duplicar nada).
4. **Errores del intermediario.** Un 502 con Lacre caído llega como página del intermediario, sin cuerpo de Lacre; un cliente debe tratar un cuerpo que no es de Lacre como fallo de transporte, no como veredicto de verificación.

**Probado en una segunda ronda:** una petición con `Content-Encoding: gzip` hacia Lacre recibe 400 de JSON mal formado, directa o a través de nginx (falla cerrado; Lacre no descomprime peticiones, así que un intermediario no debe comprimirlas). Lacre no habla HTTP/2 sin TLS: `curl --http2-prior-knowledge` termina con error de conexión (exit 56); HTTP/2 se obtiene con un intermediario que termina TLS, como en los escenarios de nginx y haproxy. Un WebSocket inactivo detrás de nginx con `proxy_read_timeout 3s` se cerró a los 3,0 s cuando Lacre no enviaba nada, y una conexión nueva por el mismo intermediario respondió. Desde P4 Lacre envía pings (§12) y esa misma conexión, inactiva 10 s, sigue abierta y responde. La suite lenta (payload de 20 MB y expiración de ≈70 s) pasó completa a través de haproxy en HTTP/1.1 y de nginx con tope de 2 MiB; con nginx a 64 MB falló el caso de 20 MB por el 502 de la regla 2. A través de haproxy con HTTP/2 ese caso agota el tiempo porque el cliente de la suite (httpx) no lee la respuesta mientras sube el cuerpo; con curl en HTTP/2 los 3 y 10 MiB dieron 413, de modo que es del cliente y no de Lacre ni de haproxy.

**haproxy con HTTP/2: subidas grandes lentas por su ventana por defecto (investigado, no es de Lacre).** El flujo de 20 MiB por partes tardó unos 34 s detrás de haproxy con h2 y unos 3 s detrás de nginx. Medido: con un servidor HTTP/1.1 trivial en Python en lugar de Lacre detrás de haproxy también hay esperas (así que no depende de Lacre); nginx sin búfer de la petición sigue en ~3 ms por petición de 400 KB y haproxy con `option http-buffer-request` no mejora (~150 ms); curl con h2 por haproxy tarda ~3 ms por petición; un cliente h2 mínimo que escribe las tramas en ráfagas también (~2 ms), pero uno que escribe una trama por escritura y cierra con una trama vacía aparte (el patrón de httpcore, la librería de httpx) reproduce esperas de ~44 ms y ~208 ms; los controles de TCP de haproxy (`tcp-smart-accept`, `tcp-smart-connect`), `TCP_NODELAY` del cliente, un búfer de recepción de 4 MiB y el tamaño de trama no cambian nada; **`tune.h2.initial-window-size 1048576` baja las esperas de 13–16 de cada 24 peticiones a 1 de 24, y el flujo real de 20 MiB de ~33,5 s a ~8,3 s.** Con el MTU de `lo` en 1500 (en lugar de 65536) las esperas caen a 3–5 de cada 24, es decir, el MSS grande de loopback las amplifica pero no son solo de loopback. El rastro de `strace` de haproxy muestra escrituras de 16 320 bytes con `MSG_MORE` por un descriptor que, por el tamaño de lo que lleva, es el del backend (inferido, no comprobado), y los `WINDOW_UPDATE` (26 bytes) sin `MSG_MORE`. `Tools/h2_window_probe.py` reproduce las esperas sin httpx. **Mecanismo propuesto, no demostrado:** el kernel retiene esas escrituras parciales hasta el siguiente ACK (~40 ms) o hasta ~200 ms, y el cliente espera el `WINDOW_UPDATE` que haproxy emite tras reenviarlas; encaja con todo lo medido pero no se capturó el tráfico para ver la retención. Reducir el tamaño de las partes **no** ayuda (0,22 a 0,61 MiB/s sin patrón entre partes de 16 y 200 KiB). Recomendación comprobada: con haproxy y clientes h2 que suban cuerpos grandes, `tune.h2.initial-window-size 1048576` en la sección `global`.

**No probado:** reintentos automáticos reales de un balanceador (solo se emularon con peticiones duplicadas del cliente, que para Lacre son idénticas); cierre de WebSocket con el tiempo por defecto de cada intermediario (se midió con 3 s, con ping de 1 s; el valor por defecto de 25 s no se midió contra un tiempo de 30 s); TLS en Lacre mismo; Cloudflare, HTTP/3 y gRPC.

## 12. Tolerancia a intermediarios

Cinco piezas, todas fuera de `lacre-core` (su huella no cambió) y aditivas: el observable de wire v1 no cambia salvo lo marcado.

**P1. Token en el cuerpo.** Forma de referencia para los clientes; `Authorization: Bearer` sigue aceptado. Si vienen los dos, gana el cuerpo (ya era así).

**P2. Sellado por partes.** `POST /v1/seal/open` (cuerpo: `profile`, y como en `/v1/seal` opcionalmente `version`, `suite`, `session_id`, `token`) devuelve `session_id`, `capabilities`, `slot_size`, `window_frames` y `max_part_bytes` (el mínimo entre 256 KiB y `window_frames × slot_size`; **se publica aquí y no en el descubrimiento**, para que esté disponible aunque el descubrimiento esté apagado). `POST /v1/seal/part` (cuerpo: `session_id`, `token` de escritura, `part_index`, `payload_hex`, `is_last`) corta la parte en frames de `slot_size`, sin `total_fragments`, con `is_last` solo en el último frame de la última parte, y devuelve `frames` y `pending_frames`. Reglas: `part_index` empieza en 0 y avanza de uno en uno; repetir la última parte con el mismo contenido devuelve los mismos frames sin sellar de nuevo (también tras la parte final); mismo índice con otro contenido, índice saltado o parte tras la final dan 409; una parte vacía solo es válida como final; una parte mayor que `max_part_bytes` da 400; el sellador admite como mucho `window_frames` frames sin confirmar y una parte que lo desborde recibe 429 hasta que el cliente confirme con `/v1/ack`; si un frame falla a mitad de una parte la sesión queda inservible (409 en adelante). Se aplican la política y la cuarentena de v2 en cada parte, y la admisión de coste alto. Vault v1 y v2 firman cada frame. Estas sesiones se guardan en el almacén de selladores para todos los perfiles (también `core` y `lite`), con el tope `LACRE_MAX_SEALER_SESSIONS`.

**P3. Verificación idempotente.** Ver la regla 3 de §11. La petición se identifica por un SHA-256 de su forma canónica (versión, perfil, `session_id`, `key_id`, `reassemble`, `ruleset`, `suite` y frames; sin el token). Solo se recuerda la última petición aceptada de la sesión y solo si su respuesta serializada cabe en 16 KiB; si no cabe, una repetición recibe el rechazo de antes. La consulta ocurre después de la autenticación. **Cambio de semántica:** repetir idéntica la última petición aceptada ya no se rechaza como replay; quien tiene el token de `verify` recibe de nuevo la misma respuesta (incluido `payload_hex` si pidió `reassemble`), nada que no hubiera recibido ya.

**P4. Pings de WebSocket.** Cada conexión recibe un Ping cada `LACRE_WS_PING_SECS` segundos (entero positivo; por defecto 25; el arranque imprime el valor y si es el predeterminado).

**P5. Errores negociados.** Con `Accept: application/problem+json`, o si el cuerpo de la petición trae `"version": 2`, los errores de texto salen como `application/problem+json` con `type` (`urn:lacre:error:<code>`), `title`, `status`, `detail` (el mismo texto que v1) y `code`. Sin eso, el texto plano de siempre. Se convierten también el 413 del límite de cuerpo y los rechazos de los extractores. Códigos: `body-too-large`, `malformed-body`, `unknown-profile`, `invalid-hex`, `missing-or-invalid-token`, `session-already-completed`, `version-not-accepted`, `part-out-of-order`, `part-conflict`, `window-full`; el resto de errores usa un código por estado (`bad-request`, `unauthorized`, `forbidden`, `conflict`, `not-found`, `unprocessable`, `too-many-requests`, `unavailable`, `deadline-exceeded`, `internal`). Un error de v2 que no llega al manejador (por ejemplo un cuerpo mal formado) solo se convierte si el cliente envió `Accept`: sin cuerpo legible no se sabe la versión.

**Medido** (`Tools/intermediaries.py`, serie `intermediaries-2026-10-17-tolerancia.json`): 381 de 381 casos de la suite externa en 14 de los 15 escenarios (la línea base y 13 con intermediario, incluido el que borra `Authorization` con el token en el cuerpo); el que lo borra con el token en la cabecera falla a propósito (la suite corrió 315 casos y 101 fallaron); 20 MiB por partes (103 partes, 20 480 frames, verificados y confirmados) detrás de nginx con `client_max_body_size 1m` y detrás de haproxy con TLS y cliente HTTP/2; WebSocket inactivo 10 s detrás de nginx con `proxy_read_timeout 3s` y `LACRE_WS_PING_SECS=1`, abierto y respondiendo, frente a la misma configuración sin ping, cortada a los 3,0 s.

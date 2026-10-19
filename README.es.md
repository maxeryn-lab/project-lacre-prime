# Lacre Prime

**Un Protocolo de Integridad en Tránsito: demuestra que una respuesta llegó a quien la consume byte por byte como la produjo la fuente.**

Lacre fragmenta una respuesta, sella cada fragmento con una etiqueta de autenticación que viaja solo en la cabecera del transporte, y purga el estado de cada fragmento cuando se confirma la entrega. No inspecciona el contenido ni dice si es verdadero, solo si está intacto. Es de propósito general: respuestas de API, salida de modelos de IA, resultados de herramientas, o cualquier flujo que cruce infraestructura que no controlás del todo.

🇬🇧 [Read in English](README.md)

## Por qué

TLS protege la tubería, no el agua. Muestra que el canal no fue alterado y que el servidor es quien dice ser. No dice nada de si una respuesta fue cambiada después de generarse, por un proxy comprometido, un paso de serialización defectuoso o alguien con acceso aguas abajo de TLS. La verificación pesada (pruebas de conocimiento cero, consenso entre nodos) cierra esa brecha a un costo de segundos a minutos. Lacre queda entre "sin verificación extra" y eso.

## Arquitectura

Cuatro capas con un límite impuesto por las dependencias entre crates, no por convención:

```
Adaptadores  lacre-adapter-declarative / -http / -ws, compuestos por lacre-server
Capa de app  lacre-domain    tipos de cable, operaciones, stores de sesión, política
Profiles     lacre-profiles  trabajan sobre frames que el Núcleo ya verificó
Núcleo       lacre-core      fragmenta, sella, verifica, purga; no nombra ningún algoritmo
```

Los algoritmos no están en el Núcleo. Viven en `lacre-seals` (el catálogo), y un nodo se compone con los que su operador compila y permite por política. `lacre-seal-conformance` es la suite que todo algoritmo debe pasar.

## Qué hay

- **Wire v1** (congelado) y **wire v2** (aditivo): el contrato está en [`Code/workspace/spec/`](Code/workspace/spec/). v2 agrega descriptores de suite, un archivo de política del operador y firmas como contrato propio.
- **Algoritmos de sello** en el catálogo: `hmac-sha256`, `hmac-sha512`, `hmac-sha3-512`, `blake2b-keyed`, `blake3-keyed-xof`, `aes-cmac` y `kmac256` (marcado Experimental). `hmac-sha1` existe solo tras la característica de Cargo `legacy-seals` y la política por defecto lo bloquea.
- **Esquema de firma**: `ed25519`, para el perfil `vault` bajo wire v2.
- **Ejemplo de tercero**: [`Code/third-party/`](Code/third-party/) agrega `hmac-sha3-256` desde un workspace de Cargo aparte, sin cambiar un byte de `lacre-core` (comprobado con una huella de archivos).
- **Servidor**: HTTP (`/v1/handshake`, `/v1/seal`, `/v1/verify`, `/v1/ack`, `/v1/receipts`, `/v1/validate`, `/v1/seal-algorithms`, `/v1/profiles`, `/v1/toolchain/...`) y WebSocket (`/v1/ws`).
- **Detrás de intermediarios reales**: `Tools/intermediaries.py` corre la suite externa a través de nginx, haproxy y mitmproxy (y cadenas de ellos). 12 de 13 escenarios pasan los 337 casos; el que borra `Authorization` falla cerrado y funciona con el token en el cuerpo. Un intermediario que altera se detecta siempre. Resultados y requisitos de despliegue: [`LACRE-WIRE-v2.md` §11](Code/workspace/spec/LACRE-WIRE-v2.md).
- **Herramientas de verificación** en [`Tools/`](Tools/): una suite externa de caja negra, arneses de mutación que comprueban que los tests fallan cuando se rompe el código, y generadores que escriben los vectores de respuesta conocida desde implementaciones independientes (Python se usa solo ahí; el protocolo es Rust).

## Compilar y probar

Requiere Rust 1.91+. No necesita servicios externos.

```bash
git clone https://github.com/maxeryn-lab/project-lacre-prime.git
cd project-lacre-prime/Code/workspace
cargo test --workspace
```

Al momento de esta actualización, `cargo test --workspace` corre 522 tests y todos pasan. El Núcleo no depende de `tokio` ni de ningún runtime asíncrono: `cd lacre-core && cargo tree -i tokio` no encuentra ese paquete.

## Correr un nodo

```bash
cd Code/workspace
LACRE_SEAL_POLICY=preset:standard cargo run -p lacre-server -- --serve
```

Sin `LACRE_SEAL_POLICY` el nodo habla solo wire v1; no hay valores por defecto silenciosos para v2. Para algo más que una prueba local, definí `LACRE_MASTER_KEY` y `LACRE_VAULT_SIGNING_KEY`; si no, el nodo genera claves aleatorias y avisa al arrancar. Los demás ajustes son variables de entorno con prefijo `LACRE_` (dirección de escucha, límites de sesión, plazo de petición, tope de cuerpo `LACRE_MAX_BODY_BYTES` con 2 MiB por defecto, clave de firma de `vault`).

Para correr la suite externa contra un servidor recién compilado, desde `Code/workspace`: `python3 ../../Tools/external_suite.py --spawn target/debug/lacre-server`.

## Lo que falta

- No hay adaptador gRPC.
- Los recibos y las marcas de sesión completada viven en memoria con un límite de tiempo. Una auditoría permanente necesita un almacenamiento que elija quien despliega.
- `kmac256` se comprobó solo contra la muestra 4 de NIST SP 800-185.
- Todavía no hay un despliegue de terceros ni una auditoría independiente.

## Principios de diseño

- **El Núcleo nunca inspecciona el contenido.** La neutralidad es una decisión de diseño.
- **La purga es una garantía de seguridad, no limpieza de memoria.**
- **Falla cerrado.** Un sello malo, una firma ausente o una versión desconocida descartan el fragmento o la sesión.
- **Detectabilidad, no prevención.** Lacre no afirma que la manipulación sea imposible, solo que se detecta.

## Licencia

GNU Affero General Public License v3.0 (AGPL-3.0). Ver [`LICENSE`](LICENSE).

## Contribuir

Se aceptan issues y pull requests. Para algo más que una corrección chica, abrí primero un issue.

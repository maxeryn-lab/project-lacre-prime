# Lacre Prime

**Un protocolo de integridad de tránsito para respuestas de APIs y modelos de IA consumidas por agentes autónomos.**

Lacre certifica que una respuesta fragmentada llega a su consumidor sin alteraciones — idéntica, byte a byte, a lo que la fuente produjo — con latencia inferior al milisegundo y sin necesidad de inspeccionar el contenido que transporta. No certifica que el contenido sea veraz, solo que es íntegro.

🇬🇧 [Read in English](README.md)

## Por qué

TLS protege el tubo, no el agua. HTTPS garantiza que un canal no fue alterado en tránsito y que el servidor es quien dice ser — no dice nada sobre si la respuesta en sí fue alterada después de generarse, por un proxy comprometido, un paso de serialización corrupto, o un atacante con acceso a infraestructura posterior a la terminación TLS. Para un agente autónomo que toma una decisión en tiempo real a partir de una respuesta de API o de un modelo, esa brecha importa.

La verificación pesada (pruebas de conocimiento cero, consenso multi-nodo) cierra esa brecha, pero cuesta de segundos a minutos — incompatible con un agente que decide en tiempo real. Lacre ocupa el espacio entre "sin verificación adicional" y "verificación pesada": fragmentar la respuesta en unidades pequeñas, sellar cada fragmento con un código de autenticación de mensajes que viaja exclusivamente en la cabecera de transporte, y purgar el estado asociado a cada fragmento de inmediato tras confirmar su entrega.

## Arquitectura

Tres capas con una frontera estricta, exigida de forma estructural — no por convención:

```
Adaptadores  (lacre-adapter-declarative / -ws / -http, compuestos por lacre-server)
                              — conocen HTTP/WebSocket/tokio, traducen un transporte concreto
Capa de app  (lacre-domain)   — DTOs de cable, operaciones de dominio, stores de sesión, AppState
Profiles     (lacre-profiles) — operan sobre frames YA verificados por el Núcleo
Núcleo       (lacre-core)     — invariante: fragmenta, sella/verifica, purga
```

Las capas son crates separados dentro de un workspace de Cargo (`lacre-core`, `lacre-profiles`, `lacre-domain`, `lacre-adapter-*`, `lacre-server`, `lacre-tokio`); cada uno se compila y testea solo con `cargo test -p <crate>`. El Núcleo no tiene ninguna dependencia de `tokio`, `axum`, ni ningún runtime asíncrono — verificable de forma directa:

```bash
cd lacre-core && cargo tree -i tokio
# package ID specification `tokio` did not match any packages
```

## Qué está implementado

Verificado con `cargo test --workspace` — no afirmado de memoria.

### Núcleo (`lacre-core`)

- Fragmentación de payload, sello HMAC (SHA-256 / Blake3) encadenado a través de la secuencia de fragmentos
- Tipo de frame inmutable con máquinas de estado separadas para los roles de sellador y verificador
- Buffer circular preasignado con purga por ACK y purga por timeout forzado
- Firma Ed25519 opcional sobre el sello (no repudio, perfil Vault)
- Recibo post-purga de solo adición (`SHA-256(sello)`, nunca recuperable hacia el contenido)
- Derivación de clave de sesión vía HKDF, con intercambio de clave efímero X25519

### Adaptadores (`lacre-server`)

- **HTTP**: `/v1/health`, `/v1/handshake`, `/v1/seal`, `/v1/verify`, `/v1/ack`, `/v1/receipts/{session_id}`
- **WebSocket**: `/v1/ws` — las mismas operaciones (`handshake`, `seal`, `verify`, `ack`) sobre una conexión persistente, confirmando que el Núcleo permanece agnóstico a qué transporte lo lleva
- Perfiles de despliegue: **Core** (propósito general), **Vault** (grado financiero, Ed25519 + recibos), **Lite** (checksum ligero vía Blake3, sin HMAC completo)

### Qué no está implementado todavía

- Adaptador gRPC (dependencia presente en `Cargo.toml`, no conectado aún)
- Perfiles de despliegue adicionales más allá de Core / Vault / Lite

## Compilación

```bash
git clone https://github.com/<tu-usuario>/lacre-prime.git
cd lacre-prime
cargo test --workspace
```

Requiere Rust 1.91+ (edición 2021). No se necesitan servicios externos para correr la suite de tests.

## Estructura del proyecto

```
lacre-core/            El Núcleo. Sin tokio, sin regex. Sin HTTP. Sin conocimiento de "perfiles".
  src/
    core.rs             SealerCore / VerifierCore — fragmentación, sellado, purga
    frame.rs             Frame inmutable + máquinas de estado por rol
    hmac_seal.rs          Sellado HMAC-SHA256 / Blake3, comparación en tiempo constante
    buffer.rs             Buffer circular preasignado, lógica de purga
    session.rs             Derivación de clave de sesión X25519 + HKDF
    vault_signature.rs      Firma Ed25519 (perfil Vault)
    receipt.rs               Recibo post-purga de solo adición
    profile.rs                 Reensamblado de frames (el único Profile de inspección de contenido hasta ahora)

lacre-profiles/        Profiles (Motor de Reglas, Guardian, Certifier, Toolchain, Reassemble, ...). Depende solo de lacre-core.
lacre-domain/          Capa de aplicación compartida por todos los Adaptadores. Sin axum.
lacre-adapter-*/       Adaptadores Declarativo (sin axum), WebSocket y HTTP.
lacre-server/          Binario de composición. Depende de tokio/axum.
  src/
    http_server.rs        Rutas HTTP
    websocket_adapter.rs    Manejo del protocolo WebSocket
    profile_config.rs        Presets de perfiles de despliegue (Core / Vault / Lite)
```

## Presentación al hackathon

El despliegue de referencia público actual envuelve la API gratuita de Open-Meteo como un Miner de Telegraph Protocol (intents `weather_forecast` / `weather_check`) sobre Base Sepolia, sellando cada fragmento de respuesta con el mecanismo descrito arriba. Esa capa de integración no forma parte de este repositorio — este repositorio es la implementación del protocolo en sí, agnóstica de transporte y de caso de uso.

## Principios de diseño

- **El Núcleo nunca inspecciona contenido.** La neutralidad es una decisión de diseño, no una limitación técnica — exigida manteniendo toda lógica de inspección de contenido enteramente en una capa separada (Profiles), nunca en el Núcleo.
- **La purga es una garantía de seguridad, no housekeeping de memoria.** Eliminar el estado de un fragmento tras la confirmación de entrega se trata con la misma prioridad que calcular el propio sello.
- **Fallo cerrado, siempre.** Cualquier fallo de verificación — un sello inválido, una firma faltante, una versión de protocolo no reconocida — descarta el fragmento o la sesión. Sin aceptación parcial, sin degradación silenciosa.
- **Detectabilidad, no prevención.** Lacre no promete que la alteración sea imposible. Promete que, si ocurre, se detecta de inmediato y con certeza matemática — la misma propiedad que siempre tuvo un sello de cera sobre el cajón de una obra de museo.

## Licencia

Licenciado bajo **GNU Affero General Public License v3.0** (AGPL-3.0). Ver [`LICENSE`](LICENSE).

En el futuro podría ofrecerse una licencia comercial para casos de uso incompatibles con los términos de copyleft de red de AGPL-3.0; contactar al mantenedor para consultas.

## Contribuir

Este proyecto está en desarrollo activo. Issues y pull requests son bienvenidos — por favor abrí un issue primero para cualquier cosa más allá de una corrección pequeña, para alinear la dirección antes de invertir trabajo en ello.

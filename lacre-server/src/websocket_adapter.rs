//! Segundo Adaptador real: WebSocket sobre `axum` — la prueba empírica
//! de DECISIONS.md punto 16 ("Adaptadores son un eje de extensión de
//! primer nivel, sustituible sin tocar la lógica de negocio").
//!
//! # Por qué WebSocket, específicamente, como segundo Adaptador
//!
//! Se eligió deliberadamente por ser estructuralmente OPUESTO a HTTP:
//! HTTP es request/response sin estado — cada `POST /v1/seal` abre y
//! cierra su propio ciclo, sin memoria de la conexión anterior.
//! WebSocket es una conexión PERSISTENTE, donde ambas partes pueden
//! enviar mensajes en cualquier momento, sin la disciplina de
//! "primero pido, después me responden". Si la costura
//! Núcleo/`domain.rs`/Adaptador solo funcionaba para el caso fácil
//! (request/response), este Adaptador lo habría revelado: hubiera
//! necesitado reescribir la lógica de negocio, o el `AppState` hubiera
//! necesitado saber algo sobre WebSocket. Ninguna de las dos cosas
//! ocurrió — ver `domain.rs` para el detalle de qué se extrajo antes
//! de construir este módulo, y por qué ese refactor era una precondición
//! honesta, no un paso salteable.
//!
//! # Protocolo de mensajes
//!
//! Una única conexión WebSocket multiplexa las 5 operaciones del
//! protocolo (handshake, seal, verify, ack, receipts) — algo que HTTP
//! no puede hacer sin abrir 5 conexiones TCP separadas. Cada mensaje de
//! texto entrante es un JSON con la forma:
//!
//! ```json
//! {"kind": "seal", "payload": { ...SealRequest... }}
//! ```
//!
//! Y cada respuesta:
//!
//! ```json
//! {"kind": "seal_response", "payload": { ...SealResponse... }}
//! ```
//!
//! o, ante un error de dominio:
//!
//! ```json
//! {"kind": "error", "payload": {"message": "..."}}
//! ```
//!
//! Los tipos `payload` son EXACTAMENTE los mismos `*Request`/`*Response`
//! de `http_adapter.rs` — no hay ningún tipo nuevo para el contenido de
//! los mensajes, solo el sobre (`kind`) que los distingue dentro de la
//! misma conexión. Esto es deliberado: si este Adaptador hubiera
//! necesitado sus propios tipos de request/response, eso habría sido
//! evidencia de que `http_adapter.rs` no era realmente agnóstico de
//! HTTP, sino que solo parecía serlo.
//!
//! # Qué NO resuelve este Adaptador
//!
//! No hay ningún mecanismo de correlación petición/respuesta (un `id`
//! de mensaje que el cliente pueda usar para saber a cuál de sus
//! mensajes corresponde cada respuesta) — las respuestas se envían en
//! el mismo orden en que llegan los mensajes, sobre la misma conexión.
//! Un cliente que necesite pipelining real (enviar varios mensajes sin
//! esperar respuesta y luego correlacionarlos) necesitaría un campo
//! `id` explícito — no implementado en esta primera vuelta, mismo
//! criterio de alcance acotado que ya se aplicó en Fase 3 con la
//! variante streaming de HTTP (anotada como candidata futura, no
//! bloqueante).

use crate::domain::{self, DomainError};
use crate::http_adapter::{AckRequest, HandshakeRequest, SealRequest, VerifyRequest};
use crate::http_server::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// `GET /v1/ws` — upgrade de la conexión HTTP a WebSocket. axum maneja
/// el handshake HTTP de upgrade (RFC 6455) internamente; a partir de
/// ahí, `handle_socket` toma el control de la conexión persistente.
pub async fn handle_ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// El sobre de un mensaje entrante — `kind` decide a cuál de las 5
/// operaciones de `domain.rs` corresponde `payload`. Deserializado en
/// dos pasos (primero el sobre completo como `serde_json::Value`,
/// después `payload` al tipo concreto según `kind`) porque `serde`
/// no soporta de forma nativa "el tipo de este campo depende del valor
/// de otro campo del mismo objeto" sin un tagging manual.
#[derive(Debug, Deserialize)]
struct IncomingEnvelope {
    kind: String,
    payload: serde_json::Value,
}

/// El sobre de un mensaje saliente.
#[derive(Debug, Serialize)]
struct OutgoingEnvelope<T: Serialize> {
    kind: &'static str,
    payload: T,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    message: String,
}

/// Bucle principal de una conexión WebSocket: lee mensajes de texto uno
/// por uno, los despacha a `domain.rs`, escribe la respuesta. La
/// conexión permanece abierta hasta que el cliente la cierra o llega un
/// mensaje que axum reporta como error de protocolo — ninguna de esas
/// dos condiciones the trata como una request "fallida" del propio
/// protocolo Lacre, son eventos de transporte, no de dominio.
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    while let Some(Ok(msg)) = socket.recv().await {
        let text = match msg {
            Message::Text(text) => text,
            Message::Close(_) => break,
            // Ping/Pong los maneja axum automáticamente antes de que
            // lleguen acá (responde Pong a un Ping de forma
            // transparente); un mensaje binario no tiene significado
            // en este protocolo — se ignora en vez de cerrar la
            // conexión, para no ser más frágil de lo necesario ante un
            // cliente que envíe, por ejemplo, un frame de keepalive
            // binario propio de su librería de WebSocket.
            _ => continue,
        };

        let response_text = dispatch(&state, &text);

        if socket.send(Message::Text(response_text.into())).await.is_err() {
            // El cliente cerró la conexión mientras se preparaba la
            // respuesta — no hay nada más que hacer que terminar el
            // bucle; no es un error del protocolo Lacre.
            break;
        }
    }
}

/// Despacha un único mensaje de texto a la operación de `domain.rs`
/// correspondiente, y serializa la respuesta (o el error) al mismo
/// formato de sobre. Separado de `handle_socket` para poder testearse
/// sin necesitar un socket real — ver tests al final de este archivo.
fn dispatch(state: &AppState, text: &str) -> String {
    let envelope: IncomingEnvelope = match serde_json::from_str(text) {
        Ok(e) => e,
        Err(e) => return error_envelope(format!("mensaje no es un sobre JSON válido: {e}")),
    };

    match envelope.kind.as_str() {
        "handshake" => respond(envelope.payload, "handshake_response", |req: HandshakeRequest| {
            domain::handshake(state, &req)
        }),
        "seal" => respond(envelope.payload, "seal_response", |req: SealRequest| domain::seal(state, &req)),
        "verify" => respond(envelope.payload, "verify_response", |req: VerifyRequest| domain::verify(state, &req)),
        "ack" => respond(envelope.payload, "ack_response", |req: AckRequest| domain::ack(state, &req)),
        "receipts" => respond(envelope.payload, "receipts_response", |req: ReceiptsSessionId| {
            domain::receipts(state, &req.session_id)
        }),
        other => error_envelope(format!("kind desconocido: {other}")),
    }
}

/// `receipts` no tiene un `*Request` propio en `http_adapter.rs` (el
/// Adaptador HTTP lo recibe como parte de la URL, no del cuerpo) — acá
/// se envuelve en un tipo mínimo solo para mantener la misma forma de
/// despacho que las otras 4 operaciones. No es un tipo de dominio
/// nuevo: es, literalmente, el mismo `String` que `domain::receipts`
/// ya recibía como segundo parámetro.
#[derive(Debug, Deserialize)]
struct ReceiptsSessionId {
    session_id: String,
}

/// Deserializa `payload` al tipo `Req`, ejecuta `op`, serializa el
/// resultado bajo `response_kind` — o el error bajo `"error"`. Genérico
/// sobre `Req`/`Resp` para no repetir esta traducción 5 veces con
/// pequeñas variaciones.
fn respond<Req, Resp>(
    payload: serde_json::Value,
    response_kind: &'static str,
    op: impl FnOnce(Req) -> Result<Resp, DomainError>,
) -> String
where
    Req: for<'de> Deserialize<'de>,
    Resp: Serialize,
{
    let req: Req = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => return error_envelope(format!("payload inválido: {e}")),
    };

    match op(req) {
        Ok(resp) => serde_json::to_string(&OutgoingEnvelope { kind: response_kind, payload: resp })
            .unwrap_or_else(|e| error_envelope(format!("fallo al serializar la respuesta: {e}"))),
        Err(domain_err) => error_envelope(domain_error_message(domain_err)),
    }
}

/// Traduce un `DomainError` al vocabulario de error de ESTE Adaptador
/// — un mensaje de texto dentro del mismo protocolo de frames de
/// WebSocket, sin ningún código de estado (WebSocket no tiene un
/// concepto directamente equivalente a `StatusCode` de HTTP para un
/// error de aplicación dentro de una conexión ya establecida). Cada
/// Adaptador decide cómo traducir `DomainError` a su propio
/// vocabulario — comparar con `domain_error_to_http` en
/// `http_server.rs`.
fn domain_error_message(err: DomainError) -> String {
    match err {
        DomainError::BadRequest(msg) => msg,
        DomainError::Unprocessable(msg) => msg,
        DomainError::NotFound(msg) => msg,
    }
}

fn error_envelope(message: String) -> String {
    serde_json::to_string(&OutgoingEnvelope { kind: "error", payload: ErrorPayload { message } })
        .unwrap_or_else(|_| r#"{"kind":"error","payload":{"message":"fallo interno al serializar el error"}}"#.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::session::MasterKeyRing;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_state() -> AppState {
        let vault_signing_key = lacre_core::vault_signature::VaultSigningKey::generate();
        AppState::new_for_test(
            Arc::new(MasterKeyRing::new(
                0,
                b"clave-de-test-para-websocket-32byt".to_vec(),
                Duration::from_secs(60),
            )),
            Arc::new(crate::session_store::InMemorySessionStore::new(Duration::from_secs(60))),
            vault_signing_key,
            Arc::new(crate::sealer_session_store::SealerSessionStore::new(Duration::from_secs(60))),
        )
    }

    /// El test central: sellar y verificar bajo el perfil Core a través
    /// del protocolo de mensajes WebSocket (sin abrir un socket real —
    /// `dispatch` es una función pura de `&str` a `String`), confirmando
    /// que produce exactamente el mismo resultado que el Adaptador HTTP
    /// ya probaba — porque ambos llaman a la MISMA función de
    /// `domain.rs`.
    #[test]
    fn seal_then_verify_round_trip_over_websocket_protocol() {
        let state = test_state();

        let seal_msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "core", "payload_hex": hex::encode(b"mensaje via websocket")}
        })
        .to_string();
        let seal_resp_text = dispatch(&state, &seal_msg);
        let seal_resp: serde_json::Value = serde_json::from_str(&seal_resp_text).unwrap();
        assert_eq!(seal_resp["kind"], "seal_response", "seal_resp_text: {seal_resp_text}");

        let session_id = seal_resp["payload"]["session_id"].clone();
        let frames = seal_resp["payload"]["frames"].clone();

        let verify_msg = serde_json::json!({
            "kind": "verify",
            "payload": {"profile": "core", "session_id": session_id, "key_id": 0, "frames": frames}
        })
        .to_string();
        let verify_resp_text = dispatch(&state, &verify_msg);
        let verify_resp: serde_json::Value = serde_json::from_str(&verify_resp_text).unwrap();
        assert_eq!(verify_resp["kind"], "verify_response");
        assert_eq!(verify_resp["payload"]["all_verified"], serde_json::json!(true), "verify_resp_text: {verify_resp_text}");
    }

    /// Confirma multiplexado real: dos operaciones DISTINTAS (seal bajo
    /// Lite y un handshake) sobre la MISMA conexión lógica (mismo
    /// `AppState`, que en un socket real sería la misma conexión TCP
    /// persistente), sin que una interfiera con la otra — algo que
    /// HTTP no puede expresar sin dos conexiones separadas.
    #[test]
    fn multiplexes_different_operations_over_the_same_state() {
        let state = test_state();

        let seal_msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "lite", "payload_hex": hex::encode(b"telemetria")}
        })
        .to_string();
        let handshake_msg = serde_json::json!({
            "kind": "handshake",
            "payload": {"client_public_key_hex": "00".repeat(32)}
        })
        .to_string();

        let seal_resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &seal_msg)).unwrap();
        let handshake_resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &handshake_msg)).unwrap();

        assert_eq!(seal_resp["kind"], "seal_response");
        assert_eq!(handshake_resp["kind"], "handshake_response");
    }

    /// Vault por WebSocket: firma presente en la respuesta, mismo
    /// mecanismo que por HTTP — confirma que `domain::seal` no
    /// perdió ningún comportamiento al extraerse de `http_server.rs`.
    #[test]
    fn vault_seal_over_websocket_carries_signature() {
        let state = test_state();
        let msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "vault", "payload_hex": hex::encode(b"orden con no repudio")}
        })
        .to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "seal_response");
        assert!(resp["payload"]["frames"][0]["vault_signature_hex"].is_string());
    }

    /// Un `kind` desconocido debe producir un sobre `"error"`, no un
    /// panic ni un mensaje sin estructura.
    #[test]
    fn unknown_kind_produces_error_envelope() {
        let state = test_state();
        let msg = serde_json::json!({"kind": "algo-que-no-existe", "payload": {}}).to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
        assert!(resp["payload"]["message"].as_str().unwrap().contains("kind desconocido"));
    }

    /// Un `payload` que no decodifica al tipo esperado por `kind` debe
    /// producir un error de dominio, no un panic — mismo criterio de
    /// A4 (fallo cerrado) que ya aplican los Adaptadores HTTP.
    #[test]
    fn malformed_payload_produces_error_envelope_not_panic() {
        let state = test_state();
        let msg = serde_json::json!({"kind": "seal", "payload": {"profile": 123}}).to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
    }

    /// Un `session_id` de handshake desconocido pasado a `seal` debe
    /// reportarse como error de dominio (Unprocessable, en HTTP sería
    /// 422) — mismo comportamiento exacto que ya prueba
    /// `seal_with_unknown_handshake_session_id_is_rejected_not_silently_downgraded`
    /// en http_server.rs, confirmando que ambos Adaptadores comparten
    /// la misma regla de negocio a través de domain.rs.
    #[test]
    fn seal_with_unknown_handshake_session_id_is_rejected() {
        let state = test_state();
        let fake_id = hex::encode(lacre_core::session::SessionId::generate().0);
        let msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "core", "payload_hex": "aa", "session_id": fake_id}
        })
        .to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
        assert!(resp["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("no corresponde a ningún handshake"));
    }
}

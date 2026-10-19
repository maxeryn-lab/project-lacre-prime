//! Second real Adapter: WebSocket over `axum` — the empirical proof of
//! DECISIONS.md point 16 ("Adapters are a first-level extension axis,
//! replaceable without touching business logic").
//!
//! # Why WebSocket, specifically, as the second Adapter
//!
//! Deliberately chosen for being structurally OPPOSITE to HTTP: HTTP
//! is stateless request/response — each `POST /v1/seal` opens and
//! closes its own cycle, with no memory of the previous connection.
//! WebSocket is a PERSISTENT connection, where either party can send
//! messages at any time, without the "first I ask, then I get
//! answered" discipline. If the Core/`domain.rs`/Adapter seam only
//! worked for the easy case (request/response), this Adapter would
//! have revealed it — it would have needed to rewrite business logic,
//! or `AppState` would have needed to know something about WebSocket.
//! Neither happened — see `domain.rs` for what was extracted before
//! building this module, and why that refactor was an honest
//! precondition, not a skippable step.
//!
//! # Message protocol
//!
//! A single WebSocket connection multiplexes the protocol's eight
//! operations (handshake, seal, verify, ack, receipts, plus the three
//! Toolchain Integrity operations) — something HTTP can't do without
//! opening eight separate TCP connections. Each incoming text message
//! is JSON shaped like:
//!
//! ```json
//! {"kind": "seal", "payload": { ...SealRequest... }}
//! ```
//!
//! And each response:
//!
//! ```json
//! {"kind": "seal_response", "payload": { ...SealResponse... }}
//! ```
//!
//! or, on a domain error:
//!
//! ```json
//! {"kind": "error", "payload": {"message": "..."}}
//! ```
//!
//! The `payload` types are EXACTLY the same `*Request`/`*Response`
//! types from `http_adapter.rs` — there is no new type for message
//! content, only the envelope (`kind`) that distinguishes them within
//! the same connection. This is deliberate: if this Adapter had needed
//! its own request/response types, that would have been evidence that
//! `http_adapter.rs` wasn't really HTTP-agnostic, only appeared to be.
//!
//! # What this Adapter does NOT solve
//!
//! There is no request/response correlation mechanism (a message `id`
//! the client could use to know which of its messages a given response
//! corresponds to) — responses are sent in the same order messages
//! arrive, over the same connection. A client needing real pipelining
//! (sending several messages without waiting for a response and then
//! correlating them) would need an explicit `id` field — not
//! implemented in this first pass, same bounded-scope criterion already
//! applied to the streaming variant of HTTP (noted as a future
//! candidate, not blocking).

use lacre_domain::domain::DomainError;
use lacre_domain::app_state::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// `GET /v1/ws` — upgrades the HTTP connection to WebSocket. axum
/// handles the HTTP upgrade handshake (RFC 6455) internally; from
/// there, `handle_socket` takes over the persistent connection.
pub async fn handle_ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// An incoming message's envelope — `kind` decides which of
/// `domain.rs`'s operations `payload` corresponds to. Deserialized in
/// two steps (first the complete envelope as `serde_json::Value`, then
/// `payload` into the concrete type according to `kind`) because
/// `serde` doesn't natively support "this field's type depends on the
/// value of another field in the same object" without manual tagging.
#[derive(Debug, Deserialize)]
struct IncomingEnvelope {
    kind: String,
    payload: serde_json::Value,
}

/// An outgoing message's envelope.
#[derive(Debug, Serialize)]
struct OutgoingEnvelope<T: Serialize> {
    kind: &'static str,
    payload: T,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    message: String,
}

/// A WebSocket connection's main loop: reads text messages one by one,
/// dispatches them to `domain.rs`, writes the response. The connection
/// stays open until the client closes it or a message arrives that
/// axum reports as a protocol error — neither of those two conditions
/// is treated as a "failed" request of the Lacre protocol itself, they
/// are transport events, not domain ones.
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    // A Ping at a fixed interval keeps an idle connection alive through a
    // proxy or balancer that closes silent connections. The first tick is one
    // full interval away; the Pong that answers it is handled by axum.
    let period = state.ws_ping_interval();
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let msg = tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(m)) => m,
                _ => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
                continue;
            }
        };
        let text = match msg {
            Message::Text(text) => text,
            Message::Close(_) => break,
            // Ping/Pong are handled by axum automatically before they
            // get here (it transparently responds Pong to a Ping); a
            // binary message has no meaning in this protocol — it's
            // ignored instead of closing the connection, so as not to
            // be more fragile than necessary against a client that
            // sends, for example, a binary keepalive frame of its own
            // WebSocket library.
            _ => continue,
        };

        // Captured once, at the same structural point every real
        // Adapter in this codebase captures it — see
        // `TransitIdentity::capture`'s own documentation for why this
        // is a shared `lacre-core` function call rather than a
        // hand-rolled `SystemTime::now()` specific to this Adapter.
        // `network_path` is `None` here because axum's `WebSocketUpgrade`
        // extractor, as wired in this file's own `ws_handler`, does not
        // currently thread the peer's remote address down to this
        // point — that's a real, separate piece of wiring (reading
        // `ConnectInfo<SocketAddr>`, per axum's own extractor for it),
        // not something this capture point should silently fabricate.
        let _arrival = lacre_profiles::transit_taxonomy::TransitIdentity::capture(None);

        let response_text = dispatch_async(&state, &text).await;

        if socket.send(Message::Text(response_text.into())).await.is_err() {
            // The client closed the connection while the response was
            // being prepared — there's nothing else to do but end the
            // loop; this isn't a Lacre protocol error.
            break;
        }
    }
}

/// Dispatches a single text message to the corresponding `domain.rs`
/// operation, through `declarative_adapter`'s generic dispatch table,
/// and serializes the result (or error) into this Adapter's own
/// envelope format.
///
/// This used to be a hand-written 5-arm `match`, one per operation,
/// each calling `respond` with its own request type and `domain::x`
/// closure — see `PENDING.md` / `ARCHITECTURE_NOTES.md` for the Annex
/// 5.0 Declarative Adapter work this replaces it with.
/// `lacre_adapter_declarative::Operation::from_name` and `dispatch_json` now
/// do the same decode-then-dispatch step generically, so this
/// function's only remaining job is the WebSocket-specific envelope
/// framing (which legitimately differs from HTTP's status-code framing
/// and therefore isn't, and shouldn't be, generalized away).
///
/// Three operations take a session ID out of the envelope's own
/// `payload` object rather than through the generic
/// `dispatch_json` path: `Receipts`, `AddToolchainNode`, and
/// `VerifyToolchainOutput` — the same split
/// `declarative_adapter.rs`'s own header comment documents for HTTP's
/// URL path parameter, translated here to "a `session_id` field inside
/// the same JSON payload", since WebSocket has no equivalent to a URL
/// path segment. (An earlier version of this function only handled
/// `Receipts` this way and let the two Toolchain session-scoped
/// operations fall through to `dispatch_json`, which rejects them —
/// a real gap fixed while translating this file, not something this
/// translation introduced.)
#[cfg(test)]
fn dispatch(state: &AppState, text: &str) -> String {
    let (operation, payload) = match parse_message(text) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // One arrival capture per message (the WebSocket twin of the HTTP
    // middleware's per-request capture).
    let arrival = lacre_profiles::transit_taxonomy::TransitIdentity::capture(None);
    let result = lacre_adapter_declarative::dispatch_with_transit(state, operation, payload, Some(&arrival));
    render(operation, result)
}

/// The connection loop's version: Seal and Verify run on a blocking thread
/// with the operator's optional admission and deadline (see
/// `lacre_adapter_declarative::dispatch_offloaded`).
async fn dispatch_async(state: &AppState, text: &str) -> String {
    let (operation, payload) = match parse_message(text) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let arrival = lacre_profiles::transit_taxonomy::TransitIdentity::capture(None);
    let result = lacre_adapter_declarative::dispatch_offloaded(state, operation, payload, Some(arrival)).await;
    render(operation, result)
}

fn parse_message(text: &str) -> Result<(lacre_adapter_declarative::Operation, serde_json::Value), String> {
    let envelope: IncomingEnvelope = serde_json::from_str(text)
        .map_err(|e| error_envelope(format!("message is not a valid JSON envelope: {e}")))?;
    let Some(operation) = lacre_adapter_declarative::Operation::from_name(&envelope.kind) else {
        return Err(error_envelope(format!("unknown kind: {}", envelope.kind)));
    };
    Ok((operation, envelope.payload))
}

fn render(operation: lacre_adapter_declarative::Operation, result: Result<serde_json::Value, DomainError>) -> String {
    match result {
        Ok(payload) => serde_json::to_string(&OutgoingEnvelope { kind: operation.response_kind(), payload })
            .unwrap_or_else(|e| error_envelope(format!("failed to serialize the response: {e}"))),
        Err(domain_err) => error_envelope(domain_error_message(domain_err)),
    }
}

/// Translates a `DomainError` to THIS Adapter's error vocabulary — a
/// text message inside the same WebSocket frame protocol, with no
/// status code at all (WebSocket has no concept directly equivalent to
/// HTTP's `StatusCode` for an application error within an
/// already-established connection). Each Adapter decides how to
/// translate `DomainError` to its own vocabulary — compare with
/// `domain_error_to_http` in `http_server.rs`.
fn domain_error_message(err: DomainError) -> String {
    match err {
        DomainError::BadRequest(msg) => msg,
        DomainError::Unprocessable(msg) => msg,
        DomainError::NotFound(msg) => msg,
        DomainError::Unavailable(msg) => msg,
        DomainError::Unauthorized(msg) => msg,
        DomainError::TooManyRequests(msg) => msg,
        DomainError::Forbidden(msg) => msg,
        DomainError::Conflict(msg) => msg,
        DomainError::Internal(msg) => msg,
        DomainError::DeadlineExceeded(msg) => msg,
    }
}

fn error_envelope(message: String) -> String {
    serde_json::to_string(&OutgoingEnvelope { kind: "error", payload: ErrorPayload { message } })
        .unwrap_or_else(|_| r#"{"kind":"error","payload":{"message":"internal failure while serializing the error"}}"#.to_string())
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
                b"test-key-for-websocket-32-bytes-he".to_vec(),
                Duration::from_secs(60),
            )),
            Arc::new(lacre_domain::session_store::InMemorySessionStore::new(Duration::from_secs(60))),
            vault_signing_key,
            Arc::new(lacre_domain::sealer_session_store::SealerSessionStore::new(Duration::from_secs(60))),
        )
    }

    /// The central test: seal and verify under the Core profile through
    /// the WebSocket message protocol (without opening a real socket —
    /// `dispatch` is a pure function from `&str` to `String`),
    /// confirming it produces exactly the same result the HTTP Adapter
    /// already tests — because both call the SAME `domain.rs` function.
    #[test]
    fn seal_then_verify_round_trip_over_websocket_protocol() {
        let state = test_state();

        let seal_msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "core", "payload_hex": hex::encode(b"message via websocket")}
        })
        .to_string();
        let seal_resp_text = dispatch(&state, &seal_msg);
        let seal_resp: serde_json::Value = serde_json::from_str(&seal_resp_text).unwrap();
        assert_eq!(seal_resp["kind"], "seal_response", "seal_resp_text: {seal_resp_text}");

        let session_id = seal_resp["payload"]["session_id"].clone();
        let frames = seal_resp["payload"]["frames"].clone();

        let verify_msg = serde_json::json!({
            "kind": "verify",
            "payload": {"profile": "core", "session_id": session_id, "key_id": 0, "frames": frames, "token": seal_resp["payload"]["capabilities"]["verify"]}
        })
        .to_string();
        let verify_resp_text = dispatch(&state, &verify_msg);
        let verify_resp: serde_json::Value = serde_json::from_str(&verify_resp_text).unwrap();
        assert_eq!(verify_resp["kind"], "verify_response");
        assert_eq!(verify_resp["payload"]["all_verified"], serde_json::json!(true), "verify_resp_text: {verify_resp_text}");
    }

    /// Confirms real multiplexing: two DIFFERENT operations (seal under
    /// Lite and a handshake) over the SAME logical connection (same
    /// `AppState`, which in a real socket would be the same persistent
    /// TCP connection), without one interfering with the other —
    /// something HTTP can't express without two separate connections.
    #[test]
    fn multiplexes_different_operations_over_the_same_state() {
        let state = test_state();

        let seal_msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "lite", "payload_hex": hex::encode(b"telemetry")}
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

    /// Vault over WebSocket: signature present in the response, same
    /// mechanism as over HTTP — confirms `domain::seal` lost no
    /// behavior when extracted from `http_server.rs`.
    #[test]
    fn vault_seal_over_websocket_carries_signature() {
        let state = test_state();
        let msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "vault", "payload_hex": hex::encode(b"order with non-repudiation")}
        })
        .to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "seal_response");
        assert!(resp["payload"]["frames"][0]["vault_signature_hex"].is_string());
    }

    /// An unknown `kind` must produce an `"error"` envelope, never a
    /// panic or an unstructured message.
    #[test]
    fn unknown_kind_produces_error_envelope() {
        let state = test_state();
        let msg = serde_json::json!({"kind": "something-that-does-not-exist", "payload": {}}).to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
        assert!(resp["payload"]["message"].as_str().unwrap().contains("unknown kind"));
    }

    /// `receipts` over WebSocket, end to end: seal under Vault, ack the
    /// resulting frame, then read receipts back — all through the same
    /// `dispatch` function.
    #[test]
    fn receipts_round_trip_over_websocket_protocol() {
        let state = test_state();

        let seal_msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "vault", "payload_hex": hex::encode(b"receipts over websocket")}
        })
        .to_string();
        let seal_resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &seal_msg)).unwrap();
        let session_id = seal_resp["payload"]["session_id"].as_str().unwrap().to_string();
        let index = seal_resp["payload"]["frames"][0]["index"].clone();

        let ack_msg = serde_json::json!({
            "kind": "ack",
            "payload": {"session_id": session_id, "indices": [index], "token": seal_resp["payload"]["capabilities"]["ack"]}
        })
        .to_string();
        let ack_resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &ack_msg)).unwrap();
        assert_eq!(ack_resp["kind"], "ack_response");
        assert_eq!(ack_resp["payload"]["total_receipts"], serde_json::json!(1));

        let receipts_msg = serde_json::json!({
            "kind": "receipts",
            "payload": {"session_id": session_id, "token": seal_resp["payload"]["capabilities"]["write"]}
        })
        .to_string();
        let receipts_resp: serde_json::Value =
            serde_json::from_str(&dispatch(&state, &receipts_msg)).unwrap();
        assert_eq!(receipts_resp["kind"], "receipts_response");
        assert_eq!(receipts_resp["payload"]["entries"].as_array().unwrap().len(), 1);
    }

    /// A `receipts` message whose payload is missing the `session_id`
    /// field must produce a structured error envelope, not a panic.
    #[test]
    fn receipts_without_session_id_field_produces_error_envelope() {
        let state = test_state();
        let msg = serde_json::json!({"kind": "receipts", "payload": {}}).to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
        assert!(resp["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("session_id"));
    }

    /// A `payload` that doesn't decode into the type expected by
    /// `kind` must produce a domain error, not a panic — same A4
    /// (fail-closed) criterion the HTTP Adapters already apply.
    #[test]
    fn malformed_payload_produces_error_envelope_not_panic() {
        let state = test_state();
        let msg = serde_json::json!({"kind": "seal", "payload": {"profile": 123}}).to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
    }

    /// An unknown handshake `session_id` passed to `seal` must be
    /// reported as a domain error (Unprocessable, 422 in HTTP) — same
    /// exact behavior already tested by
    /// `seal_with_unknown_handshake_session_id_is_rejected_not_silently_downgraded`
    /// in http_server.rs, confirming both Adapters share the same
    /// business rule through domain.rs.
    #[test]
    fn seal_with_unknown_handshake_session_id_is_rejected() {
        let state = test_state();
        let fake = lacre_core::session::SessionId::generate();
        let fake_id = hex::encode(fake.0);
        let token = state.capabilities().token_hex(lacre_domain::capability::Scope::Write, &fake.0);
        let msg = serde_json::json!({
            "kind": "seal",
            "payload": {"profile": "core", "payload_hex": "aa", "session_id": fake_id, "token": token}
        })
        .to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
        assert!(resp["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("does not correspond to any active handshake"));
    }

    // --- Toolchain Integrity (Annex 4.0) over WebSocket ---
    //
    // Confirms the real gap fixed in `dispatch` above: before this
    // pass, `AddToolchainNode`/`VerifyToolchainOutput` fell through to
    // `dispatch_json`, which explicitly rejects them (see
    // `declarative_adapter.rs`), so these two operations were entirely
    // unreachable over WebSocket. These tests exercise the fixed path
    // end to end, mirroring the HTTP router integration tests in
    // `http_server.rs`.

    /// The Annex 4.0 diamond-shaped-graph example, dispatched entirely
    /// through the WebSocket message protocol: create an episode, add
    /// a root node and two parallel children plus a combining node,
    /// then verify the output.
    #[test]
    fn toolchain_diamond_graph_verifies_over_websocket_protocol() {
        let state = test_state();

        let create_msg = serde_json::json!({
            "kind": "toolchain_create_episode",
            "payload": {
                "episode_id_hex": hex::encode(b"websocket-episode"),
                "algo": "sha256",
                "max_node_age_ms": 3_600_000u64,
            }
        })
        .to_string();
        let create_resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &create_msg)).unwrap();
        assert_eq!(create_resp["kind"], "toolchain_episode_response");
        let session_id = create_resp["payload"]["session_id"].as_str().unwrap().to_string();
        let write_token = create_resp["payload"]["capabilities"]["write"].as_str().unwrap().to_string();
        let verify_token = create_resp["payload"]["capabilities"]["verify"].as_str().unwrap().to_string();

        let add_node = |node_id: &str, content: &[u8], parent_ids: Vec<&str>| {
            let msg = serde_json::json!({
                "kind": "toolchain_add_node",
                "payload": {
                    "session_id": session_id,
                    "node_id": node_id,
                    "content_hex": hex::encode(content),
                    "parent_ids": parent_ids,
                    "token": write_token,
                }
            })
            .to_string();
            let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
            assert_eq!(resp["kind"], "toolchain_node_response", "node {node_id}: {resp}");
        };

        add_node("prompt", b"sell BTC if the price goes up", vec![]);
        add_node("market_price", b"BTC=65000", vec!["prompt"]);
        add_node("news", b"no relevant events", vec!["prompt"]);
        add_node(
            "recommendation",
            b"sell: favorable price, no news risk",
            vec!["market_price", "news"],
        );

        let verify_msg = serde_json::json!({
            "kind": "toolchain_verify_output",
            "payload": {
                "session_id": session_id,
                "token": verify_token,
                "output_node_id": "recommendation",
                "contents_hex": {
                    "prompt": hex::encode(b"sell BTC if the price goes up"),
                    "market_price": hex::encode(b"BTC=65000"),
                    "news": hex::encode(b"no relevant events"),
                    "recommendation": hex::encode(b"sell: favorable price, no news risk"),
                },
            }
        })
        .to_string();
        let verify_resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &verify_msg)).unwrap();
        assert_eq!(verify_resp["kind"], "toolchain_verify_response");
        assert_eq!(verify_resp["payload"]["valid"], serde_json::json!(true));
    }

    /// A Toolchain session operation whose payload is missing
    /// `session_id` must produce a structured error, not a panic —
    /// same fail-closed discipline as the `receipts` case above.
    #[test]
    fn toolchain_add_node_without_session_id_field_produces_error_envelope() {
        let state = test_state();
        let msg = serde_json::json!({
            "kind": "toolchain_add_node",
            "payload": {"node_id": "orphan", "content_hex": hex::encode(b"data"), "parent_ids": []}
        })
        .to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
        assert!(resp["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("session_id"));
    }

    /// Adding a node to an episode `session_id` that was never created
    /// must produce a `NotFound`-shaped domain error over WebSocket too
    /// — confirming the same `ToolchainSessionStore` error surfaces
    /// identically regardless of which Adapter reached it.
    #[test]
    fn toolchain_add_node_to_unknown_episode_produces_error_envelope() {
        let state = test_state();
        let msg = serde_json::json!({
            "kind": "toolchain_add_node",
            "payload": {
                "session_id": "00000000000000000000000000000000",
                "node_id": "orphan",
                "content_hex": hex::encode(b"data"),
                "parent_ids": [],
            }
        })
        .to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "error");
    }

    /// Store ceilings surface over WebSocket the same way they do over HTTP (503 there): as an
    /// error envelope carrying the domain's "retry shortly" message, because both Adapters map the
    /// same `DomainError::Unavailable` (the 503 path had only been tested over HTTP).
    #[test]
    fn handshake_ceiling_is_reported_as_an_error_envelope() {
        let mut state = test_state();
        state.handshake_sessions = Arc::new(lacre_domain::session_store::InMemorySessionStore::with_ceiling(
            Duration::from_secs(60),
            1,
        ));
        let msg = |k: &str| serde_json::json!({"kind": "handshake", "payload": {"client_public_key_hex": k.repeat(32)}}).to_string();
        let first: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg("00"))).unwrap();
        assert_eq!(first["kind"], "handshake_response");
        let second: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg("01"))).unwrap();
        assert_eq!(second["kind"], "error");
        assert!(second["payload"]["message"].as_str().unwrap().contains("maximum number of concurrent handshake sessions"));
    }

    #[test]
    fn vault_seal_ceiling_is_reported_as_an_error_envelope() {
        let mut state = test_state();
        state.sealer_sessions = Arc::new(lacre_domain::sealer_session_store::SealerSessionStore::with_ceiling(
            Duration::from_secs(60),
            1,
        ));
        let seal = || serde_json::json!({"kind": "seal", "payload": {"profile": "vault", "payload_hex": "41"}}).to_string();
        let first: serde_json::Value = serde_json::from_str(&dispatch(&state, &seal())).unwrap();
        assert_eq!(first["kind"], "seal_response");
        let second: serde_json::Value = serde_json::from_str(&dispatch(&state, &seal())).unwrap();
        assert_eq!(second["kind"], "error");
        assert!(second["payload"]["message"].as_str().unwrap().contains("maximum number of concurrent seal sessions"));
    }

    /// Same rules over WebSocket: no token, or the wrong scope, is an
    /// error envelope and nothing is acknowledged.
    #[test]
    fn ack_over_websocket_needs_the_ack_token() {
        let state = test_state();
        let seal_msg = serde_json::json!({"kind":"seal","payload":{"profile":"vault","payload_hex":"aabbcc"}}).to_string();
        let sealed: serde_json::Value = serde_json::from_str(&dispatch(&state, &seal_msg)).unwrap();
        let sid = sealed["payload"]["session_id"].clone();
        let caps = &sealed["payload"]["capabilities"];
        for payload in [
            serde_json::json!({"session_id": sid, "indices": [0]}),
            serde_json::json!({"session_id": sid, "indices": [0], "token": caps["write"]}),
            serde_json::json!({"session_id": sid, "indices": [0], "token": caps["verify"]}),
        ] {
            let msg = serde_json::json!({"kind":"ack","payload":payload}).to_string();
            let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
            assert_eq!(resp["kind"], "error", "ack accepted: {resp}");
            assert!(resp["payload"]["message"].as_str().unwrap().contains("capability"));
        }
        let msg = serde_json::json!({"kind":"ack","payload":{"session_id":sid,"indices":[0],"token":caps["ack"]}}).to_string();
        let resp: serde_json::Value = serde_json::from_str(&dispatch(&state, &msg)).unwrap();
        assert_eq!(resp["kind"], "ack_response");
        assert_eq!(resp["payload"]["total_receipts"], serde_json::json!(1));
    }

    /// `validate`, `ruleset` on seal and `reassemble` on verify, over the
    /// WebSocket protocol (same domain, second Adapter).
    #[test]
    fn rulesets_and_reassembly_work_over_websocket() {
        let mut state = test_state();
        state.rulesets = Arc::new(
            lacre_domain::rulesets::RuleSets::from_json(
                r#"{"orders":{"kind":"guardian","fields":[{"name":"order_id","type":"integer","digits":8}]}}"#,
            )
            .unwrap(),
        );
        let call = |kind: &str, payload: serde_json::Value| -> serde_json::Value {
            serde_json::from_str(&dispatch(&state, &serde_json::json!({"kind": kind, "payload": payload}).to_string())).unwrap()
        };
        let v = call("validate", serde_json::json!({"ruleset":"orders","payload_hex":hex::encode(br#"{"order_id":12345678}"#)}));
        assert_eq!(v["kind"], "validate_response");
        assert_eq!(v["payload"]["outcome"], "passed");
        let v = call("validate", serde_json::json!({"ruleset":"orders","payload_hex":hex::encode(br#"{"order_id":1}"#)}));
        assert_eq!(v["payload"]["outcome"], "rejected");
        let refused = call("seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(b"{}"),"ruleset":"orders"}));
        assert_eq!(refused["kind"], "error");

        let original: Vec<u8> = (0..3500).map(|i| (i % 251) as u8).collect();
        let sealed = call("seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(&original)}));
        let p = &sealed["payload"];
        let done = call("verify", serde_json::json!({
            "profile":"core","session_id":p["session_id"],"key_id":0,"frames":p["frames"],
            "token":p["capabilities"]["verify"],"reassemble":true}));
        assert_eq!(done["payload"]["payload_hex"].as_str().unwrap(), hex::encode(&original));
    }

    /// A8 over the WebSocket protocol: same domain check, second Adapter.
    #[test]
    fn protocol_version_is_enforced_over_websocket() {
        let state = test_state();
        let call = |kind: &str, payload: serde_json::Value| -> serde_json::Value {
            serde_json::from_str(&dispatch(&state, &serde_json::json!({"kind": kind, "payload": payload}).to_string())).unwrap()
        };
        let hex_payload = hex::encode(b"abc");
        for bad in [serde_json::json!(0), serde_json::json!(2), serde_json::json!("1")] {
            let r = call("seal", serde_json::json!({"profile":"core","payload_hex":hex_payload,"version":bad}));
            assert_eq!(r["kind"], "error", "version {bad}: {r}");
        }
        let ok = call("seal", serde_json::json!({"profile":"core","payload_hex":hex_payload,"version":1}));
        assert_eq!(ok["kind"], "seal_response");
        assert_eq!(ok["payload"]["version"], 1);
        let p = &ok["payload"];
        let refused = call("verify", serde_json::json!({"profile":"core","session_id":p["session_id"],"key_id":0,"frames":p["frames"],"token":p["capabilities"]["verify"],"version":7}));
        assert_eq!(refused["kind"], "error");
    }
}

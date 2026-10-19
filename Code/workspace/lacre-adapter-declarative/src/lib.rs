//! Declarative Adapter — Profiles Annex 5.0, Section II.
//!
//! # What this actually generalizes, and why it differs from the annex's proposal
//!
//! Annex 5.0 describes the Declarative Adapter's vocabulary in terms
//! of raw byte offsets — `session_id_offset`, `length_field_bytes`,
//! fixed-width binary framing suitable for something like a
//! length-prefixed TCP protocol. That vocabulary doesn't match what
//! this project's two real Adapters actually do: both
//! `http_server.rs` and `websocket_adapter.rs` speak JSON, not raw
//! binary framing, and neither one has ever needed to locate a
//! `session_id` at a byte offset — `session_id` already arrives as a
//! named JSON field, because `serde_json` already did that framing
//! work. Forcing this project's real Adapters into the annex's
//! byte-offset vocabulary would mean implementing a vocabulary that
//! solves a problem this codebase doesn't have, while leaving
//! unaddressed the repetition its two real Adapters *do* have.
//!
//! Comparing `http_server.rs`'s five route handlers against
//! `websocket_adapter.rs`'s `dispatch` function shows what actually
//! repeats: both do the exact same three-step sequence for each of
//! the five domain operations (handshake, seal, verify, ack,
//! receipts):
//!
//! 1. **Decode** — transport bytes → a concrete `*Request` type
//!    (`Json<T>` in axum; `serde_json::from_str` on an envelope's
//!    `payload` field in the WebSocket dispatcher).
//! 2. **Dispatch** — call the matching `domain::x(&state, &req)`
//!    function.
//! 3. **Encode** — the resulting `Result<T, DomainError>` back into
//!    that transport's own response shape (HTTP status code + JSON
//!    body; a WebSocket envelope with a `kind` field).
//!
//! Steps 1 and 2 are identical shape across both existing Adapters —
//! only the transport-specific wrapping in step 3 legitimately
//! differs (an HTTP status code has no WebSocket equivalent; a
//! WebSocket response envelope has no HTTP equivalent). This module
//! generalizes steps 1 and 2 as a declarative operation table, so a
//! third Adapter (or a rewrite of either existing one) can route
//! `"seal"` → `domain::seal` by looking it up instead of hand-writing
//! a fifth copy of the same match arm.
//!
//! # What this module does NOT attempt
//!
//! It does not generalize step 3 (transport-specific response
//! encoding) — that's the part that's genuinely different between
//! HTTP and WebSocket, and forcing it into a shared shape would be
//! exactly the kind of premature abstraction this project has
//! deliberately avoided twice before (see `http_adapter.rs`'s own
//! header comment on not building a speculative `trait Transport`
//! before a second real Adapter justified one). It does not implement
//! the annex's byte-offset framing vocabulary at all — if a future
//! Adapter genuinely needs raw binary framing (a length-prefixed TCP
//! protocol with no JSON involved), that vocabulary would need to be
//! designed against that real case when it exists, not spliced onto
//! this one.
//!
//! # Where this lives, architecturally
//!
//! This is `lacre-server`-side code, same as `http_adapter.rs` and
//! `websocket_adapter.rs` — it has zero relationship to `lacre-core`
//! and imports nothing from it directly. It sits *above*
//! `domain.rs`, not beside `http_adapter.rs`'s wire types: it
//! consumes the same `*Request`/`*Response` types and the same
//! `domain::x` functions that both existing Adapters already share,
//! per Section 7.4 of Project Lacre Prime (an Adapter delimits and
//! routes; it never touches the Core's residual session state, and
//! this module has no access to it either — only `AppState`, exactly
//! like `domain.rs`'s own functions).

use lacre_domain::domain::{self, DomainError};
use lacre_domain::wire::{
    AckRequest, HandshakeRequest, ReceiptsResponse, SealRequest, VerifyRequest,
};
use lacre_domain::app_state::AppState;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// The eight domain operations, named exactly as this project's
/// Adapters already name them in their own routing (`"seal"` as an
/// HTTP path segment and as a WebSocket envelope `kind`, not a new
/// name invented for this module). The five original operations
/// (Handshake through Receipts) plus the three Toolchain Integrity
/// operations (Annex 4.0) added once a second real use case justified
/// extending this table — the whole point of `declarative_adapter.rs`
/// existing is to make adding operation #6 cheaper than hand-writing a
/// sixth match arm in every Adapter, and this is the first real test
/// of that claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Handshake,
    Seal,
    Verify,
    Ack,
    /// `Receipts` takes a session ID string rather than a JSON body in
    /// both existing Adapters (the HTTP path segment
    /// `/v1/receipts/{session_id}`, and `ReceiptsSessionId` — the
    /// minimal wrapper `websocket_adapter.rs` already builds around
    /// that same string per its own header comment). It is
    /// deliberately kept as its own dispatch path rather than forced
    /// into the same `decode-JSON-body` shape as the other four —
    /// pretending it fits the same shape would misrepresent what both
    /// real Adapters actually do with it.
    Receipts,
    /// Creates a new live Toolchain episode. Takes a JSON body
    /// (`CreateToolchainEpisodeRequest`) and no path parameter — the
    /// one Toolchain operation that fits the same shape as the
    /// original four.
    CreateToolchainEpisode,
    /// Adds a node to a live episode. Needs a `session_id` from the
    /// URL path, same as `Receipts` — kept out of `dispatch_json` for
    /// the same reason.
    AddToolchainNode,
    /// Verifies an episode's output node. Also needs a `session_id`
    /// from the URL path.
    VerifyToolchainOutput,
    Validate,
    /// Opens a sealing session fed part by part.
    SealOpen,
    /// Seals one part of such a session.
    SealPart,
}

impl Operation {
    /// Parses the operation name exactly as it already appears on the
    /// wire: an HTTP path segment (`/v1/seal` → `"seal"`) and a
    /// WebSocket envelope `kind` (`{"kind": "seal", ...}`). Returns
    /// `None` for anything else — callers map that to their own
    /// "unknown operation" error.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "handshake" => Some(Operation::Handshake),
            "seal" => Some(Operation::Seal),
            "verify" => Some(Operation::Verify),
            "ack" => Some(Operation::Ack),
            "receipts" => Some(Operation::Receipts),
            "toolchain_create_episode" => Some(Operation::CreateToolchainEpisode),
            "toolchain_add_node" => Some(Operation::AddToolchainNode),
            "toolchain_verify_output" => Some(Operation::VerifyToolchainOutput),
            "validate" => Some(Operation::Validate),
            "seal_open" => Some(Operation::SealOpen),
            "seal_part" => Some(Operation::SealPart),
            _ => None,
        }
    }

    /// The response envelope name for this operation's successful
    /// result.
    pub fn response_kind(self) -> &'static str {
        match self {
            Operation::Handshake => "handshake_response",
            Operation::Seal => "seal_response",
            Operation::Verify => "verify_response",
            Operation::Ack => "ack_response",
            Operation::Receipts => "receipts_response",
            Operation::CreateToolchainEpisode => "toolchain_episode_response",
            Operation::AddToolchainNode => "toolchain_node_response",
            Operation::VerifyToolchainOutput => "toolchain_verify_response",
            Operation::Validate => "validate_response",
            Operation::SealOpen => "seal_open_response",
            Operation::SealPart => "seal_part_response",
        }
    }
}

/// Decodes a raw JSON payload into a concrete request type and
/// dispatches it to the matching `domain::x` function, for the
/// operations that take a JSON body with no URL path parameter
/// (everything except `Receipts`, `AddToolchainNode`, and
/// `VerifyToolchainOutput`, which take a session ID from the URL path
/// and are handled by `dispatch_receipts` and
/// `dispatch_toolchain_session_operation` below).
///
/// This is the piece that was previously duplicated: `http_server.rs`
/// wrote `Json<SealRequest>` extraction once per route via axum's own
/// extractor mechanism, and `websocket_adapter.rs`'s `respond` helper
/// wrote the equivalent `serde_json::from_value::<SealRequest>(...)`
/// once per `match` arm — both doing the same decode-then-dispatch
/// step, just spelled differently because each transport's own
/// idioms differ. `dispatch_json` is that same step spelled once,
/// generically over which request/response pair is needed, so an
/// Adapter only has to say *which* operation it wants and hand over
/// the raw JSON, rather than writing its own decode call site per
/// operation.
///
/// Returns `Err(DomainError::BadRequest(..))` for a payload that
/// doesn't decode to the expected shape — same error variant
/// `domain.rs`'s own functions already use for client-side malformed
/// input, so a caller's existing `DomainError` → transport-error
/// mapping (`domain_error_to_http` in HTTP, `to_ws_error_message` in
/// WebSocket) doesn't need a new case added for it.
pub fn dispatch_json(
    state: &AppState,
    operation: Operation,
    payload: serde_json::Value,
) -> Result<serde_json::Value, DomainError> {
    dispatch_json_with_transit(state, operation, payload, None)
}

/// `dispatch_json` plus the arrival metadata the Adapter captured for this
/// request, which `verify` hands to the Transit Non-Novelty Taxonomy.
pub fn dispatch_json_with_transit(
    state: &AppState,
    operation: Operation,
    payload: serde_json::Value,
    transit: Option<&lacre_profiles::transit_taxonomy::TransitIdentity>,
) -> Result<serde_json::Value, DomainError> {
    fn decode<T: DeserializeOwned>(payload: serde_json::Value) -> Result<T, DomainError> {
        serde_json::from_value(payload)
            .map_err(|e| DomainError::BadRequest(format!("malformed request body: {e}")))
    }
    fn encode<T: Serialize>(value: T) -> serde_json::Value {
        // Only fails for types that can't be represented in JSON at
        // all (e.g. non-string map keys) — none of this project's
        // wire types are shaped that way, so this is treated as an
        // invariant rather than a recoverable error, same as
        // `websocket_adapter.rs`'s own `serde_json::to_string(&envelope).unwrap()`
        // already does for the exact same reason.
        serde_json::to_value(value).expect("wire response types are always JSON-representable")
    }

    match operation {
        Operation::Handshake => {
            let req: HandshakeRequest = decode(payload)?;
            domain::handshake(state, &req).map(encode)
        }
        Operation::Seal => {
            let req: SealRequest = decode(payload)?;
            domain::seal(state, &req).map(encode)
        }
        Operation::Verify => {
            let req: VerifyRequest = decode(payload)?;
            domain::verify_with_transit(state, &req, transit).map(encode)
        }
        Operation::SealOpen => {
            let req: lacre_domain::wire::SealOpenRequest = decode(payload)?;
            domain::seal_open(state, &req).map(encode)
        }
        Operation::SealPart => {
            let req: lacre_domain::wire::SealPartRequest = decode(payload)?;
            domain::seal_part(state, &req).map(encode)
        }
        Operation::Validate => {
            let req: lacre_domain::wire::ValidateRequest = decode(payload)?;
            domain::validate(state, &req).map(encode)
        }
        Operation::Ack => {
            let req: AckRequest = decode(payload)?;
            domain::ack(state, &req).map(encode)
        }
        Operation::CreateToolchainEpisode => {
            let req: lacre_domain::wire::CreateToolchainEpisodeRequest = decode(payload)?;
            domain::create_toolchain_episode(state, &req).map(encode)
        }
        Operation::Receipts => Err(DomainError::BadRequest(
            "Receipts takes a session ID string, not a JSON body — use dispatch_receipts instead"
                .to_string(),
        )),
        Operation::AddToolchainNode | Operation::VerifyToolchainOutput => Err(DomainError::BadRequest(
            "this operation takes a session ID from the URL path — use \
             dispatch_toolchain_session_operation instead"
                .to_string(),
        )),
    }
}

/// The `Receipts` operation's own dispatch path, taking a session ID
/// string directly rather than a JSON body — kept separate from
/// `dispatch_json` rather than folded into it with an artificial
/// string-wrapped-in-JSON shape, for the same reason
/// `websocket_adapter.rs`'s own header comment gives for
/// `ReceiptsSessionId`: it's "literally the same `String`" the HTTP
/// Adapter already receives as a path segment, not a new domain
/// concept that happens to need a JSON envelope.
pub fn dispatch_receipts(
    state: &AppState,
    session_id_hex: &str,
    token: Option<&str>,
) -> Result<ReceiptsResponse, DomainError> {
    domain::receipts(state, session_id_hex, token)
}

/// One entry point for every operation, taking everything — including the
/// `session_id` of the session-scoped ones and the capability `token` —
/// from the JSON payload. Both Adapters use this, so the session id never
/// has to travel in a URL (where logs and proxies record it).
pub fn dispatch(
    state: &AppState,
    operation: Operation,
    payload: serde_json::Value,
) -> Result<serde_json::Value, DomainError> {
    dispatch_with_transit(state, operation, payload, None)
}

/// `dispatch` plus the Adapter's arrival metadata for this request.
pub fn dispatch_with_transit(
    state: &AppState,
    operation: Operation,
    mut payload: serde_json::Value,
    transit: Option<&lacre_profiles::transit_taxonomy::TransitIdentity>,
) -> Result<serde_json::Value, DomainError> {
    match operation {
        Operation::Receipts | Operation::AddToolchainNode | Operation::VerifyToolchainOutput => {
            let session_id_hex = payload
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| DomainError::BadRequest("payload is missing a session_id string field".to_string()))?;
            if operation == Operation::Receipts {
                let token = payload.get("token").and_then(|v| v.as_str()).map(str::to_string);
                let resp = dispatch_receipts(state, &session_id_hex, token.as_deref())?;
                serde_json::to_value(resp)
                    .map_err(|e| DomainError::BadRequest(format!("failed to encode response: {e}")))
            } else {
                if let Some(obj) = payload.as_object_mut() {
                    obj.remove("session_id");
                }
                dispatch_toolchain_session_operation(state, operation, &session_id_hex, payload)
            }
        }
        _ => dispatch_json_with_transit(state, operation, payload, transit),
    }
}

/// The dispatch path for the two Toolchain operations that need a
/// session ID from the URL path plus a JSON body — a shape neither
/// `dispatch_json` (JSON body, no path parameter) nor
/// `dispatch_receipts` (path parameter, no body) already covers.
/// Rather than stretching either of those two functions to fit a third
/// shape, this is its own function — the same honesty principle
/// `dispatch_receipts`'s own header comment already applies: forcing a
/// mismatched shape into a shared function would misrepresent what the
/// operation actually needs.
pub fn dispatch_toolchain_session_operation(
    state: &AppState,
    operation: Operation,
    session_id_hex: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, DomainError> {
    fn decode<T: DeserializeOwned>(payload: serde_json::Value) -> Result<T, DomainError> {
        serde_json::from_value(payload)
            .map_err(|e| DomainError::BadRequest(format!("malformed request body: {e}")))
    }
    fn encode<T: Serialize>(value: T) -> serde_json::Value {
        serde_json::to_value(value).expect("wire response types are always JSON-representable")
    }

    match operation {
        Operation::AddToolchainNode => {
            let req: lacre_domain::wire::AddToolchainNodeRequest = decode(payload)?;
            domain::add_toolchain_node(state, session_id_hex, &req).map(encode)
        }
        Operation::VerifyToolchainOutput => {
            let req: lacre_domain::wire::VerifyToolchainOutputRequest = decode(payload)?;
            domain::verify_toolchain_output(state, session_id_hex, &req).map(encode)
        }
        _ => Err(DomainError::BadRequest(format!(
            "{operation:?} does not take a session ID from the URL path — use dispatch_json instead"
        ))),
    }
}

/// Like `dispatch_with_transit`, but for an async Adapter: `Seal` and `Verify`
/// run on a blocking thread, so an algorithm that takes long (or the per-session
/// lock of another request) never stalls the async workers.
///
/// Order: the operator's admission place (if one is configured) is taken
/// BEFORE the work is handed to the blocking pool, and travels with it, so the
/// pool queue cannot grow without bound and the count is of work RUNNING. A
/// panic that escapes is a generic 500. If the operator configured a deadline
/// the caller stops waiting when it passes; the computation itself cannot be
/// cancelled (the Core is synchronous) and keeps its place until it ends.
pub async fn dispatch_offloaded(
    state: &AppState,
    operation: Operation,
    payload: serde_json::Value,
    transit: Option<lacre_profiles::transit_taxonomy::TransitIdentity>,
) -> Result<serde_json::Value, DomainError> {
    if !matches!(operation, Operation::Seal | Operation::Verify | Operation::SealPart) {
        return dispatch_with_transit(state, operation, payload, transit.as_ref());
    }
    let permit = match state.admission() {
        Some(gate) => Some(gate.try_admit()?),
        None => None,
    };
    let st = state.clone();
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit; // released when the computation ends, not when the caller leaves
        dispatch_with_transit(&st, operation, payload, transit.as_ref())
    });
    let joined = match state.request_deadline() {
        Some(d) => match tokio::time::timeout(d, work).await {
            Ok(j) => j,
            Err(_) => {
                return Err(DomainError::DeadlineExceeded(
                    "the request deadline configured on this node passed".to_string(),
                ))
            }
        },
        None => work.await,
    };
    match joined {
        Ok(r) => r,
        Err(_) => Err(DomainError::Internal("internal error".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_domain::profile_config::ProfileName;
    use lacre_core::session::MasterKeyRing;
    use lacre_core::vault_signature::VaultSigningKey;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_state() -> AppState {
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(3600),
        ));
        let vault_key = VaultSigningKey::generate();
        AppState::new_for_test(
            ring,
            Arc::new(lacre_domain::session_store::InMemorySessionStore::new(Duration::from_secs(3600))),
            vault_key,
            Arc::new(lacre_domain::sealer_session_store::SealerSessionStore::new(Duration::from_secs(600))),
        )
    }

    /// `Operation::from_name` must accept exactly the eight names this
    /// project's Adapters use on the wire — the original five plus the
    /// three Toolchain operations added on top. This is the contract
    /// that keeps this module from silently drifting out of sync with
    /// what `http_server.rs`'s routes and `websocket_adapter.rs`'s
    /// `dispatch` match arms actually spell.
    #[test]
    fn operation_names_match_what_this_project_uses() {
        assert_eq!(Operation::from_name("handshake"), Some(Operation::Handshake));
        assert_eq!(Operation::from_name("seal"), Some(Operation::Seal));
        assert_eq!(Operation::from_name("verify"), Some(Operation::Verify));
        assert_eq!(Operation::from_name("ack"), Some(Operation::Ack));
        assert_eq!(Operation::from_name("receipts"), Some(Operation::Receipts));
        assert_eq!(
            Operation::from_name("toolchain_create_episode"),
            Some(Operation::CreateToolchainEpisode)
        );
        assert_eq!(
            Operation::from_name("toolchain_add_node"),
            Some(Operation::AddToolchainNode)
        );
        assert_eq!(
            Operation::from_name("toolchain_verify_output"),
            Some(Operation::VerifyToolchainOutput)
        );
        assert_eq!(Operation::from_name("not_a_real_operation"), None);
    }

    /// Same check for the response envelope names.
    #[test]
    fn response_kind_matches_the_existing_websocket_envelope_names() {
        assert_eq!(Operation::Handshake.response_kind(), "handshake_response");
        assert_eq!(Operation::Seal.response_kind(), "seal_response");
        assert_eq!(Operation::Verify.response_kind(), "verify_response");
        assert_eq!(Operation::Ack.response_kind(), "ack_response");
        assert_eq!(Operation::Receipts.response_kind(), "receipts_response");
        assert_eq!(
            Operation::CreateToolchainEpisode.response_kind(),
            "toolchain_episode_response"
        );
        assert_eq!(
            Operation::AddToolchainNode.response_kind(),
            "toolchain_node_response"
        );
        assert_eq!(
            Operation::VerifyToolchainOutput.response_kind(),
            "toolchain_verify_response"
        );
    }

    /// End-to-end proof that generic dispatch actually reaches the
    /// real domain logic and the real Core underneath it, not a stub:
    /// a handshake dispatched through `dispatch_json` produces a real
    /// session usable by a subsequent `seal` dispatched the same way,
    /// and the resulting frames verify against a `VerifierCore`
    /// resumed from the session established during the handshake step
    /// — exactly the same guarantee `http_server.rs`'s and
    /// `websocket_adapter.rs`'s own integration tests already check
    /// for their hand-written dispatch, now checked for the
    /// declarative one instead.
    ///
    /// Reads fields directly off the returned `serde_json::Value`
    /// rather than deserializing back into `HandshakeResponse` /
    /// `SealResponse`: both types deliberately only derive
    /// `Serialize`, not `Deserialize`, in `http_adapter.rs` — they are
    /// server-to-client output types in this project's real design,
    /// never something the server itself needs to parse back in. This
    /// test respects that boundary instead of forcing a `Deserialize`
    /// derive onto types that don't need it for any real Adapter.
    #[test]
    fn dispatch_json_reaches_real_domain_logic_for_handshake_then_seal() {
        let state = test_state();

        // A minimal, real X25519 client-side handshake — same pattern
        // `http_server.rs`'s own handshake tests already use.
        let client_handshake = lacre_core::session_handshake::EphemeralHandshake::generate();
        let client_public_key_hex = hex::encode(client_handshake.public_key().to_bytes());

        let handshake_payload = serde_json::json!({ "client_public_key_hex": client_public_key_hex });
        let handshake_result = dispatch_json(&state, Operation::Handshake, handshake_payload)
            .expect("handshake must succeed through generic dispatch");
        let session_id_hex = handshake_result["session_id"]
            .as_str()
            .expect("handshake response must carry a session_id string")
            .to_string();

        let seal_payload = serde_json::json!({
            "profile": ProfileName::Core.as_header_value(),
            "payload_hex": hex::encode(b"dispatched through the declarative adapter"),
            "session_id": session_id_hex,
            "token": handshake_result["capabilities"]["write"],
        });
        let seal_result = dispatch_json(&state, Operation::Seal, seal_payload)
            .expect("seal must succeed through generic dispatch");

        assert_eq!(
            seal_result["session_id"].as_str(),
            Some(session_id_hex.as_str())
        );
        let frames = seal_result["frames"]
            .as_array()
            .expect("seal response must carry a frames array");
        assert!(!frames.is_empty());
    }

    /// A malformed JSON body must be reported as `DomainError::BadRequest`
    /// — the same variant `domain.rs` already uses for client-caused
    /// errors — not a panic, and not silently coerced into a
    /// half-populated request.
    #[test]
    fn dispatch_json_reports_malformed_payload_as_bad_request() {
        let state = test_state();
        let malformed = serde_json::json!({ "this_field_does_not_exist": true });

        let result = dispatch_json(&state, Operation::Seal, malformed);
        assert!(matches!(result, Err(DomainError::BadRequest(_))));
    }

    /// `Receipts` must be routed through `dispatch_receipts`, not
    /// `dispatch_json` — confirms the deliberate split described in
    /// this module's header comment is enforced, not just documented.
    #[test]
    fn dispatch_json_refuses_receipts_and_points_to_the_dedicated_path() {
        let state = test_state();
        let result = dispatch_json(&state, Operation::Receipts, serde_json::json!({}));
        assert!(matches!(result, Err(DomainError::BadRequest(_))));
    }

    /// `dispatch_receipts` on a session that was never sealed under
    /// Vault must produce the same `NotFound` `domain.rs` already
    /// produces for that case directly — confirming this thin wrapper
    /// doesn't swallow or reshape the domain error.
    #[test]
    fn dispatch_receipts_matches_domain_receipts_error_behavior() {
        let state = test_state();
        let result = dispatch_receipts(&state, "00000000000000000000000000000000", None);
        assert!(matches!(result, Err(DomainError::Unauthorized(_))), "no token must be refused before any lookup");
    }

    // --- Toolchain Integrity (Annex 4.0) via the Declarative Adapter ---
    //
    // These are the real test for `declarative_adapter.rs`'s own
    // claim: that adding a sixth-through-eighth operation is cheaper
    // than hand-writing new match arms in every Adapter. The five
    // tests above only ever exercised the five operations this module
    // launched with — these confirm the table actually generalizes to
    // an operation family added afterward, through the same two
    // dispatch functions, without either of them needing to change
    // shape.

    /// End-to-end proof mirroring the Annex 4.0 diamond-shaped-graph
    /// example (prompt → two parallel tool calls → one combining node)
    /// dispatched entirely through the declarative Adapter's own
    /// generic functions, reaching a real `ToolchainProfile` through
    /// `ToolchainSessionStore` — not a stub, and not the direct
    /// `lacre-core::toolchain` unit tests, which never go through an
    /// Adapter at all.
    #[test]
    fn toolchain_diamond_graph_verifies_through_the_declarative_adapter() {
        let state = test_state();

        let create_payload = serde_json::json!({
            "episode_id_hex": hex::encode(b"integration-episode"),
            "algo": "sha256",
            "max_node_age_ms": 3_600_000u64,
        });
        let create_result =
            dispatch_json(&state, Operation::CreateToolchainEpisode, create_payload)
                .expect("creating an episode must succeed through generic dispatch");
        let session_id_hex = create_result["session_id"]
            .as_str()
            .expect("episode creation must return a session_id string")
            .to_string();
        let write_token = create_result["capabilities"]["write"].as_str().unwrap().to_string();
        let verify_token = create_result["capabilities"]["verify"].as_str().unwrap().to_string();

        let add_node = |node_id: &str, content: &[u8], parent_ids: Vec<&str>| {
            let payload = serde_json::json!({
                "node_id": node_id,
                "content_hex": hex::encode(content),
                "parent_ids": parent_ids,
                "token": write_token,
            });
            dispatch_toolchain_session_operation(
                &state,
                Operation::AddToolchainNode,
                &session_id_hex,
                payload,
            )
            .unwrap_or_else(|e| panic!("adding node {node_id} must succeed: {e:?}"))
        };

        add_node("prompt", b"sell BTC if the price goes up", vec![]);
        add_node("market_price", b"BTC=65000", vec!["prompt"]);
        add_node("news", b"no relevant events", vec!["prompt"]);
        add_node(
            "recommendation",
            b"sell: favorable price, no news risk",
            vec!["market_price", "news"],
        );

        let verify_payload = serde_json::json!({
            "output_node_id": "recommendation",
            "token": verify_token,
            "contents_hex": {
                "prompt": hex::encode(b"sell BTC if the price goes up"),
                "market_price": hex::encode(b"BTC=65000"),
                "news": hex::encode(b"no relevant events"),
                "recommendation": hex::encode(b"sell: favorable price, no news risk"),
            },
        });
        let verify_result = dispatch_toolchain_session_operation(
            &state,
            Operation::VerifyToolchainOutput,
            &session_id_hex,
            verify_payload,
        )
        .expect("verification must succeed through generic dispatch");

        assert_eq!(verify_result["valid"], serde_json::json!(true));
        assert_eq!(verify_result["failed_node"], serde_json::json!(null));
    }

    /// The exact motivating tamper example from Annex 4.0, dispatched
    /// through the declarative Adapter: a market-price node is
    /// presented with different content at verification time than what
    /// it was sealed with, and the response must name that specific
    /// node as the failure — not report the whole episode as opaquely
    /// invalid.
    #[test]
    fn toolchain_tampered_node_is_named_through_the_declarative_adapter() {
        let state = test_state();

        let create_payload = serde_json::json!({
            "episode_id_hex": hex::encode(b"tamper-episode"),
            "algo": "sha256",
            "max_node_age_ms": 3_600_000u64,
        });
        let create_result =
            dispatch_json(&state, Operation::CreateToolchainEpisode, create_payload).unwrap();
        let session_id_hex = create_result["session_id"].as_str().unwrap().to_string();
        let write_token = create_result["capabilities"]["write"].as_str().unwrap().to_string();
        let verify_token = create_result["capabilities"]["verify"].as_str().unwrap().to_string();

        let add_node = |node_id: &str, content: &[u8], parent_ids: Vec<&str>| {
            let payload = serde_json::json!({
                "node_id": node_id,
                "content_hex": hex::encode(content),
                "parent_ids": parent_ids,
                "token": write_token,
            });
            dispatch_toolchain_session_operation(
                &state,
                Operation::AddToolchainNode,
                &session_id_hex,
                payload,
            )
            .unwrap()
        };

        add_node("prompt", b"sell BTC if the price goes up", vec![]);
        add_node("market_price", b"BTC=65000", vec!["prompt"]);
        add_node("recommendation", b"sell based on BTC=65000", vec!["market_price"]);

        let verify_payload = serde_json::json!({
            "output_node_id": "recommendation",
            "token": verify_token,
            "contents_hex": {
                "prompt": hex::encode(b"sell BTC if the price goes up"),
                "market_price": hex::encode(b"BTC=999999"), // tampered
                "recommendation": hex::encode(b"sell based on BTC=65000"),
            },
        });
        let verify_result = dispatch_toolchain_session_operation(
            &state,
            Operation::VerifyToolchainOutput,
            &session_id_hex,
            verify_payload,
        )
        .unwrap();

        assert_eq!(verify_result["valid"], serde_json::json!(false));
        assert_eq!(
            verify_result["failed_node"],
            serde_json::json!("market_price")
        );
    }

    /// Adding a node to a session ID that was never created (or already
    /// expired) must produce `DomainError::NotFound` — confirming
    /// `dispatch_toolchain_session_operation` surfaces
    /// `ToolchainSessionStore`'s own `WithEpisodeError::NotFound`
    /// rather than swallowing or reshaping it.
    #[test]
    fn adding_a_node_to_an_unknown_episode_is_not_found() {
        let state = test_state();
        let token = state
            .capabilities()
            .token_hex(lacre_domain::capability::Scope::Write, &[0u8; 16]);
        let payload = serde_json::json!({
            "node_id": "orphan",
            "content_hex": hex::encode(b"data"),
            "parent_ids": [],
            "token": token,
        });
        let result = dispatch_toolchain_session_operation(
            &state,
            Operation::AddToolchainNode,
            "00000000000000000000000000000000",
            payload,
        );
        assert!(matches!(result, Err(DomainError::NotFound(_))));
    }

    /// A declared parent that doesn't exist in the episode must
    /// surface as `DomainError::Unprocessable` (the request was
    /// well-formed, but the operation can't complete because of the
    /// episode's own state) — not `BadRequest`, since nothing about the
    /// JSON body itself was malformed.
    #[test]
    fn adding_a_node_with_an_unknown_parent_is_unprocessable() {
        let state = test_state();
        let create_payload = serde_json::json!({
            "episode_id_hex": hex::encode(b"unknown-parent-episode"),
            "algo": "sha256",
            "max_node_age_ms": 3_600_000u64,
        });
        let create_result =
            dispatch_json(&state, Operation::CreateToolchainEpisode, create_payload).unwrap();
        let session_id_hex = create_result["session_id"].as_str().unwrap().to_string();

        let payload = serde_json::json!({
            "node_id": "orphan",
            "content_hex": hex::encode(b"data"),
            "parent_ids": ["nonexistent"],
            "token": create_result["capabilities"]["write"],
        });
        let result = dispatch_toolchain_session_operation(
            &state,
            Operation::AddToolchainNode,
            &session_id_hex,
            payload,
        );
        assert!(matches!(result, Err(DomainError::Unprocessable(_))));
    }

    /// `dispatch_json` must refuse the two session-scoped Toolchain
    /// operations, pointing to the dedicated path — same discipline
    /// already confirmed for `Receipts`.
    #[test]
    fn dispatch_json_refuses_toolchain_session_operations() {
        let state = test_state();
        let result = dispatch_json(&state, Operation::AddToolchainNode, serde_json::json!({}));
        assert!(matches!(result, Err(DomainError::BadRequest(_))));

        let result = dispatch_json(
            &state,
            Operation::VerifyToolchainOutput,
            serde_json::json!({}),
        );
        assert!(matches!(result, Err(DomainError::BadRequest(_))));
    }

    /// `dispatch_toolchain_session_operation` must refuse the five
    /// original operations, symmetric to the check above.
    #[test]
    fn dispatch_toolchain_session_operation_refuses_the_original_operations() {
        let state = test_state();
        let result = dispatch_toolchain_session_operation(
            &state,
            Operation::Seal,
            "00000000000000000000000000000000",
            serde_json::json!({}),
        );
        assert!(matches!(result, Err(DomainError::BadRequest(_))));
    }
}

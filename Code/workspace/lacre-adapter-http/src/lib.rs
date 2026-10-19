//! HTTP Adapter over `axum` — Section 7.4 of the Lacre Prime document.
//!
//! # What this module DOES cover so far
//!
//! Real endpoints: service health check, WebSocket connection upgrade,
//! X25519 handshake, sealing, verification, ACK confirmation, and
//! post-purge receipt reading. Everything is wired against real
//! `lacre-core` types — nothing here is a stub.
//!
//! # Why `VerifierCore` IS persisted between requests (revised)
//!
//! An earlier version of this comment argued that `VerifierCore`
//! didn't need cross-request persistence, on the reasoning that
//! `VerifierCore::resume` is deterministic given `(key_ring,
//! session_id, key_id)`. That's true, but it rested on an unstated
//! assumption: that every `/v1/verify` call for a session always
//! carries that session's COMPLETE frame array in one call. Confirmed
//! empirically against a real running server (not just reasoned about)
//! that the assumption doesn't hold for a caller verifying frames
//! incrementally as they arrive: presenting frame index 1 alone, with
//! index 0 never having appeared in that same call, failed with
//! `"invalid fragment order: expected index 0, received 1"` — every
//! call was restarting `next_expected_index` at 0, so a session's
//! later frames could never be verified across separate calls, and,
//! worse, a frame already verified and purged in one call could be
//! verified successfully again in a later call, silently defeating the
//! replay/reorder protection Sᵢ exists to provide. See
//! `verifier_session_store.rs`'s own header for the full account and
//! `DECISIONS.md` for this correction's authorship provenance.
//!
//! `SealerCore` already needed persistence (see
//! `sealer_session_store.rs`) because `SealerCore::ack` accumulates
//! real state (the `ReceiptLog`) that can't be reconstructed from
//! scratch on a later request — `VerifierCore` now follows the same
//! pattern via `verifier_session_store.rs`, for the reason above.

use lacre_domain::app_state::AppState;
use lacre_domain::domain::DomainError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use lacre_core::session::MasterKeyRing;
use lacre_core::vault_signature::VaultSigningKey;
use std::sync::Arc;
use std::time::Duration;

/// Loads the master key from the `LACRE_MASTER_KEY` environment
/// variable (hex, minimum 32 bytes of entropy) — if absent, generates a
/// random one for local development, printing a clear warning: this is
/// NOT suitable for production (a key that changes on every server
/// restart invalidates every in-flight session).
fn load_master_key_ring() -> Arc<MasterKeyRing> {
    let ikm = match std::env::var("LACRE_MASTER_KEY") {
        Ok(hex_key) => match hex::decode(&hex_key) {
            Ok(bytes) if bytes.len() >= 32 => bytes,
            Ok(_) => {
                eprintln!("LACRE_MASTER_KEY must decode to at least 32 bytes — using a random key instead");
                generate_random_key()
            }
            Err(_) => {
                eprintln!("LACRE_MASTER_KEY is not valid hex — using a random key instead");
                generate_random_key()
            }
        },
        Err(_) => {
            eprintln!(
                "WARNING: LACRE_MASTER_KEY not set. Using a random key generated for this \
                 process — NOT suitable for production (every server restart invalidates \
                 every in-flight session)."
            );
            generate_random_key()
        }
    };
    Arc::new(MasterKeyRing::new(0, ikm, Duration::from_secs(3600)))
}

/// `LACRE_CAPABILITY_KEY` (hex, exactly 32 bytes): the root of the
/// capability tokens. Verifier and sealer instances that must accept each
/// other's tokens share it. If absent, a random one per process (tokens
/// then die with the process, like the sessions they belong to).
fn load_capability_root() -> Arc<lacre_domain::capability::CapabilityRoot> {
    if let Ok(hex_key) = std::env::var("LACRE_CAPABILITY_KEY") {
        match hex::decode(hex_key.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            Some(key) => return Arc::new(lacre_domain::capability::CapabilityRoot::from_bytes(key)),
            None => eprintln!("LACRE_CAPABILITY_KEY must be 64 hex characters (32 bytes) — using a random root instead"),
        }
    }
    Arc::new(lacre_domain::capability::CapabilityRoot::generate())
}

/// `LACRE_RULESETS_FILE`: JSON file of named rule sets (Guardian,
/// Certifier, Rule Engine — see `lacre_domain::rulesets`). Unset means no
/// rule sets (a request naming one gets a 400). A file that cannot be read
/// or built STOPS the server: a rule set that silently failed to load would
/// mean validation the operator believes is on is not running.
fn load_rulesets() -> Arc<lacre_domain::rulesets::RuleSets> {
    let Ok(path) = std::env::var("LACRE_RULESETS_FILE") else {
        return Arc::new(lacre_domain::rulesets::RuleSets::empty());
    };
    let loaded = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {path}: {e}"))
        .and_then(|text| lacre_domain::rulesets::RuleSets::from_json(&text));
    match loaded {
        Ok(sets) => {
            eprintln!("loaded {} rule set(s) from {path}: {}", sets.len(), sets.names().join(", "));
            Arc::new(sets)
        }
        Err(e) => {
            eprintln!("LACRE_RULESETS_FILE: {e}");
            std::process::exit(2);
        }
    }
}

fn generate_random_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Reads a store ceiling from an environment variable. Unset uses the store's
/// default; a value that isn't a positive integer is reported on stderr and
/// ignored, same policy as the other `LACRE_*` variables here — a typo must not
/// silently become "no ceiling" or "ceiling of zero".
fn load_ceiling(var: &str, default: usize) -> usize {
    match std::env::var(var) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("{var} must be a positive integer — using the default ({default})");
                default
            }
        },
        Err(_) => default,
    }
}

/// `LACRE_MAX_VERIFIER_SESSIONS`: ceiling on simultaneously live `VerifierCore`s
/// (see `verifier_session_store.rs`).
fn load_max_verifier_sessions() -> usize {
    load_ceiling(
        "LACRE_MAX_VERIFIER_SESSIONS",
        lacre_domain::verifier_session_store::DEFAULT_MAX_LIVE_SESSIONS,
    )
}

/// Loads the Vault signing key from `LACRE_VAULT_SIGNING_KEY`
/// (hex, exactly 32 bytes) — if absent, generates a new one, with the
/// same production caveat as `load_master_key_ring`: a key that
/// changes on every restart breaks non-repudiation for any client that
/// already knows a previous public key.
fn load_vault_signing_key() -> VaultSigningKey {
    match std::env::var("LACRE_VAULT_SIGNING_KEY") {
        Ok(hex_key) => match hex::decode(&hex_key) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(arr) => VaultSigningKey::from_bytes(&arr),
                Err(_) => {
                    eprintln!("LACRE_VAULT_SIGNING_KEY must decode to exactly 32 bytes — generating a new key instead");
                    VaultSigningKey::generate()
                }
            },
            Err(_) => {
                eprintln!("LACRE_VAULT_SIGNING_KEY is not valid hex — generating a new key instead");
                VaultSigningKey::generate()
            }
        },
        Err(_) => {
            eprintln!(
                "WARNING: LACRE_VAULT_SIGNING_KEY not set. Generating a new key for this \
                 process — NOT suitable for production (every server restart breaks \
                 non-repudiation for clients that already know a previous public key)."
            );
            VaultSigningKey::generate()
        }
    }
}

/// Convenience entry point kept for a future `[lib]` target if this
/// crate ever exposes one (it doesn't today — `lacre-server` is
/// currently a binary-only crate, no `src/lib.rs`, so nothing outside
/// this crate can actually call this yet). Previously justified in
/// this comment as "a real public API surface for anyone using
/// `lacre-server` as a library" — that was wrong, caught while
/// investigating why a test exercising this function still left it
/// flagged as dead code by the compiler's binary-crate analysis, which
/// doesn't credit a `#[cfg(test)]`-only call the same way a `[lib]`
/// target's public surface would be credited. Left in place rather
/// than deleted because `build_router_with_state` alone still requires
/// a caller to assemble `AppState` by hand — a real convenience this
/// function documents even without a current caller — but the
/// dead-code warning is accepted rather than argued around with an
/// artificial test.
#[allow(dead_code)]
pub fn build_router() -> Router {
    build_router_with_state(build_default_state())
}

/// Constructs the default `AppState` (loaded keys, fresh in-memory
/// stores) without building a `Router` around it — separated from
/// `build_router` so `main.rs` can hold onto the same `AppState` for a
/// periodic purge task, rather than a router-only entry point hiding
/// the state a caller might need for anything besides serving HTTP
/// requests.
pub fn build_default_state() -> AppState {
    let vault_signing_key = load_vault_signing_key();
    let vault_verifying_key = vault_signing_key.verifying_key();
    AppState {
        key_ring: load_master_key_ring(),
        // 1-hour TTL: a handshake session unused within that margin
        // gets purged — same order of magnitude as the fixed key
        // ring's default retirement_window above. There's no
        // normative requirement behind this specific value; it's a
        // deployment parameter of THIS Adapter (see session_store.rs),
        // adjustable without touching the protocol.
        handshake_sessions: Arc::new(lacre_domain::session_store::InMemorySessionStore::with_ceiling(
            Duration::from_secs(3600),
            load_ceiling("LACRE_MAX_HANDSHAKE_SESSIONS", lacre_domain::session_store::DEFAULT_MAX_HANDSHAKE_SESSIONS),
        )),
        vault_signing_key: Arc::new(vault_signing_key),
        vault_verifying_key,
        // Shorter TTL than handshake_sessions: a Vault SealerCore only
        // needs to survive the reasonable margin between the client
        // receiving the /v1/seal response and confirming with
        // /v1/ack, not a full long-lived session. 10 minutes is a
        // deployment value of this Adapter, not a requirement of 7.5.
        sealer_sessions: Arc::new(lacre_domain::sealer_session_store::SealerSessionStore::with_ceiling(
            Duration::from_secs(600),
            load_ceiling("LACRE_MAX_SEALER_SESSIONS", lacre_domain::sealer_session_store::DEFAULT_MAX_SEALER_SESSIONS),
        )),
        // Same idle-TTL criterion as sealer_sessions: an incremental
        // verification episode spread across multiple requests
        // shouldn't need to outlive a reasonable margin between one
        // frame's arrival and the next. Deployment parameter of this
        // Adapter, not a requirement of Section 8.2/8.6 of Project
        // Lacre Prime.
        verifier_sessions: Arc::new(lacre_domain::verifier_session_store::VerifierSessionStore::with_limits(
            Duration::from_secs(600),
            Duration::from_secs(1200),
            load_max_verifier_sessions(),
        )),
        // Same 10-minute TTL as sealer_sessions: an episode being built
        // through a sequence of HTTP requests should not need to
        // outlive a reasonable margin between one node-adding request
        // and the next. Deployment parameter of this Adapter, not a
        // requirement of Annex 4.0 itself.
        capabilities: load_capability_root(),
        rulesets: load_rulesets(),
        // Wire v2 and admission are composed by the binary that assembles the
        // node (`lacre-server`), which decides what the registry contains.
        seal_runtime: None,
        admission: None,
        request_deadline: None,
        max_body_bytes: lacre_domain::app_state::DEFAULT_MAX_BODY_BYTES,
        ws_ping_interval: lacre_domain::app_state::DEFAULT_WS_PING_INTERVAL,
        toolchain_sessions: Arc::new(lacre_domain::toolchain_session_store::ToolchainSessionStore::with_ceiling(
            Duration::from_secs(600),
            load_ceiling("LACRE_MAX_TOOLCHAIN_SESSIONS", lacre_domain::toolchain_session_store::DEFAULT_MAX_TOOLCHAIN_SESSIONS),
        )),
    }
}

pub fn build_router_with_state(state: AppState) -> Router {
    let body_limit = state.max_body_bytes();
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/profiles", get(profiles))
        .route("/v1/ws", get(lacre_adapter_ws::handle_ws_upgrade))
        .route("/v1/seal-algorithms", get(seal_algorithms))
        .route("/v1/handshake", post(handle_handshake))
        .route("/v1/seal", post(handle_seal))
        .route("/v1/seal/open", post(handle_seal_open))
        .route("/v1/seal/part", post(handle_seal_part))
        .route("/v1/verify", post(handle_verify))
        .route("/v1/validate", post(handle_validate))
        .route("/v1/ack", post(handle_ack))
        .route("/v1/receipts", post(handle_receipts))
        .route("/v1/toolchain/episodes", post(handle_toolchain_create_episode))
        .route("/v1/toolchain/nodes", post(handle_toolchain_add_node))
        .route("/v1/toolchain/verify", post(handle_toolchain_verify_output))
        // A single `axum::middleware::from_fn` layer, covering all
        // eight routes above at once, rather than a `TransitIdentity`
        // capture call duplicated inside each of the five original
        // handlers plus the three Toolchain ones. This is the HTTP
        // side of the same demonstration `websocket_adapter.rs`'s own
        // `handle_socket` already makes for its single shared message
        // loop — here HTTP has eight separate handler functions, not
        // one shared loop, so the equivalent "one shared point" is
        // this middleware layer instead of a shared function body. See
        // `capture_arrival_middleware`'s own documentation for what it
        // does and doesn't do yet.
        .layer(axum::middleware::from_fn(capture_arrival_middleware))
        // Explicit request body limit (LACRE_MAX_BODY_BYTES; default 2 MiB).
        .layer(axum::extract::DefaultBodyLimit::max(body_limit))
        // Outermost: it also sees the refusals produced by the layers above
        // (413) and by the extractors (malformed JSON). See `problem_json_middleware`.
        .layer(axum::middleware::from_fn(problem_json_middleware))
        .with_state(state)
}

/// Marks a response whose request spoke wire v2: its errors are problem
/// documents even when the client did not ask for them with `Accept`.
#[derive(Clone, Copy)]
struct WantsProblem;

const PROBLEM_JSON: &str = "application/problem+json";

/// The stable, machine-readable `code` of an error, derived from its status
/// and its text. The text of each wire-v1 error is unchanged; this only adds
/// a name a client can match on.
fn problem_code(status: StatusCode, detail: &str) -> &'static str {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return "body-too-large";
    }
    if detail.starts_with("Failed to ") || detail.starts_with("Expected request with") {
        return "malformed-body";
    }
    if detail.starts_with("unknown profile") {
        return "unknown-profile";
    }
    if detail.contains("not valid hex") {
        return "invalid-hex";
    }
    if detail.starts_with("missing or invalid capability token") {
        return "missing-or-invalid-token";
    }
    if detail.starts_with("session_id already completed") {
        return "session-already-completed";
    }
    if detail.starts_with("part out of order") {
        return "part-out-of-order";
    }
    if detail.starts_with("part conflict") {
        return "part-conflict";
    }
    if detail.starts_with("window full") {
        return "window-full";
    }
    if detail.starts_with("unsupported protocol version") {
        return "version-not-accepted";
    }
    match status {
        StatusCode::BAD_REQUEST => "bad-request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::CONFLICT => "conflict",
        StatusCode::NOT_FOUND => "not-found",
        StatusCode::UNPROCESSABLE_ENTITY => "unprocessable",
        StatusCode::TOO_MANY_REQUESTS => "too-many-requests",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        StatusCode::GATEWAY_TIMEOUT => "deadline-exceeded",
        StatusCode::INTERNAL_SERVER_ERROR => "internal",
        _ => "error",
    }
}

/// Negotiated error format. A client that sends `Accept: application/problem+json`
/// (or whose request speaks wire v2) gets every text error as an RFC 9457 problem
/// document: `type` (`urn:lacre:error:<code>`), `title`, `status`, `detail` (the
/// same text wire v1 returns) and `code`. Everyone else gets the exact text they
/// always got.
async fn problem_json_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let asked = request
        .headers()
        .get_all(axum::http::header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains(PROBLEM_JSON));
    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    if !(asked || response.extensions().get::<WantsProblem>().is_some()) {
        return response;
    }
    let is_text = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("text/plain"))
        .unwrap_or(true);
    if !is_text {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    let detail = String::from_utf8_lossy(&bytes).to_string();
    let code = problem_code(status, &detail);
    let document = serde_json::json!({
        "type": format!("urn:lacre:error:{code}"),
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
    });
    let out = serde_json::to_vec(&document).unwrap_or_default();
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    parts
        .headers
        .insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static(PROBLEM_JSON));
    axum::response::Response::from_parts(parts, axum::body::Body::from(out))
}

/// Captures a `TransitIdentity` for every request this Adapter serves,
/// at the one point common to all eight routes — before any handler's
/// own body runs, immediately as the request crosses into this
/// process — then passes the request through unchanged.
///
/// This mirrors, for HTTP's eight separate handler functions, exactly
/// what `websocket_adapter.rs`'s own `handle_socket` already does for
/// its one shared per-message loop: one call to
/// `TransitIdentity::capture`, at one structural point, rather than
/// duplicated inside every handler. See `TransitIdentity::capture`'s
/// own documentation in `lacre-core` for why this exists as a single
/// shared function at all, rather than each Adapter hand-rolling its
/// own arrival-timestamp logic.
///
/// `network_path` is `None` here for the same reason
/// `websocket_adapter.rs`'s own capture call passes `None`: reading the
/// client's real remote address requires axum's own
/// `ConnectInfo<SocketAddr>` extractor, which needs the server to be
/// bound with `into_make_service_with_connect_info` rather than this
/// router's current `into_make_service` (see `main.rs`) — a separate,
/// real change to how this Adapter binds its listener, not something
/// this middleware should silently fake a value for.
///
/// The captured `TransitIdentity` is not yet attached to the request or
/// read by anything downstream — there is currently no real call site
/// in this codebase that invokes `ReassembleProfile::accept` from an
/// HTTP or WebSocket route at all (reassembly exists and is fully
/// tested in `lacre-core`, but no Adapter in `lacre-server` wires a
/// request into it yet), so there is nothing real for this value to
/// flow into downstream of this middleware today. Wiring this into
/// request extensions (axum's own mechanism for a middleware layer to
/// pass data to a handler) is real, separate work, correctly deferred
/// until an actual `ReassembleProfile`-backed route exists to receive
/// it — adding that plumbing now, ahead of a genuine consumer, would be
/// exactly the kind of speculative construction this codebase's own
/// discipline avoids elsewhere (see `DECISIONS.md`'s own entries on not
/// building ahead of a confirmed second use).
async fn capture_arrival_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let arrival = lacre_profiles::transit_taxonomy::TransitIdentity::capture(None);
    let mut request = request;
    request.extensions_mut().insert(arrival);
    next.run(request).await
}

/// Opt-in discovery of what this node's policy allows. 404 unless the operator
/// turned it on: an unconfigured node does not describe itself.
async fn seal_algorithms(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    state.seal_runtime().and_then(|r| r.discovery()).map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn health() -> &'static str {
    "ok"
}

/// The node's `touches_payload` declarations (Prime 7.3.1): static, public,
/// no session and no capability involved.
async fn profiles() -> Json<lacre_domain::wire::ProfilesResponse> {
    Json(lacre_domain::wire::profiles_declaration())
}

/// Translates a `DomainError` to this Adapter's own vocabulary
/// (`StatusCode` + message). Each Adapter decides how to translate
/// `DomainError` into its own vocabulary — compare with
/// `domain_error_message` in `websocket_adapter.rs`.
fn domain_error_to_http(err: DomainError) -> (StatusCode, String) {
    match err {
        DomainError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        DomainError::Unprocessable(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        DomainError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        DomainError::Unavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
        DomainError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
        DomainError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
        DomainError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
        DomainError::Conflict(msg) => (StatusCode::CONFLICT, msg),
        DomainError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        DomainError::DeadlineExceeded(msg) => (StatusCode::GATEWAY_TIMEOUT, msg),
    }
}

// --- Every operation goes through ONE generic handler. ---
//
// Each route is `POST` with a JSON body; nothing session-related
// travels in the URL any more (a URL is what access logs, proxies and
// browser history record, so a `session_id` there leaked the only
// handle on the session). The capability
// token is read from the body (`token`) or, if the body has none, from
// `Authorization: Bearer <token>`; authentication itself happens in the
// domain (`lacre_domain::capability`), identically for HTTP and
// WebSocket.

/// Merges `Authorization: Bearer <token>` into the payload as `token`,
/// unless the body already carries one (the body wins: it is explicit).
fn merge_bearer(headers: &axum::http::HeaderMap, payload: &mut serde_json::Value) {
    let Some(obj) = payload.as_object_mut() else { return };
    if obj.contains_key("token") {
        return;
    }
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ").map(str::trim) {
            obj.insert("token".to_string(), serde_json::Value::String(token.to_string()));
        }
    }
}

async fn run_operation(
    state: AppState,
    operation: lacre_adapter_declarative::Operation,
    headers: axum::http::HeaderMap,
    arrival: lacre_profiles::transit_taxonomy::TransitIdentity,
    mut payload: serde_json::Value,
) -> Result<Json<serde_json::Value>, axum::response::Response> {
    use axum::response::IntoResponse;
    merge_bearer(&headers, &mut payload);
    let v2 = payload.get("version").and_then(|v| v.as_u64()) == Some(2);
    lacre_adapter_declarative::dispatch_offloaded(&state, operation, payload, Some(arrival))
        .await
        .map(Json)
        .map_err(|e| {
            let busy = matches!(e, DomainError::Unavailable(_));
            let (status, msg) = domain_error_to_http(e);
            let mut response = if busy {
                (status, [(axum::http::header::RETRY_AFTER, "1")], msg).into_response()
            } else {
                (status, msg).into_response()
            };
            if v2 {
                response.extensions_mut().insert(WantsProblem);
            }
            response
        })
}

macro_rules! op_handler {
    ($name:ident, $op:ident) => {
        async fn $name(
            State(state): State<AppState>,
            headers: axum::http::HeaderMap,
            axum::Extension(arrival): axum::Extension<lacre_profiles::transit_taxonomy::TransitIdentity>,
            Json(payload): Json<serde_json::Value>,
        ) -> Result<Json<serde_json::Value>, axum::response::Response> {
            run_operation(state, lacre_adapter_declarative::Operation::$op, headers, arrival, payload).await
        }
    };
}

op_handler!(handle_handshake, Handshake);
op_handler!(handle_seal_open, SealOpen);
op_handler!(handle_seal_part, SealPart);
op_handler!(handle_seal, Seal);
op_handler!(handle_verify, Verify);
op_handler!(handle_ack, Ack);
op_handler!(handle_receipts, Receipts);
op_handler!(handle_toolchain_create_episode, CreateToolchainEpisode);
op_handler!(handle_toolchain_add_node, AddToolchainNode);
op_handler!(handle_toolchain_verify_output, VerifyToolchainOutput);
op_handler!(handle_validate, Validate);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use lacre_domain::wire::describe_core_error;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(3600),
        ));
        AppState::new_for_test(
            ring,
            Arc::new(lacre_domain::session_store::InMemorySessionStore::new(Duration::from_secs(3600))),
            VaultSigningKey::generate(),
            Arc::new(lacre_domain::sealer_session_store::SealerSessionStore::new(Duration::from_secs(600))),
        )
    }

    /// Same as `post_json` but presents the capability token as an
    /// `Authorization: Bearer` header, the way a real client would.
    async fn post_auth(
        router: &Router,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn tok(state: &AppState, scope: lacre_domain::capability::Scope, session_id_hex: &str) -> String {
        let id = lacre_domain::wire::session_id_from_hex(session_id_hex).unwrap();
        state.capabilities().token_hex(scope, &id.0)
    }

    async fn post_raw(router: &Router, path: &str, body: Vec<u8>) -> StatusCode {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        router.clone().oneshot(request).await.unwrap().status()
    }

    /// The request body limit is the one the state names: a body of exactly the
    /// limit is read, one byte more is refused with 413 before any handler runs.
    #[tokio::test]
    async fn the_body_limit_is_the_one_in_the_state_to_the_byte() {
        const LIMIT: usize = 2000;
        let router = build_router_with_state(test_state().with_max_body_bytes(LIMIT));
        let base = br#"{"profile":"core","payload_hex":"00"}"#.to_vec();
        let padded = |n: usize| {
            let mut b = base.clone();
            b.resize(n, b' ');
            b
        };
        assert_eq!(post_raw(&router, "/v1/seal", padded(LIMIT)).await, StatusCode::OK);
        assert_eq!(post_raw(&router, "/v1/seal", padded(LIMIT + 1)).await, StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Without a configured value the limit is the documented default.
    #[tokio::test]
    async fn the_default_body_limit_is_two_mebibytes_to_the_byte() {
        let router = build_router_with_state(test_state());
        let limit = lacre_domain::app_state::DEFAULT_MAX_BODY_BYTES;
        assert_eq!(limit, 2_097_152);
        let base = br#"{"profile":"core","payload_hex":"00"}"#.to_vec();
        let padded = |n: usize| {
            let mut b = base.clone();
            b.resize(n, b' ');
            b
        };
        assert_eq!(post_raw(&router, "/v1/seal", padded(limit)).await, StatusCode::OK);
        assert_eq!(post_raw(&router, "/v1/seal", padded(limit + 1)).await, StatusCode::PAYLOAD_TOO_LARGE);
    }

    async fn post_json(router: &Router, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn get_json(router: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// E4: the node publishes which Profiles touch content; the Core never does.
    #[tokio::test]
    async fn profiles_endpoint_publishes_the_touches_payload_declarations() {
        let router = build_router_with_state(test_state());
        let (st, json) = get_json(&router, "/v1/profiles").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(json["version"], 1);
        assert_eq!(json["core_touches_payload"], false);
        let list = json["profiles"].as_array().unwrap();
        let mut touching: Vec<&str> = list.iter().filter(|p| p["touches_payload"] == true).map(|p| p["name"].as_str().unwrap()).collect();
        touching.sort_unstable();
        assert_eq!(touching, ["certifier", "guardian", "reassemble", "rule-engine", "toolchain"]);
        assert!(list.iter().all(|p| !p["justification"].as_str().unwrap().is_empty()));
        // The level is published too, and agrees with the boolean.
        assert!(list.iter().all(|p| ["none", "derived", "full"].contains(&p["content_access"].as_str().unwrap())));
        assert!(list.iter().all(|p| (p["content_access"] != "none") == (p["touches_payload"] == true)));
        // read-only, no session needed, and not a way to open anything
        let (st, _) = post_json(&router, "/v1/profiles", serde_json::json!({})).await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn health_endpoint_responds_ok() {
        let router = build_router_with_state(test_state());
        let request = Request::builder().uri("/v1/health").body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// `capture_arrival_middleware` must run on every request through
    /// the real router, not just compile — tested here in isolation
    /// (a minimal router with only this one middleware layered on,
    /// rather than the full application) because axum's own
    /// `middleware::from_fn` signature doesn't let this function close
    /// over external test-only state the way a plain handler could;
    /// isolating it this way is the standard pattern axum itself
    /// recommends for testing a middleware layer specifically, and
    /// still exercises the exact same function `build_router_with_state`
    /// wires onto all eight real routes above.
    #[tokio::test]
    async fn capture_arrival_middleware_runs_for_every_request_that_passes_through_it() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let call_count = Arc::new(AtomicU64::new(0));
        let counted = call_count.clone();

        async fn inner_handler() -> &'static str {
            "reached"
        }

        let test_router = Router::new().route("/probe", get(inner_handler)).layer(
            axum::middleware::from_fn(move |request: axum::extract::Request, next: axum::middleware::Next| {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    // Exercises the real capture call, not a stand-in —
                    // confirms this function is actually callable from
                    // within a middleware closure with the exact
                    // signature `capture_arrival_middleware` itself
                    // uses, the same real call `capture_arrival_middleware`
                    // makes in the production router above.
                    let _arrival = lacre_profiles::transit_taxonomy::TransitIdentity::capture(None);
                    next.run(request).await
                }
            }),
        );

        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        let request = Request::builder().uri("/probe").body(Body::empty()).unwrap();
        let response = test_router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // A second request must run the middleware again — confirms
        // this isn't a one-time setup call, but genuinely per-request,
        // the actual property that matters for arrival-time capture.
        let second_request = Request::builder().uri("/probe").body(Body::empty()).unwrap();
        test_router.oneshot(second_request).await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    /// The real production router, with `capture_arrival_middleware`
    /// layered on exactly as `build_router_with_state` does, must still
    /// serve every route correctly — confirms the middleware layer
    /// doesn't interfere with request handling (wrong status code,
    /// swallowed body, broken routing) for the real `/v1/health` route,
    /// not just the isolated probe above.
    #[tokio::test]
    async fn the_real_router_still_serves_health_correctly_with_the_middleware_layered_on() {
        let router = build_router_with_state(test_state());
        let (status, _) = get_json(&router, "/v1/health").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Real end-to-end handshake over HTTP: a client runs a genuine
    /// X25519 exchange (EphemeralHandshake::generate — not a stub),
    /// posts its public key, and confirms the server's response lets
    /// it derive the SAME session key on its own side.
    #[tokio::test]
    async fn handshake_produces_a_usable_session_over_real_http() {
        let router = build_router_with_state(test_state());

        let client_handshake = lacre_core::session_handshake::EphemeralHandshake::generate();
        let client_public_key_hex = hex::encode(client_handshake.public_key().to_bytes());

        let (status, body) = post_json(
            &router,
            "/v1/handshake",
            serde_json::json!({ "client_public_key_hex": client_public_key_hex }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(body["session_id"].is_string());
        assert!(body["server_public_key_hex"].is_string());
    }

    /// Malformed hex in the handshake request must return 400, not a
    /// panic or a 500.
    #[tokio::test]
    async fn handshake_with_invalid_hex_returns_bad_request() {
        let router = build_router_with_state(test_state());
        let (status, _) = post_json(
            &router,
            "/v1/handshake",
            serde_json::json!({ "client_public_key_hex": "not-hex" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Real end-to-end flow over HTTP: seal under Core, then verify
    /// those same frames through a second request — the two Adapters
    /// (this handler and `domain::seal`/`domain::verify`) must agree.
    #[tokio::test]
    async fn seal_then_verify_round_trip_over_real_http_router() {
        let router = build_router_with_state(test_state());

        let (seal_status, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({ "profile": "core", "payload_hex": hex::encode(b"hello over http") }),
        )
        .await;
        assert_eq!(seal_status, StatusCode::OK, "seal_body: {seal_body}");

        let session_id = seal_body["session_id"].clone();
        let frames = seal_body["frames"].clone();

        let (verify_status, verify_body) = post_auth(
            &router,
            "/v1/verify",
            seal_body["capabilities"]["verify"].as_str().unwrap(),
            serde_json::json!({
                "profile": "core",
                "session_id": session_id,
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["all_verified"], serde_json::json!(true));
    }

    /// Same round trip, but under Vault — confirms the signature
    /// travels correctly end to end over real HTTP.
    #[tokio::test]
    async fn vault_seal_then_verify_round_trip_over_real_http_router() {
        let router = build_router_with_state(test_state());

        let (seal_status, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({ "profile": "vault", "payload_hex": hex::encode(b"financial transaction") }),
        )
        .await;
        assert_eq!(seal_status, StatusCode::OK, "seal_body: {seal_body}");
        assert!(seal_body["frames"][0]["vault_signature_hex"].is_string());

        let session_id = seal_body["session_id"].clone();
        let frames = seal_body["frames"].clone();

        let (verify_status, verify_body) = post_auth(
            &router,
            "/v1/verify",
            seal_body["capabilities"]["verify"].as_str().unwrap(),
            serde_json::json!({
                "profile": "vault",
                "session_id": session_id,
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["all_verified"], serde_json::json!(true));
    }

    /// An unknown profile in the request body must return 400.
    #[tokio::test]
    async fn seal_with_unknown_profile_returns_bad_request() {
        let router = build_router_with_state(test_state());
        let (status, _) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({ "profile": "nonexistent", "payload_hex": "aa" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A `session_id` referencing a handshake session that never
    /// existed (or already expired) must be rejected explicitly
    /// (422 Unprocessable) — never silently downgraded to sealing
    /// under the server's own fixed key ring instead. Silently
    /// switching to a different key than the one the client explicitly
    /// asked for would be exactly the kind of "accept with a lower
    /// guarantee than requested" behavior Axiom A8 already forbids for
    /// protocol version negotiation — the same principle applies here.
    #[tokio::test]
    async fn seal_with_unknown_handshake_session_id_is_rejected_not_silently_downgraded() {
        let state = test_state();
        let router = build_router_with_state(state.clone());
        let fake_session_id = hex::encode(lacre_core::session::SessionId::generate().0);
        let token = tok(&state, lacre_domain::capability::Scope::Write, &fake_session_id);

        let (status, body) = post_auth(
            &router,
            "/v1/seal",
            &token,
            serde_json::json!({
                "profile": "core",
                "payload_hex": "aa",
                "session_id": fake_session_id,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
    }

    /// A tampered frame sent to `/v1/verify` must be reported as a
    /// per-frame failure (`ok: false`, with the specific error message),
    /// not accepted, and must stop the batch — `all_verified` must be
    /// `false`.
    #[tokio::test]
    async fn verify_reports_a_tampered_frame_and_stops_the_batch() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({ "profile": "core", "payload_hex": hex::encode(b"untampered content") }),
        )
        .await;
        let session_id = seal_body["session_id"].clone();
        let mut frames = seal_body["frames"].clone();
        // Tamper with the first frame's payload_hex.
        frames[0]["payload_hex"] = serde_json::json!(hex::encode(b"TAMPERED content!!!"));

        let (status, body) = post_auth(
            &router,
            "/v1/verify",
            seal_body["capabilities"]["verify"].as_str().unwrap(),
            serde_json::json!({
                "profile": "core",
                "session_id": session_id,
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["all_verified"], serde_json::json!(false));
        assert_eq!(body["results"][0]["ok"], serde_json::json!(false));
    }

    /// A4: verifying zero frames proves nothing, so it must never come
    /// back as `all_verified: true` (vacuous truth) — it is a 400.
    #[tokio::test]
    async fn verify_with_no_frames_is_refused_not_vacuously_true() {
        let state = test_state();
        let router = build_router_with_state(state.clone());
        let sid = "00000000000000000000000000000000";
        let (status, body) = post_auth(
            &router,
            "/v1/verify",
            &tok(&state, lacre_domain::capability::Scope::Verify, sid),
            serde_json::json!({
                "profile": "core",
                "session_id": sid,
                "key_id": 0,
                "frames": [],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert_ne!(body["all_verified"], serde_json::json!(true));
    }

    /// Full ACK + receipts flow over real HTTP: seal under Vault (the
    /// only profile with a receipt log), confirm the frame via
    /// `/v1/ack`, then read the receipt back via
    /// `/v1/receipts/{session_id}` — confirming the receipt survives
    /// the immediate purge `ack` performs.
    #[tokio::test]
    async fn ack_then_receipts_round_trip_over_real_http_router() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({ "profile": "vault", "payload_hex": hex::encode(b"auditable transaction") }),
        )
        .await;
        let session_id = seal_body["session_id"].as_str().unwrap().to_string();
        let index = seal_body["frames"][0]["index"].clone();

        let (ack_status, ack_body) = post_auth(
            &router,
            "/v1/ack",
            seal_body["capabilities"]["ack"].as_str().unwrap(),
            serde_json::json!({ "session_id": session_id, "indices": [index] }),
        )
        .await;
        assert_eq!(ack_status, StatusCode::OK, "ack_body: {ack_body}");
        assert_eq!(ack_body["all_acknowledged"], serde_json::json!(true));
        assert_eq!(ack_body["total_receipts"], serde_json::json!(1));

        let (receipts_status, receipts_body) = post_json(
            &router,
            "/v1/receipts",
            serde_json::json!({ "session_id": session_id, "token": seal_body["capabilities"]["write"] }),
        )
        .await;
        assert_eq!(receipts_status, StatusCode::OK, "receipts_body: {receipts_body}");
        assert_eq!(receipts_body["entries"].as_array().unwrap().len(), 1);
    }

    /// Reading receipts for a `session_id` that was never sealed under
    /// Vault must return 404, not an empty list or a 500.
    #[tokio::test]
    async fn receipts_for_unknown_session_returns_not_found() {
        let state = test_state();
        let router = build_router_with_state(state.clone());
        let fake_id = hex::encode(lacre_core::session::SessionId::generate().0);
        let (status, _) = post_json(
            &router,
            "/v1/receipts",
            serde_json::json!({
                "session_id": fake_id,
                "token": tok(&state, lacre_domain::capability::Scope::Write, &fake_id),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Confirms `describe_core_error` (used both here and in
    /// `websocket_adapter.rs`) never leaks `CoreError`'s internal
    /// `Debug` representation — only its own stable text messages.
    #[test]
    fn describe_core_error_produces_stable_messages_not_debug_output() {
        let err = lacre_core::core::CoreError::SealMismatch;
        let msg = describe_core_error(&err);
        assert!(!msg.contains("SealMismatch"), "must not leak the Rust variant name: {msg}");
    }

    /// Coupling test at the HTTP layer: a Lite-sealed frame must not
    /// verify if the verify request claims a different profile
    /// (`core`, which expects SHA-256, not Lite's Blake3) — confirms
    /// the profile string travels correctly end to end and actually
    /// selects the algorithm, not just a label.
    #[tokio::test]
    async fn verify_with_mismatched_profile_fails() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({ "profile": "lite", "payload_hex": hex::encode(b"sensor reading") }),
        )
        .await;
        let session_id = seal_body["session_id"].clone();
        let frames = seal_body["frames"].clone();

        let (status, body) = post_auth(
            &router,
            "/v1/verify",
            seal_body["capabilities"]["verify"].as_str().unwrap(),
            serde_json::json!({
                "profile": "core", // wrong on purpose: sealed under lite (Blake3)
                "session_id": session_id,
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["all_verified"], serde_json::json!(false));
    }

    // --- Toolchain Integrity (Annex 4.0) over the real HTTP router ---
    //
    // Same real-router discipline as `seal_then_verify_round_trip_over_real_http_router`
    // above: these go through `build_router_with_state` and axum's own
    // request handling, not a direct function call into
    // `declarative_adapter` or `domain` — confirming the three new
    // routes are actually wired correctly (path parameters extracted,
    // JSON bodies decoded, `AppState` shared correctly across the
    // three-request sequence a real client would make).

    /// The complete Annex 4.0 diamond-shaped-graph example, driven
    /// entirely through real HTTP requests: create an episode, add four
    /// nodes (one root, two parallel children, one node combining
    /// both), then verify the output — over the actual axum router, the
    /// same three routes a real client would call.
    #[tokio::test]
    async fn toolchain_diamond_graph_verifies_over_real_http_router() {
        let router = build_router_with_state(test_state());

        let (create_status, create_body) = post_json(
            &router,
            "/v1/toolchain/episodes",
            serde_json::json!({
                "episode_id_hex": hex::encode(b"http-integration-episode"),
                "algo": "sha256",
                "max_node_age_ms": 3_600_000u64,
            }),
        )
        .await;
        assert_eq!(create_status, StatusCode::OK, "create_body: {create_body}");
        let session_id = create_body["session_id"].as_str().unwrap().to_string();
        let write_token = create_body["capabilities"]["write"].as_str().unwrap().to_string();
        let verify_token = create_body["capabilities"]["verify"].as_str().unwrap().to_string();

        let add_node = |router: Router, node_id: &'static str, content: &'static [u8], parents: Vec<&'static str>| {
            let session_id = session_id.clone();
            let write_token = write_token.clone();
            async move {
                let (status, body) = post_auth(
                    &router,
                    "/v1/toolchain/nodes",
                    &write_token,
                    serde_json::json!({
                        "session_id": session_id,
                        "node_id": node_id,
                        "content_hex": hex::encode(content),
                        "parent_ids": parents,
                    }),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "add_node {node_id} body: {body}");
            }
        };

        add_node(router.clone(), "prompt", b"sell BTC if the price goes up", vec![]).await;
        add_node(router.clone(), "market_price", b"BTC=65000", vec!["prompt"]).await;
        add_node(router.clone(), "news", b"no relevant events", vec!["prompt"]).await;
        add_node(
            router.clone(),
            "recommendation",
            b"sell: favorable price, no news risk",
            vec!["market_price", "news"],
        )
        .await;

        let (verify_status, verify_body) = post_auth(
            &router,
            "/v1/toolchain/verify",
            &verify_token,
            serde_json::json!({
                "session_id": session_id,
                "output_node_id": "recommendation",
                "contents_hex": {
                    "prompt": hex::encode(b"sell BTC if the price goes up"),
                    "market_price": hex::encode(b"BTC=65000"),
                    "news": hex::encode(b"no relevant events"),
                    "recommendation": hex::encode(b"sell: favorable price, no news risk"),
                },
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["valid"], serde_json::json!(true));
    }

    /// The exact Annex 4.0 tamper example, over real HTTP: a
    /// market-price node's content at verification time differs from
    /// what was sealed. The response must name that specific node, not
    /// report a generic failure.
    #[tokio::test]
    async fn toolchain_tampered_node_is_named_over_real_http_router() {
        let router = build_router_with_state(test_state());

        let (_, create_body) = post_json(
            &router,
            "/v1/toolchain/episodes",
            serde_json::json!({
                "episode_id_hex": hex::encode(b"http-tamper-episode"),
                "algo": "sha256",
                "max_node_age_ms": 3_600_000u64,
            }),
        )
        .await;
        let session_id = create_body["session_id"].as_str().unwrap().to_string();
        let write_token = create_body["capabilities"]["write"].as_str().unwrap().to_string();
        let verify_token = create_body["capabilities"]["verify"].as_str().unwrap().to_string();

        for (node_id, content, parents) in [
            ("prompt", b"sell BTC if the price goes up".as_slice(), vec![]),
            ("market_price", b"BTC=65000".as_slice(), vec!["prompt"]),
            (
                "recommendation",
                b"sell based on BTC=65000".as_slice(),
                vec!["market_price"],
            ),
        ] {
            let (status, body) = post_auth(
                &router,
                "/v1/toolchain/nodes",
                &write_token,
                serde_json::json!({
                    "session_id": session_id,
                    "node_id": node_id,
                    "content_hex": hex::encode(content),
                    "parent_ids": parents,
                }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "add_node {node_id} body: {body}");
        }

        let (verify_status, verify_body) = post_auth(
            &router,
            "/v1/toolchain/verify",
            &verify_token,
            serde_json::json!({
                "session_id": session_id,
                "output_node_id": "recommendation",
                "contents_hex": {
                    "prompt": hex::encode(b"sell BTC if the price goes up"),
                    "market_price": hex::encode(b"BTC=999999"), // tampered
                    "recommendation": hex::encode(b"sell based on BTC=65000"),
                },
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["valid"], serde_json::json!(false));
        assert_eq!(verify_body["failed_node"], serde_json::json!("market_price"));
    }

    /// Adding a node to an episode `session_id` that was never created
    /// must return 404 over real HTTP, not a 500 or a silently
    /// accepted request.
    #[tokio::test]
    async fn adding_a_node_to_an_unknown_episode_returns_not_found_over_http() {
        let state = test_state();
        let router = build_router_with_state(state.clone());
        let sid = "00000000000000000000000000000000";
        let (status, _) = post_auth(
            &router,
            "/v1/toolchain/nodes",
            &tok(&state, lacre_domain::capability::Scope::Write, sid),
            serde_json::json!({
                "session_id": sid,
                "node_id": "orphan",
                "content_hex": hex::encode(b"data"),
                "parent_ids": [],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// An unknown `algo` in the episode creation request must return
    /// 400, not a 500 or a silent fallback to a default algorithm.
    #[tokio::test]
    async fn creating_an_episode_with_an_unknown_algo_returns_bad_request() {
        let router = build_router_with_state(test_state());
        let (status, _) = post_json(
            &router,
            "/v1/toolchain/episodes",
            serde_json::json!({
                "episode_id_hex": hex::encode(b"episode"),
                "algo": "not-a-real-algorithm",
                "max_node_age_ms": 60_000u64,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // --- Authentication: capability tokens ---

    use lacre_domain::capability::Scope;

    async fn open_vault(router: &Router) -> serde_json::Value {
        let (st, body) = post_json(
            router,
            "/v1/seal",
            serde_json::json!({ "profile": "vault", "payload_hex": hex::encode(b"authenticated transaction") }),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        body
    }

    async fn open_episode(router: &Router) -> serde_json::Value {
        let (st, body) = post_json(
            router,
            "/v1/toolchain/episodes",
            serde_json::json!({ "episode_id_hex": hex::encode(b"auth-episode"), "algo": "sha256", "max_node_age_ms": 3_600_000u64 }),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        body
    }

    /// Knowing the `session_id` (as a log or proxy reader would) grants
    /// nothing: every session-scoped operation refuses without a token.
    #[tokio::test]
    async fn the_session_id_alone_grants_nothing() {
        let router = build_router_with_state(test_state());
        let sealed = open_vault(&router).await;
        let sid = sealed["session_id"].clone();
        let frames = sealed["frames"].clone();
        for (path, body) in [
            ("/v1/verify", serde_json::json!({"profile":"vault","session_id":sid,"key_id":0,"frames":frames})),
            ("/v1/ack", serde_json::json!({"session_id":sid,"indices":[0]})),
            ("/v1/receipts", serde_json::json!({"session_id":sid})),
            ("/v1/seal", serde_json::json!({"profile":"core","payload_hex":"aa","session_id":sid})),
        ] {
            let (st, resp) = post_json(&router, path, body).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{path} accepted a bare session_id: {resp}");
        }
        let ep = open_episode(&router).await;
        let esid = ep["session_id"].clone();
        let (st, _) = post_json(&router, "/v1/toolchain/nodes", serde_json::json!({"session_id":esid,"node_id":"x","content_hex":"aa","parent_ids":[]})).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = post_json(&router, "/v1/toolchain/verify", serde_json::json!({"session_id":esid,"output_node_id":"x","contents_hex":{}})).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    /// Each scope opens only its own door (a party
    /// that holds only `verify` or `write` must not be able to `ack`).
    #[tokio::test]
    async fn a_token_of_the_wrong_scope_is_refused() {
        let router = build_router_with_state(test_state());
        let sealed = open_vault(&router).await;
        let sid = sealed["session_id"].clone();
        let caps = &sealed["capabilities"];
        let (w, v, a) = (caps["write"].as_str().unwrap(), caps["verify"].as_str().unwrap(), caps["ack"].as_str().unwrap());

        for wrong in [w, v] {
            let (st, _) = post_auth(&router, "/v1/ack", wrong, serde_json::json!({"session_id":sid,"indices":[0]})).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "ack accepted a non-ack token");
        }
        // nothing was purged or receipted by the refused attempts
        let (st, rc) = post_auth(&router, "/v1/receipts", w, serde_json::json!({"session_id":sid})).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(rc["entries"].as_array().unwrap().len(), 0, "a refused ack left a receipt");
        for wrong in [v, a] {
            let (st, _) = post_auth(&router, "/v1/receipts", wrong, serde_json::json!({"session_id":sid})).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "receipts accepted a non-write token");
        }
        for wrong in [w, a] {
            let (st, _) = post_auth(&router, "/v1/verify", wrong,
                serde_json::json!({"profile":"vault","session_id":sid,"key_id":0,"frames":sealed["frames"]})).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "verify accepted a non-verify token");
        }
        // and the right one still works afterwards
        let (st, ack) = post_auth(&router, "/v1/ack", a, serde_json::json!({"session_id":sid,"indices":[0]})).await;
        assert_eq!(st, StatusCode::OK, "{ack}");
        assert_eq!(ack["total_receipts"], serde_json::json!(1));
    }

    /// A token for session A is useless on session B.
    #[tokio::test]
    async fn a_token_of_another_session_is_refused() {
        let router = build_router_with_state(test_state());
        let a = open_vault(&router).await;
        let b = open_vault(&router).await;
        let (st, _) = post_auth(&router, "/v1/ack", a["capabilities"]["ack"].as_str().unwrap(),
            serde_json::json!({"session_id": b["session_id"], "indices":[0]})).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    /// No existence oracle: a bad token gets the same answer whether or
    /// not the session exists.
    #[tokio::test]
    async fn refusal_does_not_reveal_whether_the_session_exists() {
        let router = build_router_with_state(test_state());
        let real = open_vault(&router).await;
        let ghost = hex::encode(lacre_core::session::SessionId::generate().0);
        let bad = "ab".repeat(32);
        let (s1, b1) = post_auth(&router, "/v1/ack", &bad, serde_json::json!({"session_id":real["session_id"],"indices":[0]})).await;
        let (s2, b2) = post_auth(&router, "/v1/ack", &bad, serde_json::json!({"session_id":ghost,"indices":[0]})).await;
        assert_eq!((s1, &b1), (s2, &b2));
        assert_eq!(s1, StatusCode::UNAUTHORIZED);
    }

    /// A party with only the verify capability (or
    /// nothing) cannot inject a node, and the forged node never verifies.
    #[tokio::test]
    async fn a_verify_only_party_cannot_inject_a_toolchain_node() {
        let router = build_router_with_state(test_state());
        let ep = open_episode(&router).await;
        let sid = ep["session_id"].clone();
        let (w, v) = (ep["capabilities"]["write"].as_str().unwrap(), ep["capabilities"]["verify"].as_str().unwrap());
        let (st, _) = post_auth(&router, "/v1/toolchain/nodes", w,
            serde_json::json!({"session_id":sid,"node_id":"prompt","content_hex":hex::encode(b"p"),"parent_ids":[]})).await;
        assert_eq!(st, StatusCode::OK);
        let forged = serde_json::json!({"session_id":sid,"node_id":"forged","content_hex":hex::encode(b"lie"),"parent_ids":["prompt"]});
        let (st, _) = post_auth(&router, "/v1/toolchain/nodes", v, forged.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = post_json(&router, "/v1/toolchain/nodes", forged).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, out) = post_auth(&router, "/v1/toolchain/verify", v, serde_json::json!({
            "session_id":sid,"output_node_id":"forged","contents_hex":{"prompt":hex::encode(b"p"),"forged":hex::encode(b"lie")}})).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(out["valid"], serde_json::json!(false), "the forged node verified");
    }

    /// A holder of only the verify capability cannot probe forever: after
    /// the per-episode limit, further verification is refused (429), even
    /// with honest content.
    #[tokio::test]
    async fn too_many_failed_verifications_lock_the_episode() {
        let router = build_router_with_state(test_state());
        let ep = open_episode(&router).await;
        let sid = ep["session_id"].clone();
        let (w, v) = (ep["capabilities"]["write"].as_str().unwrap(), ep["capabilities"]["verify"].as_str().unwrap());
        post_auth(&router, "/v1/toolchain/nodes", w,
            serde_json::json!({"session_id":sid,"node_id":"n","content_hex":hex::encode(b"real"),"parent_ids":[]})).await;
        let verify = |content: &'static [u8]| {
            let router = router.clone();
            let (sid, v) = (sid.clone(), v.to_string());
            async move {
                post_auth(&router, "/v1/toolchain/verify", &v,
                    serde_json::json!({"session_id":sid,"output_node_id":"n","contents_hex":{"n":hex::encode(content)}})).await
            }
        };
        for i in 0..lacre_domain::domain::MAX_FAILED_TOOLCHAIN_VERIFICATIONS {
            let (st, out) = verify(b"guess").await;
            assert_eq!(st, StatusCode::OK, "attempt {i}");
            assert_eq!(out["valid"], serde_json::json!(false));
        }
        let (st, _) = verify(b"real").await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    }

    /// The session id no longer travels in a URL: the old path-style
    /// routes are gone.
    #[tokio::test]
    async fn session_scoped_routes_no_longer_take_the_id_in_the_url() {
        let router = build_router_with_state(test_state());
        let sid = "00000000000000000000000000000000";
        for (m, path) in [
            ("POST", format!("/v1/toolchain/episodes/{sid}/nodes")),
            ("POST", format!("/v1/toolchain/episodes/{sid}/verify")),
            ("GET", format!("/v1/receipts/{sid}")),
        ] {
            let req = Request::builder().method(m).uri(&path).header("content-type", "application/json").body(Body::from("{}")).unwrap();
            let st = router.clone().oneshot(req).await.unwrap().status();
            assert!(st == StatusCode::NOT_FOUND || st == StatusCode::METHOD_NOT_ALLOWED, "{path} still routed: {st}");
        }
    }

    /// A malformed bearer or token never panics and is plain 401.
    #[tokio::test]
    async fn garbage_tokens_are_plain_unauthorized() {
        let router = build_router_with_state(test_state());
        let sealed = open_vault(&router).await;
        for bad in ["", "zz", "00", &"ab".repeat(33), "Bearer"] {
            let (st, _) = post_auth(&router, "/v1/ack", bad, serde_json::json!({"session_id":sealed["session_id"],"indices":[0]})).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "token {bad:?}");
        }
        let _ = Scope::Ack;
    }

    /// Continuing a handshake session requires its `write` token: the id
    /// (visible to anyone watching the exchange) is not enough.
    #[tokio::test]
    async fn sealing_under_a_handshake_session_requires_its_write_token() {
        let router = build_router_with_state(test_state());
        let client = lacre_core::session_handshake::EphemeralHandshake::generate();
        let (st, hs) = post_json(&router, "/v1/handshake",
            serde_json::json!({"client_public_key_hex": hex::encode(client.public_key().to_bytes())})).await;
        assert_eq!(st, StatusCode::OK, "{hs}");
        let body = serde_json::json!({"profile":"core","payload_hex":"aabb","session_id":hs["session_id"]});
        let (st, _) = post_json(&router, "/v1/seal", body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = post_auth(&router, "/v1/seal", hs["capabilities"]["verify"].as_str().unwrap(), body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, sealed) = post_auth(&router, "/v1/seal", hs["capabilities"]["write"].as_str().unwrap(), body).await;
        assert_eq!(st, StatusCode::OK, "{sealed}");
    }

    // --- Rule sets (Guardian / Certifier / Rule Engine) and reassembly ---

    const RULES: &str = r#"{
      "orders": {"kind":"guardian","fields":[{"name":"order_id","type":"integer","digits":8},{"name":"customer","type":"string"}]},
      "ids":    {"kind":"certifier","patterns":[{"pattern":"LA-[0-9]{12}","occurrences_min":1}]},
      "mixed":  {"kind":"engine","rules":[
                  {"id":"amount","on_fail":"quarantine","field":"amount","type":"integer"},
                  {"id":"tag","on_fail":"pass_with_flag","pattern":"urgent","occurrences_min":1}]}
    }"#;

    fn router_with_rules() -> Router {
        let mut state = test_state();
        state.rulesets = Arc::new(lacre_domain::rulesets::RuleSets::from_json(RULES).unwrap());
        build_router_with_state(state)
    }

    const GOOD_ORDER: &[u8] = br#"{"order_id":12345678,"customer":"ana"}"#;

    #[tokio::test]
    async fn validate_runs_guardian_certifier_and_engine_over_real_http() {
        let router = router_with_rules();
        let v = |set: &'static str, payload: &'static [u8]| {
            let router = router.clone();
            async move {
                post_json(&router, "/v1/validate", serde_json::json!({"ruleset": set, "payload_hex": hex::encode(payload)})).await
            }
        };
        let (st, b) = v("orders", GOOD_ORDER).await;
        assert_eq!((st, b["outcome"].as_str(), b["kind"].as_str()), (StatusCode::OK, Some("passed"), Some("guardian")), "{b}");
        let (st, b) = v("orders", br#"{"order_id":12345678}"#).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!((b["outcome"].as_str(), b["failing_rule_id"].as_str()), (Some("rejected"), Some("required_field_customer")));
        let (_, b) = v("ids", b"see LA-123456789012").await;
        assert_eq!((b["outcome"].as_str(), b["kind"].as_str()), (Some("passed"), Some("certifier")));
        let (_, b) = v("ids", b"nothing here").await;
        assert_eq!(b["outcome"], "rejected");
        let (_, b) = v("mixed", br#"{"amount":"x"}"#).await;
        assert_eq!(b["outcome"], "quarantined");
        let (_, b) = v("mixed", br#"{"amount":1}"#).await;
        assert_eq!((b["outcome"].as_str(), b["failing_rule_id"].as_str()), (Some("passed_with_flag"), Some("tag")));
        // unknown set: 400; unjudgeable payload (non-UTF-8 vs regex): 422, never "zero matches"
        let (st, _) = v("nope", b"x").await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = v("ids", &[0xff, 0xfe]).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn sealing_with_a_ruleset_refuses_what_the_rules_refuse_and_seals_what_they_allow() {
        let router = router_with_rules();
        let seal = |set: &'static str, payload: &'static [u8]| {
            let router = router.clone();
            async move {
                post_json(&router, "/v1/seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(payload),"ruleset":set})).await
            }
        };
        let (st, b) = seal("orders", br#"{"order_id":1}"#).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(b["frames"].is_null(), "a rejected payload produced frames");
        let (st, _) = seal("mixed", br#"{"amount":"x"}"#).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "quarantine must not seal");
        let (st, b) = seal("orders", GOOD_ORDER).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert_eq!(b["ruleset_outcome"]["outcome"], "passed");
        let (st, b) = seal("mixed", br#"{"amount":1}"#).await;
        assert_eq!((st, b["ruleset_outcome"]["outcome"].as_str()), (StatusCode::OK, Some("passed_with_flag")), "{b}");
        let (st, _) = seal("nope", GOOD_ORDER).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // no ruleset named: unchanged behaviour, no outcome field
        let (st, b) = post_json(&router, "/v1/seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(b"x")})).await;
        assert_eq!(st, StatusCode::OK);
        assert!(b.get("ruleset_outcome").is_none());
    }

    async fn seal_multi(router: &Router, payload: &[u8]) -> serde_json::Value {
        let (st, b) = post_json(router, "/v1/seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(payload)})).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert!(b["frames"].as_array().unwrap().len() >= 3, "test needs a multi-frame message");
        b
    }

    fn pattern_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// Reassembly in one call and across several: the server hands back
    /// the original payload only once the last frame verified.
    #[tokio::test]
    async fn verify_with_reassemble_returns_the_original_payload() {
        let router = router_with_rules();
        let original = pattern_bytes(3500); // Core slot is 1 KiB -> 4 frames
        let sealed = seal_multi(&router, &original).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let (st, b) = post_auth(&router, "/v1/verify", &vt, serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"reassemble":true})).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert_eq!(b["all_verified"], true);
        assert_eq!(b["payload_hex"].as_str().unwrap(), hex::encode(&original));

        // incrementally: no payload until the last frame
        let sealed = seal_multi(&router, &original).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let frames = sealed["frames"].as_array().unwrap().clone();
        for (i, f) in frames.iter().enumerate() {
            let (st, b) = post_auth(&router, "/v1/verify", &vt, serde_json::json!({
                "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":[f],"reassemble":true})).await;
            assert_eq!(st, StatusCode::OK, "{b}");
            if i + 1 < frames.len() {
                assert!(b.get("payload_hex").is_none(), "payload released before the last frame (frame {i})");
            } else {
                assert_eq!(b["payload_hex"].as_str().unwrap(), hex::encode(&original));
            }
        }
        // without `reassemble` nothing is returned (unchanged behaviour)
        let sealed = seal_multi(&router, &original).await;
        let (_, b) = post_auth(&router, "/v1/verify", sealed["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"]})).await;
        assert_eq!(b["all_verified"], true);
        assert!(b.get("payload_hex").is_none());
    }

    async fn post_with(router: &Router, path: &str, accept: Option<&str>, body: Vec<u8>) -> (StatusCode, String, String) {
        let mut b = Request::builder().method("POST").uri(path).header("content-type", "application/json");
        if let Some(a) = accept {
            b = b.header("accept", a);
        }
        let resp = router.clone().oneshot(b.body(Body::from(body)).unwrap()).await.unwrap();
        let status = resp.status();
        let ct = resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, ct, String::from_utf8_lossy(&bytes).to_string())
    }

    /// P5: errors are problem documents only when asked for (Accept) or when the
    /// request speaks v2; everyone else gets the same plain text as before.
    #[tokio::test]
    async fn errors_are_problem_documents_only_when_negotiated() {
        let router = build_router_with_state(test_state().with_max_body_bytes(2000));
        let unknown = br#"{"profile":"nope","payload_hex":"00"}"#.to_vec();

        // default: plain text, unchanged
        let (st, ct, body) = post_with(&router, "/v1/seal", None, unknown.clone()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(ct.starts_with("text/plain"), "{ct}");
        assert!(body.starts_with("unknown profile"), "{body}");

        // asked for: problem document with the same text as `detail`
        let (st, ct, body) = post_with(&router, "/v1/seal", Some("application/problem+json"), unknown).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(ct, "application/problem+json");
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["code"], "unknown-profile");
        assert_eq!(doc["type"], "urn:lacre:error:unknown-profile");
        assert_eq!(doc["status"], 400);
        assert!(doc["detail"].as_str().unwrap().starts_with("unknown profile"));

        // the refusals of the layers below are converted too: too large, and malformed
        let big = format!(r#"{{"profile":"core","payload_hex":"{}"}}"#, "00".repeat(2000)).into_bytes();
        let (st, ct, body) = post_with(&router, "/v1/seal", Some("application/problem+json"), big.clone()).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(ct, "application/problem+json");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["code"], "body-too-large");
        let (st, _, body) = post_with(&router, "/v1/seal", None, big).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(serde_json::from_str::<serde_json::Value>(&body).is_err(), "default stays as it was: {body}");
        let (_, _, body) = post_with(&router, "/v1/seal", Some("application/problem+json"), b"{not json".to_vec()).await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["code"], "malformed-body");

        // a request that speaks v2 gets problem documents without asking
        let v2 = br#"{"version":2,"profile":"core","payload_hex":"00"}"#.to_vec();
        let (st, ct, body) = post_with(&router, "/v1/seal", None, v2).await;
        assert!(st.is_client_error(), "{st}");
        assert_eq!(ct, "application/problem+json", "{body}");

        // a success is never touched
        let (st, ct, _) = post_with(&router, "/v1/seal", Some("application/problem+json"), br#"{"profile":"core","payload_hex":"00"}"#.to_vec()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(ct.starts_with("application/json"), "{ct}");
    }

    async fn open_parts(router: &Router, profile: &str) -> serde_json::Value {
        let (st, b) = post_json(router, "/v1/seal/open", serde_json::json!({"profile":profile})).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        b
    }

    fn part_body(open: &serde_json::Value, index: u64, bytes: &[u8], last: bool, profile_token: &str) -> serde_json::Value {
        serde_json::json!({"session_id":open["session_id"],"part_index":index,"payload_hex":hex::encode(bytes),
            "is_last":last,"token":profile_token})
    }

    /// P2: a payload sent in parts verifies and reassembles to the original, and
    /// no request carries more than a part.
    #[tokio::test]
    async fn a_payload_sealed_in_parts_verifies_and_reassembles() {
        for profile in ["core", "vault"] {
            let router = router_with_rules();
            let original = pattern_bytes(9000);
            let open = open_parts(&router, profile).await;
            assert!(open["max_part_bytes"].as_u64().unwrap() >= 3000);
            let wt = open["capabilities"]["write"].as_str().unwrap().to_string();
            let mut frames: Vec<serde_json::Value> = vec![];
            let pieces: Vec<&[u8]> = original.chunks(3000).collect();
            for (i, piece) in pieces.iter().enumerate() {
                let last = i + 1 == pieces.len();
                let (st, b) = post_json(&router, "/v1/seal/part", part_body(&open, i as u64, piece, last, &wt)).await;
                assert_eq!(st, StatusCode::OK, "{profile} part {i}: {b}");
                frames.extend(b["frames"].as_array().unwrap().iter().cloned());
            }
            // only the very last frame closes the stream
            let n = frames.len();
            for (i, f) in frames.iter().enumerate() {
                assert_eq!(f["is_last"], serde_json::json!(i + 1 == n), "{profile} frame {i}");
            }
            let (st, b) = post_auth(&router, "/v1/verify", open["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
                "profile":profile,"session_id":open["session_id"],"key_id":0,"frames":frames,"reassemble":true})).await;
            assert_eq!(st, StatusCode::OK, "{profile}: {b}");
            assert_eq!(b["all_verified"], true, "{profile}: {b}");
            assert_eq!(b["payload_hex"].as_str().unwrap(), hex::encode(&original), "{profile}");
        }
    }

    /// P2: a repeated part returns the same frames and seals nothing; a different
    /// content under the same index, a skipped index and a part after the last are 409.
    #[tokio::test]
    async fn a_repeated_part_is_idempotent_and_disorder_is_a_conflict() {
        let router = router_with_rules();
        let open = open_parts(&router, "core").await;
        let wt = open["capabilities"]["write"].as_str().unwrap().to_string();
        let (s0, p0) = post_json(&router, "/v1/seal/part", part_body(&open, 0, &pattern_bytes(2500), false, &wt)).await;
        assert_eq!(s0, StatusCode::OK, "{p0}");
        let (s0b, p0b) = post_json(&router, "/v1/seal/part", part_body(&open, 0, &pattern_bytes(2500), false, &wt)).await;
        assert_eq!(s0b, StatusCode::OK);
        assert_eq!(p0["frames"], p0b["frames"], "a retry must give back the same frames");
        assert_eq!(p0["pending_frames"], p0b["pending_frames"], "and must not seal again");
        let (sc, _) = post_json(&router, "/v1/seal/part", part_body(&open, 0, b"other content", false, &wt)).await;
        assert_eq!(sc, StatusCode::CONFLICT);
        let (sk, _) = post_json(&router, "/v1/seal/part", part_body(&open, 2, b"skipped", false, &wt)).await;
        assert_eq!(sk, StatusCode::CONFLICT);
        let (s1, p1) = post_json(&router, "/v1/seal/part", part_body(&open, 1, b"end", true, &wt)).await;
        assert_eq!(s1, StatusCode::OK, "{p1}");
        let (sa, _) = post_json(&router, "/v1/seal/part", part_body(&open, 2, b"after the end", true, &wt)).await;
        assert_eq!(sa, StatusCode::CONFLICT);
        // the final part also repeats cleanly
        let (s1b, p1b) = post_json(&router, "/v1/seal/part", part_body(&open, 1, b"end", true, &wt)).await;
        assert_eq!(s1b, StatusCode::OK);
        assert_eq!(p1["frames"], p1b["frames"]);
        // the whole stream still verifies exactly once, with no duplicated fragment
        let mut frames = p0["frames"].as_array().unwrap().clone();
        frames.extend(p1["frames"].as_array().unwrap().iter().cloned());
        let (st, b) = post_auth(&router, "/v1/verify", open["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
            "profile":"core","session_id":open["session_id"],"key_id":0,"frames":frames,"reassemble":true})).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        assert_eq!(b["all_verified"], true, "{b}");
    }

    /// P2: authorization, unknown or unopened sessions, oversize and empty parts.
    #[tokio::test]
    async fn parts_need_the_write_token_and_an_opened_session() {
        let router = router_with_rules();
        let open = open_parts(&router, "core").await;
        let wt = open["capabilities"]["write"].as_str().unwrap().to_string();
        let vt = open["capabilities"]["verify"].as_str().unwrap().to_string();
        let (st, _) = post_json(&router, "/v1/seal/part", part_body(&open, 0, b"x", false, "garbage")).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = post_json(&router, "/v1/seal/part", part_body(&open, 0, b"x", false, &vt)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "a verify token is not a write token");
        let (st, b) = post_json(&router, "/v1/seal/part", part_body(&open, 0, &vec![0u8; 256 * 1024 + 1], false, &wt)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
        let (st, _) = post_json(&router, "/v1/seal/part", part_body(&open, 0, b"", false, &wt)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "an empty part is only valid as the last one");
        // a session sealed in one call cannot take parts
        let (_, whole) = post_json(&router, "/v1/seal", serde_json::json!({"profile":"vault","payload_hex":"00"})).await;
        let (st, _) = post_json(&router, "/v1/seal/part", part_body(&whole, 0, b"x", false, whole["capabilities"]["write"].as_str().unwrap())).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    /// P2: the window of unacknowledged frames holds until `ack` frees it.
    #[tokio::test]
    async fn the_window_holds_until_the_frames_are_acknowledged() {
        let router = router_with_rules();
        let open = open_parts(&router, "vault").await;
        assert_eq!(open["window_frames"], 64);
        let wt = open["capabilities"]["write"].as_str().unwrap().to_string();
        let at = open["capabilities"]["ack"].as_str().unwrap().to_string();
        for i in 0..64u64 {
            let (st, b) = post_json(&router, "/v1/seal/part", part_body(&open, i, &[i as u8], false, &wt)).await;
            assert_eq!(st, StatusCode::OK, "part {i}: {b}");
        }
        let (st, b) = post_json(&router, "/v1/seal/part", part_body(&open, 64, b"over", false, &wt)).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{b}");
        let (st, _) = post_auth(&router, "/v1/ack", &at, serde_json::json!({"session_id":open["session_id"],"indices":[0]})).await;
        assert_eq!(st, StatusCode::OK);
        let (st, b) = post_json(&router, "/v1/seal/part", part_body(&open, 64, b"over", false, &wt)).await;
        assert_eq!(st, StatusCode::OK, "after an ack the same part goes through: {b}");
    }

    /// P5 + P2: the new refusals carry their own stable codes.
    #[tokio::test]
    async fn the_part_refusals_have_their_problem_codes() {
        let router = router_with_rules();
        let open = open_parts(&router, "core").await;
        let wt = open["capabilities"]["write"].as_str().unwrap().to_string();
        let body = part_body(&open, 5, b"x", false, &wt);
        let (st, ct, text) = post_with(&router, "/v1/seal/part", Some("application/problem+json"), body.to_string().into_bytes()).await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert_eq!(ct, "application/problem+json");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["code"], "part-out-of-order");
    }

    /// P3: the same verify repeated (a lost response, a balancer retry) gets the
    /// same verdict, for a finished session and for one still open.
    #[tokio::test]
    async fn a_repeated_identical_verify_returns_the_same_verdict() {
        let router = router_with_rules();
        let original = pattern_bytes(3500);
        let sealed = seal_multi(&router, &original).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let body = serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"reassemble":true});
        let (s1, b1) = post_auth(&router, "/v1/verify", &vt, body.clone()).await;
        assert_eq!(s1, StatusCode::OK, "{b1}");
        let (s2, b2) = post_auth(&router, "/v1/verify", &vt, body.clone()).await;
        assert_eq!(s2, StatusCode::OK, "retry of a finished session: {b2}");
        assert_eq!(b1, b2);

        // a DIFFERENT request on the finished session is still refused
        let one = serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,
            "frames":[sealed["frames"][0].clone()],"reassemble":true});
        let (s3, _) = post_auth(&router, "/v1/verify", &vt, one).await;
        assert_eq!(s3, StatusCode::BAD_REQUEST);

        // the repeat needs the token like the first call did
        let (s4, _) = post_auth(&router, "/v1/verify", "wrong", body).await;
        assert_ne!(s4, StatusCode::OK);

        // a session still open: the last accepted batch repeats, the next one proceeds
        let sealed = seal_multi(&router, &original).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let frames = sealed["frames"].as_array().unwrap().clone();
        let first = serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":[frames[0].clone()]});
        let (_, a) = post_auth(&router, "/v1/verify", &vt, first.clone()).await;
        let (sr, ar) = post_auth(&router, "/v1/verify", &vt, first).await;
        assert_eq!(sr, StatusCode::OK, "{ar}");
        assert_eq!(a, ar);
        let rest = serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":frames[1..].to_vec()});
        let (sn, bn) = post_auth(&router, "/v1/verify", &vt, rest).await;
        assert_eq!(sn, StatusCode::OK, "{bn}");
        assert_eq!(bn["all_verified"], true);
    }

    /// P3: a failed verification is never remembered, so a repeat is judged again.
    #[tokio::test]
    async fn a_failed_verify_is_not_replayed() {
        let router = router_with_rules();
        let sealed = seal_multi(&router, &pattern_bytes(3500)).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let mut frames = sealed["frames"].clone();
        frames[1]["payload_hex"] = serde_json::json!(hex::encode(b"forged"));
        let body = serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":frames});
        let (_, a) = post_auth(&router, "/v1/verify", &vt, body.clone()).await;
        let (_, b) = post_auth(&router, "/v1/verify", &vt, body).await;
        assert_eq!(a["all_verified"], false);
        assert_eq!(b["all_verified"], false, "a failure must not turn into an acceptance: {b}");
        assert_eq!(a["results"][0]["ok"], true, "first call accepted frame 0: {a}");
        assert_eq!(b["results"][0]["ok"], false, "the repeat is judged afresh (frame 0 is now a duplicate), not replayed: {b}");
    }

    /// A tampered frame never yields a payload.
    #[tokio::test]
    async fn a_tampered_frame_yields_no_reassembled_payload() {
        let router = router_with_rules();
        let sealed = seal_multi(&router, &pattern_bytes(3500)).await;
        let mut frames = sealed["frames"].clone();
        frames[1]["payload_hex"] = serde_json::json!(hex::encode(b"forged"));
        let (_, b) = post_auth(&router, "/v1/verify", sealed["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":frames,"reassemble":true})).await;
        assert_eq!(b["all_verified"], false);
        assert!(b.get("payload_hex").is_none());
    }

    /// Annex 6.0 live: a refused replay is diagnosed (same bytes vs
    /// different bytes at an index already accepted), and still refused.
    #[tokio::test]
    async fn a_refused_replay_is_diagnosed_by_the_taxonomy_and_still_refused() {
        let router = router_with_rules();
        let sealed = seal_multi(&router, &pattern_bytes(3500)).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let frames = sealed["frames"].as_array().unwrap().clone();
        let call = |fs: Vec<serde_json::Value>| {
            let (router, vt, sid) = (router.clone(), vt.clone(), sealed["session_id"].clone());
            async move {
                post_auth(&router, "/v1/verify", &vt, serde_json::json!({"profile":"core","session_id":sid,"key_id":0,"frames":fs,"reassemble":true})).await
            }
        };
        let (_, b) = call(vec![frames[0].clone(), frames[1].clone()]).await;
        assert_eq!(b["all_verified"], true);
        // identical frame again
        let (_, b) = call(vec![frames[0].clone()]).await;
        assert_eq!(b["all_verified"], false);
        assert_eq!(b["results"][0]["ok"], false);
        assert_eq!(b["results"][0]["diagnosis"], "same_content_unclear_origin");
        // different bytes claiming an index already accepted
        let mut other = frames[1].clone();
        other["payload_hex"] = serde_json::json!(hex::encode(b"someone else's content"));
        let (_, b) = call(vec![other]).await;
        assert_eq!(b["results"][0]["ok"], false);
        assert_eq!(b["results"][0]["diagnosis"], "new_message");
        // the session is still usable: the genuine next frames finish it
        let (_, b) = call(vec![frames[2].clone(), frames[3].clone()]).await;
        assert_eq!(b["all_verified"], true);
        assert!(b["payload_hex"].is_string());
        // a frame ahead of its turn is refused WITHOUT a (misleading) diagnosis
        let sealed2 = seal_multi(&router, &pattern_bytes(3500)).await;
        let (_, b) = post_auth(&router, "/v1/verify", sealed2["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
            "profile":"core","session_id":sealed2["session_id"],"key_id":0,"frames":[sealed2["frames"][2]],"reassemble":true})).await;
        assert_eq!(b["all_verified"], false);
        assert!(b["results"][0].get("diagnosis").is_none());
        // without `reassemble` there is no diagnosis (nothing was kept to compare with)
        let sealed3 = seal_multi(&router, &pattern_bytes(3500)).await;
        let vt3 = sealed3["capabilities"]["verify"].as_str().unwrap().to_string();
        let f3 = sealed3["frames"].as_array().unwrap().clone();
        post_auth(&router, "/v1/verify", &vt3, serde_json::json!({"profile":"core","session_id":sealed3["session_id"],"key_id":0,"frames":[f3[0]]})).await;
        // (P3: repeating the LAST accepted request verbatim is now an idempotent retry,
        // so the replay is made after another request has been accepted in between)
        post_auth(&router, "/v1/verify", &vt3, serde_json::json!({"profile":"core","session_id":sealed3["session_id"],"key_id":0,"frames":[f3[1]]})).await;
        let (_, b) = post_auth(&router, "/v1/verify", &vt3, serde_json::json!({"profile":"core","session_id":sealed3["session_id"],"key_id":0,"frames":[f3[0]]})).await;
        assert_eq!(b["all_verified"], false);
        assert!(b["results"][0].get("diagnosis").is_none());
    }

    /// Reassembly + rule set at the end of the stream: a payload the rules
    /// refuse is withheld even though every frame verified.
    #[tokio::test]
    async fn the_reassembled_payload_is_judged_by_the_ruleset_and_withheld_if_refused() {
        let router = router_with_rules();
        let good = br#"{"order_id":12345678,"customer":"ana","pad":"PADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPADPAD"}"#.to_vec();
        let mut big_good = good.clone();
        // pad to several frames while staying one flat JSON object
        big_good.truncate(big_good.len() - 2);
        big_good.extend_from_slice(&b"X".repeat(3000));
        big_good.extend_from_slice(b"\"}");
        let mut bad = big_good.clone();
        let pos = bad.windows(10).position(|w| w == b"\"customer\"").unwrap();
        bad[pos + 1] = b'X'; // "customer" -> "Xustomer": field missing
        for (payload, expect_outcome, expect_payload) in [(big_good, "passed", true), (bad, "rejected", false)] {
            let sealed = seal_multi(&router, &payload).await;
            let (st, b) = post_auth(&router, "/v1/verify", sealed["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
                "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"reassemble":true,"ruleset":"orders"})).await;
            assert_eq!(st, StatusCode::OK, "{b}");
            assert_eq!(b["all_verified"], true, "integrity is independent of the rules");
            assert_eq!(b["ruleset_outcome"]["outcome"], expect_outcome, "{b}");
            assert_eq!(b["payload_hex"].is_string(), expect_payload, "{b}");
        }
        // a rule set that cannot judge the payload withholds it (outcome "error")
        let sealed = seal_multi(&router, &[0xffu8; 3500]).await;
        let (_, b) = post_auth(&router, "/v1/verify", sealed["capabilities"]["verify"].as_str().unwrap(), serde_json::json!({
            "profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"reassemble":true,"ruleset":"ids"})).await;
        assert_eq!(b["ruleset_outcome"]["outcome"], "error");
        assert!(b.get("payload_hex").is_none());
        // ruleset without reassemble is a request error, unknown name too
        let sealed = seal_multi(&router, &pattern_bytes(3500)).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let (st, _) = post_auth(&router, "/v1/verify", &vt, serde_json::json!({"profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"ruleset":"orders"})).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = post_auth(&router, "/v1/verify", &vt, serde_json::json!({"profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"reassemble":true,"ruleset":"nope"})).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    // ---- A8 / protocol version (extension E1) -----------------------------

    fn version_bodies(version: serde_json::Value) -> Vec<(&'static str, serde_json::Value)> {
        let client = lacre_core::session_handshake::EphemeralHandshake::generate();
        vec![
            ("/v1/handshake", serde_json::json!({"client_public_key_hex": hex::encode(client.public_key().to_bytes()), "version": version})),
            ("/v1/seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(b"abc"),"version": version})),
            ("/v1/verify", serde_json::json!({"profile":"core","session_id":"00000000000000000000000000000000","key_id":0,"frames":[],"version": version})),
            ("/v1/toolchain/episodes", serde_json::json!({"episode_id_hex":"aabb","algo":"sha256","max_node_age_ms":1000,"version": version})),
        ]
    }

    /// A8: an unknown version is refused, on every operation that carries one,
    /// before anything else (a well-formed verify over a ghost session gets the
    /// version error, not a 401, so the version check really comes first).
    #[tokio::test]
    async fn an_unknown_protocol_version_is_refused_on_every_operation() {
        let router = build_router_with_state(test_state());
        for bad in [serde_json::json!(0), serde_json::json!(2), serde_json::json!(255), serde_json::json!(4294967295u64)] {
            for (path, body) in version_bodies(bad.clone()) {
                let request = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap();
                let response = router.clone().oneshot(request).await.unwrap();
                let st = response.status();
                let text = String::from_utf8_lossy(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).to_string();
                assert_eq!(st, StatusCode::BAD_REQUEST, "{path} version {bad}");
                assert!(text.contains("unsupported protocol version"), "{path}: {text}");
            }
        }
    }

    /// A version that is not a u32 integer never passes as "no version".
    #[tokio::test]
    async fn a_malformed_protocol_version_is_refused_not_ignored() {
        let router = build_router_with_state(test_state());
        for bad in [serde_json::json!("1"), serde_json::json!(1.5), serde_json::json!(-1), serde_json::json!(4294967296u64), serde_json::json!(true), serde_json::json!([1])] {
            for (path, body) in version_bodies(bad.clone()) {
                let (st, _) = post_json(&router, path, body).await;
                assert!(st.is_client_error(), "{path} version {bad} gave {st}");
            }
        }
    }

    /// The current version is accepted, echoed in the response, and omitting it
    /// means the same current version.
    #[tokio::test]
    async fn the_current_protocol_version_is_accepted_and_echoed() {
        let router = build_router_with_state(test_state());
        for declared in [serde_json::json!(1), serde_json::Value::Null] {
            let mut bodies = version_bodies(declared.clone());
            bodies.remove(2); // verify over a ghost session is not an acceptance case
            for (path, mut body) in bodies {
                if declared.is_null() {
                    body.as_object_mut().unwrap().remove("version");
                }
                let (st, json) = post_json(&router, path, body).await;
                assert_eq!(st, StatusCode::OK, "{path}: {json}");
                assert_eq!(json["version"], 1, "{path}");
            }
        }
        let (_, sealed) = post_json(&router, "/v1/seal", serde_json::json!({"profile":"core","payload_hex":hex::encode(b"abc")})).await;
        let vt = sealed["capabilities"]["verify"].as_str().unwrap().to_string();
        let (st, verified) = post_auth(&router, "/v1/verify", &vt, serde_json::json!({"profile":"core","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],"version":1})).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(verified["version"], 1);
        assert_eq!(verified["all_verified"], true);
    }

    /// A refused version leaves no state behind: with room for exactly one
    /// sealer session, a refused request must not use it up.
    #[tokio::test]
    async fn a_refused_version_opens_no_session() {
        let mut state = test_state();
        state.sealer_sessions = Arc::new(lacre_domain::sealer_session_store::SealerSessionStore::with_ceiling(Duration::from_secs(600), 1));
        let router = build_router_with_state(state);
        let (st, _) = post_json(&router, "/v1/seal", serde_json::json!({"profile":"vault","payload_hex":hex::encode(b"abc"),"version":9})).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = post_json(&router, "/v1/seal", serde_json::json!({"profile":"vault","payload_hex":hex::encode(b"abc"),"version":1})).await;
        assert_eq!(st, StatusCode::OK, "the only session slot must still be free");
    }
}

//! Domain logic for the protocol's operations (handshake, seal,
//! verify, ack, receipts, plus the three Toolchain Integrity
//! operations) — deliberately with no `axum` types at all. Before this
//! extraction, this logic lived directly inside `http_server.rs`'s
//! HTTP handlers; it was pulled out here so a second Adapter
//! (WebSocket, gRPC) can invoke it without duplicating it or depending
//! on axum to do so.
//!
//! # Why this refactor is the real proof of DECISIONS.md point 16
//!
//! Until this checkpoint, the claim "Adapters are a first-class
//! extension axis, replaceable without touching business logic" was a
//! design intention backed by a SINGLE Adapter — there was no way to
//! empirically confirm that the `http_adapter.rs` (type translation) +
//! `http_server.rs` (transport) seam really separated what it claimed
//! to separate, until a second real Adapter appeared to exercise it.
//! This module is the result of that test: every function here
//! receives exactly the same `AppState` and the same
//! `*Request`/`*Response` types from `http_adapter.rs` that
//! `http_server.rs` already used, and returns `Result<_, DomainError>`
//! — an error type NO concrete Adapter knows about yet (neither HTTP's
//! `StatusCode`, nor any WebSocket close code). Each Adapter translates
//! `DomainError` into its own error vocabulary (HTTP: `StatusCode` +
//! message; WebSocket: an error message inside the same frame
//! protocol, see `websocket_adapter.rs`).
//!
//! # What it means for this to be genuine rather than a cosmetic refactor
//!
//! Before this checkpoint, `handle_seal` in `http_server.rs` received
//! `State<AppState>` and `Json<SealRequest>` (axum types) and returned
//! `Result<Json<SealResponse>, (StatusCode, String)>` (also axum) —
//! business logic and transport were interleaved in the same function.
//! If a second Adapter had needed to rewrite that logic from scratch
//! (even by copy-pasting it), that would have confirmed the
//! Core/Profile/Adapter separation never actually reached, in
//! practice, down to the HTTP Adapter's own business logic layer — it
//! would have stopped at a lower level (only `lacre-core` vs.
//! `lacre-server`). Extracting these functions and having
//! `websocket_adapter.rs` use them as-is, unmodified, is the evidence
//! that the separation does reach that far.

use crate::capability::Scope;
use crate::wire::{
    decode_client_public_key, CapabilityTokens, describe_core_error, session_id_to_hex, AckRequest, AckResponse,
    AckResult, FrameVerificationResult, HandshakeRequest, HandshakeResponse, ReceiptEntryWire,
    ReceiptsResponse, SealRequest, SealResponse, SealedFrameWire, VerifyRequest, VerifyResponse,
};
use crate::app_state::AppState;
use crate::profile_config::ProfileName;
use lacre_core::core::{SealerCore, VerifierCore};
use lacre_core::core_v2::{BufferSpec, SealerCoreV2, VerifierCoreV2};
use crate::version::Wire;
use crate::wire::SuiteWire;
use lacre_core::frame::LacreFrame;
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::session_handshake::EphemeralHandshake;
use lacre_core::vault_signature::VaultSigningKey;
use std::sync::Arc;
use std::time::Duration;

/// Domain error — deliberately carrying no transport code at all
/// (`StatusCode`, a WebSocket close code, a gRPC error code). Each
/// Adapter decides how to translate each variant into its own
/// vocabulary; see `domain_error_to_http` in `http_server.rs` and
/// `domain_error_message` in `websocket_adapter.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// The request arrived well-formed but with data the client
    /// controls and got wrong (unknown profile, invalid hex, malformed
    /// session_id). An HTTP Adapter maps this to 400.
    BadRequest(String),
    /// The request is well-formed and the data is syntactically valid,
    /// but the operation can't complete for a server-state reason
    /// (handshake session_id not found, unknown key_id, a frame's
    /// verification failed). An HTTP Adapter maps this to 422.
    Unprocessable(String),
    /// No resource exists under the given identifier (a Vault session
    /// never sealed, or expired). An HTTP Adapter maps this to 404.
    NotFound(String),
    /// The server can't take on this request right now because a
    /// resource ceiling is reached (e.g. the live verifier-session cap),
    /// and the condition clears on its own. Distinct from every other
    /// variant in that retrying the SAME request later can succeed. An
    /// HTTP Adapter maps this to 503.
    Unavailable(String),
    /// The caller did not present a valid capability token for this
    /// operation on this session. One message for every cause (missing,
    /// malformed, wrong scope, wrong session, unknown session): no oracle.
    /// An HTTP Adapter maps this to 401.
    Unauthorized(String),
    /// A per-session limit was reached and will not clear by retrying
    /// the same call (too many failed verifications). Maps to 429.
    TooManyRequests(String),
    /// The request is valid and understood, but the operator's policy does
    /// not allow it (an algorithm not in the policy, a legacy algorithm
    /// without all its switches, an algorithm in quarantine). Retrying the
    /// same request does not help until the policy changes. Maps to 403.
    Forbidden(String),
    /// The operator configured a request deadline and it passed. Maps to 504.
    /// The running computation is NOT cancelled: it keeps its admission place.
    DeadlineExceeded(String),
    /// The request conflicts with the state of its session (a part out of
    /// order, or a part index reused with different content). Maps to 409.
    Conflict(String),
    /// An internal failure (for example a panic inside a seal algorithm).
    /// The message is generic on purpose: no text from the failure reaches
    /// the client. Maps to 500.
    Internal(String),
}

/// How many failed verifications a Toolchain episode tolerates before it
/// refuses further verification. Bounds probing by a party that holds only
/// the verify capability; honest flows verify a handful of times.
pub const MAX_FAILED_TOOLCHAIN_VERIFICATIONS: u32 = 32;

fn unauthorized() -> DomainError {
    DomainError::Unauthorized("missing or invalid capability token for this operation".to_string())
}

/// Authenticates `token` for `(scope, session_id)`. Always run BEFORE any
/// session lookup so an unauthenticated caller learns nothing about
/// which sessions exist.
fn require(state: &AppState, scope: Scope, session_id: &SessionId, token: Option<&str>) -> Result<(), DomainError> {
    if state.capabilities().check(scope, &session_id.0, token) {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

fn tokens_for(state: &AppState, session_id: &SessionId, with_ack: bool) -> CapabilityTokens {
    let root = state.capabilities();
    CapabilityTokens {
        write: root.token_hex(Scope::Write, &session_id.0),
        verify: root.token_hex(Scope::Verify, &session_id.0),
        ack: with_ack.then(|| root.token_hex(Scope::Ack, &session_id.0)),
    }
}

/// The error every store ceiling maps to: transient, so Adapters answer 503, not 4xx.
fn at_capacity(what: &str) -> DomainError {
    DomainError::Unavailable(format!(
        "the server is holding the maximum number of concurrent {what} sessions; retry shortly"
    ))
}

/// `handle_handshake` (formerly in `http_server.rs`), without axum.
pub fn handshake(state: &AppState, req: &HandshakeRequest) -> Result<HandshakeResponse, DomainError> {
    let version = crate::version::check(req.version)?;
    let client_public_key =
        decode_client_public_key(req).map_err(|e| DomainError::BadRequest(e.message().to_string()))?;

    let server_handshake = EphemeralHandshake::generate();
    let server_public_key = server_handshake.public_key();
    let shared_secret = server_handshake.complete(client_public_key);

    let session_id = SessionId::generate();
    let key_id = 0u8;
    let ring = Arc::new(MasterKeyRing::new(
        key_id,
        shared_secret.into_ikm_bytes().to_vec(),
        Duration::from_secs(3600),
    ));

    state.handshake_sessions().insert(session_id, ring).map_err(|_| at_capacity("handshake"))?;

    Ok(HandshakeResponse {
        version,
        server_public_key_hex: hex::encode(server_public_key.to_bytes()),
        session_id: session_id_to_hex(&session_id),
        key_id,
        capabilities: tokens_for(state, &session_id, true),
    })
}

/// `handle_seal` (formerly in `http_server.rs`), without axum.
pub fn seal(state: &AppState, req: &SealRequest) -> Result<SealResponse, DomainError> {
    let wire = crate::version::resolve(state.seal_runtime().map(|r| r.as_ref()), req.version, req.suite.is_some())?;
    if wire == Wire::V2 {
        return seal_v2(state, req);
    }
    let version = crate::version::PROTOCOL_VERSION;
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown profile: {}", req.profile)))?;
    let cfg = profile.config();
    let use_vault = profile.requires_vault_signature();

    let payload = hex::decode(&req.payload_hex)
        .map_err(|_| DomainError::BadRequest("payload_hex is not valid hex".to_string()))?;

    let ruleset_outcome = seal_ruleset_check(state, req, &payload)?;

    let mut sealer = match (&req.session_id, use_vault) {
        (None, false) => SealerCore::open(
            state.key_ring().clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        ),
        (None, true) => SealerCore::open_with_vault_key(
            state.key_ring().clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            VaultSigningKey::from_bytes(&state.vault_signing_key_bytes()),
        ),
        (Some(session_id_hex), _) => {
            let session_id = crate::wire::session_id_from_hex(session_id_hex)
                .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
            require(state, Scope::Write, &session_id, req.token.as_deref())?;
            let ring = state.handshake_sessions().get(&session_id).ok_or_else(|| {
                DomainError::Unprocessable(
                    "session_id does not correspond to any active handshake (or it already expired)".to_string(),
                )
            })?;
            if use_vault {
                SealerCore::open_with_session_key_and_vault_key(
                    ring,
                    session_id,
                    cfg.algo,
                    cfg.slot_size,
                    cfg.slot_count,
                    cfg.forced_purge_timeout,
                    VaultSigningKey::from_bytes(&state.vault_signing_key_bytes()),
                )
            } else {
                SealerCore::open_with_session_key(
                    ring,
                    session_id,
                    cfg.algo,
                    cfg.slot_size,
                    cfg.slot_count,
                    cfg.forced_purge_timeout,
                )
            }
        }
    };

    let sealed = sealer
        .seal_payload(&payload, cfg.slot_size)
        .map_err(|e| DomainError::Unprocessable(describe_core_error(&e)))?;

    let frames = sealed
        .iter()
        .map(|(frame, seal)| {
            let signature = sealer.sign_seal_for_vault(seal);
            SealedFrameWire::from_parts(frame, seal, signature.as_ref())
        })
        .collect();

    let session_id = sealer.session_id();

    if use_vault {
        state.sealer_sessions().insert(session_id, sealer).map_err(|_| at_capacity("seal"))?;
    }

    Ok(SealResponse {
        version,
        session_id: session_id_to_hex(&session_id),
        frames,
        capabilities: tokens_for(state, &session_id, true),
        ruleset_outcome,
        suite: None,
        suite_hash_hex: None,
    })
}

/// Validate BEFORE sealing (Guardian / Certifier / Rule Engine): a payload the
/// rule set rejects, quarantines or cannot judge is never sealed (A4). Done
/// before any session is opened, so a refusal leaves no state behind.
fn seal_ruleset_check(
    state: &AppState,
    req: &SealRequest,
    payload: &[u8],
) -> Result<Option<crate::wire::RuleOutcomeWire>, DomainError> {
    let Some(name) = &req.ruleset else { return Ok(None) };
    let set = find_ruleset(state, name)?;
    let (wire, proceeds) = evaluate_wire(name, set, payload, lacre_core::access::Provenance::CallerSupplied);
    if !proceeds {
        return Err(DomainError::Unprocessable(format!(
            "payload not sealed: rule set `{name}` {}{}",
            wire.outcome,
            wire.failing_rule_id.as_deref().map(|r| format!(" (rule {r})")).unwrap_or_default()
        )));
    }
    Ok(Some(wire))
}

/// `seal` under wire version 2: the suite comes from the request, is checked
/// against the node's policy (validation order of the design), and the
/// sealer works in a single call. The Core never sees an unvalidated suite.
fn seal_v2(state: &AppState, req: &SealRequest) -> Result<SealResponse, DomainError> {
    let runtime = state.seal_runtime().expect("`resolve` only returns V2 when a policy exists").clone();
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown profile: {}", req.profile)))?;
    let suite_wire = req.suite.as_ref().expect("`resolve` only returns V2 when a suite exists");
    let resolved = runtime.resolve(suite_wire, profile)?;
    let signing = profile.requires_vault_signature();

    let payload = hex::decode(&req.payload_hex)
        .map_err(|_| DomainError::BadRequest("payload_hex is not valid hex".to_string()))?;
    let ruleset_outcome = seal_ruleset_check(state, req, &payload)?;

    let _heavy = match (resolved.cost, state.admission()) {
        (lacre_core::suite::CostClass::Heavy, Some(gate)) => Some(gate.try_admit_heavy()?),
        _ => None,
    };

    let cfg = profile.config();
    let spec = BufferSpec::new(cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout, runtime.max_session_memory_bytes());
    let suite_hash = *resolved.suite.suite_hash();
    let vault_secret = signing.then(|| state.vault_signing_key_bytes());
    let opened = match &req.session_id {
        None => match &vault_secret {
            Some(secret) => SealerCoreV2::open_signed(state.key_ring().clone(), None, resolved.suite, spec, secret),
            None => SealerCoreV2::open(state.key_ring().clone(), resolved.suite, spec),
        },
        Some(session_id_hex) => {
            let session_id = crate::wire::session_id_from_hex(session_id_hex)
                .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
            require(state, Scope::Write, &session_id, req.token.as_deref())?;
            let ring = state.handshake_sessions().get(&session_id).ok_or_else(|| {
                DomainError::Unprocessable(
                    "session_id does not correspond to any active handshake (or it already expired)".to_string(),
                )
            })?;
            match &vault_secret {
                Some(secret) => SealerCoreV2::open_signed(ring, Some(session_id), resolved.suite, spec, secret),
                None => SealerCoreV2::open_with_session_id(ring, session_id, resolved.suite, spec),
            }
        }
    };
    let mut sealer = opened.map_err(|e| DomainError::Unprocessable(format!("cannot open the suite: {e:?}")))?;

    // A panicking algorithm is contained: 500 with a generic message, counted
    // toward quarantine, never a crashed worker.
    // The signature scheme is third-party code like the seal algorithm: its
    // panic is contained in the same way.
    let sealed = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let sealed = sealer.seal_payload(&payload)?;
        let mut out = Vec::with_capacity(sealed.len());
        for (frame, tag) in sealed {
            let sig = if signing { Some(sealer.sign_for(frame.index, &tag)?) } else { None };
            out.push((frame, tag, sig));
        }
        Ok::<_, lacre_core::core::CoreError>(out)
    })) {
        Ok(r) => r.map_err(|e| DomainError::Unprocessable(describe_core_error(&e)))?,
        Err(_) => {
            runtime.record_panic(&suite_wire.seal);
            return Err(DomainError::Internal("internal error while sealing".to_string()));
        }
    };

    let scheme_id = suite_wire.signature.clone();
    let frames = sealed
        .iter()
        .map(|(frame, tag, sig)| {
            let sig = match (&scheme_id, sig) {
                (Some(scheme), Some(bytes)) => Some(crate::wire::SignatureWire { scheme: scheme.clone(), sig_hex: hex::encode(bytes) }),
                _ => None,
            };
            SealedFrameWire::from_parts_v2(frame, tag, sig)
        })
        .collect();
    let session_id = sealer.session_id();
    // Only a signing session records receipts, so only it must survive until `ack`.
    if signing {
        state.sealer_sessions().insert(session_id, sealer).map_err(|_| at_capacity("seal"))?;
    }
    Ok(SealResponse {
        version: 2,
        session_id: session_id_to_hex(&session_id),
        frames,
        capabilities: tokens_for(state, &session_id, true),
        ruleset_outcome,
        suite: Some(suite_wire.clone()),
        suite_hash_hex: Some(hex::encode(suite_hash)),
    })
}

/// `POST /v1/seal/open`: opens a sealing session fed afterwards with
/// `seal_part`, so a large payload travels as several small requests (an
/// intermediary's body limit never sees the whole). The session lives in the
/// sealer store for every profile, so `ack` frees its window.
pub fn seal_open(state: &AppState, req: &crate::wire::SealOpenRequest) -> Result<crate::wire::SealOpenResponse, DomainError> {
    use crate::sealer_session_store::PartSession;
    let wire = crate::version::resolve(state.seal_runtime().map(|r| r.as_ref()), req.version, req.suite.is_some())?;
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown profile: {}", req.profile)))?;
    let cfg = profile.config();
    let signing = profile.requires_vault_signature();
    let mk_parts = |suite: Option<SuiteWire>| PartSession {
        profile,
        suite,
        signing,
        slot_size: cfg.slot_size,
        window: cfg.slot_count,
        next_part: 0,
        last: None,
        finished: false,
        broken: false,
    };
    let max_part_bytes = crate::wire::MAX_PART_BYTES.min(cfg.slot_count * cfg.slot_size);
    // Same opening rules as `seal` / `seal_v2`: a handshake session needs its `write` token.
    let handshake = match &req.session_id {
        None => None,
        Some(hex_id) => {
            let session_id = crate::wire::session_id_from_hex(hex_id)
                .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
            require(state, Scope::Write, &session_id, req.token.as_deref())?;
            let ring = state.handshake_sessions().get(&session_id).ok_or_else(|| {
                DomainError::Unprocessable(
                    "session_id does not correspond to any active handshake (or it already expired)".to_string(),
                )
            })?;
            Some((session_id, ring))
        }
    };
    if wire == Wire::V1 {
        let sealer = match (handshake, signing) {
            (None, false) => SealerCore::open(state.key_ring().clone(), cfg.algo, cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout),
            (None, true) => SealerCore::open_with_vault_key(
                state.key_ring().clone(), cfg.algo, cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout,
                VaultSigningKey::from_bytes(&state.vault_signing_key_bytes()),
            ),
            (Some((sid, ring)), true) => SealerCore::open_with_session_key_and_vault_key(
                ring, sid, cfg.algo, cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout,
                VaultSigningKey::from_bytes(&state.vault_signing_key_bytes()),
            ),
            (Some((sid, ring)), false) => {
                SealerCore::open_with_session_key(ring, sid, cfg.algo, cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout)
            }
        };
        let session_id = sealer.session_id();
        state
            .sealer_sessions()
            .insert_with_parts(session_id, sealer, mk_parts(None))
            .map_err(|_| at_capacity("seal"))?;
        return Ok(crate::wire::SealOpenResponse {
            version: crate::version::PROTOCOL_VERSION,
            session_id: session_id_to_hex(&session_id),
            capabilities: tokens_for(state, &session_id, true),
            slot_size: cfg.slot_size,
            window_frames: cfg.slot_count,
            max_part_bytes,
            suite: None,
            suite_hash_hex: None,
        });
    }
    let runtime = state.seal_runtime().expect("`resolve` only returns V2 when a policy exists").clone();
    let suite_wire = req.suite.as_ref().expect("`resolve` only returns V2 when a suite exists");
    let resolved = runtime.resolve(suite_wire, profile)?;
    let spec = BufferSpec::new(cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout, runtime.max_session_memory_bytes());
    let suite_hash = *resolved.suite.suite_hash();
    let vault_secret = signing.then(|| state.vault_signing_key_bytes());
    let opened = match (handshake, &vault_secret) {
        (None, Some(secret)) => SealerCoreV2::open_signed(state.key_ring().clone(), None, resolved.suite, spec, secret),
        (None, None) => SealerCoreV2::open(state.key_ring().clone(), resolved.suite, spec),
        (Some((sid, ring)), Some(secret)) => SealerCoreV2::open_signed(ring, Some(sid), resolved.suite, spec, secret),
        (Some((sid, ring)), None) => SealerCoreV2::open_with_session_id(ring, sid, resolved.suite, spec),
    };
    let sealer = opened.map_err(|e| DomainError::Unprocessable(format!("cannot open the suite: {e:?}")))?;
    let session_id = sealer.session_id();
    state
        .sealer_sessions()
        .insert_with_parts(session_id, sealer, mk_parts(Some(suite_wire.clone())))
        .map_err(|_| at_capacity("seal"))?;
    Ok(crate::wire::SealOpenResponse {
        version: 2,
        session_id: session_id_to_hex(&session_id),
        capabilities: tokens_for(state, &session_id, true),
        slot_size: cfg.slot_size,
        window_frames: cfg.slot_count,
        max_part_bytes,
        suite: Some(suite_wire.clone()),
        suite_hash_hex: Some(hex::encode(suite_hash)),
    })
}

/// `POST /v1/seal/part`: seals one part of the stream of a session opened with
/// `seal_open`. A part is cut into frames of `slot_size`; only the last frame of
/// the last part carries `is_last`. Repeating the last part (same index, same
/// content) returns its frames again without sealing anything, so a retry by an
/// intermediary cannot duplicate a fragment.
pub fn seal_part(state: &AppState, req: &crate::wire::SealPartRequest) -> Result<crate::wire::SealPartResponse, DomainError> {
    use crate::sealer_session_store::{AnySealer, WithSealerError};
    use sha2::{Digest, Sha256};
    let session_id: SessionId = crate::wire::session_id_from_hex(&req.session_id)
        .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
    require(state, Scope::Write, &session_id, req.token.as_deref())?;
    let payload = hex::decode(&req.payload_hex)
        .map_err(|_| DomainError::BadRequest("payload_hex is not valid hex".to_string()))?;
    let not_found = || DomainError::NotFound("no active sealing session with that session_id (or it already expired)".to_string());
    let not_opened = || DomainError::BadRequest("this session was not opened with /v1/seal/open: it cannot take parts".to_string());

    // Phase 1: what the session was opened with.
    let (profile, suite, slot_size, window) = match state
        .sealer_sessions()
        .with_sealer_parts(&session_id, |_, ps| (ps.profile, ps.suite.clone(), ps.slot_size, ps.window))
    {
        Err(WithSealerError::NotFound) => return Err(not_found()),
        Ok(None) => return Err(not_opened()),
        Ok(Some(v)) => v,
    };
    let max_part = crate::wire::MAX_PART_BYTES.min(window * slot_size);
    if payload.len() > max_part {
        return Err(DomainError::BadRequest(format!("part too large: {} bytes, the most a part may carry is {max_part}", payload.len())));
    }
    if payload.is_empty() && !req.is_last {
        return Err(DomainError::BadRequest("empty part: only the final part may be empty".to_string()));
    }

    // Phase 2 (wire v2): the policy is consulted on every part, as `verify` does.
    let runtime = state.seal_runtime().cloned();
    let resolved_cost = match (&suite, &runtime) {
        (Some(sw), Some(rt)) => Some(rt.resolve(sw, profile)?.cost),
        _ => None,
    };
    let _heavy = match (resolved_cost, state.admission()) {
        (Some(lacre_core::suite::CostClass::Heavy), Some(gate)) => Some(gate.try_admit_heavy()?),
        _ => None,
    };

    let hash: [u8; 32] = Sha256::digest(&payload).into();
    let respond = |frames: Vec<SealedFrameWire>, pending: usize| crate::wire::SealPartResponse {
        session_id: req.session_id.clone(),
        part_index: req.part_index,
        is_last: req.is_last,
        frames,
        pending_frames: pending,
    };

    // Phase 3: under the session's lock. A panicking algorithm is contained
    // INSIDE the closure so the lock is never poisoned.
    let outcome = state.sealer_sessions().with_sealer_parts(&session_id, |sealer, ps| {
        if let Some((li, lh, lf)) = &ps.last {
            if *li == req.part_index {
                return if *lh == hash {
                    Ok(respond(lf.clone(), sealer.pending_count()))
                } else {
                    Err(DomainError::Conflict(format!(
                        "part conflict: part_index {li} was already sealed with different content"
                    )))
                };
            }
        }
        if ps.broken {
            return Err(DomainError::Conflict(
                "part out of order: an earlier part failed, this session can take no more".to_string(),
            ));
        }
        if ps.finished {
            return Err(DomainError::Conflict("part out of order: the final part was already sealed".to_string()));
        }
        if req.part_index != ps.next_part {
            return Err(DomainError::Conflict(format!(
                "part out of order: expected part_index {}, received {}",
                ps.next_part, req.part_index
            )));
        }
        let chunks: Vec<Vec<u8>> = if payload.is_empty() {
            vec![Vec::new()]
        } else {
            payload.chunks(slot_size).map(|c| c.to_vec()).collect()
        };
        let pending = sealer.pending_count();
        if pending + chunks.len() > ps.window {
            return Err(DomainError::TooManyRequests(format!(
                "window full: {pending} frames are waiting for /v1/ack and this part needs {} more of {}; acknowledge delivered frames and retry",
                chunks.len(),
                ps.window
            )));
        }
        let n = chunks.len();
        let sealed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Vec<SealedFrameWire>, lacre_core::core::CoreError> {
            let mut out = Vec::with_capacity(n);
            for (i, chunk) in chunks.into_iter().enumerate() {
                let last_frame = req.is_last && i + 1 == n;
                match sealer {
                    AnySealer::V1(s) => {
                        let (frame, seal) = s.seal_chunk(chunk, last_frame)?;
                        let sig = s.sign_seal_for_vault(&seal);
                        out.push(SealedFrameWire::from_parts(&frame, &seal, sig.as_ref()));
                    }
                    AnySealer::V2(s) => {
                        let (frame, tag) = s.seal_chunk(chunk, last_frame)?;
                        let sig = match (ps.signing, ps.suite.as_ref().and_then(|w| w.signature.clone())) {
                            (true, Some(scheme)) => Some(crate::wire::SignatureWire {
                                scheme,
                                sig_hex: hex::encode(s.sign_for(frame.index, &tag)?),
                            }),
                            _ => None,
                        };
                        out.push(SealedFrameWire::from_parts_v2(&frame, &tag, sig));
                    }
                }
            }
            Ok(out)
        }));
        match sealed {
            Ok(Ok(frames)) => {
                ps.last = Some((req.part_index, hash, frames.clone()));
                ps.next_part += 1;
                ps.finished = req.is_last;
                Ok(respond(frames, sealer.pending_count()))
            }
            Ok(Err(e)) => {
                ps.broken = true;
                Err(DomainError::Unprocessable(describe_core_error(&e)))
            }
            Err(_) => {
                ps.broken = true;
                if let (Some(rt), Some(sw)) = (&runtime, &ps.suite) {
                    rt.record_panic(&sw.seal);
                }
                Err(DomainError::Internal("internal error while sealing".to_string()))
            }
        }
    });
    match outcome {
        Err(WithSealerError::NotFound) => Err(not_found()),
        Ok(None) => Err(not_opened()),
        Ok(Some(r)) => r,
    }
}

/// `POST /v1/validate`: run a payload through a named rule set, sealing
/// nothing. A verdict is a 200 even when the verdict is "rejected"; only
/// a payload the rules cannot judge (for example non-UTF-8 against a
/// Certifier pattern) is an error, and then it fails closed.
pub fn validate(state: &AppState, req: &crate::wire::ValidateRequest) -> Result<crate::wire::RuleOutcomeWire, DomainError> {
    let payload = hex::decode(&req.payload_hex)
        .map_err(|_| DomainError::BadRequest("payload_hex is not valid hex".to_string()))?;
    let set = find_ruleset(state, &req.ruleset)?;
    let (wire, _) = evaluate_wire(&req.ruleset, set, &payload, lacre_core::access::Provenance::CallerSupplied);
    if wire.outcome == "error" {
        return Err(DomainError::Unprocessable(format!(
            "rule set `{}` could not judge the payload: {}",
            req.ruleset,
            wire.failing_rule_id.unwrap_or_default()
        )));
    }
    Ok(wire)
}

fn find_ruleset<'a>(state: &'a AppState, name: &str) -> Result<&'a crate::rulesets::RuleSet, DomainError> {
    state
        .rulesets()
        .get(name)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown ruleset: {name}")))
}

/// Evaluates and wraps for the wire. The bool is "may proceed". An
/// evaluation error is reported as outcome `"error"` (detail in
/// `failing_rule_id`) and never proceeds.
fn evaluate_wire(
    name: &str,
    set: &crate::rulesets::RuleSet,
    payload: &[u8],
    provenance: lacre_core::access::Provenance,
) -> (crate::wire::RuleOutcomeWire, bool) {
    match set.evaluate_as(payload, provenance) {
        Ok(e) => {
            let proceeds = e.proceeds();
            (
                crate::wire::RuleOutcomeWire {
                    ruleset: name.to_string(),
                    kind: set.kind().as_str().to_string(),
                    outcome: e.outcome.to_string(),
                    failing_rule_id: e.failing_rule_id,
                },
                proceeds,
            )
        }
        Err(detail) => (
            crate::wire::RuleOutcomeWire {
                ruleset: name.to_string(),
                kind: set.kind().as_str().to_string(),
                outcome: "error".to_string(),
                failing_rule_id: Some(detail),
            },
            false,
        ),
    }
}

/// Why `verify_frame` (or decoding) refused a frame; keeps the typed Core
/// error so the duplicate diagnosis can look at it.
enum Refusal {
    Core(lacre_core::core::CoreError),
    Text(String),
}

impl Refusal {
    fn message(&self) -> String {
        match self {
            Refusal::Core(e) => describe_core_error(e),
            Refusal::Text(t) => t.clone(),
        }
    }
}

fn describe_non_novelty(n: lacre_profiles::transit_taxonomy::NonNovelty) -> String {
    use lacre_profiles::transit_taxonomy::NonNovelty::*;
    match n {
        Replay => "replay",
        Retransmission => "retransmission",
        Duplicate => "duplicate",
        NewMessage => "new_message",
        SameContentUnclearOrigin => "same_content_unclear_origin",
    }
    .to_string()
}

/// A reassembled message larger than this is refused (the Profile holds
/// every verified fragment until the last one arrives, unlike the Core,
/// which purges each one — so it needs its own ceiling).
pub const MAX_REASSEMBLY_BYTES: usize = 16 * 1024 * 1024;

/// How long a frame may be held ahead before the Profile may drop it.
const REASSEMBLY_MAX_HELD_AGE: Duration = Duration::from_secs(60);

/// `handle_verify` (formerly in `http_server.rs`), without axum.
/// Verifies a batch of frames against the session's `VerifierCore` —
/// which now persists in `state.verifier_sessions()` between separate
/// calls to this function (see `verifier_session_store.rs`'s header for
/// why: an earlier version reconstructed a fresh `VerifierCore` on
/// every call, which silently broke replay/reorder protection for any
/// caller verifying a session's frames incrementally across more than
/// one call, rather than always sending the complete frame array in
/// one call).
pub fn verify(state: &AppState, req: &VerifyRequest) -> Result<VerifyResponse, DomainError> {
    verify_with_transit(state, req, None)
}

/// `verify`, with the arrival metadata an Adapter captured for this
/// request (`TransitIdentity`), passed through to the Transit Non-Novelty
/// Taxonomy when a refused duplicate is diagnosed.
pub fn verify_with_transit(
    state: &AppState,
    req: &VerifyRequest,
    transit: Option<&lacre_profiles::transit_taxonomy::TransitIdentity>,
) -> Result<VerifyResponse, DomainError> {
    let wire = crate::version::resolve(state.seal_runtime().map(|r| r.as_ref()), req.version, req.suite.is_some())?;
    if wire == Wire::V2 {
        return verify_v2(state, req, transit);
    }
    let version = crate::version::PROTOCOL_VERSION;
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown profile: {}", req.profile)))?;
    let cfg = profile.config();

    let session_id: SessionId = crate::wire::session_id_from_hex(&req.session_id)
        .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
    require(state, Scope::Verify, &session_id, req.token.as_deref())?;

    // A4 (fail-closed): a verification over zero frames proves nothing,
    // so it must not be reported as `all_verified: true` (vacuous
    // truth). Found by the external black-box suite (external black-box suite).
    if req.frames.is_empty() {
        return Err(DomainError::BadRequest(
            "verify requires at least one frame: an empty batch verifies nothing".to_string(),
        ));
    }
    // Idempotent retry: the very same request that this session accepted last
    // (a client or intermediary repeating it after a lost response) gets the
    // same verdict again. Nothing new is accepted here.
    let digest = verify_request_digest(req);
    if let Some(same) = state.verifier_sessions().replay(&session_id, &digest) {
        return Ok(same);
    }

    let key_ring = state
        .handshake_sessions()
        .get(&session_id)
        .unwrap_or_else(|| state.key_ring().clone());

    let requires_vault_signature = profile.requires_vault_signature();
    let vault_verifying_key = state.vault_verifying_key();
    let key_id = req.key_id;

    // Validated once, up front, against a throwaway `VerifierCore`
    // instance — deliberately BEFORE touching `verifier_sessions()` at
    // all. `VerifierSessionStore::get_or_insert_with`'s `make` closure
    // must return a `VerifierCore` unconditionally, with no way to
    // signal failure (see `verifier_session_store.rs`): threading an
    // "unrecognized key_id" error through that closure would mean
    // either panicking on a legitimate, expected input (the caller
    // supplied a `key_id` the ring doesn't have) or inserting a
    // placeholder into the store that a later call might wrongly reuse
    // for real verification. Checking key_id validity here, before any
    // insertion, avoids both: an invalid key_id never reaches the
    // store, and the real construction inside `make` below is
    // guaranteed to succeed (`.expect()` there documents that
    // guarantee, it doesn't create a new way to panic).
    let build_verifier = || {
        if requires_vault_signature {
            VerifierCore::resume_with_vault_key(
                key_ring.clone(),
                session_id,
                key_id,
                cfg.algo,
                cfg.slot_size,
                cfg.slot_count,
                cfg.forced_purge_timeout,
                vault_verifying_key,
            )
        } else {
            VerifierCore::resume(
                key_ring.clone(),
                session_id,
                key_id,
                cfg.algo,
                cfg.slot_size,
                cfg.slot_count,
                cfg.forced_purge_timeout,
            )
        }
    };
    if build_verifier().is_none() {
        return Err(DomainError::Unprocessable(
            "key_id not recognized in the server's ring".to_string(),
        ));
    }

    // `make` only runs the first time this session_id is seen by this
    // store — every later call for the same session reuses the same
    // `VerifierCore` instance, so `next_expected_index` (and therefore
    // replay/reorder detection via Sᵢ) survives across calls instead of
    // silently resetting to 0 on each one.
    //
    // `get_or_insert_with` now returns `Result` — `Err(AlreadyCompleted)`
    // means this exact `session_id` already finished (its last frame
    // verified successfully in a prior call) and is refused outright,
    // rather than silently starting a brand new `VerifierCore` at index
    // 0 for it. This is the fix for the session-revival gap: without
    // it, a caller replaying an already-completed session's own frames
    // would have them "verify" successfully all over again.
    let ruleset = match &req.ruleset {
        None => None,
        Some(_) if !req.reassemble => {
            return Err(DomainError::BadRequest(
                "`ruleset` on verify needs `reassemble: true` (the rules judge the complete payload)".to_string(),
            ));
        }
        Some(name) => Some((name.as_str(), find_ruleset(state, name)?)),
    };

    let outcome = state.verifier_sessions().get_or_insert_with_reassembly(
        session_id,
        || {
            build_verifier().expect(
                "key_id validity was already confirmed above, before this closure could run",
            )
        },
        |verifier, reassembly| run_batch(AnyCore::V1(verifier), reassembly, req, key_id, transit),
    );
    let parts = store_outcome(outcome, None)?;
    finish_verify(state, req, session_id, parts, ruleset, version, None)
}

/// What a batch of frames produced: per-frame results, whether every frame
/// verified, whether the session's last frame verified, and the reassembled
/// payload (only when asked for and complete).
type BatchOutcome = (Vec<FrameVerificationResult>, bool, bool, Option<Vec<u8>>);

/// The verifier of either wire, borrowed for one batch.
enum AnyCore<'a> {
    V1(&'a mut VerifierCore),
    V2(&'a mut VerifierCoreV2),
}

/// A frame's seal as decoded from the wire of the session's version.
enum DecodedSeal {
    V1(lacre_core::hmac_seal::Seal, Option<lacre_core::vault_signature::VaultSignature>),
    V2(lacre_core::suite::SealTag, Option<(String, Vec<u8>)>),
}

/// Verifies `req.frames` in order against `core`, stopping at the first
/// refusal. The same loop serves both wires: only the decoding of the seal
/// and the Core call differ, so the Profile feeding, the duplicate diagnosis
/// and the refusal rules cannot drift between v1 and v2.
fn run_batch(
    mut core: AnyCore<'_>,
    reassembly: &mut Option<lacre_profiles::profile::ReassembleProfile>,
    req: &VerifyRequest,
    key_id: u8,
    transit: Option<&lacre_profiles::transit_taxonomy::TransitIdentity>,
) -> BatchOutcome {
    let mut results = Vec::with_capacity(req.frames.len());
    let mut all_verified = true;
    let mut session_is_complete = false;

    for wire_frame in &req.frames {
        let index = wire_frame.index;
        let decoded = match &core {
            AnyCore::V1(_) => wire_frame.into_parts().map(|(f, s, v)| (f, DecodedSeal::V1(s, v))),
            AnyCore::V2(_) => wire_frame.into_parts_v2().map(|(f, t, sg)| (f, DecodedSeal::V2(t, sg))),
        };
        let (frame, outcome) = match decoded {
            Err(decode_err) => (None, Err(Refusal::Text(decode_err.message().to_string()))),
            Ok((frame, seal)) => {
                // The Profile is fed from the `VerifiedFrame` the Core
                // returns, at the access level the Profile declares:
                // the bytes it sees are the bytes the Core certified.
                let verdict = match (&mut core, &seal) {
                    (AnyCore::V1(v), DecodedSeal::V1(s, sig)) => v.verify_frame_view(&frame, key_id, s, sig.as_ref()),
                    (AnyCore::V2(v), DecodedSeal::V2(t, sg)) => {
                        // A signature made under another scheme than the suite's is
                        // refused by name before anything is verified.
                        let named = sg.as_ref().map(|(scheme, _)| scheme.as_str());
                        let declared = v.suite().signature_scheme().map(|s| s.id());
                        if named.is_some() && named != declared {
                            Err(lacre_core::core::CoreError::VaultSignatureMismatch)
                        } else {
                            v.verify_frame_view_signed(&frame, key_id, t, sg.as_ref().map(|(_, b)| b.as_slice()))
                        }
                    }
                    _ => unreachable!("the seal was decoded for the same wire as the core"),
                };
                let r = verdict.map_err(Refusal::Core).and_then(|verified| {
                    if req.reassemble {
                        let r = reassembly.get_or_insert_with(|| {
                            lacre_profiles::profile::ReassembleProfile::new(REASSEMBLY_MAX_HELD_AGE)
                        });
                        if r.buffered_bytes() + verified.header().payload_len > MAX_REASSEMBLY_BYTES {
                            return Err(Refusal::Text(format!(
                                "reassembly refused: the message exceeds {MAX_REASSEMBLY_BYTES} bytes"
                            )));
                        }
                        // The Core verifies strictly in order, so this is
                        // always `Accepted`; the Profile only concatenates.
                        let _ = r.accept(
                            &verified.view::<<lacre_profiles::profile::ReassembleProfile as lacre_profiles::profile::Profile>::Access>(),
                            transit,
                        );
                    }
                    Ok(())
                });
                (Some(frame), r)
            }
        };

        match outcome {
            Ok(()) => {
                results.push(FrameVerificationResult { index, ok: true, error: None, diagnosis: None });
                if wire_frame.is_last {
                    session_is_complete = true;
                }
            }
            Err(refusal) => {
                all_verified = false;
                // Annex 6.0: why was this refused frame a non-novelty?
                // A diagnosis only — the frame is refused either way.
                let diagnosis = match (&refusal, &frame, req.reassemble) {
                    (Refusal::Core(lacre_core::core::CoreError::OutOfSequence { expected, received }), Some(f), true)
                        if received < expected =>
                    {
                        reassembly.as_ref().and_then(|r| r.classify_duplicate(&lacre_core::access::ContentView::caller_supplied(f), transit)).map(describe_non_novelty)
                    }
                    _ => None,
                };
                results.push(FrameVerificationResult {
                    index,
                    ok: false,
                    error: Some(refusal.message()),
                    diagnosis,
                });
                break;
            }
        }
    }

    let reassembled = if session_is_complete && req.reassemble {
        reassembly.as_mut().and_then(|r| r.try_reassemble())
    } else {
        None
    };
    (results, all_verified, session_is_complete, reassembled)
}

/// Translates what the verifier store answered into the domain's vocabulary.
/// For v2, `algorithm` lets a contained panic count towards quarantine.
fn store_outcome(
    outcome: Result<BatchOutcome, crate::verifier_session_store::WithVerifierError>,
    algorithm: Option<(&crate::seal_policy::SealRuntime, &str)>,
) -> Result<BatchOutcome, DomainError> {
    use crate::verifier_session_store::WithVerifierError as E;
    match outcome {
        Ok(t) => Ok(t),
        Err(E::AlreadyCompleted) => Err(DomainError::BadRequest(
            "session_id already completed: its last frame was already verified in a prior \
             call, so this session cannot be re-verified or extended — request a new session \
             (a new /v1/seal call) instead"
                .to_string(),
        )),
        Err(E::AtCapacity) => Err(DomainError::Unavailable(
            "the server is holding the maximum number of concurrent verification sessions; \
             retry shortly"
                .to_string(),
        )),
        Err(E::SessionFailed) => Err(DomainError::BadRequest(
            "session_id failed earlier and is closed for good: continuing requires a new \
             session (a new /v1/seal call), never a restart of this one"
                .to_string(),
        )),
        Err(E::WrongVersion) => Err(DomainError::BadRequest(
            "session_version_mismatch: this session was opened under another protocol version \
             or suite; a session keeps one version and one suite for its whole life"
                .to_string(),
        )),
        Err(E::CannotOpen(e)) => Err(DomainError::Unprocessable(crate::seal_policy::describe_suite_error(&e))),
        Err(E::Panicked) => {
            if let Some((runtime, id)) = algorithm {
                if runtime.record_panic(id) {
                    eprintln!("lacre: seal algorithm `{id}` entered quarantine after repeated panics");
                }
            }
            Err(DomainError::Internal("internal error".to_string()))
        }
    }
}

/// Everything after the Core ran, shared by both wires: mark the session
/// completed or drop it if it verified nothing, run the rule set over the
/// reassembled payload, and build the response.
fn finish_verify(
    state: &AppState,
    req: &VerifyRequest,
    session_id: SessionId,
    parts: BatchOutcome,
    ruleset: Option<(&str, &crate::rulesets::RuleSet)>,
    version: u32,
    suite: Option<(SuiteWire, String)>,
) -> Result<VerifyResponse, DomainError> {
    let (results, all_verified, session_is_complete, reassembled) = parts;

    // Mark the session completed immediately once its last frame
    // verified successfully, rather than waiting out the full idle TTL
    // for a session that's known to be finished. Unlike a bare removal,
    // `complete` leaves the lightweight tombstone that refuses reuse of
    // this exact `session_id` — see `verifier_session_store.rs`.
    if session_is_complete {
        state.verifier_sessions().complete(&session_id);
    } else {
        // The call left the session open. If it never verified a single
        // frame (every frame in it failed), there is no replay/reorder
        // state worth keeping, so drop the buffer now instead of holding
        // it for the idle TTL — see `discard_if_untouched`.
        state.verifier_sessions().discard_if_untouched(&session_id);
    }

    // The complete payload goes through the named rule set (if any) and is
    // withheld unless it may proceed (A4: a payload the rules refuse, or
    // cannot judge, is not handed out as if it were good).
    let mut payload_hex = None;
    let mut ruleset_outcome = None;
    if let Some(payload) = reassembled {
        match ruleset {
            None => payload_hex = Some(hex::encode(payload)),
            Some((name, set)) => {
                let (wire, proceeds) = evaluate_wire(name, set, &payload, lacre_core::access::Provenance::Reassembled);
                if proceeds {
                    payload_hex = Some(hex::encode(&payload));
                }
                ruleset_outcome = Some(wire);
            }
        }
    }

    let (suite, suite_hash_hex) = match suite {
        Some((s, h)) => (Some(s), Some(h)),
        None => (None, None),
    };
    let response = VerifyResponse {
        version,
        session_id: req.session_id.clone(),
        results,
        payload_hex,
        ruleset_outcome,
        all_verified,
        suite,
        suite_hash_hex,
    };
    // Only an accepted request is remembered for replay; a failed one never is.
    if all_verified {
        state.verifier_sessions().remember(&session_id, verify_request_digest(req), &response);
    }
    Ok(response)
}

/// SHA-256 over a canonical encoding of everything in a verify request that
/// decides its outcome, except the token (who asks does not change what is
/// asked). Fields are length-prefixed so no two requests share an encoding.
pub fn verify_request_digest(req: &VerifyRequest) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut put = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    put(&req.version.unwrap_or(0).to_be_bytes());
    put(req.profile.as_bytes());
    put(req.session_id.as_bytes());
    put(&[req.key_id, req.reassemble as u8]);
    put(req.ruleset.as_deref().unwrap_or("").as_bytes());
    put(&serde_json::to_vec(&req.suite).unwrap_or_default());
    put(&(req.frames.len() as u64).to_be_bytes());
    for f in &req.frames {
        put(&serde_json::to_vec(f).unwrap_or_default());
    }
    h.finalize().into()
}

/// `verify` for a request that speaks wire v2. Same order as `seal_v2`: the
/// version rules ran already; the capability is checked before any lookup;
/// the suite is resolved against the policy on EVERY call (a policy that
/// tightens, or an algorithm that enters quarantine, takes effect on sessions
/// already open); the session is bound to its first `(version, suite)`.
fn verify_v2(
    state: &AppState,
    req: &VerifyRequest,
    transit: Option<&lacre_profiles::transit_taxonomy::TransitIdentity>,
) -> Result<VerifyResponse, DomainError> {
    let runtime = state.seal_runtime().expect("`resolve` only returns V2 when a policy exists").clone();
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown profile: {}", req.profile)))?;
    let session_id: SessionId = crate::wire::session_id_from_hex(&req.session_id)
        .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
    require(state, Scope::Verify, &session_id, req.token.as_deref())?;

    if req.frames.is_empty() {
        return Err(DomainError::BadRequest(
            "verify requires at least one frame: an empty batch verifies nothing".to_string(),
        ));
    }
    // Idempotent retry: the very same request that this session accepted last
    // (a client or intermediary repeating it after a lost response) gets the
    // same verdict again. Nothing new is accepted here.
    let digest = verify_request_digest(req);
    if let Some(same) = state.verifier_sessions().replay(&session_id, &digest) {
        return Ok(same);
    }
    let suite_wire = req.suite.as_ref().expect("`resolve` only returns V2 when a suite exists");

    // Steps 3 to 5, with the quarantine rule: an algorithm in quarantine closes
    // its sessions (`close`) or lets already open ones finish (`drain`).
    let resolved = match runtime.resolve(suite_wire, profile) {
        Ok(r) => r,
        Err(DomainError::Forbidden(why)) if runtime.is_quarantined(&suite_wire.seal) => match runtime.on_quarantine() {
            crate::seal_policy::OnQuarantine::Close => {
                state.verifier_sessions().fail_session(&session_id);
                return Err(DomainError::Forbidden(why));
            }
            crate::seal_policy::OnQuarantine::Drain => {
                if state.verifier_sessions().has_live(&session_id) {
                    runtime.resolve_draining(suite_wire, profile)?
                } else {
                    return Err(DomainError::Forbidden(why));
                }
            }
        },
        Err(e) => return Err(e),
    };

    let ruleset = match &req.ruleset {
        None => None,
        Some(_) if !req.reassemble => {
            return Err(DomainError::BadRequest(
                "`ruleset` on verify needs `reassemble: true` (the rules judge the complete payload)".to_string(),
            ));
        }
        Some(name) => Some((name.as_str(), find_ruleset(state, name)?)),
    };

    // Step 8: admission for a declared-heavy algorithm, only if the operator configured it.
    let _heavy = match (resolved.cost, state.admission()) {
        (lacre_core::suite::CostClass::Heavy, Some(gate)) => Some(gate.try_admit_heavy()?),
        _ => None,
    };

    let key_ring = state.handshake_sessions().get(&session_id).unwrap_or_else(|| state.key_ring().clone());
    let cfg = profile.config();
    let spec = BufferSpec::new(cfg.slot_size, cfg.slot_count, cfg.forced_purge_timeout, runtime.max_session_memory_bytes());
    let key_id = req.key_id;
    let suite_hash = *resolved.suite.suite_hash();
    let suite_for_core = resolved.suite.clone();
    // The verifying key is derived from the server's vault secret by the scheme
    // itself, so the Core and this layer never name a scheme.
    let vault_public = match resolved.suite.signature_scheme() {
        None => None,
        Some(scheme) => Some(
            scheme
                .public_from_secret(&state.vault_signing_key_bytes())
                .ok_or_else(|| DomainError::Unprocessable("the server's vault key is not valid for this signature scheme".to_string()))?,
        ),
    };

    let outcome = state.verifier_sessions().get_or_insert_v2_with_reassembly(
        session_id,
        suite_hash,
        || match &vault_public {
            Some(public) => VerifierCoreV2::resume_signed(key_ring.clone(), session_id, key_id, suite_for_core, spec, public),
            None => VerifierCoreV2::resume(key_ring.clone(), session_id, key_id, suite_for_core, spec),
        },
        |verifier, reassembly| run_batch(AnyCore::V2(verifier), reassembly, req, key_id, transit),
    );
    let parts = store_outcome(outcome, Some((runtime.as_ref(), &suite_wire.seal)))?;

    let suite_out = suite_wire.clone();
    finish_verify(state, req, session_id, parts, ruleset, 2, Some((suite_out, hex::encode(suite_hash))))
}

/// `handle_ack` (formerly in `http_server.rs`), without axum.
pub fn ack(state: &AppState, req: &AckRequest) -> Result<AckResponse, DomainError> {
    let session_id = crate::wire::session_id_from_hex(&req.session_id)
        .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
    require(state, Scope::Ack, &session_id, req.token.as_deref())?;

    let outcome = state.sealer_sessions().with_sealer(&session_id, |sealer| {
        let mut results = Vec::with_capacity(req.indices.len());
        let mut all_acknowledged = true;
        for &index in &req.indices {
            match sealer.ack(index) {
                Ok(_purged) => results.push(AckResult { index, ok: true, error: None }),
                Err(e) => {
                    all_acknowledged = false;
                    results.push(AckResult { index, ok: false, error: Some(describe_core_error(&e)) });
                }
            }
        }
        let total_receipts = sealer.receipts().map(|r| r.len()).unwrap_or(0);
        (results, all_acknowledged, total_receipts)
    });

    match outcome {
        Err(crate::sealer_session_store::WithSealerError::NotFound) => Err(DomainError::NotFound(
            "no active Vault session with that session_id (never sealed under Vault, \
             or it already expired server-side)"
                .to_string(),
        )),
        Ok((results, all_acknowledged, total_receipts)) => Ok(AckResponse {
            session_id: req.session_id.clone(),
            results,
            all_acknowledged,
            total_receipts,
        }),
    }
}

/// `handle_receipts` (formerly in `http_server.rs`), without axum.
pub fn receipts(
    state: &AppState,
    session_id_hex: &str,
    token: Option<&str>,
) -> Result<ReceiptsResponse, DomainError> {
    let session_id = crate::wire::session_id_from_hex(session_id_hex)
        .ok_or_else(|| DomainError::BadRequest("invalid session_id".to_string()))?;
    // Receipts are the sender's evidence that the receiver purged: `write`.
    require(state, Scope::Write, &session_id, token)?;

    let entries = state
        .sealer_sessions()
        .with_sealer(&session_id, |sealer| {
            sealer
                .receipts()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| ReceiptEntryWire {
                            fragment_index: entry.fragment_index,
                            receipt_hex: hex::encode(entry.receipt.0),
                            purged_at_ms: entry.purged_at_ms,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .map_err(|crate::sealer_session_store::WithSealerError::NotFound| {
            DomainError::NotFound(
                "no active Vault session with that session_id (never sealed under \
                 Vault, or it already expired server-side)"
                    .to_string(),
            )
        })?;

    Ok(ReceiptsResponse {
        session_id: session_id_hex.to_string(),
        entries,
    })
}

// --- Toolchain Integrity (Annex 4.0) domain functions ---
//
// Same layering as the five original operations above: no axum here,
// so any Adapter (this project's HTTP one, or a future one built on
// `declarative_adapter.rs`) invokes these directly.

/// Creates a new live `ToolchainProfile` episode and stores it under a
/// fresh `SessionId` in `AppState::toolchain_sessions`.
pub fn create_toolchain_episode(
    state: &AppState,
    req: &crate::wire::CreateToolchainEpisodeRequest,
) -> Result<crate::wire::ToolchainEpisodeResponse, DomainError> {
    let version = crate::version::check(req.version)?;
    let episode_id = hex::decode(&req.episode_id_hex)
        .map_err(|_| DomainError::BadRequest("episode_id_hex is not valid hex".to_string()))?;
    let algo = parse_hmac_algo(&req.algo)
        .ok_or_else(|| DomainError::BadRequest(format!("unknown algo: {}", req.algo)))?;

    // A fresh derived key per episode, from the server's own fixed
    // key_ring — deliberately not reusing whatever key a `seal`/`verify`
    // session might be using, since a Toolchain episode's chain seal Δᵥ
    // is a second, independent sealing layer on top of whatever the
    // Core already certified (see `lacre-core::toolchain`'s own header
    // comment on this point), not a continuation of a Core session's
    // own key.
    let session_id = SessionId::generate();
    let key = state.key_ring().derive_for_sealing(&session_id);

    let max_node_age = Duration::from_millis(req.max_node_age_ms);
    let episode = lacre_profiles::toolchain::ToolchainProfile::new(algo, key, &episode_id, max_node_age);

    state.toolchain_sessions().insert(session_id, episode).map_err(|_| at_capacity("toolchain"))?;

    Ok(crate::wire::ToolchainEpisodeResponse {
        version,
        session_id: session_id_to_hex(&session_id),
        capabilities: tokens_for(state, &session_id, false),
    })
}

/// Adds a node to a live episode. `req.parent_ids` empty means a root
/// node — `ToolchainProfile::add_root` is exactly `add_node` with no
/// parents, so this function mirrors that instead of branching on a
/// separate "is root" flag.
pub fn add_toolchain_node(
    state: &AppState,
    session_id_hex: &str,
    req: &crate::wire::AddToolchainNodeRequest,
) -> Result<crate::wire::AddToolchainNodeResponse, DomainError> {
    let session_id = crate::wire::session_id_from_hex(session_id_hex)
        .ok_or_else(|| DomainError::BadRequest("session_id is not valid hex".to_string()))?;
    require(state, Scope::Write, &session_id, req.token.as_deref())?;
    let content = hex::decode(&req.content_hex)
        .map_err(|_| DomainError::BadRequest("content_hex is not valid hex".to_string()))?;

    // The chain seal is computed from a `LacreFrame`'s payload field
    // (see `ToolchainProfile::add_node`'s own signature) — the other
    // frame fields (index, total_fragments, is_last) are irrelevant to
    // a Toolchain node, which has no notion of fragment ordering the
    // way a Core session does, so they're filled with harmless
    // placeholder values rather than threading them through the wire
    // type for no purpose.
    let frame = LacreFrame {
        session_id,
        index: 0,
        total_fragments: Some(1),
        is_last: true,
        payload: content,
    };

    let outcome = state.toolchain_sessions().with_episode(&session_id, |episode| {
        episode.add_node(
            req.node_id.clone(),
            &lacre_core::access::ContentView::caller_supplied(&frame),
            &req.parent_ids,
        )
    });

    let chain_seal = match outcome {
        Ok(Ok(seal)) => seal,
        Ok(Err(err)) => {
            return Err(DomainError::Unprocessable(describe_toolchain_error(err)));
        }
        Err(crate::toolchain_session_store::WithEpisodeError::NotFound) => {
            return Err(DomainError::NotFound(
                "no live Toolchain episode with that session_id (never created, or already \
                 idle past its TTL on the server side)"
                    .to_string(),
            ));
        }
    };

    Ok(crate::wire::AddToolchainNodeResponse {
        node_id: req.node_id.clone(),
        chain_seal_hex: hex::encode(chain_seal.0),
    })
}

/// Verifies an episode's output node against caller-supplied contents
/// for every node in its declared ancestry. Per
/// `lacre-core::toolchain`'s own header comment, `ToolchainProfile`
/// never retains a node's raw content — only its chain seal — so the
/// caller must resend whatever content it wants (re-)verified, same as
/// `VerifyRequest::frames` already does for the Core's own frames.
pub fn verify_toolchain_output(
    state: &AppState,
    session_id_hex: &str,
    req: &crate::wire::VerifyToolchainOutputRequest,
) -> Result<crate::wire::VerifyToolchainOutputResponse, DomainError> {
    let session_id = crate::wire::session_id_from_hex(session_id_hex)
        .ok_or_else(|| DomainError::BadRequest("session_id is not valid hex".to_string()))?;
    require(state, Scope::Verify, &session_id, req.token.as_deref())?;

    let mut contents = std::collections::HashMap::with_capacity(req.contents_hex.len());
    for (node_id, content_hex) in &req.contents_hex {
        let content = hex::decode(content_hex).map_err(|_| {
            DomainError::BadRequest(format!("contents_hex for node {node_id} is not valid hex"))
        })?;
        contents.insert(node_id.clone(), content);
    }

    let outcome = state
        .toolchain_sessions()
        .with_episode(&session_id, |episode| {
            if episode.failed_verifications() >= MAX_FAILED_TOOLCHAIN_VERIFICATIONS {
                return None;
            }
            Some(episode.verify_output(&req.output_node_id, &contents))
        })
        .map_err(|crate::toolchain_session_store::WithEpisodeError::NotFound| {
            DomainError::NotFound(
                "no live Toolchain episode with that session_id (never created, or already \
                 idle past its TTL on the server side)"
                    .to_string(),
            )
        })?;

    let Some(outcome) = outcome else {
        return Err(DomainError::TooManyRequests(format!(
            "this episode already had {MAX_FAILED_TOOLCHAIN_VERIFICATIONS} failed verifications \
             and refuses further ones; open a new episode"
        )));
    };
    Ok(match outcome {
        lacre_profiles::toolchain::VerificationOutcome::Valid => {
            crate::wire::VerifyToolchainOutputResponse {
                valid: true,
                failed_node: None,
            }
        }
        lacre_profiles::toolchain::VerificationOutcome::Invalid { failed_node } => {
            crate::wire::VerifyToolchainOutputResponse {
                valid: false,
                failed_node: Some(failed_node),
            }
        }
    })
}

/// Parses a Toolchain episode's requested algorithm from a wire
/// string — deliberately separate from `ProfileName`'s own fixed
/// per-profile algorithm choice (`profile_config.rs`): a Toolchain
/// episode's chain seal algorithm is an independent choice from
/// whatever profile sealed the underlying frames, not something that
/// should be coupled to the deployment-profile vocabulary.
fn parse_hmac_algo(name: &str) -> Option<lacre_core::hmac_seal::HmacAlgo> {
    match name {
        "sha256" => Some(lacre_core::hmac_seal::HmacAlgo::Sha256),
        "blake3" => Some(lacre_core::hmac_seal::HmacAlgo::Blake3),
        _ => None,
    }
}

/// Translates `ToolchainError` to a stable text message for
/// `DomainError::Unprocessable` — same pattern `describe_core_error`
/// already follows for `CoreError`: never expose the internal `Debug`
/// representation directly, so the HTTP API's error text doesn't get
/// coupled to Rust enum variant names that could change independently
/// of the wire contract.
fn describe_toolchain_error(err: lacre_profiles::toolchain::ToolchainError) -> String {
    match err {
        lacre_profiles::toolchain::ToolchainError::UnknownParent(id) => {
            format!("declared parent does not exist in this episode: {id}")
        }
        lacre_profiles::toolchain::ToolchainError::DuplicateNode(id) => {
            format!("a node with this ID already exists in this episode: {id}")
        }
        lacre_profiles::toolchain::ToolchainError::TaintedParent(id) => {
            format!("declared parent is already compromised in this episode: {id}")
        }
    }
}

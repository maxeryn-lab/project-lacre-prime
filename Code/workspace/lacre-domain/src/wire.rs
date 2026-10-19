//! Translation between `lacre-core` types and JSON — deliberately with
//! no dependency on `axum`, `tokio`, or any concrete HTTP transport
//! detail.
//!
//! # Why this module exists separately from `http_server.rs`
//!
//! See `DECISIONS.md` point 16 and `ARCHITECTURE_NOTES.md` ("Two
//! independent extension axes") for the full reasoning. Summary:
//! Adapters are, alongside Profiles, a first-class extension axis of
//! the project (7.1/7.4), not an internal `lacre-server` detail. HTTP
//! is just the first Adapter built — if a WebSocket or gRPC Adapter
//! appears tomorrow, it should be able to reuse the "lacre-core frames
//! ↔ serializable representation" translation without duplicating it
//! or depending on axum to do so.
//!
//! This separation is NOT a speculative `trait Transport` (that would
//! be exactly the over-engineering risk already identified): it's the
//! minimal hygiene refactor already known to be necessary because this
//! same HTTP Adapter uses it today. If a second real Adapter appears,
//! that's when — and not before — it gets decided whether it's worth
//! extracting a trait from the TWO concrete implementations that will
//! exist by then.
//!
//! # What this module does NOT do
//!
//! It doesn't open sockets, doesn't know what an HTTP request or
//! response is, doesn't import `axum`. It only converts between
//! `(LacreFrame, Seal, ...)` and `serde` types. `http_server.rs` is the
//! one that knows axum and calls this module to produce/consume body
//! bytes.
//!
//! # Body format chosen for this first implementation
//!
//! A JSON array with `frame` and `seal` in the same object (see
//! `SealedFrameWire`). This is a **declared deviation** from Axiom A2
//! ("the seal... never gets incorporated, modified, or mixed with the
//! content of the message body") if "transport message" is interpreted
//! as each HTTP request/response: here the seal travels in the BODY
//! alongside the fragment, not in a separate per-fragment header as 9.3
//! literally suggests ("...specific header...associated with each
//! fragment").
//!
//! Chosen this way, deliberately, for this first implementation because
//! it's verifiable end to end with curl in a single HTTP exchange,
//! leaving the 9.3-faithful variant (one HTTP chunk per frame, seal in
//! an `X-Lacre-Seal` header per chunk) as the natural candidate for a
//! second HTTP Adapter implementation — reusing, in large part, this
//! same translation module (the `*Wire` types don't change; what would
//! change is how `http_server.rs` transports them). See PENDING.md for
//! tracking this point.

use lacre_core::core::CoreError;
use lacre_core::frame::LacreFrame;
use lacre_core::hmac_seal::Seal;
use lacre_core::session::SessionId;
use lacre_core::vault_signature::VaultSignature;
use serde::{Deserialize, Serialize};

/// JSON representation of a `SessionId` (fixed 16 bytes) — hex instead
/// of base64 for direct readability in curl/logs, regardless of the
/// cost of a few extra bytes: a session_id is never the response's
/// bulk body.
pub fn session_id_to_hex(id: &SessionId) -> String {
    hex::encode(id.0)
}

/// Inverse of `session_id_to_hex`. Returns `None` if the string doesn't
/// decode to exactly 16 bytes of valid hex — never produces a partial
/// or zero-padded `SessionId` for convenience (A4, fail-closed: a
/// corrupt session_id must not be interpreted *as if* it were a
/// different session_id, it must be rejected).
pub fn session_id_from_hex(s: &str) -> Option<SessionId> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 16] = bytes.try_into().ok()?;
    Some(SessionId(arr))
}

/// A frame + its seal, in the form that travels in the JSON body.
/// `LacreFrame`'s fields are flattened here instead of deriving
/// `Serialize` directly on `LacreFrame` — `LacreFrame` is a
/// `lacre-core` type, and `lacre-core` must not depend on `serde` (no
/// business reason for the Core to know what JSON is). This `struct`
/// lives entirely on the Adapter side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedFrameWire {
    pub session_id: String,
    pub index: u64,
    pub total_fragments: Option<u64>,
    pub is_last: bool,
    /// Payload in hex, not a JSON array of numbers — more compact and
    /// easier to inspect by hand in a curl response.
    pub payload_hex: String,
    pub seal_hex: String,
    /// Present only if the session is Vault (9.5/15.3). Absent (`null`
    /// in JSON) for every other profile — not an empty field or a
    /// "none" string, so absence is indistinguishable from "this
    /// profile doesn't use Vault" and not from "Vault failed blank".
    pub vault_signature_hex: Option<String>,
    /// Wire v2 only: the vault signature as `{scheme, sig_hex}`. Never serialized
    /// when absent, so every wire-v1 body stays byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureWire>,
}

/// A frame's signature under wire v2: the scheme is named so that a verifier
/// can refuse a signature made under another scheme before verifying anything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureWire {
    pub scheme: String,
    pub sig_hex: String,
}

impl SealedFrameWire {
    pub fn from_parts(
        frame: &LacreFrame,
        seal: &Seal,
        vault_signature: Option<&VaultSignature>,
    ) -> Self {
        SealedFrameWire {
            session_id: session_id_to_hex(&frame.session_id),
            index: frame.index,
            total_fragments: frame.total_fragments,
            is_last: frame.is_last,
            payload_hex: hex::encode(&frame.payload),
            seal_hex: hex::encode(seal.0),
            vault_signature_hex: vault_signature.map(|sig| hex::encode(sig.to_bytes())),
            signature: None,
        }
    }

    /// Reconstructs `(LacreFrame, Seal, Option<VaultSignature>)` from
    /// the wire representation. Returns an explicit translation error
    /// (not an `Option`/panic) because the caller (`http_server.rs`)
    /// needs to distinguish "the JSON doesn't decode to a valid frame"
    /// (400 error, client problem) from "the frame decoded but doesn't
    /// verify" (integrity error, handled by `verify_frame` — a problem
    /// of a different nature).
    pub fn into_parts(&self) -> Result<(LacreFrame, Seal, Option<VaultSignature>), WireDecodeError> {
        if self.signature.is_some() {
            return Err(WireDecodeError::SignatureNotAllowedInV1);
        }
        let session_id =
            session_id_from_hex(&self.session_id).ok_or(WireDecodeError::InvalidSessionId)?;
        let payload = hex::decode(&self.payload_hex).map_err(|_| WireDecodeError::InvalidPayloadHex)?;
        let seal_bytes = hex::decode(&self.seal_hex).map_err(|_| WireDecodeError::InvalidSealHex)?;
        let seal_arr: [u8; 32] = seal_bytes
            .try_into()
            .map_err(|_| WireDecodeError::InvalidSealLength)?;

        let vault_signature = match &self.vault_signature_hex {
            None => None,
            Some(hex_str) => {
                let bytes = hex::decode(hex_str).map_err(|_| WireDecodeError::InvalidVaultSignatureHex)?;
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| WireDecodeError::InvalidVaultSignatureLength)?;
                Some(VaultSignature::from_bytes(&arr))
            }
        };

        let frame = LacreFrame {
            session_id,
            index: self.index,
            total_fragments: self.total_fragments,
            is_last: self.is_last,
            payload,
        };

        Ok((frame, Seal(seal_arr), vault_signature))
    }

    /// Wire v2: the frame as a seal of any length 1..=1024 bytes.
    pub fn from_parts_v2(frame: &LacreFrame, tag: &lacre_core::suite::SealTag, signature: Option<SignatureWire>) -> Self {
        SealedFrameWire {
            session_id: session_id_to_hex(&frame.session_id),
            index: frame.index,
            total_fragments: frame.total_fragments,
            is_last: frame.is_last,
            payload_hex: hex::encode(&frame.payload),
            seal_hex: hex::encode(tag.as_bytes()),
            vault_signature_hex: None,
            signature,
        }
    }

    /// Wire v2 counterpart of `into_parts`: a variable-length tag and, if the
    /// frame carries one, its signature `(scheme, bytes)`.
    pub fn into_parts_v2(&self) -> Result<V2Parts, WireDecodeError> {
        let session_id =
            session_id_from_hex(&self.session_id).ok_or(WireDecodeError::InvalidSessionId)?;
        let payload = hex::decode(&self.payload_hex).map_err(|_| WireDecodeError::InvalidPayloadHex)?;
        if self.vault_signature_hex.is_some() {
            return Err(WireDecodeError::SignatureNotAllowedInV2);
        }
        let tag_bytes = hex::decode(&self.seal_hex).map_err(|_| WireDecodeError::InvalidSealHex)?;
        let tag = lacre_core::suite::SealTag::new(tag_bytes).map_err(|_| WireDecodeError::InvalidTagLength)?;
        let signature = match &self.signature {
            None => None,
            Some(sg) => Some((sg.scheme.clone(), hex::decode(&sg.sig_hex).map_err(|_| WireDecodeError::InvalidSignatureHex)?)),
        };
        let frame = LacreFrame {
            session_id,
            index: self.index,
            total_fragments: self.total_fragments,
            is_last: self.is_last,
            payload,
        };
        Ok((frame, tag, signature))
    }
}

/// A v2 frame decoded: frame, tag and optional `(scheme, signature bytes)`.
pub type V2Parts = (LacreFrame, lacre_core::suite::SealTag, Option<(String, Vec<u8>)>);

/// Failure translating a `SealedFrameWire` received over HTTP back into
/// `lacre-core` types — always a problem with the RECEIVED BODY
/// (malformed JSON, invalid hex, wrong length), never an integrity
/// verification failure. `http_server.rs` maps this to HTTP 400 (Bad
/// Request); a real `CoreError::SealMismatch`, in contrast, maps to 422
/// (see `core_error_to_status_and_message`) — these are different error
/// layers and must not be conflated in the HTTP status code the client
/// receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDecodeError {
    InvalidSessionId,
    InvalidPayloadHex,
    InvalidSealHex,
    InvalidSealLength,
    InvalidVaultSignatureHex,
    InvalidVaultSignatureLength,
    /// Wire v2: `seal_hex` must decode to 1..=1024 bytes.
    InvalidTagLength,
    /// Wire v2 frames carry no Vault signature (E5).
    SignatureNotAllowedInV2,
    InvalidSignatureHex,
    SignatureNotAllowedInV1,
}

impl WireDecodeError {
    pub fn message(self) -> &'static str {
        match self {
            WireDecodeError::InvalidSessionId => "session_id must be exactly 16 bytes of hex (32 characters)",
            WireDecodeError::InvalidPayloadHex => "payload_hex is not valid hex",
            WireDecodeError::InvalidSealHex => "seal_hex is not valid hex",
            WireDecodeError::InvalidSealLength => "seal_hex must decode to exactly 32 bytes",
            WireDecodeError::InvalidVaultSignatureHex => "vault_signature_hex is not valid hex",
            WireDecodeError::InvalidVaultSignatureLength => {
                "vault_signature_hex must decode to exactly 64 bytes"
            }
            WireDecodeError::InvalidTagLength => "seal_hex must decode to between 1 and 1024 bytes",
            WireDecodeError::SignatureNotAllowedInV2 => {
                "vault_signature_hex is not allowed under version 2: use `signature {scheme, sig_hex}`"
            }
            WireDecodeError::InvalidSignatureHex => "signature.sig_hex is not valid hex",
            WireDecodeError::SignatureNotAllowedInV1 => {
                "`signature` is not allowed under version 1: use `vault_signature_hex`"
            }
        }
    }
}

/// The seal suite of a wire v2 session, as it travels in the JSON body
/// (spec/LACRE-WIRE-v2.md). Structured, never opaque bytes, so there
/// is exactly one representation. Unknown fields are refused: nothing inside
/// `suite` is silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuiteWire {
    /// Algorithm id, as in the catalogue (for example `blake3-keyed-xof`).
    pub seal: String,
    /// Tag length in BYTES. Required for XOF algorithms, forbidden for
    /// fixed-length ones. (Bits and bytes are never mixed: the suffix says which.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_len_bytes: Option<u32>,
    /// Signature scheme. Always `null` in E4 (signature schemes arrive in E5).
    #[serde(default)]
    pub signature: Option<String>,
}

/// Body of the `POST /v1/seal` request.
#[derive(Debug, Clone, Deserialize)]
pub struct SealRequest {
    /// Protocol version this request speaks (A8). Absent = the current
    /// version; an unknown value is refused (see `version.rs`).
    #[serde(default)]
    pub version: Option<u32>,
    /// Deployment profile, same value as the `lacre-profile` header
    /// from 15.2 — accepted in the body instead of a header in this
    /// first implementation for simplicity of testing with curl (`-d`
    /// is simpler than `-H` for the smoke-test use case); not a final
    /// decision, see PENDING.md.
    pub profile: String,
    /// The complete payload to fragment and seal, in hex — not plain
    /// text, so as not to impose a text encoding on a payload that 8.1
    /// doesn't require to be text.
    pub payload_hex: String,
    /// If present, the corresponding handshake session's
    /// `MasterKeyRing` is used (see `POST /v1/handshake`) and that same
    /// `session_id`, instead of generating a new one under the
    /// server's fixed ring. Absent by default — consistent with the
    /// behavior that already existed before the handshake endpoint was
    /// added, without breaking it.
    #[serde(default)]
    pub session_id: Option<String>,
    /// `write` capability token. Required only when `session_id` is
    /// present (continuing a handshake session); opening a new session
    /// needs none. Also accepted as `Authorization: Bearer` over HTTP.
    #[serde(default)]
    pub token: Option<String>,
    /// Name of a deployment rule set to validate the payload against
    /// BEFORE sealing (Guardian / Certifier / Rule Engine). A payload
    /// the rule set rejects or quarantines is not sealed (A4).
    #[serde(default)]
    pub ruleset: Option<String>,
    /// Seal suite. Present exactly when `version` is 2 (wire v2); a `suite`
    /// under v1 or without a version is refused, never reinterpreted.
    #[serde(default)]
    pub suite: Option<SuiteWire>,
}

/// What a rule set decided about a payload.
#[derive(Debug, Clone, Serialize)]
pub struct RuleOutcomeWire {
    pub ruleset: String,
    pub kind: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failing_rule_id: Option<String>,
}

/// Body of `POST /v1/validate`: run a payload through a named rule set
/// without sealing anything. Stateless, so it needs no token.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateRequest {
    pub ruleset: String,
    pub payload_hex: String,
}

/// The three capability tokens of a session (see `capability.rs`). The
/// opener receives all of them and hands each to the party that needs it:
/// `write` to the sender, `verify` to whoever checks integrity, `ack` to
/// the receiver. `None` fields are omitted (a Toolchain episode has no
/// receiver, so no `ack`).
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityTokens {
    pub write: String,
    pub verify: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<String>,
}

/// Body of the `POST /v1/seal` response: the complete sequence of
/// sealed frames `SealerCore::seal_payload` produced at once — unlike
/// the old server (one frame per request on `/v1/seal`, see
/// PENDING.md §3), the current `lacre-core` interface already fragments
/// internally and returns everything together.
#[derive(Debug, Clone, Serialize)]
pub struct SealResponse {
    /// Protocol version the session uses (A8).
    pub version: u32,
    pub session_id: String,
    pub frames: Vec<SealedFrameWire>,
    pub capabilities: CapabilityTokens,
    /// Present when the request named a `ruleset` (a flagged-but-passed
    /// payload shows which rule flagged it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_outcome: Option<RuleOutcomeWire>,
    /// Wire v2 only: the canonical suite the session was sealed under.
    /// Absent under v1, so v1 responses are byte-identical to before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<SuiteWire>,
    /// Wire v2 only: hex of the SHA-256 hash of the canonical descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_hash_hex: Option<String>,
}

/// Body of the `POST /v1/verify` request: the session it belongs to
/// (to be able to invoke `VerifierCore::resume` server-side) plus the
/// list of frames to verify in order.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyRequest {
    /// Protocol version this request speaks (A8). Absent = the current
    /// version; an unknown value is refused (see `version.rs`).
    #[serde(default)]
    pub version: Option<u32>,
    pub profile: String,
    pub session_id: String,
    pub key_id: u8,
    pub frames: Vec<SealedFrameWire>,
    /// `verify` capability token (or `Authorization: Bearer`).
    #[serde(default)]
    pub token: Option<String>,
    /// Reassemble the verified payload server-side and return it as
    /// `payload_hex` when the last frame verifies. Also enables the
    /// duplicate diagnosis (`diagnosis`) on refused replays.
    #[serde(default)]
    pub reassemble: bool,
    /// With `reassemble`: also run the complete payload through this
    /// named rule set; a payload it rejects or quarantines is withheld.
    #[serde(default)]
    pub ruleset: Option<String>,
    /// Seal suite of the session. Present exactly when `version` is 2.
    #[serde(default)]
    pub suite: Option<SuiteWire>,
}

/// Result of verifying a single frame — reported one per frame, not an
/// aggregate boolean for the whole request, because A4 (fail-closed)
/// requires knowing EXACTLY which fragment failed, not just that
/// "something" failed in the sequence.
#[derive(Debug, Clone, Serialize)]
pub struct FrameVerificationResult {
    pub index: u64,
    pub ok: bool,
    /// Present only if `ok == false`.
    pub error: Option<String>,
    /// With `reassemble`: why a refused frame was a non-novelty, from the
    /// Transit Non-Novelty Taxonomy (Annex 6.0). A diagnosis, not an
    /// exception: the frame is refused either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnosis: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResponse {
    /// Protocol version the session uses (A8).
    pub version: u32,
    pub session_id: String,
    pub results: Vec<FrameVerificationResult>,
    /// With `reassemble`: the complete payload, once its last frame
    /// verified (and the rule set, if named, let it through).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hex: Option<String>,
    /// With `reassemble` and `ruleset`: the rule set's decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_outcome: Option<RuleOutcomeWire>,
    /// `true` only if EVERY frame in the request verified. A
    /// convenience summary — `results` remains the per-frame source of
    /// truth.
    pub all_verified: bool,
    /// Wire v2 only: the suite the session verifies under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<SuiteWire>,
    /// Wire v2 only: hex of the SHA-256 hash of the canonical descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_hash_hex: Option<String>,
}

/// Translates a `CoreError` into a stable text message to include in
/// `FrameVerificationResult::error` or in a 4xx/5xx body. Doesn't
/// expose `CoreError`'s internal `Debug` directly to the client: that
/// would couple the HTTP API's format to the variant names of a
/// `lacre-core` enum, which can change independently of the Adapter's
/// public API.
pub fn describe_core_error(err: &CoreError) -> String {
    match err {
        CoreError::Buffer(_) => "session buffer failure (capacity, timeout, or duplicate)".to_string(),
        CoreError::FrameState(_) => "invalid frame state transition".to_string(),
        CoreError::UnknownKeyId => "key_id not recognized in this session's ring".to_string(),
        CoreError::SealMismatch => "the seal doesn't verify against the received fragment".to_string(),
        CoreError::OutOfSequence { expected, received } => {
            format!("invalid fragment order: expected index {expected}, received {received}")
        }
        CoreError::VaultSignatureMismatch => {
            "the session requires a Vault signature and it is absent or doesn't verify".to_string()
        }
    }
}

// -----------------------------------------------------------------
// X25519 handshake (8.4, step 1 — lacre-core's session_handshake.rs)
// -----------------------------------------------------------------
//
// Protocol chosen for this first implementation: ClientInitiated, a
// single POST/response exchange (see the design discussion in
// CHANGELOG.md). The client generates its ephemeral pair and sends its
// public key; the server generates its own, computes the DH secret,
// builds the resulting MasterKeyRing, decides a session_id, stores it
// in its SessionStore (see session_store.rs — deliberately a decision
// of THIS Adapter, not of the protocol), and responds with its own
// public key plus the agreed session_id.
//
// Documented explicitly because it isn't the only possible variant:
// ServerAdvertised (the server publishes its public key on a static GET
// and the client POSTs its own) is equally valid within 8.4 and could
// be implemented as an alternative HTTP route, or as part of a future
// WebSocket/QUIC/gRPC Adapter, without touching session_handshake.rs in
// lacre-core or this translation module beyond, perhaps, an additional
// wire type — the exchange mechanism itself belongs to the Adapter,
// just as 8.4/7.4 already separate "what the protocol guarantees" from
// "how the bytes arrive".

/// Body of `POST /v1/handshake`: the client's ephemeral public key, in
/// hex (fixed 32 bytes of X25519).
#[derive(Debug, Clone, Deserialize)]
pub struct HandshakeRequest {
    /// Protocol version this request speaks (A8). Absent = the current
    /// version; an unknown value is refused (see `version.rs`).
    #[serde(default)]
    pub version: Option<u32>,
    pub client_public_key_hex: String,
}

/// Response of `POST /v1/handshake`: the server's ephemeral public key
/// (so the client can derive the same secret on its side) and the
/// `session_id` under which the server registered the resulting
/// `MasterKeyRing` — the same `session_id` the client must then use in
/// `POST /v1/seal`/`POST /v1/verify`.
#[derive(Debug, Clone, Serialize)]
pub struct HandshakeResponse {
    /// Protocol version the session uses (A8).
    pub version: u32,
    pub server_public_key_hex: String,
    pub session_id: String,
    /// `key_id` under which the ring was registered — always `0` today
    /// (a single `MasterKeyRing` per session, no rotation), but exposed
    /// explicitly instead of assuming it client-side, so as not to
    /// couple the client to a value `MasterKeyRing::new` might not, in
    /// the future, default to `0`.
    pub key_id: u8,
    pub capabilities: CapabilityTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeDecodeError {
    InvalidClientPublicKeyHex,
    InvalidClientPublicKeyLength,
}

impl HandshakeDecodeError {
    pub fn message(self) -> &'static str {
        match self {
            HandshakeDecodeError::InvalidClientPublicKeyHex => {
                "client_public_key_hex is not valid hex"
            }
            HandshakeDecodeError::InvalidClientPublicKeyLength => {
                "client_public_key_hex must decode to exactly 32 bytes"
            }
        }
    }
}

/// Decodes `client_public_key_hex` into `session_handshake`'s types.
/// Separated from `http_server.rs` so wire translation stays in a
/// single place, same as `SealedFrameWire::into_parts`.
pub fn decode_client_public_key(
    req: &HandshakeRequest,
) -> Result<lacre_core::session_handshake::EphemeralPublicKey, HandshakeDecodeError> {
    let bytes = hex::decode(&req.client_public_key_hex)
        .map_err(|_| HandshakeDecodeError::InvalidClientPublicKeyHex)?;
    lacre_core::session_handshake::EphemeralPublicKey::from_slice(&bytes)
        .map_err(|_| HandshakeDecodeError::InvalidClientPublicKeyLength)
}

// -----------------------------------------------------------------
// ACK and post-purge receipt (7.5) — exclusive to the Vault profile
// -----------------------------------------------------------------
//
// See `sealer_session_store.rs`'s own header comment for the full
// reasoning on why this needs a live `SealerCore` between `POST
// /v1/seal` and `POST /v1/ack`, and why it was explicitly decided NOT
// to trigger `ack()` implicitly from an HTTP 200 (CHANGELOG.md Etapa
// 16).

/// Body of `POST /v1/ack`: the corresponding Vault session and the
/// fragment indices the client confirms having received and processed.
/// In a batch, not one per index — consistent with `POST /v1/seal` also
/// returning the complete sequence at once, instead of forcing one HTTP
/// round trip per fragment.
#[derive(Debug, Clone, Deserialize)]
pub struct AckRequest {
    pub session_id: String,
    pub indices: Vec<u64>,
    /// `ack` capability token (or `Authorization: Bearer`).
    #[serde(default)]
    pub token: Option<String>,
}

/// Result of confirming an index — one per index, not an aggregate
/// boolean, same criterion as `FrameVerificationResult`: A4 requires
/// knowing EXACTLY which index failed, not just that "something" failed
/// in the batch.
///
/// `ok: false` occurs only if `SealerCore::ack` returns `Err` (an
/// invalid `FrameState` transition — see core.rs) — not for an index
/// already confirmed before: `ack()` is idempotent by Core design (a
/// second `ack()` on the same index finds nothing to purge and doesn't
/// duplicate the receipt, and returns `Ok(false)`, not an error). A
/// client that retries an ACK due to a lost HTTP response, for example,
/// must not interpret `ok: true` on the second attempt as a second
/// receipt having been generated — `total_receipts` in `AckResponse` is
/// the source of truth on how many receipts really exist.
#[derive(Debug, Clone, Serialize)]
pub struct AckResult {
    pub index: u64,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AckResponse {
    pub session_id: String,
    pub results: Vec<AckResult>,
    pub all_acknowledged: bool,
    /// Total count of receipts accumulated in this session's
    /// `ReceiptLog` so far — not just those confirmed in THIS request,
    /// so the client can know whether the record is still alive
    /// server-side without having to keep the count itself.
    pub total_receipts: usize,
}

// -----------------------------------------------------------------
// Reading receipts — GET /v1/receipts/{session_id}
// -----------------------------------------------------------------
//
// See `handle_receipts`'s header comment in `http_server.rs` for the
// important scope limitation: receipts live inside the same
// `SealerSessionStore` with TTL that `handle_ack` already uses, NOT in
// an independent long-term audit record. This endpoint exposes what 7.5
// requires while the session stays alive server-side; it doesn't
// replace a permanent filing system if the real use case needs one.

/// A `ReceiptEntry` (`lacre-core`) translated to JSON. `receipt_hex` is
/// the value derived from the seal (`SHA-256(seal)`, 32 bytes) — NOT
/// recoverable back to the content nor to the original seal, exactly
/// as 7.5 explicitly requires ("not recoverable back to the content,
/// nor from the content itself"). `purged_at_ms` is relative to the
/// start of the session's `ReceiptLog` (same internal `lacre-core`
/// value, without reinterpreting it as an absolute timestamp — the
/// `ReceiptLog` itself doesn't know the wall-clock time it started at,
/// only how much time has passed since its own `epoch`).
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptEntryWire {
    pub fragment_index: u64,
    pub receipt_hex: String,
    pub purged_at_ms: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptsResponse {
    pub session_id: String,
    pub entries: Vec<ReceiptEntryWire>,
}

// --- Toolchain Integrity (Annex 4.0) wire types ---
//
// Deliberately three operations, not the annex's full CRUD-shaped
// vocabulary: `create_episode`, `add_node` (unified for root and
// non-root nodes — `ToolchainProfile::add_root` is just `add_node`
// with an empty parent list, so the wire type mirrors that rather than
// introducing a separate `AddRootRequest`), and `verify_output`. This
// is the complete public surface `ToolchainProfile` itself exposes for
// building and checking a graph — nothing more was invented on top of
// it.

/// Body of `POST /v1/toolchain/episodes`. `episode_id` is the
/// caller-chosen identifier fed into `ToolchainProfile::new` as
/// `episode_id` (distinct from the session ID that identifies the live
/// server-side session in `ToolchainSessionStore` — see
/// `ToolchainEpisodeResponse`'s own doc comment for why these are two
/// different identifiers).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateToolchainEpisodeRequest {
    /// Protocol version this request speaks (A8). Absent = the current
    /// version; an unknown value is refused (see `version.rs`).
    #[serde(default)]
    pub version: Option<u32>,
    pub episode_id_hex: String,
    /// Which HMAC algorithm to seal each node's chain seal Δᵥ with —
    /// same two options `hmac_seal::HmacAlgo` already offers for the
    /// Core's own δᵢ, exposed the same way `SealRequest`'s `profile`
    /// field is: a string the Adapter parses, not a value the wire
    /// type itself constrains at the type level.
    pub algo: String,
    /// Maximum time (milliseconds) a node may sit unresolved in the
    /// graph before `sweep_expired` may taint it — see
    /// `ToolchainProfile::new`'s own doc comment on why this has no
    /// default. Required here for the same reason: Annex 5.0 Section
    /// 3.5's own mitigation against an unbounded retention window
    /// "by omission".
    pub max_node_age_ms: u64,
}

/// Response of `POST /v1/toolchain/episodes`.
///
/// `session_id` (the live server-side session, looked up in
/// `ToolchainSessionStore` by every subsequent request against this
/// episode) is a different identifier from `episode_id_hex` (baked
/// into every node's Δᵥ computation, per
/// `lacre-core::toolchain`'s own formal model — two different episodes
/// with different `episode_id` never produce the same Δᵥ for identical
/// content). Conflating them would mean a client could not, in
/// principle, resume a `ToolchainProfile` under a *new* live session
/// while preserving the *same* cryptographic episode identity — this
/// wire design keeps that possibility open even though this first
/// implementation only ever uses one live session per episode.
#[derive(Debug, Clone, Serialize)]
pub struct ToolchainEpisodeResponse {
    /// Protocol version the session uses (A8).
    pub version: u32,
    pub session_id: String,
    pub capabilities: CapabilityTokens,
}

/// Body of `POST /v1/toolchain/episodes/{session_id}/nodes`.
#[derive(Debug, Clone, Deserialize)]
pub struct AddToolchainNodeRequest {
    pub node_id: String,
    /// Hex-encoded content for this node — same encoding convention
    /// `SealRequest::payload_hex` already uses, for the same reason:
    /// not imposing a text encoding on content the protocol doesn't
    /// require to be text.
    pub content_hex: String,
    /// Empty for a root node — mirrors `ToolchainProfile::add_root`
    /// being `add_node` with an empty parent list, rather than this
    /// wire type having a separate boolean or variant for "is this a
    /// root".
    #[serde(default)]
    pub parent_ids: Vec<String>,
    /// `write` capability token (or `Authorization: Bearer`).
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddToolchainNodeResponse {
    pub node_id: String,
    /// Hex-encoded Δᵥ for this node — exposed mainly for a caller that
    /// wants to display or log the chain seal; verification itself
    /// (`verify_output`) recomputes it server-side and never trusts a
    /// value a client could have sent back.
    pub chain_seal_hex: String,
}

/// Body of `POST /v1/toolchain/episodes/{session_id}/verify`.
///
/// `contents` mirrors `VerifyRequest::frames` in spirit: the client
/// resends the content it wants verified, the server never assumes it
/// remembers a node's raw content on its own (`ToolchainProfile` only
/// stores each node's *chain seal*, never its raw payload — see
/// `lacre-core::toolchain`'s own `ChainNode` struct, which has no
/// content field at all). This is a deliberate consequence of the same
/// separation `VerifierCore` already has between the sealed frame (kept)
/// and its content (purged) — a `ToolchainProfile` never retains
/// anything that would let it reconstruct a node's content from memory
/// alone.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyToolchainOutputRequest {
    pub output_node_id: String,
    /// Map from node ID to hex-encoded content, for every node in the
    /// output's ancestry the caller wants (re-)verified.
    pub contents_hex: std::collections::HashMap<String, String>,
    /// `verify` capability token (or `Authorization: Bearer`).
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyToolchainOutputResponse {
    pub valid: bool,
    /// Present only if `valid == false` — the node named as the root
    /// cause, per `lacre-core::toolchain::VerificationOutcome`'s own
    /// design principle of never reporting an opaque episode-wide
    /// failure (see Annex 4.0, "What Toolchain Integrity DOES solve").
    pub failed_node: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;

    fn sample_frame() -> (LacreFrame, Seal) {
        let session_id = SessionId([7u8; 16]);
        let frame = LacreFrame {
            session_id,
            index: 3,
            total_fragments: Some(5),
            is_last: false,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let seal = Seal([9u8; 32]);
        (frame, seal)
    }

    #[test]
    fn the_two_signature_fields_never_mix_across_versions() {
        let (frame, seal) = sample_frame();
        let mut v1 = SealedFrameWire::from_parts(&frame, &seal, None);
        v1.signature = Some(SignatureWire { scheme: "ed25519".into(), sig_hex: "00".repeat(64) });
        assert_eq!(v1.into_parts().err(), Some(WireDecodeError::SignatureNotAllowedInV1));

        let tag = lacre_core::suite::SealTag::new(vec![1; 32]).unwrap();
        let mut v2 = SealedFrameWire::from_parts_v2(&frame, &tag, None);
        v2.vault_signature_hex = Some("00".repeat(64));
        assert_eq!(v2.into_parts_v2().err(), Some(WireDecodeError::SignatureNotAllowedInV2));

        let mut bad = SealedFrameWire::from_parts_v2(&frame, &tag, Some(SignatureWire { scheme: "x".into(), sig_hex: "zz".into() }));
        assert_eq!(bad.into_parts_v2().err(), Some(WireDecodeError::InvalidSignatureHex));
        bad.signature = Some(SignatureWire { scheme: "x".into(), sig_hex: "0a0b".into() });
        let (_, _, sig) = bad.into_parts_v2().unwrap();
        assert_eq!(sig, Some(("x".to_string(), vec![0x0a, 0x0b])));
    }

    #[test]
    fn a_v1_frame_serializes_without_the_v2_field() {
        let (frame, seal) = sample_frame();
        let json = serde_json::to_string(&SealedFrameWire::from_parts(&frame, &seal, None)).unwrap();
        assert!(!json.contains("signature\""), "{json}");
        let with = serde_json::to_string(&SealedFrameWire::from_parts_v2(
            &frame,
            &lacre_core::suite::SealTag::new(vec![1; 32]).unwrap(),
            Some(SignatureWire { scheme: "s".into(), sig_hex: "00".into() }),
        ))
        .unwrap();
        assert!(with.contains(r#""signature":{"scheme":"s","sig_hex":"00"}"#), "{with}");
        let unknown = r#"{"scheme":"s","sig_hex":"00","extra":1}"#;
        assert!(serde_json::from_str::<SignatureWire>(unknown).is_err());
    }

    /// The frame → wire → frame round trip must be exact, field by
    /// field. If this fails, anything built on top of it (the real
    /// HTTP server) would fail in a much harder to diagnose way.
    #[test]
    fn sealed_frame_wire_round_trips_exactly() {
        let (frame, seal) = sample_frame();
        let wire = SealedFrameWire::from_parts(&frame, &seal, None);

        let (decoded_frame, decoded_seal, decoded_sig) = wire.into_parts().unwrap();

        assert_eq!(decoded_frame, frame);
        assert_eq!(decoded_seal.0, seal.0);
        assert!(decoded_sig.is_none());
    }

    /// `vault_signature_hex` must be `None` when no signature was
    /// passed — confirms the absence of Vault isn't accidentally
    /// encoded as an empty string or a literal "none".
    #[test]
    fn sealed_frame_wire_omits_vault_signature_when_absent() {
        let (frame, seal) = sample_frame();
        let wire = SealedFrameWire::from_parts(&frame, &seal, None);
        assert!(wire.vault_signature_hex.is_none());

        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"vault_signature_hex\":null"));
    }

    /// `session_id_from_hex` must reject, not pad or truncate, hex of
    /// incorrect length — consistent with A4.
    #[test]
    fn session_id_from_hex_rejects_wrong_length() {
        assert!(session_id_from_hex("aabb").is_none()); // too short
        assert!(session_id_from_hex(&"aa".repeat(20)).is_none()); // too long
        assert!(session_id_from_hex("not hex").is_none());
    }

    /// `into_parts` must return a specific, stable error, never panic,
    /// for each kind of JSON body corruption — tested one by one so a
    /// future change doesn't collapse several distinct cases into the
    /// same generic message.
    ///
    /// Uses an explicit `match` instead of `.unwrap_err()`:
    /// `into_parts`'s `Ok` type includes `VaultSignature`, which
    /// deliberately doesn't implement `Debug` in `lacre-core` (it's no
    /// more secret than a public signature, but there's no business
    /// reason to add it just so an Adapter test can use `unwrap_err`) —
    /// not worth touching Phase 1 for the convenience of a Phase 3 test
    /// helper.
    #[test]
    fn into_parts_reports_specific_errors_for_malformed_wire_data() {
        fn expect_decode_err(
            result: Result<(LacreFrame, Seal, Option<VaultSignature>), WireDecodeError>,
            expected: WireDecodeError,
        ) {
            match result {
                Err(actual) => assert_eq!(actual, expected),
                Ok(_) => panic!("expected WireDecodeError::{expected:?}, decoding succeeded instead"),
            }
        }

        let (frame, seal) = sample_frame();

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.session_id = "zz".to_string();
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidSessionId);

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.payload_hex = "not-hex-here".to_string();
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidPayloadHex);

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.seal_hex = "aabb".to_string(); // valid hex, wrong length
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidSealLength);

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.vault_signature_hex = Some("aabb".to_string());
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidVaultSignatureLength);
    }

    /// Confirms the seal algorithm doesn't get lost in the round-trip
    /// translation when really sealed with hmac_seal — not just with
    /// arbitrary test bytes like in `sample_frame`.
    #[test]
    fn round_trip_preserves_a_real_seal_computed_with_hmac_seal() {
        use lacre_core::hmac_seal::seal_fragment;
        use lacre_core::session::MasterKeyRing;
        use std::time::Duration;

        let session_id = SessionId([1u8; 16]);
        let frame = LacreFrame {
            session_id,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"real test content".to_vec(),
        };
        // Real key-derivation path — there is no (and there must not
        // be) any shortcut that builds a SessionKey without going
        // through MasterKeyRing::derive_for_sealing, which is the only
        // point where HKDF with salt=session_id (8.4) actually occurs.
        let ring = MasterKeyRing::new(0, b"test-key-for-this-test-32-bytes-".to_vec(), Duration::from_secs(60));
        let key = ring.derive_for_sealing(&session_id);
        let seal = seal_fragment(HmacAlgo::Sha256, &key, &frame.payload, b"state-0");

        let wire = SealedFrameWire::from_parts(&frame, &seal, None);
        let (decoded_frame, decoded_seal, _) = wire.into_parts().unwrap();

        assert_eq!(decoded_frame.payload, frame.payload);
        assert_eq!(decoded_seal.0, seal.0);
    }
}

// ── touches_payload declarations (Prime 7.3.1) ─────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ProfileDeclarationWire {
    pub name: String,
    /// `none`, `derived` or `full` (spec §13).
    pub content_access: String,
    /// `true` for `derived` and `full`.
    pub touches_payload: bool,
    pub justification: String,
}

/// What a node declares about content neutrality. `core_touches_payload` is
/// always false: the Core never interprets content (A1), which is checked by
/// `lacre-core/tests/neutrality.rs`. The list is every extension Profile this
/// build contains and whether it touches content.
#[derive(Debug, Clone, Serialize)]
pub struct ProfilesResponse {
    pub version: u32,
    pub core_touches_payload: bool,
    pub profiles: Vec<ProfileDeclarationWire>,
}

pub fn profiles_declaration() -> ProfilesResponse {
    ProfilesResponse {
        version: crate::version::PROTOCOL_VERSION,
        core_touches_payload: false,
        profiles: lacre_profiles::declaration::DECLARATIONS
            .iter()
            .map(|d| ProfileDeclarationWire {
                name: d.name.to_string(),
                content_access: d.access.name().to_string(),
                touches_payload: d.touches_payload,
                justification: d.justification.to_string(),
            })
            .collect(),
    }
}


// ---- Part-wise sealing over HTTP ----

/// Largest payload a single part may carry, in bytes (before hex). Published in
/// the response of `seal/open`. A part's request body is about twice this in hex,
/// which stays below the 1 MB default body limit of common intermediaries.
pub const MAX_PART_BYTES: usize = 256 * 1024;

/// Body of `POST /v1/seal/open`: opens a sealing session that is then fed with
/// `POST /v1/seal/part`. Same opening fields as `seal`, without a payload.
#[derive(Debug, Clone, Deserialize)]
pub struct SealOpenRequest {
    #[serde(default)]
    pub version: Option<u32>,
    pub profile: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub suite: Option<SuiteWire>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SealOpenResponse {
    pub version: u32,
    pub session_id: String,
    pub capabilities: CapabilityTokens,
    /// Bytes of payload per frame in this profile.
    pub slot_size: usize,
    /// Unacknowledged frames the session holds at most; a part that would pass it waits for `ack`.
    pub window_frames: usize,
    /// Largest `payload_hex` of a part, in bytes before hex.
    pub max_part_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<SuiteWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_hash_hex: Option<String>,
}

/// Body of `POST /v1/seal/part`.
#[derive(Debug, Clone, Deserialize)]
pub struct SealPartRequest {
    pub session_id: String,
    #[serde(default)]
    pub token: Option<String>,
    /// 0, 1, 2… in order. Repeating the last one (same content) returns its frames again.
    pub part_index: u64,
    pub payload_hex: String,
    /// True on the final part: its last frame closes the stream.
    #[serde(default)]
    pub is_last: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SealPartResponse {
    pub session_id: String,
    pub part_index: u64,
    pub is_last: bool,
    pub frames: Vec<SealedFrameWire>,
    /// Frames sealed and not yet acknowledged, after this part.
    pub pending_frames: usize,
}

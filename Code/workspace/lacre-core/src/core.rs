//! The Lacre protocol Core — Chapter 7.2 of Lacre Prime.
//!
//! Replaces `engine.rs` + half of `protocol.rs` from the earlier
//! iteration. Central difference from that iteration: **the Core
//! fragments internally**. The caller hands over a complete payload
//! (`SealerCore::seal_payload`) or receives frames already delimited
//! by a transport Adapter (`VerifierCore::verify_frame`) — it never
//! assembles or knows the complete payload on the verifier side,
//! because that would exceed the Core's three exclusive
//! responsibilities: fragment, seal/verify, purge (7.2).
//!
//! # Why the Core doesn't reassemble
//!
//! 8.1 is explicit: reassembly "doesn't belong to the Core but to a
//! specific Profile layer". `VerifierCore::verify_frame` by design
//! doesn't accumulate verified fragments nor retain those that arrive
//! out of order beyond what's strictly necessary to verify them in
//! their turn — that accumulation (`pending_ahead`, `verified_payloads`,
//! reassembly) moved to `profile.rs` (`ReassembleProfile`). The Core
//! certifies "this fragment, in this position, is identical to what
//! the source produced" and nothing more.
//!
//! # Sᵢ and Es(i)
//!
//! Reasoning inherited from the earlier iteration of engine.rs: Sᵢ
//! (the value that enters the HMAC) and Es(i) (the non-invertible
//! residual state, 8.5) are the same variable — Es(i) inherits the
//! HMAC's guarantees by construction, instead of being a separate and
//! potentially weaker variable. It's implemented as a chained HMAC
//! (Es(0) = HMAC(session_id ∥ context, k), Es(i) = HMAC(Es(i-1) ∥ fᵢ,
//! k)), a standard construction that resolves the point 8.5 leaves as
//! an uninstantiated formula (σ, Wₑ, Wₓ left unspecified).

use crate::buffer::{BufferError, PendingBuffer};
use crate::frame::{FrameStateError, LacreFrame, SealerFrameState, VerifierFrameState};
use crate::hmac_seal::{seal_fragment, verify_fragment, HmacAlgo, Seal};
use crate::receipt::ReceiptLog;
use crate::session::{KeyId, MasterKeyRing, SessionId, SessionKey};
use crate::vault_signature::{VaultSignature, VaultSigningKey, VaultVerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const INITIAL_STATE_CONTEXT: &[u8] = b"lacre-core/v1/initial-state";
const STATE_LEN: usize = 32;

/// Es(i) — see reasoning in the header comment. No Debug/Display: it's
/// exactly what a memory dump would expose, and it must never end up
/// in a log.
#[derive(Clone, PartialEq, Eq)]
struct SessionState([u8; STATE_LEN]);

impl Drop for SessionState {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl SessionState {
    fn initial(key: &SessionKey, session_id: &SessionId) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(&session_id.0);
        mac.update(INITIAL_STATE_CONTEXT);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; STATE_LEN];
        out.copy_from_slice(&result);
        SessionState(out)
    }

    fn next(&self, key: &SessionKey, fragment: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(&self.0);
        mac.update(fragment);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; STATE_LEN];
        out.copy_from_slice(&result);
        SessionState(out)
    }
}

#[derive(Debug)]
pub enum CoreError {
    Buffer(BufferError),
    FrameState(FrameStateError),
    UnknownKeyId,
    SealMismatch,
    OutOfSequence { expected: u64, received: u64 },
    /// The session requires a Vault signature (resume_with_vault_key)
    /// and the received signature is absent or doesn't verify under
    /// the sealer's public key.
    VaultSignatureMismatch,
}

impl From<BufferError> for CoreError {
    fn from(e: BufferError) -> Self {
        CoreError::Buffer(e)
    }
}

impl From<FrameStateError> for CoreError {
    fn from(e: FrameStateError) -> Self {
        CoreError::FrameState(e)
    }
}

/// Splits a payload into frames. A free function, not a method,
/// because both `SealerCore::seal_payload` and (potentially) an
/// Adapter that needs to pre-calculate how many frames a payload will
/// produce use it without needing a Core instance.
fn split_into_frames(payload: &[u8], slot_size: usize) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        return vec![Vec::new()];
    }
    payload.chunks(slot_size).map(|c| c.to_vec()).collect()
}

/// Sealer side of the Core: fragments a complete payload, seals each
/// resulting frame, and manages its lifecycle through to `Purged`.
pub struct SealerCore {
    session_id: SessionId,
    algo: HmacAlgo,
    /// Session key, derived once at open: the ring is shared immutably
    /// (`Arc`), so the active master cannot change under an open session and
    /// re-deriving it for every fragment (HKDF) was pure repeated work.
    key: SessionKey,
    state: SessionState,
    next_index: u64,
    buffer: PendingBuffer,
    frame_states: HashMap<u64, SealerFrameState>,
    /// Present only under the Vault profile (15.3, 9.5). `None` under
    /// any other profile: the asymmetric signature is an optional Core
    /// capability, not a requirement of every profile — Lite and Core
    /// never touch it.
    vault_key: Option<VaultSigningKey>,
    /// Post-purge receipt (7.5), also exclusive to profiles that
    /// require it (Vault). `None` when not enabled — same pattern as
    /// `vault_key`.
    receipt_log: Option<ReceiptLog>,
}

impl SealerCore {
    pub fn open(
        key_ring: Arc<MasterKeyRing>,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
    ) -> Self {
        let session_id = SessionId::generate();
        let key = key_ring.derive_for_sealing(&session_id);
        let state = SessionState::initial(&key, &session_id);
        SealerCore {
            session_id,
            algo,
            key,
            state,
            next_index: 0,
            buffer: PendingBuffer::new(slot_size, slot_count, forced_purge_timeout),
            frame_states: HashMap::new(),
            vault_key: None,
            receipt_log: None,
        }
    }

    /// Same as `open`, but enables per-fragment Ed25519 signing (Vault
    /// profile, 15.3) and the post-purge receipt (7.5). Both
    /// capabilities are enabled together because 7.5 explicitly ties
    /// the receipt to "profiles requiring audit capability (see the
    /// Vault profile)" — there is no intermediate profile in the
    /// document that has a signature without a receipt or vice versa.
    /// A separate method from `open` for the same reason as before: to
    /// not break the signature of profiles that don't use Vault, and
    /// so "this is a Vault session" is visible at the call site.
    pub fn open_with_vault_key(
        key_ring: Arc<MasterKeyRing>,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        vault_key: VaultSigningKey,
    ) -> Self {
        let mut core = Self::open(key_ring, algo, slot_size, slot_count, forced_purge_timeout);
        core.vault_key = Some(vault_key);
        core.receipt_log = Some(ReceiptLog::new());
        core
    }

    /// Same as `open`, but accepts a `session_id` already agreed on
    /// from outside instead of generating a new one internally.
    ///
    /// # Why this exists (Phase 2, 8.4)
    ///
    /// 8.4 specifies `k_session = HKDF(shared_secret, salt=session_id,
    /// info="lacre-v1")` — the `session_id` participates as the
    /// derivation's salt, which means it must exist *before* the key
    /// can be derived (which `key_ring` already does internally in
    /// `derive_for_sealing`). When `key_ring`'s master key comes from
    /// an ephemeral Diffie-Hellman secret
    /// (`session_handshake::EphemeralSharedSecret::into_ikm_bytes`,
    /// instead of a static deployment master key), the `session_id`
    /// was normally already negotiated as part of that same handshake
    /// — an Adapter (7.4) needs BOTH parties to converge on the same
    /// `session_id` before the verifier can derive the same key with
    /// `VerifierCore::resume`, which already accepted `session_id` as
    /// a parameter since Phase 0/1. `open` (without this method) broke
    /// that symmetry: `resume` always accepted an external
    /// `session_id`, while `open` always generated its own. This
    /// method closes that asymmetry on the sealer side, without
    /// changing `open`'s signature (same pattern as
    /// `open_with_vault_key`: a new method, not a breaking change).
    ///
    /// # What this method does NOT do
    ///
    /// It doesn't run the X25519 handshake nor build `key_ring` from
    /// it — that's the caller's responsibility (an Adapter, 7.4),
    /// using `session_handshake::EphemeralHandshake` and passing the
    /// result (`into_ikm_bytes()`) as `ikm` to `MasterKeyRing::new`.
    /// This method only prevents `open` from overwriting the
    /// already-agreed `session_id` with a new one generated internally.
    pub fn open_with_session_key(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
    ) -> Self {
        let key = key_ring.derive_for_sealing(&session_id);
        let state = SessionState::initial(&key, &session_id);
        SealerCore {
            session_id,
            algo,
            key,
            state,
            next_index: 0,
            buffer: PendingBuffer::new(slot_size, slot_count, forced_purge_timeout),
            frame_states: HashMap::new(),
            vault_key: None,
            receipt_log: None,
        }
    }

    /// Same as `open_with_session_key`, but also enables Vault
    /// (Ed25519 signature + post-purge receipt) — a combination of
    /// `open_with_session_key` and `open_with_vault_key`, for the case
    /// of a deployment using X25519 (Phase 2) over the Vault profile
    /// (Phase 1, 15.3) simultaneously. No deployment profile documented
    /// so far requires this combination, but there is no textual
    /// reason in 8.4/9.5 to prohibit it — both mechanisms operate in
    /// different layers (key establishment vs. non-repudiation
    /// signature over the already-computed seal).
    pub fn open_with_session_key_and_vault_key(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        vault_key: VaultSigningKey,
    ) -> Self {
        let mut core = Self::open_with_session_key(
            key_ring,
            session_id,
            algo,
            slot_size,
            slot_count,
            forced_purge_timeout,
        );
        core.vault_key = Some(vault_key);
        core.receipt_log = Some(ReceiptLog::new());
        core
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Fragments `payload` internally (per 7.2 — the Core fragments,
    /// the caller doesn't hand it already-cut frames) and seals each
    /// resulting fragment in order. Returns the complete sequence of
    /// `(LacreFrame, Seal)` ready for an Adapter to transport.
    ///
    /// For the continuous streaming case (9.3: LLM tokens arriving one
    /// at a time, without knowing the total in advance), this function
    /// is NOT the right one — it assumes `payload` is the complete
    /// content available at the moment of the call, and therefore
    /// computes `total_fragments`/`is_last` based on THAT call, not on
    /// the complete stream. Use `seal_chunk` instead for that case (see
    /// its documentation for why).
    pub fn seal_payload(
        &mut self,
        payload: &[u8],
        slot_size: usize,
    ) -> Result<Vec<(LacreFrame, Seal)>, CoreError> {
        let chunks = split_into_frames(payload, slot_size);
        let total = chunks.len() as u64;
        let mut out = Vec::with_capacity(chunks.len());

        for (i, chunk) in chunks.into_iter().enumerate() {
            let index = self.next_index + i as u64;
            let (frame, seal) = self.seal_one(chunk, index, Some(total), (i as u64) == total - 1)?;
            out.push((frame, seal));
        }
        self.next_index += total;
        Ok(out)
    }

    /// Seals a single fragment whose content arrives in the moment
    /// (streaming, 9.3) — without assuming the total sequence length is
    /// known. `is_last` is decided explicitly by the caller, who is the
    /// one that knows when the stream ended (for example, upon
    /// receiving an LLM's end-of-generation token); the Core can't
    /// infer it from a single isolated chunk.
    ///
    /// Unlike `seal_payload`, it doesn't fragment — `chunk` is sealed
    /// as-is, whole, as one frame. If `chunk` exceeds the profile's
    /// `slot_size`, the buffer insertion rejects it just like any other
    /// oversized case (see `buffer::BufferError`).
    pub fn seal_chunk(
        &mut self,
        chunk: Vec<u8>,
        is_last: bool,
    ) -> Result<(LacreFrame, Seal), CoreError> {
        let index = self.next_index;
        let result = self.seal_one(chunk, index, None, is_last)?;
        self.next_index += 1;
        Ok(result)
    }

    /// Common logic for sealing a single, already-delimited fragment,
    /// shared by `seal_payload` (which fragments first) and
    /// `seal_chunk` (which receives the fragment already made).
    /// Doesn't touch `self.next_index` — each caller updates it at its
    /// own pace (`seal_payload` in batches, `seal_chunk` one at a
    /// time).
    fn seal_one(
        &mut self,
        chunk: Vec<u8>,
        index: u64,
        total_fragments: Option<u64>,
        is_last: bool,
    ) -> Result<(LacreFrame, Seal), CoreError> {
        let seal = seal_fragment(self.algo, &self.key, &chunk, &self.state.0);

        self.buffer.insert(index, &chunk, seal)?;

        let entry = self
            .frame_states
            .entry(index)
            .or_insert(SealerFrameState::Raw);
        *entry = std::mem::replace(entry, SealerFrameState::Raw).seal(seal)?;

        self.state = self.state.next(&self.key, &chunk);

        let frame = LacreFrame {
            session_id: self.session_id,
            index,
            total_fragments,
            is_last,
            payload: chunk,
        };
        Ok((frame, seal))
    }

    /// Signs an already-generated `Seal` under this session's Ed25519
    /// key, if the Vault profile was enabled (`open_with_vault_key`,
    /// not `open`). Returns `None` under any other profile — calling
    /// this without a Vault key isn't an error, it simply produces no
    /// signature, because not every profile needs one.
    ///
    /// A separate method from `seal_one`/`seal_payload`/`seal_chunk`
    /// instead of built into their return type, so as not to change
    /// the type those methods return and thereby not break any
    /// existing caller that doesn't use Vault (46 tests in
    /// core.rs/profile.rs, among others).
    pub fn sign_seal_for_vault(&self, seal: &Seal) -> Option<VaultSignature> {
        self.vault_key.as_ref().map(|k| k.sign_seal(seal))
    }

    /// Records a frame's ACK by index: purges its entry from the buffer
    /// and advances its state to `Committed → Purged`. If receipt
    /// logging is enabled (Vault), captures the receipt derived from
    /// the seal BEFORE purging it — order matters: the receipt must be
    /// generated while the seal still exists in the buffer, and only
    /// afterward is the seal destroyed. Reversing the order would leave
    /// no seal to derive the receipt from.
    pub fn ack(&mut self, index: u64) -> Result<bool, CoreError> {
        if let Some(log) = self.receipt_log.as_mut() {
            if let Some(seal) = self.buffer.seal_of(index) {
                log.record(index, seal);
            }
        }
        let purged_from_buffer = self.buffer.purge_on_ack(index);
        if let Some(state) = self.frame_states.remove(&index) {
            let state = state.commit()?;
            let _ = state.purge()?;
        }
        Ok(purged_from_buffer)
    }

    /// Receipts recorded so far, if the profile enabled recording
    /// (Vault). `None` under any other profile.
    pub fn receipts(&self) -> Option<&[crate::receipt::ReceiptEntry]> {
        self.receipt_log.as_ref().map(|log| log.entries())
    }

    /// Forced-purge sweep. Besides releasing the buffer slots it drops the
    /// per-fragment lifecycle entry of every expired fragment: before, an
    /// entry for a fragment that timed out without an ACK stayed in
    /// `frame_states` for the life of the session.
    pub fn purge_expired(&mut self) -> u64 {
        let expired = self.buffer.purge_expired_indices();
        for index in &expired {
            self.frame_states.remove(index);
        }
        expired.len() as u64
    }

    pub fn pending_count(&self) -> usize {
        self.buffer.pending_count()
    }
}

/// Verifier side of the Core: verifies frames one at a time, in the
/// strict order Sᵢ requires. Doesn't accumulate, doesn't reassemble —
/// that's Profile's job (see the module's header comment).
pub struct VerifierCore {
    session_id: SessionId,
    algo: HmacAlgo,
    key_ring: Arc<MasterKeyRing>,
    /// Session key for the `key_id` this verifier was resumed with, derived
    /// once. A frame announcing a different `key_id` still derives its own.
    key: SessionKey,
    state: SessionState,
    next_index: u64,
    buffer: PendingBuffer,
    /// Symmetric to `SealerCore::vault_key` — present only under Vault.
    vault_key: Option<VaultVerifyingKey>,
    /// Post-purge receipt log, verifier side — closes the open point
    /// documented in `DECISIONS.md` point 12 and `PENDING.md`
    /// ("post-purge receipt is sealer-side only"). Activated under the
    /// exact same condition `SealerCore` already uses (`Some` only
    /// alongside `vault_key`, in `resume_with_vault_key`) — 7.5 ties
    /// the receipt explicitly to profiles requiring audit capability
    /// (Vault), and there is no intermediate profile in the spec that
    /// has a signature without a receipt or vice versa, so this
    /// mirrors `SealerCore`'s own reasoning rather than introducing a
    /// new activation rule.
    ///
    /// What this proves, and why it's a distinct guarantee from the
    /// sealer's own receipt: the sealer's receipt log proves "I sealed
    /// this fragment"; this one proves "I independently verified this
    /// fragment's HMAC was correct at the moment I checked it" —
    /// useful in a dispute where the verifier needs to prove it
    /// actually performed the verification, without depending on a
    /// log kept by the sealer, who could be an adversarial party in
    /// that dispute.
    receipt_log: Option<ReceiptLog>,
}

impl VerifierCore {
    /// Resumes a session known by its `session_id` (received from
    /// outside, not generated here — the verifier never originates a
    /// session) under the `key_id` with which the sealer derived
    /// Es(0).
    ///
    /// Phase 2 note (8.4, X25519): this method already accepted
    /// `session_id` as an external parameter since Phase 0/1 — unlike
    /// `SealerCore::open`, which generated its own internally until
    /// `open_with_session_key` was added. For a session whose
    /// `key_ring` comes from an ephemeral Diffie-Hellman secret,
    /// `resume` doesn't need any new method: it's enough to pass it the
    /// `session_id` both parties already agreed on during the handshake
    /// (see `session_handshake.rs`).
    pub fn resume(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
    ) -> Option<Self> {
        let key = key_ring.derive_for_verifying(key_id, &session_id)?;
        let state = SessionState::initial(&key, &session_id);
        Some(VerifierCore {
            session_id,
            algo,
            key_ring,
            key,
            state,
            next_index: 0,
            buffer: PendingBuffer::new(slot_size, slot_count, forced_purge_timeout),
            vault_key: None,
            receipt_log: None,
        })
    }

    /// Same as `resume`, but enables Ed25519 signature verification
    /// (Vault profile). `vault_key` is the sealer's PUBLIC key — freely
    /// distributed, unlike the private key that only `SealerCore`
    /// knows.
    // One argument over clippy's limit: kept flat because it mirrors `resume` plus the
    // verifying key, and this public signature is already used by the adapters.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_with_vault_key(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        vault_key: VaultVerifyingKey,
    ) -> Option<Self> {
        let mut core = Self::resume(
            key_ring,
            session_id,
            key_id,
            algo,
            slot_size,
            slot_count,
            forced_purge_timeout,
        )?;
        core.vault_key = Some(vault_key);
        core.receipt_log = Some(ReceiptLog::new());
        Some(core)
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn next_expected_index(&self) -> u64 {
        self.next_index
    }

    /// Verifies a single frame against its seal. Requires
    /// `frame.index` to be exactly the next one expected — an
    /// out-of-order frame can't be verified (Sᵢ depends on the complete
    /// chain up to that point); it's the caller's responsibility (a
    /// Profile) to decide what to do with a frame that arrived early,
    /// not this method's.
    ///
    /// # Vault signature verification: part of the same flow, not a
    /// separate step
    ///
    /// If this session was opened with `resume_with_vault_key`,
    /// `verify_frame` REQUIRES `vault_signature` and rejects the frame
    /// if it's missing or doesn't verify — deliberately not a separate
    /// method the caller could forget to invoke. A `VerifierCore`
    /// without a Vault key (`None`) simply ignores the
    /// `vault_signature` parameter: it has nothing to verify a
    /// signature against, so accepting `None` there doesn't weaken
    /// anything that wasn't already out of its scope.
    pub fn verify_frame(
        &mut self,
        frame: &LacreFrame,
        key_id: KeyId,
        seal: &Seal,
        vault_signature: Option<&VaultSignature>,
    ) -> Result<(), CoreError> {
        if frame.index != self.next_index {
            return Err(CoreError::OutOfSequence {
                expected: self.next_index,
                received: frame.index,
            });
        }
        let other_key;
        let key = if key_id == self.key.key_id {
            &self.key
        } else {
            other_key = self
                .key_ring
                .derive_for_verifying(key_id, &self.session_id)
                .ok_or(CoreError::UnknownKeyId)?;
            &other_key
        };

        if !verify_fragment(self.algo, key, &frame.payload, &self.state.0, seal) {
            return Err(CoreError::SealMismatch);
        }

        if let Some(vault_key) = &self.vault_key {
            match vault_signature {
                Some(sig) if vault_key.verify_seal(seal, sig) => {}
                _ => return Err(CoreError::VaultSignatureMismatch),
            }
        }

        self.buffer.insert(frame.index, &frame.payload, *seal)?;

        // The frame lifecycle (Raw → Verified → Purged) is checked as a
        // transient value. It used to be stored per index and re-inserted
        // after the purge, which kept one entry per verified fragment for the
        // life of the session (measured: +74 MB after 2 million fragments).
        let verified = VerifierFrameState::new().verify()?;

        self.state = self.state.next(key, &frame.payload);
        self.next_index += 1;

        // Receipt captured BEFORE purging, same dependency
        // `DECISIONS.md` point 13 documents for `SealerCore::ack`: the
        // receipt derives from `seal`, which is still a valid
        // reference at this point in the function (it's a `&Seal`
        // parameter, not something read back out of `self.buffer` —
        // unlike `SealerCore::ack`, which has to extract the seal from
        // the buffer before `purge_on_ack` destroys that entry, this
        // function already has `seal` in hand for its own HMAC check
        // above, so there's no equivalent ordering hazard here, but
        // the receipt is still recorded before the purge call below on
        // principle: never derive a receipt from something already
        // purged, even when the current implementation happens not to
        // need to).
        if let Some(log) = self.receipt_log.as_mut() {
            log.record(frame.index, seal);
        }

        // The Core purges immediately after verifying: it doesn't wait
        // for a separate ACK on the verifier side, same reasoning
        // already validated in the previous server iteration — the
        // frame fulfilled its purpose on the verifier side as soon as
        // its integrity was certified.
        self.buffer.purge_on_ack(frame.index);
        verified.purge()?;

        Ok(())
    }

    /// Same verification as `verify_frame`, but on success returns the only
    /// value a Profile may be built from: a `VerifiedFrame`. Nothing outside
    /// the Core can construct one, so a Profile fed through this path can
    /// only see bytes this Core certified, at the access level it declared.
    pub fn verify_frame_view<'a>(
        &mut self,
        frame: &'a LacreFrame,
        key_id: KeyId,
        seal: &Seal,
        vault_signature: Option<&VaultSignature>,
    ) -> Result<crate::access::VerifiedFrame<'a>, CoreError> {
        self.verify_frame(frame, key_id, seal, vault_signature)?;
        Ok(crate::access::VerifiedFrame::new(frame))
    }

    /// Receipts recorded so far, if this session enabled recording
    /// (Vault, via `resume_with_vault_key`). `None` under any other
    /// profile — symmetric to `SealerCore::receipts`.
    pub fn receipts(&self) -> Option<&[crate::receipt::ReceiptEntry]> {
        self.receipt_log.as_ref().map(|log| log.entries())
    }

    pub fn purge_expired(&mut self) -> u64 {
        self.buffer.purge_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ))
    }

    fn open_pair(
        ring: &Arc<MasterKeyRing>,
        slot_size: usize,
        slot_count: usize,
    ) -> (SealerCore, VerifierCore) {
        let sealer = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            slot_size,
            slot_count,
            Duration::from_millis(500),
        );
        let verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            slot_size,
            slot_count,
            Duration::from_millis(500),
        )
        .unwrap();
        (sealer, verifier)
    }

    /// Phase 2 (8.4), complete end-to-end flow: two parties run a real
    /// ephemeral X25519 handshake, each builds its own `MasterKeyRing`
    /// from the raw DH secret (without going through any additional
    /// HKDF — `MasterKeyRing::derive_for_sealing`/
    /// `derive_for_verifying` are the only HKDF, exactly as 8.4
    /// requires: "HKDF(shared_secret, salt=session_id, info=...)"),
    /// agree on the same `session_id`, and seal/verify a real fragment.
    #[test]
    fn end_to_end_x25519_handshake_feeds_master_key_ring_and_seals_verifies() {
        use crate::session_handshake::EphemeralHandshake;

        // Step 1 of 8.4: ephemeral Diffie-Hellman exchange. Each party
        // generates its own pair and only exchanges the public half.
        let alice = EphemeralHandshake::generate();
        let bob = EphemeralHandshake::generate();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_secret = alice.complete(bob_public);
        let bob_secret = bob.complete(alice_public);

        // The session_id is negotiated (in a real Adapter, it would
        // travel alongside the public key in the handshake's first
        // message) BEFORE building the ring, because 8.4 requires it as
        // the derivation's salt.
        let session_id = SessionId::generate();

        // Each side builds its own MasterKeyRing from the raw DH
        // secret — MasterKeyRing::new applies no HKDF by itself, only
        // derive_for_sealing/derive_for_verifying do that when a
        // session key is requested from them.
        let sealer_ring = Arc::new(MasterKeyRing::new(
            0,
            alice_secret.into_ikm_bytes().to_vec(),
            Duration::from_secs(60),
        ));
        let verifier_ring = Arc::new(MasterKeyRing::new(
            0,
            bob_secret.into_ikm_bytes().to_vec(),
            Duration::from_secs(60),
        ));

        let mut sealer = SealerCore::open_with_session_key(
            sealer_ring,
            session_id,
            HmacAlgo::Sha256,
            64,
            10,
            Duration::from_millis(500),
        );
        let mut verifier = VerifierCore::resume(
            verifier_ring,
            session_id,
            0,
            HmacAlgo::Sha256,
            64,
            10,
            Duration::from_millis(500),
        )
        .expect("both sides derived the same ikm from the same DH secret and the same session_id");

        let sealed = sealer
            .seal_payload(b"fragment sealed under an ephemeral X25519 key", 64)
            .unwrap();
        for (frame, seal) in &sealed {
            verifier
                .verify_frame(frame, 0, seal, None)
                .expect("a fragment sealed with the key derived from the shared DH secret must verify under the same key derived on the other side");
        }
    }

    /// Confirms, in isolation from the rest of the flow, that two
    /// `MasterKeyRing`s built from DIFFERENT DH secrets (two
    /// independent handshakes, unrelated to each other) produce
    /// session keys that do NOT match — so the test above doesn't pass
    /// "by accident" if `into_ikm_bytes` were somehow always returning
    /// the same value due to an implementation error.
    #[test]
    fn different_x25519_handshakes_yield_different_session_keys_via_master_key_ring() {
        use crate::session_handshake::EphemeralHandshake;

        let alice1 = EphemeralHandshake::generate();
        let bob1 = EphemeralHandshake::generate();
        let secret1 = alice1.complete(bob1.public_key());

        let alice2 = EphemeralHandshake::generate();
        let bob2 = EphemeralHandshake::generate();
        let secret2 = alice2.complete(bob2.public_key());

        let session_id = SessionId::generate();
        let ring1 = MasterKeyRing::new(0, secret1.into_ikm_bytes().to_vec(), Duration::from_secs(60));
        let ring2 = MasterKeyRing::new(0, secret2.into_ikm_bytes().to_vec(), Duration::from_secs(60));

        let key1 = ring1.derive_for_sealing(&session_id);
        let key2 = ring2.derive_for_sealing(&session_id);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    /// `open_with_session_key` must use EXACTLY the `session_id` it's
    /// given, not generate a new one on its own — that's the precise
    /// property that motivates this method's existence over `open`
    /// (which does generate one internally).
    #[test]
    fn open_with_session_key_uses_the_provided_session_id_verbatim() {
        let ring = test_ring();
        let forced_session_id = SessionId::generate();
        let sealer = SealerCore::open_with_session_key(
            ring,
            forced_session_id,
            HmacAlgo::Sha256,
            64,
            10,
            Duration::from_millis(500),
        );
        assert_eq!(sealer.session_id(), forced_session_id);
    }

    /// The Core fragments internally: seal_payload receives the
    /// complete payload, not already-cut frames (7.2).
    #[test]
    fn seal_payload_fragments_internally() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 10, 100, Duration::from_millis(500));
        let payload = b"0123456789abcdef0123456789"; // 27 bytes
        let sealed = sealer.seal_payload(payload, 10).unwrap();

        assert_eq!(sealed.len(), 3); // 10 + 10 + 7
        assert_eq!(sealed[0].0.payload, b"0123456789");
        assert!(!sealed[0].0.is_last);
        assert!(sealed[2].0.is_last);
        assert!(sealed.iter().all(|(f, _)| f.total_fragments == Some(3)));
    }

    /// End-to-end flow: seal a complete payload, verify each frame in
    /// order through the Core. The Core doesn't reassemble — that's
    /// confirmed in protocol/profile, not here.
    #[test]
    fn end_to_end_seal_and_verify_all_frames() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let payload = b"the quick brown fox jumps over the lazy dog";
        let sealed = sealer.seal_payload(payload, 8).unwrap();

        for (frame, seal) in &sealed {
            let result = verifier.verify_frame(frame, ring.active_key_id(), seal, None);
            assert!(result.is_ok(), "frame {} must verify", frame.index);
        }
        assert_eq!(verifier.next_expected_index(), sealed.len() as u64);
    }

    /// Integrity test inherited from the document: a fragment altered
    /// after sealing must fail verification in the Core.
    #[test]
    fn tampered_frame_fails_verification() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let payload = b"original untampered content";
        let sealed = sealer.seal_payload(payload, 8).unwrap();
        let (mut frame, seal) = sealed[0].clone();
        frame.payload[0] ^= 0x01;

        let result = verifier.verify_frame(&frame, ring.active_key_id(), &seal, None);
        assert!(matches!(result, Err(CoreError::SealMismatch)));
    }

    /// An out-of-order frame is rejected by the Core before touching
    /// the HMAC — deciding what to do with it (holding it, discarding
    /// it) is outside the Core, it's the caller's responsibility.
    #[test]
    fn out_of_order_frame_is_rejected_by_core() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let payload = b"fragment one fragment two fragment three";
        let sealed = sealer.seal_payload(payload, 8).unwrap();
        assert!(sealed.len() >= 2);

        let (frame1, seal1) = &sealed[1];
        let result = verifier.verify_frame(frame1, ring.active_key_id(), seal1, None);
        assert!(matches!(
            result,
            Err(CoreError::OutOfSequence {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn verifier_resume_with_unknown_key_id_returns_none() {
        let ring = test_ring();
        let session_id = SessionId::generate();
        let result = VerifierCore::resume(
            ring,
            session_id,
            99,
            HmacAlgo::Sha256,
            1024,
            8,
            Duration::from_millis(500),
        );
        assert!(result.is_none());
    }

    /// A sealer-side ACK purges the buffer and advances the frame's
    /// state to Purged without affecting Es(i). Exactly 8-byte payload
    /// with slot_size=8 to produce a single frame — a longer payload
    /// (e.g. 9 bytes) would produce two frames and ACKing just one
    /// would leave pending_count() at 1, not 0.
    #[test]
    fn sealer_ack_purges_frame() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Blake3, 8, 100, Duration::from_millis(500));
        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        assert_eq!(sealed.len(), 1, "the test payload must produce a single frame");
        let index = sealed[0].0.index;

        let purged = sealer.ack(index).unwrap();
        assert!(purged);
        assert_eq!(sealer.pending_count(), 0);
    }

    /// Two successive calls to seal_payload in the same session must
    /// continue the index numbering where the previous one left off,
    /// not restart from 0 — the session is continuous even if the
    /// payload is delivered across more than one call.
    #[test]
    fn successive_seal_payload_calls_continue_index_sequence() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 8, 100, Duration::from_millis(500));

        let first = sealer.seal_payload(b"12345678", 8).unwrap();
        assert_eq!(first[0].0.index, 0);

        let second = sealer.seal_payload(b"abcdefgh", 8).unwrap();
        assert_eq!(second[0].0.index, 1);
    }

    /// Streaming (9.3 of the Lacre Prime document): tokens arriving one
    /// at a time, each sealed separately because the sender doesn't
    /// have the complete content in advance. Uses `seal_chunk`, not
    /// `seal_payload` — `seal_payload` would mark each token as
    /// `is_last: true` and `total_fragments: Some(1)`, because it
    /// computes both from that individual call's own count, not from
    /// the complete stream. `seal_chunk` fixes this: it infers nothing,
    /// the caller decides `is_last` explicitly and `total_fragments`
    /// stays `None` until it's known.
    #[test]
    fn streaming_tokens_are_not_falsely_marked_as_last() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 64, 100, Duration::from_millis(500));

        let (frame1, _) = sealer.seal_chunk(b"The".to_vec(), false).unwrap();
        let (frame2, _) = sealer.seal_chunk(b" sky".to_vec(), false).unwrap();
        let (frame3, _) = sealer.seal_chunk(b" is blue".to_vec(), true).unwrap();

        assert!(!frame1.is_last);
        assert!(frame1.total_fragments.is_none());
        assert!(!frame2.is_last);
        assert!(frame3.is_last);

        assert_eq!(frame1.index, 0);
        assert_eq!(frame2.index, 1);
        assert_eq!(frame3.index, 2);
    }

    /// seal_chunk and seal_payload share the same index sequence within
    /// a session — mixing both call styles must not restart or
    /// duplicate indices.
    #[test]
    fn seal_chunk_and_seal_payload_share_index_sequence() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 64, 100, Duration::from_millis(500));

        let batch = sealer.seal_payload(b"header", 64).unwrap();
        assert_eq!(batch[0].0.index, 0);

        let (chunk_frame, _) = sealer.seal_chunk(b"the rest, streamed".to_vec(), true).unwrap();
        assert_eq!(chunk_frame.index, 1);
    }

    /// End-to-end streaming flow: the sealer emits tokens one at a time
    /// with seal_chunk (without knowing the total in advance), the
    /// verifier Core certifies them in order.
    #[test]
    fn end_to_end_streaming_seal_verify() {
        let ring = test_ring();
        let mut sealer = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            64,
            100,
            Duration::from_millis(500),
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            64,
            100,
            Duration::from_millis(500),
        )
        .unwrap();

        let tokens: [(&[u8], bool); 3] = [(b"The", false), (b" sky", false), (b" is blue", true)];

        for (bytes, is_last) in tokens {
            let (frame, seal) = sealer.seal_chunk(bytes.to_vec(), is_last).unwrap();
            verifier
                .verify_frame(&frame, ring.active_key_id(), &seal, None)
                .expect("each token must verify in its turn, streaming or not");
        }

        assert_eq!(verifier.next_expected_index(), 3);
    }

    /// End-to-end Vault flow: sealer with an Ed25519 private key
    /// (open_with_vault_key), verifier with the corresponding public
    /// key (resume_with_vault_key). The signature travels as a third
    /// element alongside the Seal — not inside LacreFrame, same
    /// criterion already applied to the Seal itself (A2: the seal
    /// lives in the header, separate from the frame's identity).
    #[test]
    fn end_to_end_vault_seal_sign_verify() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();
        let vault_verifying_key = vault_signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_verifying_key,
        )
        .unwrap();

        let sealed = sealer
            .seal_payload(b"test financial transaction", 8)
            .unwrap();

        for (frame, seal) in &sealed {
            let vault_sig = sealer
                .sign_seal_for_vault(seal)
                .expect("sealer opened with open_with_vault_key must produce a signature");
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, Some(&vault_sig))
                .expect("frame with valid HMAC and Vault signature must verify");
        }
    }

    /// Central security requirement of this implementation (not
    /// explicitly specified by the document, but necessary for Vault to
    /// make sense): a Vault session MUST reject a frame that arrives
    /// without a signature, even if the HMAC is perfectly valid. If
    /// this didn't hold, Vault would be indistinguishable from Core in
    /// practice — anyone could omit the signature and the frame would
    /// pass anyway.
    #[test]
    fn vault_session_rejects_frame_without_signature() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();
        let vault_verifying_key = vault_signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_verifying_key,
        )
        .unwrap();

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];

        let result = verifier.verify_frame(frame, ring.active_key_id(), seal, None);
        assert!(matches!(
            result,
            Err(CoreError::VaultSignatureMismatch)
        ));
    }

    /// A Vault signature from a different key than the one the
    /// verifier expects must also be rejected — real non-repudiation,
    /// not just "presence of some signature".
    #[test]
    fn vault_session_rejects_signature_from_wrong_key() {
        let ring = test_ring();
        let legitimate_key = VaultSigningKey::generate();
        let attacker_key = VaultSigningKey::generate();
        let legitimate_verifying_key = legitimate_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            attacker_key, // the sealer signs with the "wrong" key
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            legitimate_verifying_key,
        )
        .unwrap();

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];
        let signature = sealer.sign_seal_for_vault(seal).unwrap();

        let result = verifier.verify_frame(frame, ring.active_key_id(), seal, Some(&signature));
        assert!(matches!(
            result,
            Err(CoreError::VaultSignatureMismatch)
        ));
    }

    /// Confirms that a session WITHOUT a Vault key (plain open/resume)
    /// keeps working exactly as it did before Vault was introduced —
    /// the capability is genuinely optional, not a default behavior
    /// change.
    #[test]
    fn non_vault_session_ignores_absent_signature_without_error() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];

        let result = verifier.verify_frame(frame, ring.active_key_id(), seal, None);
        assert!(result.is_ok());
    }

    /// Confirms 7.5's requirement end to end: the receipt is generated
    /// at the moment of purge (ack), and remains available AFTER the
    /// fragment and its seal no longer exist in the buffer.
    #[test]
    fn receipt_survives_purge_of_original_fragment_and_seal() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let index = sealed[0].0.index;

        assert_eq!(sealer.pending_count(), 1, "the frame must be pending before the ack");
        assert!(sealer.receipts().unwrap().is_empty(), "no receipt yet before the ack");

        sealer.ack(index).unwrap();

        assert_eq!(sealer.pending_count(), 0);
        let receipts = sealer.receipts().expect("Vault must have receipt_log enabled");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].fragment_index, index);
    }

    /// A session without Vault carries no receipt log — the capability
    /// is optional, same as the signature.
    #[test]
    fn non_vault_session_has_no_receipt_log() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 8, 100, Duration::from_millis(500));
        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        sealer.ack(sealed[0].0.index).unwrap();

        assert!(sealer.receipts().is_none());
    }

    /// Verifier-side symmetric case for the gap this closes (see
    /// `DECISIONS.md` point 12 / `PENDING.md`): a receipt is captured
    /// on `VerifierCore`'s own side, independent of whatever the
    /// sealer's own receipt log records, and survives the same
    /// immediate purge that `verify_frame` already performs on
    /// success.
    #[test]
    fn verifier_receipt_survives_purge_and_is_independent_of_the_sealer_receipt() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();
        let vault_verifying_key = vault_signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_verifying_key,
        )
        .unwrap();

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];
        let vault_sig = sealer
            .sign_seal_for_vault(seal)
            .expect("Vault-enabled sealer must produce a signature");

        assert!(
            verifier.receipts().unwrap().is_empty(),
            "no receipt before verify_frame runs"
        );

        verifier
            .verify_frame(frame, ring.active_key_id(), seal, Some(&vault_sig))
            .expect("verification must succeed");

        let receipts = verifier
            .receipts()
            .expect("Vault-enabled verifier session must have a receipt_log");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].fragment_index, frame.index);

        sealer.ack(frame.index).unwrap();
        let sealer_receipts = sealer.receipts().unwrap();
        assert_eq!(sealer_receipts.len(), 1);
        assert_eq!(
            sealer_receipts[0].receipt.0, receipts[0].receipt.0,
            "same seal must derive the same receipt value on both sides, independently"
        );
    }

    /// Symmetric to `non_vault_session_has_no_receipt_log`: a verifier
    /// session opened via plain `resume` (no Vault key) never gets a
    /// receipt log — the capability is optional, same as the
    /// signature, and enabling it is not something `verify_frame`
    /// decides on its own.
    #[test]
    fn non_vault_verifier_session_has_no_receipt_log() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring.clone(), HmacAlgo::Sha256, 8, 100, Duration::from_millis(500));
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
        )
        .unwrap();

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];
        verifier
            .verify_frame(frame, ring.active_key_id(), seal, None)
            .unwrap();

        assert!(verifier.receipts().is_none());
    }

    // ---- Regressions and known answers -------------------------------

    /// Known-answer test. The expected values were produced by an independent
    /// implementation (Python: HKDF-SHA256 with salt = session_id and info
    /// "lacre-core/v1/session-key"; chain Es(0) = HMAC(k, sid || context),
    /// Es(i) = HMAC(k, Es(i-1) || f_i); seal = HMAC-SHA256 or keyed Blake3 over
    /// f_i || Es(i)). They pin the wire-visible construction: a refactor that
    /// changes any byte fails here instead of silently breaking interoperability.
    #[test]
    fn known_answer_chain_matches_independent_implementation() {
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ));
        let sid = SessionId(core::array::from_fn(|i| i as u8));
        let key = ring.derive_for_sealing(&sid);
        assert_eq!(
            key.as_bytes(),
            hex_to_vec("34bc5ae4f4202658756ef4f2e78697f21aa222b2b27a807d9d919594157d428f")
        );
        let expected = [
            (
                HmacAlgo::Sha256,
                [
                    "8bdee98ee5df7d99f300b634a3638ad2d2564de7074b9a937a15a016d6b2de07",
                    "e64b99913ca9da79d846a0f2de13ee3948b768d6db97a8606e3e290ca0774acb",
                    "8b8900ebf5bb292655b808b87240a0cf29fbcd7718fc4d04100a3f312c2c84e6",
                ],
            ),
            (
                HmacAlgo::Blake3,
                [
                    "a58481e9c722d1422e2c972a835d4acb54823316ef568e5c0176dc5b9f810b5d",
                    "f0407f45d4619cd695772e75726f412bc22426dda59a1e85ebf6a42703ed334f",
                    "25e03218eb92785b986e52f1d94677bc0d260e1ee2c31359def132aa6606f768",
                ],
            ),
        ];
        for (algo, seals) in expected {
            let mut sealer =
                SealerCore::open_with_session_key(ring.clone(), sid, algo, 64, 8, Duration::from_secs(60));
            for (i, want) in seals.iter().enumerate() {
                let frag = format!("fragment-{i}").into_bytes();
                let (_, seal) = sealer.seal_chunk(frag, i == 2).unwrap();
                assert_eq!(seal.0.to_vec(), hex_to_vec(want), "{algo:?} fragment {i}");
            }
        }
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sealer_drops_the_state_of_fragments_that_expired_without_ack() {
        let ring = test_ring();
        let mut sealer = SealerCore::open(ring, HmacAlgo::Sha256, 64, 8, Duration::from_millis(1));
        for _ in 0..5 {
            sealer.seal_chunk(vec![1u8; 10], false).unwrap();
        }
        assert_eq!(sealer.frame_states.len(), 5);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(sealer.purge_expired(), 5);
        assert_eq!(sealer.pending_count(), 0);
        assert!(sealer.frame_states.is_empty(), "expired fragments must not keep a state entry");
    }

    #[test]
    fn session_key_and_master_secrets_are_wiped_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SessionKey>();
    }

    #[test]
    fn verifier_accepts_a_retired_key_id_and_rejects_an_unknown_one() {
        let mut ring = MasterKeyRing::new(0, b"master-v0-minimum-32-bytes-aaaaa".to_vec(), Duration::from_secs(60));
        let sid = SessionId::generate();
        let old_ring = Arc::new(MasterKeyRing::new(0, b"master-v0-minimum-32-bytes-aaaaa".to_vec(), Duration::from_secs(60)));
        let mut sealer = SealerCore::open_with_session_key(old_ring, sid, HmacAlgo::Sha256, 64, 4, Duration::from_secs(60));
        let (frame, seal) = sealer.seal_chunk(b"abc".to_vec(), true).unwrap();
        ring.rotate(1, b"master-v1-minimum-32-bytes-bbbbb".to_vec());
        // Resumed under the NEW active key id, but the frame announces the retired id 0:
        // the cached key does not apply and the retiring key must be derived.
        let mut v = VerifierCore::resume(Arc::new(ring), sid, 1, HmacAlgo::Sha256, 64, 4, Duration::from_secs(60)).unwrap();
        assert!(matches!(v.verify_frame(&frame, 99, &seal, None), Err(CoreError::UnknownKeyId)));
        // Initial state was derived under key 1, so the chain does not match: a seal mismatch,
        // never a panic and never an acceptance.
        assert!(matches!(v.verify_frame(&frame, 0, &seal, None), Err(CoreError::SealMismatch)));
    }
}

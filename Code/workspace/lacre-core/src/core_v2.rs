//! Wire v2 sealer and verifier (see spec/LACRE-WIRE-v2.md).
//!
//! Additive: the v1 Core in `core.rs` is untouched, so v1 bytes cannot change.
//! What differs from v1:
//!
//! * The seal algorithm is a `SealMac` chosen per session through a
//!   `SuiteDescriptor`; the tag length is the suite's, 1..=1024 bytes.
//! * The seal key and the chain key are different keys, both derived with the
//!   hash of the whole descriptor, so a tag of one algorithm never verifies
//!   under another and the chain key never authenticates a seal.
//! * The seal authenticates `u64be(len f) ∥ f ∥ Es(i)` (`SealInput`).
//! * Es(i) is HMAC-SHA256 under the chain key, with the descriptor hash in
//!   Es(0). That suite is normative and independent of the seal.
//! * The Core builds the output buffer and compares in constant time; the
//!   algorithm only computes.
//! * The buffers' memory (`slot_count × (slot_size + tag_len)`) is checked
//!   against a cap before anything is allocated.
//!
//! Vault (stage E5): a suite whose descriptor names a `SignatureScheme` is
//! opened with `open_signed` / `resume_signed`. Every frame then carries a
//! signature over `SignInput` (suite, session, index, tag length and tag); the
//! verifier checks it after the tag and before touching its state. The signing
//! sealer also records a v2 receipt per ACK, before purging.

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::buffer::PendingBuffer;
use crate::core::CoreError;
use crate::frame::{LacreFrame, VerifierFrameState};
use crate::session::{ContextKey, KeyId, MasterKeyRing, SessionId};
use crate::receipt::{Receipt, ReceiptEntry, ReceiptLog};
use crate::suite::{
    check_memory_budget, derive_receipt_v2, SealInput, SealTag, SignInput, SuiteError, ValidatedSuite, CHAIN_STATE_LEN,
};

/// The secret key of a signing session; erased when dropped. No Debug.
struct SigningSecret(Vec<u8>);

impl Drop for SigningSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// What a signing sealer holds: the secret and the receipts it has issued.
struct Signer {
    secret: SigningSecret,
    receipts: ReceiptLog,
}

const INITIAL_STATE_CONTEXT_V2: &[u8] = b"lacre/v2/initial-state";

/// Size and lifetime of a session's buffers, plus the memory cap they must fit in.
#[derive(Debug, Clone, Copy)]
pub struct BufferSpec {
    pub slot_size: usize,
    pub slot_count: usize,
    pub forced_purge_timeout: Duration,
    /// Upper bound for `slot_count × (slot_size + tag_len)`; checked before
    /// anything is allocated.
    pub memory_cap: usize,
}

impl BufferSpec {
    pub fn new(slot_size: usize, slot_count: usize, forced_purge_timeout: Duration, memory_cap: usize) -> Self {
        BufferSpec { slot_size, slot_count, forced_purge_timeout, memory_cap }
    }
}

/// Es(i) under the v2 chain suite. No Debug: it is what a memory dump exposes.
struct ChainState([u8; CHAIN_STATE_LEN]);

impl Drop for ChainState {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl ChainState {
    /// Es(0) = HMAC(k_chain, session_id ∥ context ∥ suite_hash).
    fn initial(chain_key: &ContextKey, session_id: &SessionId, suite_hash: &[u8; 32]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(chain_key.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(&session_id.0);
        mac.update(INITIAL_STATE_CONTEXT_V2);
        mac.update(suite_hash);
        ChainState(mac.finalize().into_bytes().into())
    }

    /// Es(i) = HMAC(k_chain, Es(i-1) ∥ f_i).
    fn next(&self, chain_key: &ContextKey, fragment: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(chain_key.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(&self.0);
        mac.update(fragment);
        ChainState(mac.finalize().into_bytes().into())
    }
}

/// The tag of a fragment under this suite, computed into a Core-owned buffer.
fn compute_tag(suite: &ValidatedSuite, key: &ContextKey, fragment: &[u8], state: &ChainState) -> Vec<u8> {
    let input = SealInput::new(fragment, &state.0);
    let mut out = vec![0u8; suite.tag_len()];
    suite.mac().mac(key.as_bytes(), &input, &mut out);
    out
}

fn derive(
    ring: &MasterKeyRing,
    key_id: Option<KeyId>,
    session_id: &SessionId,
    suite: &ValidatedSuite,
) -> Result<crate::session::V2Keys, SuiteError> {
    let keys = match key_id {
        None => ring.derive_v2_for_sealing(session_id, suite.suite_hash(), suite.key_len()),
        Some(id) => ring.derive_v2_for_verifying(id, session_id, suite.suite_hash(), suite.key_len()),
    };
    keys.ok_or(match key_id {
        Some(id) if !ring.knows_key(id) => SuiteError::UnknownKeyId,
        _ => SuiteError::KeyDerivationFailed,
    })
}

/// Sealer side of wire v2.
pub struct SealerCoreV2 {
    session_id: SessionId,
    suite: ValidatedSuite,
    key_id: KeyId,
    seal_key: ContextKey,
    chain_key: ContextKey,
    state: ChainState,
    next_index: u64,
    slot_size: usize,
    /// The buffer is the single record of what is sealed and not yet
    /// acknowledged: pending iff present. (v1 keeps a second per-index state
    /// machine that mirrors it.)
    buffer: PendingBuffer,
    /// Present exactly when the suite names a signature scheme (Vault).
    signer: Option<Signer>,
}

impl SealerCoreV2 {
    /// Opens a session with a fresh `session_id`. Fails before allocating if
    /// the buffers would exceed `memory_cap`.
    pub fn open(
        key_ring: Arc<MasterKeyRing>,
        suite: ValidatedSuite,
        spec: BufferSpec,
    ) -> Result<Self, SuiteError> {
        Self::open_with_session_id(key_ring, SessionId::generate(), suite, spec)
    }

    pub fn open_with_session_id(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        suite: ValidatedSuite,
        spec: BufferSpec,
    ) -> Result<Self, SuiteError> {
        if suite.signature_scheme().is_some() {
            // A suite that names a scheme needs its secret key: `open_signed`.
            return Err(SuiteError::SignatureSchemeMismatch);
        }
        Self::build(key_ring, session_id, suite, spec, None)
    }

    /// Opens a signing session (Vault): the suite must name a scheme and
    /// `secret` must be a valid secret key of that scheme. `session_id` `None`
    /// generates a fresh one.
    pub fn open_signed(
        key_ring: Arc<MasterKeyRing>,
        session_id: Option<SessionId>,
        suite: ValidatedSuite,
        spec: BufferSpec,
        secret: &[u8],
    ) -> Result<Self, SuiteError> {
        let Some(scheme) = suite.signature_scheme() else {
            return Err(SuiteError::SignatureSchemeMismatch);
        };
        if secret.len() != scheme.secret_key_len() {
            return Err(SuiteError::SignatureKeyInvalid);
        }
        match scheme.public_from_secret(secret) {
            Some(p) if p.len() == scheme.public_key_len() => {}
            _ => return Err(SuiteError::SignatureKeyInvalid),
        }
        let signer = Signer { secret: SigningSecret(secret.to_vec()), receipts: ReceiptLog::new() };
        Self::build(key_ring, session_id.unwrap_or_else(SessionId::generate), suite, spec, Some(signer))
    }

    fn build(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        suite: ValidatedSuite,
        spec: BufferSpec,
        signer: Option<Signer>,
    ) -> Result<Self, SuiteError> {
        check_memory_budget(spec.slot_size, spec.slot_count, suite.tag_len(), spec.memory_cap)?;
        let keys = derive(&key_ring, None, &session_id, &suite)?;
        let state = ChainState::initial(&keys.chain, &session_id, suite.suite_hash());
        let buffer = PendingBuffer::with_tag_len(spec.slot_size, spec.slot_count, spec.forced_purge_timeout, suite.tag_len());
        let slot_size = spec.slot_size;
        Ok(SealerCoreV2 {
            session_id,
            key_id: keys.seal.key_id(),
            seal_key: keys.seal,
            chain_key: keys.chain,
            suite,
            state,
            next_index: 0,
            slot_size,
            buffer,
            signer,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }
    pub fn suite(&self) -> &ValidatedSuite {
        &self.suite
    }

    /// Fragments a complete payload by the session's slot size and seals each
    /// fragment.
    pub fn seal_payload(&mut self, payload: &[u8]) -> Result<Vec<(LacreFrame, SealTag)>, CoreError> {
        let chunks: Vec<Vec<u8>> = if payload.is_empty() {
            vec![Vec::new()]
        } else {
            payload.chunks(self.slot_size).map(|c| c.to_vec()).collect()
        };
        let total = chunks.len() as u64;
        let mut out = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.into_iter().enumerate() {
            let index = self.next_index;
            let sealed = self.seal_one(chunk, index, Some(total), (i as u64) == total - 1)?;
            self.next_index += 1;
            out.push(sealed);
        }
        Ok(out)
    }

    /// Seals one already-delimited fragment (streaming).
    pub fn seal_chunk(&mut self, chunk: Vec<u8>, is_last: bool) -> Result<(LacreFrame, SealTag), CoreError> {
        let index = self.next_index;
        let sealed = self.seal_one(chunk, index, None, is_last)?;
        self.next_index += 1;
        Ok(sealed)
    }

    fn seal_one(
        &mut self,
        chunk: Vec<u8>,
        index: u64,
        total_fragments: Option<u64>,
        is_last: bool,
    ) -> Result<(LacreFrame, SealTag), CoreError> {
        let tag_bytes = compute_tag(&self.suite, &self.seal_key, &chunk, &self.state);
        self.buffer.insert_tagged(index, &chunk, &tag_bytes)?;
        // The length was fixed by the suite, so this cannot fail; a failure
        // would be a bug in the Core, and the frame must not go out.
        let tag = SealTag::new(tag_bytes).map_err(|_| CoreError::SealMismatch)?;
        self.state = self.state.next(&self.chain_key, &chunk);
        let frame = LacreFrame { session_id: self.session_id, index, total_fragments, is_last, payload: chunk };
        Ok((frame, tag))
    }

    /// Delivery confirmation: purges the fragment and its tag. `false` when
    /// the index was not pending (duplicate ACK or already purged).
    ///
    /// A signing session records the receipt BEFORE purging: it derives from
    /// the tag, which the purge erases (same order as v1).
    pub fn ack(&mut self, index: u64) -> bool {
        if let Some(signer) = self.signer.as_mut() {
            if let Some(tag) = self.buffer.tag_of(index) {
                let r = derive_receipt_v2(self.suite.suite_hash(), index, tag);
                signer.receipts.record_receipt(index, Receipt(r));
            }
        }
        self.buffer.purge_on_ack(index)
    }

    /// Receipts issued so far; `None` unless this is a signing (Vault) session.
    pub fn receipts(&self) -> Option<&[ReceiptEntry]> {
        self.signer.as_ref().map(|s| s.receipts.entries())
    }

    /// The signature of a tag this session produced, over `SignInput`.
    /// Fails closed: no signer, or a scheme that returns the wrong length.
    pub fn sign_for(&self, index: u64, tag: &SealTag) -> Result<Vec<u8>, CoreError> {
        let (Some(signer), Some(scheme)) = (self.signer.as_ref(), self.suite.signature_scheme()) else {
            return Err(CoreError::VaultSignatureMismatch);
        };
        let input = SignInput::new(self.suite.suite_hash(), &self.session_id.0, index, tag.as_bytes());
        let sig = scheme.sign(&signer.secret.0, &input);
        if sig.len() != scheme.signature_len() {
            return Err(CoreError::VaultSignatureMismatch);
        }
        Ok(sig)
    }

    pub fn purge_expired(&mut self) -> u64 {
        self.buffer.purge_expired()
    }

    pub fn pending_count(&self) -> usize {
        self.buffer.pending_count()
    }
}

/// Verifier side of wire v2.
pub struct VerifierCoreV2 {
    session_id: SessionId,
    suite: ValidatedSuite,
    key_id: KeyId,
    key_ring: Arc<MasterKeyRing>,
    seal_key: ContextKey,
    chain_key: ContextKey,
    state: ChainState,
    next_index: u64,
    buffer: PendingBuffer,
    /// Present exactly when the suite names a signature scheme (Vault).
    public_key: Option<Vec<u8>>,
}

impl VerifierCoreV2 {
    /// Resumes a session known by its `session_id` under the `key_id` the
    /// sealer used. The suite must be the one the sealer declared: a
    /// different suite derives different keys and fails at the first frame.
    pub fn resume(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        suite: ValidatedSuite,
        spec: BufferSpec,
    ) -> Result<Self, SuiteError> {
        if suite.signature_scheme().is_some() {
            // A suite that names a scheme needs the public key: `resume_signed`.
            return Err(SuiteError::SignatureSchemeMismatch);
        }
        Self::build(key_ring, session_id, key_id, suite, spec, None)
    }

    /// Resumes a signing (Vault) session: every frame must carry a valid
    /// signature of the scheme the suite names, under `public_key`.
    pub fn resume_signed(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        suite: ValidatedSuite,
        spec: BufferSpec,
        public_key: &[u8],
    ) -> Result<Self, SuiteError> {
        let Some(scheme) = suite.signature_scheme() else {
            return Err(SuiteError::SignatureSchemeMismatch);
        };
        if public_key.len() != scheme.public_key_len() {
            return Err(SuiteError::SignatureKeyInvalid);
        }
        Self::build(key_ring, session_id, key_id, suite, spec, Some(public_key.to_vec()))
    }

    fn build(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        suite: ValidatedSuite,
        spec: BufferSpec,
        public_key: Option<Vec<u8>>,
    ) -> Result<Self, SuiteError> {
        check_memory_budget(spec.slot_size, spec.slot_count, suite.tag_len(), spec.memory_cap)?;
        let keys = derive(&key_ring, Some(key_id), &session_id, &suite)?;
        let state = ChainState::initial(&keys.chain, &session_id, suite.suite_hash());
        let buffer = PendingBuffer::with_tag_len(spec.slot_size, spec.slot_count, spec.forced_purge_timeout, suite.tag_len());
        Ok(VerifierCoreV2 {
            session_id,
            key_id,
            key_ring,
            seal_key: keys.seal,
            chain_key: keys.chain,
            suite,
            state,
            next_index: 0,
            buffer,
            public_key,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub fn next_expected_index(&self) -> u64 {
        self.next_index
    }
    pub fn suite(&self) -> &ValidatedSuite {
        &self.suite
    }

    /// Verifies one frame against its tag, in strict order. Fails closed:
    /// wrong tag length, wrong key, wrong suite, wrong position or altered
    /// bytes are all errors and leave the state unchanged.
    pub fn verify_frame(
        &mut self,
        frame: &LacreFrame,
        key_id: KeyId,
        tag: &SealTag,
    ) -> Result<(), CoreError> {
        self.verify_frame_signed(frame, key_id, tag, None)
    }

    /// `verify_frame` with the frame's signature. Under a suite that names a
    /// scheme the signature is mandatory, of exactly the scheme's length, and
    /// is checked after the tag and before any state changes; under a suite
    /// without one, a signature is refused.
    pub fn verify_frame_signed(
        &mut self,
        frame: &LacreFrame,
        key_id: KeyId,
        tag: &SealTag,
        signature: Option<&[u8]>,
    ) -> Result<(), CoreError> {
        if frame.index != self.next_index {
            return Err(CoreError::OutOfSequence { expected: self.next_index, received: frame.index });
        }
        if key_id != self.key_id {
            // A key this ring does not know is a different error from a
            // known key that does not match this session.
            return Err(if self.key_ring.knows_key(key_id) {
                CoreError::SealMismatch
            } else {
                CoreError::UnknownKeyId
            });
        }
        // A tag of the wrong length cannot match; refuse before computing.
        if tag.len() != self.suite.tag_len() {
            return Err(CoreError::SealMismatch);
        }
        let mut expected = compute_tag(&self.suite, &self.seal_key, &frame.payload, &self.state);
        let ok = tag.matches(&expected);
        zeroize::Zeroize::zeroize(&mut expected);
        if !ok {
            return Err(CoreError::SealMismatch);
        }

        match (self.suite.signature_scheme(), self.public_key.as_deref(), signature) {
            (None, _, None) => {}
            (Some(scheme), Some(public), Some(sig)) => {
                let input = SignInput::new(self.suite.suite_hash(), &self.session_id.0, frame.index, tag.as_bytes());
                if sig.len() != scheme.signature_len() || !scheme.verify(public, &input, sig) {
                    return Err(CoreError::VaultSignatureMismatch);
                }
            }
            _ => return Err(CoreError::VaultSignatureMismatch),
        }

        self.buffer.insert_tagged(frame.index, &frame.payload, tag.as_bytes())?;
        let verified = VerifierFrameState::new().verify()?;
        self.state = self.state.next(&self.chain_key, &frame.payload);
        self.next_index += 1;
        // Purged right after verifying, as in v1: the frame has done its job.
        self.buffer.purge_on_ack(frame.index);
        verified.purge()?;
        Ok(())
    }

    /// Same as `verify_frame`, returning the only value a Profile may be
    /// built from.
    pub fn verify_frame_view<'a>(
        &mut self,
        frame: &'a LacreFrame,
        key_id: KeyId,
        tag: &SealTag,
    ) -> Result<crate::access::VerifiedFrame<'a>, CoreError> {
        self.verify_frame(frame, key_id, tag)?;
        Ok(crate::access::VerifiedFrame::new(frame))
    }

    /// Signed counterpart of `verify_frame_view`.
    pub fn verify_frame_view_signed<'a>(
        &mut self,
        frame: &'a LacreFrame,
        key_id: KeyId,
        tag: &SealTag,
        signature: Option<&[u8]>,
    ) -> Result<crate::access::VerifiedFrame<'a>, CoreError> {
        self.verify_frame_signed(frame, key_id, tag, signature)?;
        Ok(crate::access::VerifiedFrame::new(frame))
    }
}

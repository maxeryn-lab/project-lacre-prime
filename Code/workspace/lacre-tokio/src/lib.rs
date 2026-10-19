//! Tokio Runtime wrapper for `lacre-core` — the first concrete instance
//! of the Runtime layer, an optional layer that sits *above* Core,
//! Profiles, and Adapters, never beside or inside them.
//!
//! # Why this layer exists, and why it's optional
//!
//! `lacre-core`'s `SealerCore`/`VerifierCore` are already usable from
//! any Rust code today — they are plain synchronous methods with no
//! I/O and no runtime dependency at all (see `lacre-core/Cargo.toml`'s
//! own header comment: no tokio, no async, by design). A caller
//! embedding `lacre-core` directly in synchronous code, or in a
//! different async runtime (`async-std`, `smol`), needs nothing from
//! this crate. This crate exists for one specific, narrower case: a
//! caller that already runs a Tokio application and wants to hold a
//! `SealerCore`/`VerifierCore` behind a shared, `.await`-able handle
//! — for example, a single sealing session used concurrently by
//! several Tokio tasks — without hand-rolling that synchronization
//! themselves every time. Nothing here is required to use `lacre-core`
//! under Tokio; a caller that only ever touches its session from one
//! task at a time can use `lacre-core` directly and never import this
//! crate.
//!
//! # What this crate does NOT do
//!
//! It adds no new capability, no new verification logic, and no new
//! content inspection of any kind — every `async fn` below is a thin
//! wrapper that acquires a `tokio::sync::Mutex`, calls the exact same
//! synchronous `lacre-core` method with the exact same arguments, and
//! returns its exact same result. This crate has no axioms of its own
//! to satisfy beyond "introduce no new axis of behavior" — a caller
//! that reads only `lacre-core`'s own documentation for
//! `SealerCore`/`VerifierCore` already knows the complete behavior of
//! every method here.
//!
//! It also does not wrap `lacre-server`'s HTTP/WebSocket Adapter or its
//! `domain.rs` request/response types — `lacre-server` has no `[lib]`
//! target today (it's a binary-only crate) and `domain.rs` is a
//! private `mod`, not `pub mod`, so there is nothing there to depend on
//! from outside that crate. A future wrapper around the Adapter layer
//! itself (letting a Tokio application mount Lacre's HTTP routes onto
//! its own already-running server, for instance) is a distinct,
//! separate piece of work from this one, gated on `lacre-server`
//! exposing a library surface first — not something this crate
//! attempts by depending on `lacre-server` as it stands.
//!
//! # Why `tokio::sync::Mutex` and not `std::sync::Mutex`
//!
//! `SealerCore`/`VerifierCore` methods never do I/O and never hold the
//! lock across an `.await` point in this crate's own methods — a
//! `std::sync::Mutex` would work correctly here with no deadlock risk.
//! `tokio::sync::Mutex` is used anyway for one concrete reason: its
//! guard is `Send` across `.await` points, so a caller that DOES need
//! to hold the guard across other awaited work (reading the next chunk
//! of a stream before calling `seal_chunk`, for example) can do so
//! without this crate having to anticipate that shape in advance. This
//! is the one Tokio-specific decision in this file; everything else is
//! delegation.

use lacre_core::core::{CoreError, SealerCore, VerifierCore};
use lacre_core::frame::LacreFrame;
use lacre_core::hmac_seal::Seal;
use lacre_core::session::KeyId;
use lacre_core::vault_signature::VaultSignature;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Async handle around a `SealerCore`. Construct one with
/// [`AsyncSealer::new`], passing any `SealerCore` built the same way
/// `lacre-core`'s own tests and `lacre-server`'s `domain::handshake`
/// already build one (`SealerCore::open`, `open_with_vault_key`,
/// `open_with_session_key`, or `open_with_session_key_and_vault_key`)
/// — this crate does not reimplement session construction, it only
/// wraps whatever `SealerCore` the caller already has.
#[derive(Clone)]
pub struct AsyncSealer {
    inner: Arc<Mutex<SealerCore>>,
}

impl AsyncSealer {
    /// Wraps an already-constructed `SealerCore`. `Clone`-able: every
    /// clone shares the same underlying session through the same
    /// `Arc<Mutex<_>>`, so multiple Tokio tasks can hold a clone each
    /// and call its methods concurrently — each call still runs the
    /// real `SealerCore` method to completion, one at a time, behind
    /// the lock, exactly as if the caller had wrapped it in a mutex by
    /// hand.
    pub fn new(sealer: SealerCore) -> Self {
        AsyncSealer { inner: Arc::new(Mutex::new(sealer)) }
    }

    /// `SealerCore::session_id`, unchanged — a read-only accessor with
    /// no reason to be async, exposed here only so a caller holding an
    /// `AsyncSealer` doesn't need to keep the original `SealerCore`
    /// around just to read this one field.
    pub async fn session_id(&self) -> lacre_core::session::SessionId {
        self.inner.lock().await.session_id()
    }

    /// `SealerCore::seal_payload`, unchanged in every argument and
    /// return value — see that method's own documentation for the
    /// complete behavior (it fragments `payload` internally; this
    /// wrapper does not).
    pub async fn seal_payload(
        &self,
        payload: &[u8],
        slot_size: usize,
    ) -> Result<Vec<(LacreFrame, Seal)>, CoreError> {
        self.inner.lock().await.seal_payload(payload, slot_size)
    }

    /// `SealerCore::seal_chunk`, unchanged — see that method's own
    /// documentation for why this is the correct one to use for
    /// continuous streaming instead of `seal_payload`.
    pub async fn seal_chunk(
        &self,
        chunk: Vec<u8>,
        is_last: bool,
    ) -> Result<(LacreFrame, Seal), CoreError> {
        self.inner.lock().await.seal_chunk(chunk, is_last)
    }

    /// `SealerCore::sign_seal_for_vault`, unchanged. Returns `None`
    /// under any profile that didn't enable Vault, same as the
    /// synchronous method.
    pub async fn sign_seal_for_vault(&self, seal: &Seal) -> Option<VaultSignature> {
        self.inner.lock().await.sign_seal_for_vault(seal)
    }

    /// `SealerCore::ack`, unchanged.
    pub async fn ack(&self, index: u64) -> Result<bool, CoreError> {
        self.inner.lock().await.ack(index)
    }

    /// `SealerCore::receipts`, adapted to return owned data
    /// (`Vec<ReceiptEntry>`) instead of the synchronous method's
    /// `Option<&[ReceiptEntry]>` — the lock guard borrowing the slice
    /// would need to outlive the `.await`-returned reference in a way
    /// this crate's own `Mutex` doesn't allow across the call boundary
    /// (the guard is dropped when this function returns). `ReceiptEntry`
    /// is already `Clone` in `lacre-core` (see `receipt.rs`), so this
    /// clones the entries rather than changing what data is available
    /// — a caller gets the exact same receipts, just owned instead of
    /// borrowed.
    pub async fn receipts(&self) -> Option<Vec<crate::receipt::ReceiptEntry>> {
        self.inner.lock().await.receipts().map(|entries| entries.to_vec())
    }

    /// `SealerCore::purge_expired`, unchanged.
    pub async fn purge_expired(&self) -> u64 {
        self.inner.lock().await.purge_expired()
    }

    /// `SealerCore::pending_count`, unchanged.
    pub async fn pending_count(&self) -> usize {
        self.inner.lock().await.pending_count()
    }
}

/// Re-exported so `AsyncSealer::receipts`'s return type is nameable by
/// callers of this crate without also depending on `lacre-core`
/// directly just for this one type.
pub mod receipt {
    pub use lacre_core::receipt::ReceiptEntry;
}

/// Async handle around a `VerifierCore` — same shape and same
/// reasoning as `AsyncSealer` above, mirrored for the verifier side.
#[derive(Clone)]
pub struct AsyncVerifier {
    inner: Arc<Mutex<VerifierCore>>,
}

impl AsyncVerifier {
    /// Wraps an already-constructed `VerifierCore` — same
    /// `Clone`-shares-the-same-session pattern as `AsyncSealer::new`.
    pub fn new(verifier: VerifierCore) -> Self {
        AsyncVerifier { inner: Arc::new(Mutex::new(verifier)) }
    }

    /// `VerifierCore::session_id`, unchanged.
    pub async fn session_id(&self) -> lacre_core::session::SessionId {
        self.inner.lock().await.session_id()
    }

    /// `VerifierCore::next_expected_index`, unchanged.
    pub async fn next_expected_index(&self) -> u64 {
        self.inner.lock().await.next_expected_index()
    }

    /// `VerifierCore::verify_frame`, unchanged — see that method's own
    /// documentation for the complete behavior (strict Sᵢ ordering,
    /// Vault signature requirement when enabled).
    pub async fn verify_frame(
        &self,
        frame: &LacreFrame,
        key_id: KeyId,
        seal: &Seal,
        vault_signature: Option<&VaultSignature>,
    ) -> Result<(), CoreError> {
        self.inner.lock().await.verify_frame(frame, key_id, seal, vault_signature)
    }

    /// `VerifierCore::receipts`, adapted to owned data, same reasoning
    /// as `AsyncSealer::receipts` above.
    pub async fn receipts(&self) -> Option<Vec<crate::receipt::ReceiptEntry>> {
        self.inner.lock().await.receipts().map(|entries| entries.to_vec())
    }

    /// `VerifierCore::purge_expired`, unchanged.
    pub async fn purge_expired(&self) -> u64 {
        self.inner.lock().await.purge_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;
    use lacre_core::session::MasterKeyRing;
    use std::time::Duration;

    fn test_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ))
    }

    /// The real end-to-end flow — open a `SealerCore`, wrap it, seal a
    /// payload, wrap a matching `VerifierCore`, verify every resulting
    /// frame — driven entirely through `async fn` calls under a real
    /// Tokio runtime. Proves this crate's wrapper reaches the real
    /// `lacre-core` cryptography (a tampered frame must still fail),
    /// not a stub: same discipline `declarative_adapter.rs`'s own
    /// end-to-end test already applies to the HTTP/WebSocket Adapters.
    #[tokio::test]
    async fn seal_then_verify_round_trip_through_the_async_wrapper() {
        let ring = test_ring();
        let sealer_core = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            64,
            8,
            Duration::from_millis(500),
        );
        let session_id = sealer_core.session_id();
        let verifier_core = VerifierCore::resume(
            ring.clone(),
            session_id,
            ring.active_key_id(),
            HmacAlgo::Sha256,
            64,
            8,
            Duration::from_millis(500),
        )
        .expect("resume must succeed against the same ring and session_id the sealer used");

        let sealer = AsyncSealer::new(sealer_core);
        let verifier = AsyncVerifier::new(verifier_core);

        assert_eq!(sealer.session_id().await, session_id);

        let frames = sealer
            .seal_payload(b"sealed through the tokio wrapper", 32)
            .await
            .expect("sealing a well-formed payload must succeed");
        assert!(!frames.is_empty());

        for (frame, seal) in &frames {
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, None)
                .await
                .expect("a real, untampered frame must verify");
        }
    }

    /// A tampered frame must still fail verification through the async
    /// wrapper — confirming this crate delegates to the real HMAC
    /// check rather than silently accepting everything it's handed.
    #[tokio::test]
    async fn tampered_frame_fails_verification_through_the_async_wrapper() {
        let ring = test_ring();
        let sealer_core = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            64,
            8,
            Duration::from_millis(500),
        );
        let session_id = sealer_core.session_id();
        let verifier_core = VerifierCore::resume(
            ring.clone(),
            session_id,
            ring.active_key_id(),
            HmacAlgo::Sha256,
            64,
            8,
            Duration::from_millis(500),
        )
        .unwrap();

        let sealer = AsyncSealer::new(sealer_core);
        let verifier = AsyncVerifier::new(verifier_core);

        let mut frames = sealer.seal_payload(b"original content", 32).await.unwrap();
        let (frame, seal) = frames.remove(0);
        let mut tampered = frame.clone();
        tampered.payload[0] ^= 0xFF;

        let result = verifier
            .verify_frame(&tampered, ring.active_key_id(), &seal, None)
            .await;
        assert!(matches!(result, Err(CoreError::SealMismatch)));
    }

    /// `AsyncSealer`/`AsyncVerifier` are `Clone`, and every clone
    /// shares the same underlying session — a `seal_chunk` issued
    /// through one clone must be visible (as an incrementing
    /// `next_index`) to another clone of the same handle, proving the
    /// `Arc<Mutex<_>>` is actually shared rather than each clone
    /// silently holding its own independent copy.
    #[tokio::test]
    async fn cloned_handles_share_the_same_underlying_session() {
        let ring = test_ring();
        let sealer_core = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            64,
            8,
            Duration::from_millis(500),
        );
        let session_id = sealer_core.session_id();
        let verifier_core = VerifierCore::resume(
            ring.clone(),
            session_id,
            ring.active_key_id(),
            HmacAlgo::Sha256,
            64,
            8,
            Duration::from_millis(500),
        )
        .unwrap();

        let sealer_a = AsyncSealer::new(sealer_core);
        let sealer_b = sealer_a.clone();
        let verifier = AsyncVerifier::new(verifier_core);

        assert_eq!(verifier.next_expected_index().await, 0);

        let (frame_1, seal_1) =
            sealer_a.seal_chunk(b"first chunk, sealed through clone a".to_vec(), false).await.unwrap();
        verifier.verify_frame(&frame_1, ring.active_key_id(), &seal_1, None).await.unwrap();
        assert_eq!(verifier.next_expected_index().await, 1);

        // Sealed through the OTHER clone — must continue the same
        // index sequence, not restart at 0, proving both clones
        // operate on the one shared `SealerCore`.
        let (frame_2, seal_2) =
            sealer_b.seal_chunk(b"second chunk, sealed through clone b".to_vec(), true).await.unwrap();
        assert_eq!(frame_2.index, 1);
        verifier.verify_frame(&frame_2, ring.active_key_id(), &seal_2, None).await.unwrap();
        assert_eq!(verifier.next_expected_index().await, 2);
    }
}

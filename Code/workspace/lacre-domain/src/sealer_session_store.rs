//! Where a Vault session's `SealerCore` lives between the moment
//! `POST /v1/seal` creates it and the moment `POST /v1/ack` uses it to
//! record post-purge receipts (7.5) and purge the buffer.
//!
//! # Why this exists, and why it's NOT a `trait` like `SessionStore`
//!
//! `VerifierCore::resume` is deterministic: given `(key_ring,
//! session_id, key_id)`, any reconstructed instance is equivalent —
//! that's why `handle_verify` never needed to persist a `VerifierCore`
//! between requests (see `http_server.rs`'s own header comment).
//! `SealerCore::ack` doesn't have that luxury: it accumulates real
//! state (the `ReceiptLog`, which indices have already been purged
//! from the buffer) that can't be reconstructed from scratch — it's,
//! literally, what 7.5 describes as "an append-only log" that must
//! remain the same log between one `record()` and the next, not a new
//! copy every time.
//!
//! `session_store.rs` (Etapa 15) was justified as a `trait
//! SessionStore` because it had TWO real simultaneous uses (fixed ring
//! + handshake ring, see `DECISIONS.md` point 17).
//!
//! This module has exactly one real use today — `SealerCore` for
//! Vault sessions between `seal` and `ack`. Applying the same rule
//! honestly, a single use doesn't justify extracting an interface yet
//! — it's implemented directly as `Mutex<HashMap<...>>`, no trait. If
//! a second real use for "live server-side sealers" appears in the
//! future (for example, the streaming variant already noted in
//! `PENDING.md`), that's when it's evaluated whether generalizing is
//! worthwhile, not before.
//!
//! # Scope: exclusive to Vault
//!
//! 7.5 ties the post-purge receipt to the profile that "requires
//! post-purge audit capability (see the Vault profile)" — it's not a
//! general capability the Core should inherit. This module,
//! consequently, is only used when
//! `ProfileName::requires_vault_signature()` is true; the Core profile
//! keeps persisting nothing between `POST /v1/seal` and any other
//! request.

use lacre_core::core::{CoreError, SealerCore};
use lacre_core::core_v2::SealerCoreV2;
use lacre_core::receipt::ReceiptEntry;
use lacre_core::session::SessionId;
use crate::session_store::AtCapacity;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The sealer of either wire. A session keeps the version it was opened under,
/// so `ack` and `receipts` dispatch on what is stored, never on the request.
pub enum AnySealer {
    V1(Box<SealerCore>),
    V2(Box<SealerCoreV2>),
}

impl From<SealerCore> for AnySealer {
    fn from(s: SealerCore) -> Self {
        AnySealer::V1(Box::new(s))
    }
}

impl From<SealerCoreV2> for AnySealer {
    fn from(s: SealerCoreV2) -> Self {
        AnySealer::V2(Box::new(s))
    }
}

impl AnySealer {
    /// Acknowledges a fragment. A receipt (if the session records them) is
    /// written before the purge, in both versions.
    pub fn ack(&mut self, index: u64) -> Result<bool, CoreError> {
        match self {
            AnySealer::V1(s) => s.ack(index),
            AnySealer::V2(s) => Ok(s.ack(index)),
        }
    }

    pub fn receipts(&self) -> Option<&[ReceiptEntry]> {
        match self {
            AnySealer::V1(s) => s.receipts(),
            AnySealer::V2(s) => s.receipts(),
        }
    }

    pub fn pending_count(&self) -> usize {
        match self {
            AnySealer::V1(s) => s.pending_count(),
            AnySealer::V2(s) => s.pending_count(),
        }
    }
}

/// State of a session fed part by part (`seal/open` + `seal/part`), kept next to
/// its sealer. Sessions sealed in one call (`seal`) have none.
pub struct PartSession {
    pub profile: crate::profile_config::ProfileName,
    pub suite: Option<crate::wire::SuiteWire>,
    pub signing: bool,
    pub slot_size: usize,
    pub window: usize,
    /// Index the next new part must carry.
    pub next_part: u64,
    /// The last part sealed: index, SHA-256 of its payload and the frames returned.
    pub last: Option<(u64, [u8; 32], Vec<crate::wire::SealedFrameWire>)>,
    /// The final part was sealed: nothing new is accepted.
    pub finished: bool,
    /// A part failed half way: the frame sequence is unusable, nothing more is accepted.
    pub broken: bool,
}

struct StoredSealer {
    sealer: AnySealer,
    inserted_at: Instant,
    parts: Option<PartSession>,
}

/// Fixed TTL, explicit purge — same criterion as `InMemorySessionStore`
/// (session_store.rs) and `PendingBuffer::purge_expired` in
/// `lacre-core/buffer.rs`: purging never happens implicitly inside
/// `insert`/`with_sealer`, it's invoked separately so as not to
/// penalize the hot path of each request.
pub struct SealerSessionStore {
    entries: Mutex<HashMap<[u8; 16], StoredSealer>>,
    ttl: Duration,
    max_live: usize,
}

/// Default ceiling on live Vault sealer sessions. Derived from `python3
/// Tools/measure_session_cost.py` (debug build, 2026-10-03): about 15 KB per session with a
/// 1-byte payload and about 85 KB with a 64 KB payload, because the sealer keeps the
/// sealed frames until they are acknowledged. A 64 MiB budget at the 64 KB figure is about
/// 790 sessions; rounded down to 512. The cost grows with payload size, so a deployment
/// that accepts larger payloads should lower it. Override with `LACRE_MAX_SEALER_SESSIONS`.
pub const DEFAULT_MAX_SEALER_SESSIONS: usize = 512;

/// Result of attempting to operate on a stored `SealerCore`.
#[derive(Debug)]
pub enum WithSealerError {
    /// There's no live `SealerCore` under that `session_id` — nothing
    /// was ever sealed under Vault with that id, or it was already
    /// purged by TTL, or it was already explicitly removed (see
    /// `remove`).
    NotFound,
}

impl SealerSessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self::with_ceiling(ttl, DEFAULT_MAX_SEALER_SESSIONS)
    }

    /// Same as `new`, with an explicit ceiling on live sessions.
    pub fn with_ceiling(ttl: Duration, max_live: usize) -> Self {
        SealerSessionStore {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_live,
        }
    }

    /// Stores a `SealerCore` freshly created by `POST /v1/seal` under
    /// Vault. If one already existed with the same `session_id`,
    /// replaces it — same criterion as `SessionStore::insert`.
    ///
    /// Fails with `AtCapacity` when the store already holds its maximum number of live
    /// sessions after sweeping expired ones (replacing an existing id never counts as growth).
    pub fn insert(&self, session_id: SessionId, sealer: impl Into<AnySealer>) -> Result<(), AtCapacity> {
        let sealer = sealer.into();
        let mut guard = self.entries.lock().expect("sealer mutex poisoned");
        if !guard.contains_key(&session_id.0) && guard.len() >= self.max_live {
            let ttl = self.ttl;
            guard.retain(|_, entry| entry.inserted_at.elapsed() <= ttl);
            if guard.len() >= self.max_live {
                return Err(AtCapacity);
            }
        }
        guard.insert(
            session_id.0,
            StoredSealer {
                sealer,
                inserted_at: Instant::now(),
                parts: None,
            },
        );
        Ok(())
    }

    /// Like `insert`, for a session fed part by part.
    pub fn insert_with_parts(
        &self,
        session_id: SessionId,
        sealer: impl Into<AnySealer>,
        parts: PartSession,
    ) -> Result<(), AtCapacity> {
        self.insert(session_id, sealer)?;
        let mut guard = self.entries.lock().expect("sealer mutex poisoned");
        if let Some(entry) = guard.get_mut(&session_id.0) {
            entry.parts = Some(parts);
        }
        Ok(())
    }

    /// Runs `f` on the sealer and the part state of a session opened with
    /// `seal/open`. `Ok(None)` when the session exists but was sealed in one call.
    pub fn with_sealer_parts<T>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&mut AnySealer, &mut PartSession) -> T,
    ) -> Result<Option<T>, WithSealerError> {
        let mut guard = self.entries.lock().expect("sealer mutex poisoned");
        let entry = guard.get_mut(&session_id.0).ok_or(WithSealerError::NotFound)?;
        if entry.inserted_at.elapsed() > self.ttl {
            guard.remove(&session_id.0);
            return Err(WithSealerError::NotFound);
        }
        let StoredSealer { sealer, parts, .. } = entry;
        Ok(parts.as_mut().map(|p| f(sealer, p)))
    }

    /// Runs `f` against the `SealerCore` stored under `session_id`,
    /// with mutable access — needed because `SealerCore::ack` requires
    /// `&mut self`. A closure is used instead of exposing a
    /// `MutexGuard` directly so the internal `Mutex` is never held
    /// borrowed longer than strictly necessary (the same reason
    /// `InMemorySessionStore::get` returns a cloned `Arc` instead of a
    /// guard).
    ///
    /// A session expired by TTL is treated the same as a nonexistent
    /// one (`NotFound`), without distinguishing the case — a client
    /// trying to confirm an ACK too late doesn't, in any case, have any
    /// valid receipt left to record: the server-side buffer would have
    /// already purged those frames via its own forced purge timeout
    /// long before `SealerSessionStore` discarded them by TTL (this
    /// store's TTL is deliberately more generous than the profile's
    /// `forced_purge_timeout`, to give the client margin to complete
    /// its own processing before confirming).
    pub fn with_sealer<T>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&mut AnySealer) -> T,
    ) -> Result<T, WithSealerError> {
        let mut guard = self.entries.lock().expect("sealer mutex poisoned");
        let entry = guard.get_mut(&session_id.0).ok_or(WithSealerError::NotFound)?;
        if entry.inserted_at.elapsed() > self.ttl {
            guard.remove(&session_id.0);
            return Err(WithSealerError::NotFound);
        }
        Ok(f(&mut entry.sealer))
    }

    /// Purges entries whose TTL has expired. Explicit invocation, same
    /// as `InMemorySessionStore::purge_expired`.
    pub fn purge_expired(&self) -> usize {
        let mut guard = self.entries.lock().expect("sealer mutex poisoned");
        let before = guard.len();
        guard.retain(|_, entry| entry.inserted_at.elapsed() <= self.ttl);
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;
    use lacre_core::session::MasterKeyRing;
    use lacre_core::vault_signature::VaultSigningKey;
    use std::sync::Arc;

    fn dummy_sealer() -> (SealerCore, SessionId) {
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-key-for-sealer-store-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ));
        let sealer = SealerCore::open_with_vault_key(
            ring,
            HmacAlgo::Sha256,
            256 * 1024,
            64,
            Duration::from_secs(5),
            VaultSigningKey::generate(),
        );
        let session_id = sealer.session_id();
        (sealer, session_id)
    }

    #[test]
    fn insert_then_with_sealer_can_operate_on_the_same_instance() {
        let store = SealerSessionStore::new(Duration::from_secs(60));
        let (sealer, session_id) = dummy_sealer();
        store.insert(session_id, sealer).unwrap();

        let pending_before = store
            .with_sealer(&session_id, |s| s.pending_count())
            .unwrap();
        assert_eq!(pending_before, 0);
    }

    #[test]
    fn with_sealer_returns_not_found_for_unknown_session_id() {
        let store = SealerSessionStore::new(Duration::from_secs(60));
        let unknown = SessionId::generate();
        let result = store.with_sealer(&unknown, |_| ());
        assert!(matches!(result, Err(WithSealerError::NotFound)));
    }

    /// The central case: seal a fragment, store it, then call `ack()`
    /// through the store, and confirm the receipt got recorded — not
    /// just that the closure ran, but that the EFFECT of `ack()`
    /// (populating the `ReceiptLog`) persists in the same instance
    /// across two separate calls to `with_sealer`.
    #[test]
    fn ack_through_with_sealer_records_a_receipt_that_persists_across_calls() {
        let store = SealerSessionStore::new(Duration::from_secs(60));
        let (mut sealer, session_id) = dummy_sealer();
        let sealed = sealer.seal_payload(b"test content", 256 * 1024).unwrap();
        let index = sealed[0].0.index;
        store.insert(session_id, sealer).unwrap();

        // First call: real ack().
        let ack_result = store
            .with_sealer(&session_id, |s| s.ack(index))
            .unwrap()
            .unwrap();
        assert!(ack_result, "ack() must report that it purged the frame from the buffer");

        // Second call, separate with_sealer invocation: the receipt
        // must still be present in the SAME SealerCore.
        let receipt_count = store
            .with_sealer(&session_id, |s| s.receipts().map(|r| r.len()).unwrap_or(0))
            .unwrap();
        assert_eq!(receipt_count, 1);
    }

    #[test]
    fn expired_entry_is_treated_as_not_found() {
        let store = SealerSessionStore::new(Duration::from_millis(20));
        let (sealer, session_id) = dummy_sealer();
        store.insert(session_id, sealer).unwrap();

        std::thread::sleep(Duration::from_millis(40));

        let result = store.with_sealer(&session_id, |_| ());
        assert!(matches!(result, Err(WithSealerError::NotFound)));
    }

    #[test]
    fn purge_expired_removes_only_expired_entries() {
        let store = SealerSessionStore::new(Duration::from_millis(20));
        let (stale_sealer, stale_id) = dummy_sealer();
        store.insert(stale_id, stale_sealer).unwrap();
        std::thread::sleep(Duration::from_millis(40));

        let (fresh_sealer, fresh_id) = dummy_sealer();
        store.insert(fresh_id, fresh_sealer).unwrap();

        let purged = store.purge_expired();
        assert_eq!(purged, 1);
        assert!(matches!(
            store.with_sealer(&stale_id, |_| ()),
            Err(WithSealerError::NotFound)
        ));
        assert!(store.with_sealer(&fresh_id, |_| ()).is_ok());
    }

    #[test]
    fn ceiling_refuses_new_sessions_but_not_replacement_and_sweeps_expired() {
        let store = SealerSessionStore::with_ceiling(Duration::from_millis(40), 1);
        let (s1, id1) = dummy_sealer();
        let (s2, id2) = dummy_sealer();
        let (s1b, _) = dummy_sealer();
        store.insert(id1, s1).unwrap();
        assert_eq!(store.insert(id2, s2), Err(AtCapacity));
        assert!(store.insert(id1, s1b).is_ok()); // replacement is not growth
        std::thread::sleep(Duration::from_millis(80));
        let (s3, id3) = dummy_sealer();
        assert!(store.insert(id3, s3).is_ok());
    }
}

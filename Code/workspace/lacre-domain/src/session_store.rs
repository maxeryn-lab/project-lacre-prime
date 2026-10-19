//! Where a `MasterKeyRing` derived from a handshake lives, between the
//! moment it's completed (`POST /v1/handshake`) and the moment it's
//! used (`POST /v1/seal`/`POST /v1/verify` for a session with a
//! `session_id` agreed via handshake, instead of the static
//! `LACRE_MASTER_KEY`).
//!
//! # Why this module exists, and why it's so small
//!
//! Arises from a user observation, not our own speculation: if
//! Core/Profile/Adapter are already separated (7.1/7.4, `DECISIONS.md`
//! point 16), "where session state persists between two separate HTTP
//! requests" is, by the same logic, a decision of *this* specific
//! Adapter — never of the Lacre protocol in general.
//! `session_handshake.rs` (Phase 2, `lacre-core`) is already agnostic
//! to this: it produces an `EphemeralSharedSecret` and doesn't care
//! what happens with it afterward. The only thing missing was the
//! explicit seam in the Adapter.
//!
//! This is NOT a speculative `trait Transport` with methods for
//! backends that don't exist yet (Redis, etc.) — it's the MINIMAL
//! interface that already has TWO real simultaneous uses today in
//! `http_server.rs`: the fixed ring loaded at startup (which starts
//! being treated as "just another pre-seeded session") and the new
//! ring each completed handshake produces. Two real uses is the right
//! signal to extract an interface — not anticipation of a hypothetical
//! third Adapter.
//!
//! # Which implementation is used in this first pass
//!
//! `InMemorySessionStore`: a `HashMap` protected by `Mutex`
//! (`http_server.rs` already runs on multi-threaded tokio), with
//! explicit timeout-based purging — same criterion as
//! `PendingBuffer::purge_expired` in `lacre-core/src/buffer.rs`: a
//! method invoked from outside, not an implicit background thread, so
//! as not to penalize the hot path of each request with cleanup work
//! that isn't its responsibility. Enough for a single process; a
//! distributed Adapter (several `lacre-server` instances behind a load
//! balancer) would need a different implementation (Redis or another
//! shared store) — implementing the same `SessionStore` trait, without
//! touching `http_adapter.rs`, `http_server.rs` (beyond which
//! implementation gets injected), or `lacre-core` at all.

use lacre_core::session::{MasterKeyRing, SessionId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A store refused an insert because it already holds its maximum number of live
/// sessions, even after sweeping expired ones. Transient: clears as sessions finish
/// or expire, so an Adapter reports it as "unavailable, retry" (HTTP 503), not as a
/// rejection of the request itself.
#[derive(Debug, PartialEq, Eq)]
pub struct AtCapacity;

/// Default ceiling on live handshake sessions. Derived, not copied from the verifier
/// one: `python3 Tools/measure_session_cost.py` measured about 3.3 KB of resident memory
/// per handshake session (debug build, 2026-10-03), so a 64 MiB budget for this store is
/// roughly 19 800 sessions; rounded down to a power of two. Override with
/// `LACRE_MAX_HANDSHAKE_SESSIONS`; revisit if the per-session cost changes.
pub const DEFAULT_MAX_HANDSHAKE_SESSIONS: usize = 16_384;

/// Minimal contract an HTTP Adapter needs from a store of
/// handshake-derived sessions. Three operations, nothing more: if a
/// future backend needed something additional (for example, enumerating
/// every active session), it gets added when that real need exists,
/// not before.
pub trait SessionStore: Send + Sync {
    /// Registers the ring resulting from a handshake under
    /// `session_id`. If an entry already existed for that
    /// `session_id`, replaces it — a `session_id` shouldn't be reused
    /// across different handshakes (`SessionId::generate()` uses a
    /// CSPRNG, see `session.rs`), but this trait doesn't enforce that
    /// guarantee: it's the responsibility of whoever generates the
    /// `session_id`, not the store's.
    ///
    /// Fails with `AtCapacity` when the store already holds its maximum number of
    /// live sessions (replacing an existing `session_id` never counts as growth).
    fn insert(&self, session_id: SessionId, ring: Arc<MasterKeyRing>) -> Result<(), AtCapacity>;

    /// Retrieves a session's ring, if it exists and hasn't expired.
    fn get(&self, session_id: &SessionId) -> Option<Arc<MasterKeyRing>>;

    /// Purges sessions whose TTL has already expired. Invoked
    /// explicitly (for example, before handling a request, or from a
    /// periodic task) — never implicitly inside `insert`/`get`, same
    /// criterion as `PendingBuffer::purge_expired` in `lacre-core`.
    /// Returns how many entries were purged, only for test/log
    /// observability.
    fn purge_expired(&self) -> usize;
}

struct StoredEntry {
    ring: Arc<MasterKeyRing>,
    inserted_at: Instant,
}

/// In-memory implementation of `SessionStore`, with a fixed per-instance
/// TTL — enough for a single `lacre-server` process. Doesn't survive a
/// process restart: a handshake session interrupted by a server
/// restart must be redone from scratch, consistent with A4 (fail-closed)
/// — there's no attempt to "recover" an ephemeral DH secret after
/// losing it, because trying to would violate the very notion of
/// "ephemeral".
///
/// Internally, the `HashMap`'s key is `SessionId`'s raw bytes
/// (`[u8; 16]`), not `SessionId` directly — `SessionId` doesn't
/// implement `Hash` in `lacre-core` (only `Debug, Clone, Copy,
/// PartialEq, Eq`), and it isn't appropriate to add it there just for
/// this Phase 3 module's convenience: touching a Phase 1/2 type for a
/// specific Adapter's need would invert the dependency direction the
/// project has upheld from the start (the Core doesn't adjust to its
/// consumers).
pub struct InMemorySessionStore {
    entries: Mutex<HashMap<[u8; 16], StoredEntry>>,
    ttl: Duration,
    max_live: usize,
}

impl InMemorySessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self::with_ceiling(ttl, DEFAULT_MAX_HANDSHAKE_SESSIONS)
    }

    /// Same as `new`, with an explicit ceiling on live sessions.
    pub fn with_ceiling(ttl: Duration, max_live: usize) -> Self {
        InMemorySessionStore {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_live,
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn insert(&self, session_id: SessionId, ring: Arc<MasterKeyRing>) -> Result<(), AtCapacity> {
        let mut guard = self.entries.lock().expect("session mutex poisoned");
        if !guard.contains_key(&session_id.0) && guard.len() >= self.max_live {
            // Sweep expired entries first, so abandoned sessions never turn away a
            // legitimate client for longer than it takes to notice they are dead.
            let ttl = self.ttl;
            guard.retain(|_, entry| entry.inserted_at.elapsed() <= ttl);
            if guard.len() >= self.max_live {
                return Err(AtCapacity);
            }
        }
        guard.insert(
            session_id.0,
            StoredEntry {
                ring,
                inserted_at: Instant::now(),
            },
        );
        Ok(())
    }

    fn get(&self, session_id: &SessionId) -> Option<Arc<MasterKeyRing>> {
        let guard = self.entries.lock().expect("session mutex poisoned");
        let entry = guard.get(&session_id.0)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None; // expired — purge_expired will clean it up explicitly
        }
        Some(entry.ring.clone())
    }

    fn purge_expired(&self) -> usize {
        let mut guard = self.entries.lock().expect("session mutex poisoned");
        let before = guard.len();
        guard.retain(|_, entry| entry.inserted_at.elapsed() <= self.ttl);
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dummy_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"test-key-for-session-store-32-bytes".to_vec(),
            Duration::from_secs(60),
        ))
    }

    #[test]
    fn insert_then_get_returns_the_same_ring() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        let session_id = SessionId::generate();
        let ring = dummy_ring();

        store.insert(session_id, ring.clone()).unwrap();
        let fetched = store.get(&session_id).expect("must exist right after inserting");

        assert_eq!(fetched.active_key_id(), ring.active_key_id());
    }

    #[test]
    fn get_returns_none_for_unknown_session_id() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        assert!(store.get(&SessionId::generate()).is_none());
    }

    /// A session whose TTL already expired must stop being retrievable
    /// via `get` — there's no way to implicitly "extend" the TTL with a
    /// `get`, so as not to turn a purge timeout into an inactivity
    /// timeout without that having been explicitly decided.
    #[test]
    fn expired_session_is_not_returned_by_get() {
        let store = InMemorySessionStore::new(Duration::from_millis(20));
        let session_id = SessionId::generate();
        store.insert(session_id, dummy_ring()).unwrap();

        std::thread::sleep(Duration::from_millis(40));

        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn purge_expired_removes_only_expired_entries_and_reports_count() {
        let store = InMemorySessionStore::new(Duration::from_millis(20));
        let fresh_id = SessionId::generate();
        let stale_id = SessionId::generate();

        store.insert(stale_id, dummy_ring()).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        store.insert(fresh_id, dummy_ring()).unwrap(); // inserted after "stale" already expired

        let purged = store.purge_expired();
        assert_eq!(purged, 1);
        assert!(store.get(&stale_id).is_none());
        assert!(store.get(&fresh_id).is_some());
    }

    /// `insert` over an already-existing `session_id` replaces the
    /// entry, it neither duplicates nor fails.
    #[test]
    fn insert_overwrites_existing_entry_for_the_same_session_id() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        let session_id = SessionId::generate();

        store.insert(session_id, Arc::new(MasterKeyRing::new(0, b"first-key-32-bytes-exactly-here".to_vec(), Duration::from_secs(60)))).unwrap();
        store.insert(session_id, Arc::new(MasterKeyRing::new(7, b"second-key-32-bytes-exactly-here".to_vec(), Duration::from_secs(60)))).unwrap();

        let fetched = store.get(&session_id).unwrap();
        assert_eq!(fetched.active_key_id(), 7);
    }

    #[test]
    fn ceiling_refuses_new_sessions_but_not_replacement_and_sweeps_expired() {
        let store = InMemorySessionStore::with_ceiling(Duration::from_millis(40), 2);
        let (a, b, c) = (SessionId::generate(), SessionId::generate(), SessionId::generate());
        store.insert(a, dummy_ring()).unwrap();
        store.insert(b, dummy_ring()).unwrap();
        // Full: a third, different session is refused; replacing an existing one is not growth.
        assert_eq!(store.insert(c, dummy_ring()), Err(AtCapacity));
        assert!(store.insert(a, dummy_ring()).is_ok());
        // After the TTL the abandoned entries are swept and the newcomer fits.
        std::thread::sleep(Duration::from_millis(80));
        assert!(store.insert(c, dummy_ring()).is_ok());
    }
}

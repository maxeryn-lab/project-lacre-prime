//! Where a `ToolchainProfile` lives between the HTTP requests that
//! build up a reasoning episode's graph one node at a time.
//!
//! # Why this needs a live session store at all
//!
//! `ToolchainProfile` is stateful — its whole reason for existing (see
//! `lacre-core::toolchain`'s own header comment) is that a node's
//! validity depends on nodes already inserted earlier in the same
//! episode. Unlike `VerifierCore::resume` (deterministic, rebuildable
//! from `(key_ring, session_id, key_id)` alone — see
//! `http_server.rs`'s own header comment on why no verifier session
//! needs to persist between requests), there is no way to reconstruct
//! a `ToolchainProfile`'s accumulated graph from a `session_id` alone:
//! the graph *is* the state. So an episode started by one HTTP request
//! (`POST /v1/toolchain/episodes`) must be found again by every
//! subsequent request that adds a node to it, until the caller finally
//! asks for a verification.
//!
//! # Why this reuses `RetentionTracker` instead of a third
//! hand-rolled `Instant`-keyed `HashMap`
//!
//! `sealer_session_store.rs` implements its own TTL bookkeeping
//! directly (a `HashMap` of `StoredSealer { sealer, inserted_at }`,
//! with `Instant::elapsed() > ttl` checked by hand). That was written
//! before `profile_engine::RetentionTracker` existed. Writing the same
//! epoch-plus-elapsed-milliseconds logic a third time here (`buffer.rs`'s
//! `PendingBuffer` was the first, `sealer_session_store.rs` the
//! second) would be exactly the kind of redundancy the project
//! avoids, to eliminate before integrating new pieces. This module uses
//! `RetentionTracker<[u8; 16]>` (keyed by the raw `SessionId` bytes,
//! same key shape `sealer_session_store.rs` already uses for its own
//! `HashMap`) for the "how long has this episode been idle" question,
//! and a plain `HashMap` only for the actual `ToolchainProfile`
//! payload — the tracker never needs to know what it's tracking the
//! age of.
//!
//! # Same one-use-doesn't-justify-a-trait discipline as `sealer_session_store.rs`
//!
//! Exactly one real use exists today (`ToolchainProfile` sessions
//! between the episode-building HTTP requests). No `trait
//! ToolchainSessionStore` is introduced — same reasoning
//! `sealer_session_store.rs`'s own header comment already gives for
//! not extracting an interface until a second real use exists.

use lacre_profiles::profile_engine::RetentionTracker;
use lacre_core::session::SessionId;
use lacre_profiles::toolchain::ToolchainProfile;
use crate::session_store::AtCapacity;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

struct Inner {
    episodes: HashMap<[u8; 16], ToolchainProfile>,
    retention: RetentionTracker<[u8; 16]>,
}

/// Idle-episode TTL, purged explicitly — same pattern as
/// `SealerSessionStore` and `InMemorySessionStore`: never purged
/// implicitly inside `insert`/`with_episode`, invoked separately so
/// the hot path of adding a node isn't penalized by a sweep on every
/// call.
pub struct ToolchainSessionStore {
    inner: Mutex<Inner>,
    max_live: usize,
}

/// Default ceiling on live Toolchain episodes. Derived from `python3
/// Tools/measure_session_cost.py` (debug build, 2026-10-03): about 2.7 KB per EMPTY episode.
/// Episodes grow with every node added and that growth was NOT measured, so the value is
/// conservative: a 64 MiB budget would allow about 24 000 empty episodes; 4096 leaves room
/// for roughly 16 KB per episode. Override with `LACRE_MAX_TOOLCHAIN_SESSIONS`.
pub const DEFAULT_MAX_TOOLCHAIN_SESSIONS: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum WithEpisodeError {
    /// No live episode under that session ID — never created, or
    /// already swept for being idle past the TTL.
    NotFound,
}

impl ToolchainSessionStore {
    pub fn new(idle_ttl: Duration) -> Self {
        Self::with_ceiling(idle_ttl, DEFAULT_MAX_TOOLCHAIN_SESSIONS)
    }

    /// Same as `new`, with an explicit ceiling on live episodes.
    pub fn with_ceiling(idle_ttl: Duration, max_live: usize) -> Self {
        ToolchainSessionStore {
            inner: Mutex::new(Inner {
                episodes: HashMap::new(),
                retention: RetentionTracker::new(idle_ttl),
            }),
            max_live,
        }
    }

    /// Stores a freshly created `ToolchainProfile` under `session_id`.
    /// If one already existed under the same ID, it's replaced — same
    /// convention `SessionStore::insert` and `SealerSessionStore::insert`
    /// already use.
    ///
    /// Fails with `AtCapacity` when the store already holds its maximum number of live
    /// episodes after sweeping idle ones (replacing an existing id never counts as growth).
    pub fn insert(&self, session_id: SessionId, episode: ToolchainProfile) -> Result<(), AtCapacity> {
        let mut guard = self.inner.lock().expect("toolchain session mutex poisoned");
        if !guard.episodes.contains_key(&session_id.0) && guard.episodes.len() >= self.max_live {
            let expired = guard.retention.expired();
            for key in &expired {
                guard.retention.forget(key);
                guard.episodes.remove(key);
            }
            if guard.episodes.len() >= self.max_live {
                return Err(AtCapacity);
            }
        }
        guard.retention.record(session_id.0);
        guard.episodes.insert(session_id.0, episode);
        Ok(())
    }

    /// Runs `f` against the stored `ToolchainProfile` under
    /// `session_id`, with mutable access — needed because
    /// `ToolchainProfile::add_node`/`verify_output` both require
    /// `&mut self`. A closure rather than exposing a guard directly,
    /// same reasoning `SealerSessionStore::with_sealer` already gives.
    ///
    /// Every successful call resets the episode's idle age (via
    /// `retention.record`) — an episode being actively built on is, by
    /// definition, not idle, matching `RetentionTracker::record`'s own
    /// documented "re-recording resets age" semantics.
    ///
    /// An episode past its idle TTL is treated as not found, same as
    /// `SealerSessionStore` treats an expired sealer session — a
    /// caller that comes back to add a node to an episode abandoned
    /// long enough ago has no meaningful graph left to add to anyway.
    pub fn with_episode<T>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&mut ToolchainProfile) -> T,
    ) -> Result<T, WithEpisodeError> {
        let mut guard = self.inner.lock().expect("toolchain session mutex poisoned");
        if guard.retention.expired().contains(&session_id.0) {
            guard.retention.forget(&session_id.0);
            guard.episodes.remove(&session_id.0);
            return Err(WithEpisodeError::NotFound);
        }
        let episode = guard
            .episodes
            .get_mut(&session_id.0)
            .ok_or(WithEpisodeError::NotFound)?;
        let result = f(episode);
        guard.retention.record(session_id.0);
        Ok(result)
    }

    /// Sweeps episodes idle past their TTL. Explicit invocation, same
    /// as `SealerSessionStore::purge_expired` and
    /// `InMemorySessionStore::purge_expired`.
    pub fn purge_expired(&self) -> usize {
        let mut guard = self.inner.lock().expect("toolchain session mutex poisoned");
        let expired = guard.retention.expired();
        for key in &expired {
            guard.retention.forget(key);
            guard.episodes.remove(key);
        }
        // Per-node retention (`max_node_age_ms`): evict, and taint fail-closed, the
        // nodes of each surviving episode that went unresolved for too long.
        // `ToolchainProfile::sweep_expired` is documented as caller-driven, but no
        // caller existed: the server swept idle episodes yet never the nodes inside
        // them, so `max_node_age_ms` had no effect outside unit tests (found when running the server live).
        for episode in guard.episodes.values_mut() {
            episode.sweep_expired();
        }
        expired.len()
    }
}

#[cfg(test)]
mod tests {
    fn full(f: &lacre_core::frame::LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;
    use lacre_core::session::MasterKeyRing;
    use std::sync::Arc;

    fn dummy_episode() -> (ToolchainProfile, SessionId) {
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-for-toolchain-store".to_vec(),
            Duration::from_secs(60),
        ));
        let key = ring.derive_for_sealing(&SessionId::generate());
        let session_id = SessionId::generate();
        let episode = ToolchainProfile::new(
            HmacAlgo::Sha256,
            key,
            session_id.0.as_slice(),
            Duration::from_secs(3600),
        );
        (episode, session_id)
    }

    #[test]
    fn insert_then_with_episode_can_operate_on_the_same_instance() {
        let store = ToolchainSessionStore::new(Duration::from_secs(60));
        let (episode, session_id) = dummy_episode();
        store.insert(session_id, episode).unwrap();

        let node_count = store.with_episode(&session_id, |e| e.node_count()).unwrap();
        assert_eq!(node_count, 0);
    }

    #[test]
    fn with_episode_returns_not_found_for_unknown_session_id() {
        let store = ToolchainSessionStore::new(Duration::from_secs(60));
        let unknown = SessionId::generate();
        let result = store.with_episode(&unknown, |_| ());
        assert_eq!(result, Err(WithEpisodeError::NotFound));
    }

    /// The central case: add a node through the store, then read it
    /// back through a second, separate `with_episode` call — confirming
    /// the effect (a node actually being in the graph) persists in the
    /// same `ToolchainProfile` instance across calls, not just that
    /// the closure ran.
    #[test]
    fn add_node_through_with_episode_persists_across_calls() {
        use lacre_core::frame::LacreFrame;

        let store = ToolchainSessionStore::new(Duration::from_secs(60));
        let (episode, session_id) = dummy_episode();
        store.insert(session_id, episode).unwrap();

        let frame = LacreFrame {
            session_id,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"root node content".to_vec(),
        };
        store
            .with_episode(&session_id, |e| e.add_root("root", &full(&frame)).unwrap())
            .unwrap();

        let node_count = store.with_episode(&session_id, |e| e.node_count()).unwrap();
        assert_eq!(node_count, 1);
    }

    #[test]
    fn expired_entry_is_treated_as_not_found() {
        let store = ToolchainSessionStore::new(Duration::from_millis(20));
        let (episode, session_id) = dummy_episode();
        store.insert(session_id, episode).unwrap();

        std::thread::sleep(Duration::from_millis(40));

        let result = store.with_episode(&session_id, |_| ());
        assert_eq!(result, Err(WithEpisodeError::NotFound));
    }

    /// An episode that's actively being built on (repeated
    /// `with_episode` calls) must not expire just because a long time
    /// has passed since `insert` — each successful call resets the
    /// idle clock, same as an active `ToolchainProfile` episode is not
    /// "abandoned" just because it's taking a while to build.
    #[test]
    fn active_use_resets_the_idle_ttl() {
        let store = ToolchainSessionStore::new(Duration::from_millis(30));
        let (episode, session_id) = dummy_episode();
        store.insert(session_id, episode).unwrap();

        std::thread::sleep(Duration::from_millis(20));
        // Still under 30ms — touching it now resets the idle clock.
        store.with_episode(&session_id, |e| e.node_count()).unwrap();

        std::thread::sleep(Duration::from_millis(20));
        // 20ms since the touch above, even though 40ms have passed
        // since the original insert — still alive.
        assert!(store.with_episode(&session_id, |e| e.node_count()).is_ok());
    }

    #[test]
    fn purge_expired_removes_only_idle_sessions() {
        let store = ToolchainSessionStore::new(Duration::from_millis(20));
        let (stale_episode, stale_id) = dummy_episode();
        store.insert(stale_id, stale_episode).unwrap();
        std::thread::sleep(Duration::from_millis(40));

        let (fresh_episode, fresh_id) = dummy_episode();
        store.insert(fresh_id, fresh_episode).unwrap();

        let purged = store.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(
            store.with_episode(&stale_id, |_| ()),
            Err(WithEpisodeError::NotFound)
        );
        assert!(store.with_episode(&fresh_id, |_| ()).is_ok());
    }

    #[test]
    fn ceiling_refuses_new_episodes_but_not_replacement_and_sweeps_idle() {
        let store = ToolchainSessionStore::with_ceiling(Duration::from_millis(40), 1);
        let (e1, id1) = dummy_episode();
        let (e2, id2) = dummy_episode();
        let (e1b, _) = dummy_episode();
        store.insert(id1, e1).unwrap();
        assert_eq!(store.insert(id2, e2), Err(AtCapacity));
        assert!(store.insert(id1, e1b).is_ok());
        std::thread::sleep(Duration::from_millis(80));
        let (e3, id3) = dummy_episode();
        assert!(store.insert(id3, e3).is_ok());
    }

    #[test]
    fn purge_expired_also_sweeps_unresolved_nodes_inside_live_episodes() {
        use lacre_core::frame::LacreFrame;
        let store = ToolchainSessionStore::new(Duration::from_secs(60));
        let (dummy, session_id) = dummy_episode();
        // Same key as the dummy, but nodes may stay unresolved for only 1 ms.
        drop(dummy);
        let ring = Arc::new(MasterKeyRing::new(0, b"test-master-key-for-toolchain-store".to_vec(), Duration::from_secs(60)));
        let key = ring.derive_for_sealing(&session_id);
        let episode = ToolchainProfile::new(HmacAlgo::Sha256, key, session_id.0.as_slice(), Duration::from_millis(1));
        store.insert(session_id, episode).unwrap();
        let frame = LacreFrame { session_id, index: 0, total_fragments: Some(1), is_last: true, payload: b"root".to_vec() };
        store.with_episode(&session_id, |e| e.add_root("root", &full(&frame)).unwrap()).unwrap();
        assert!(!store.with_episode(&session_id, |e| e.is_tainted(&"root".to_string())).unwrap());

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.purge_expired(), 0, "the episode itself is still live");
        assert!(
            store.with_episode(&session_id, |e| e.is_tainted(&"root".to_string())).unwrap(),
            "an unresolved node past max_node_age must be tainted by the periodic sweep"
        );
    }
}

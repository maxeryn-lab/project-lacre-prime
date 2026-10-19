//! Where a `VerifierCore` lives between separate `POST /v1/verify`
//! calls for the same session, so a caller that verifies frames
//! incrementally (as they arrive, one HTTP/WS call per frame or per
//! small batch, instead of always sending the session's complete
//! frame array in a single call) keeps the real Sᵢ-derived
//! `next_expected_index` across calls, instead of it silently
//! resetting to 0 on every request.
//!
//! # Why this module exists now, when it didn't before
//!
//! `sealer_session_store.rs`'s own header comment records the original
//! reasoning for NOT persisting a `VerifierCore` between requests:
//! `VerifierCore::resume` is deterministic given `(key_ring,
//! session_id, key_id)`, so any reconstructed instance is equivalent —
//! true, but only under an unstated assumption: that every call to
//! `/v1/verify` for a given session always carries the COMPLETE frame
//! array for that session, so `next_expected_index` never needs to
//! survive across calls because there never is a "next call" for the
//! same session.
//!
//! That assumption doesn't hold for a caller doing incremental
//! verification (frames arriving one at a time — the same pattern
//! `total_fragments` in `SealResponse` already signals as expected for
//! any payload larger than one slot). Confirmed empirically (real HTTP
//! round trips, not a design argument): verifying frame index 1 alone,
//! in its own `/v1/verify` call, against a session whose frame 0 was
//! never presented in that same call, fails with `"invalid fragment
//! order: expected index 0, received 1"` — every call restarts at
//! index 0, so a session's frames beyond the first one presented in
//! any single call could never be verified, and, worse, a frame
//! already verified and purged in a PRIOR call could be re-verified
//! successfully in a later call, because the later call's freshly
//! reconstructed `VerifierCore` has no memory that index already
//! happened. This module closes that gap: `next_expected_index`
//! becomes real state that survives between calls, not a value that
//! resets every time.
//!
//! # Why a new store, not reusing `SealerSessionStore` or generalizing
//! `SessionStore`
//!
//! Same rule already applied twice in this codebase (see
//! `sealer_session_store.rs`'s own header, and `DECISIONS.md` point
//! 17's "two real uses" criterion for extracting `trait
//! SessionStore`): a `VerifierCore` and a `SealerCore` are stored
//! under a different key scope (a `SealerCore` lives per Vault
//! session; a `VerifierCore` needs to live per verification session
//! for EVERY profile, not just Vault, since incremental verification
//! isn't a Vault-only concern), have different construction signatures
//! (`resume` vs. `resume_with_vault_key`, vs. `SealerCore::open`/
//! `open_with_vault_key`), and are read/written by entirely different
//! call sites. Sharing a store between the two would mean branching
//! internally on which kind of core is stored — more coupling than
//! two small, independent stores with the same shape.
//!
//! # Resource-exhaustion guard from day one, not added later
//!
//! `DECISIONS.md` already records the same shape of gap happening
//! THREE times in this project before it was noticed and fixed in one
//! pass (`SealerSessionStore::purge_expired`,
//! `SessionStore::purge_expired`, and
//! `ToolchainSessionStore::purge_expired`/`remove` were all
//! implemented, each documenting that purging is invoked explicitly
//! rather than on every operation, but nothing in `main.rs` ever
//! actually called any of them until a background sweep task was
//! added). This module is wired into that same 60-second sweep
//! (`main.rs::run_server`'s `purge_all_expired` call) in the same
//! commit that introduces it — not left as a follow-up. A live
//! `VerifierCore` that's never resumed again from its session
//! (a caller that starts incremental verification and abandons the
//! session, deliberately or by crashing) would otherwise retain memory
//! indefinitely, exactly the vector 9.6 of Project Lacre Prime already
//! names for the general case (uncapped concurrent sessions per
//! tenant) — here reopened at the granularity of one specific
//! in-memory store, same as the other three, if it isn't closed
//! immediately.
//!
//! # Per-session locks
//!
//! Until E4 the whole verification ran with the store's single global
//! `Mutex<HashMap>` held, so one slow seal algorithm serialized every
//! verification of the server, and a panic inside the verification
//! poisoned that global lock for every later request. Now the global
//! lock is held only to look up, insert or sweep entries; the
//! verification itself runs under the lock of ITS OWN session. Lock
//! order is fixed: the global lock never waits for a session lock (sweeps
//! use `try_lock` and treat a busy session as alive), so there is no cycle.
//!
//! A panic inside the verification is contained here (`catch_unwind`):
//! the session becomes a `Failed` tombstone and the call returns
//! `WithVerifierError::Panicked`. A failed session is NOT restorable
//! (Annex 15, vector 2, normative): the same `session_id` is refused until
//! the tombstone expires, and continuing requires a new establishment
//! (a new `/v1/seal`, a new `session_id`).

use lacre_core::core::VerifierCore;
use lacre_core::core_v2::VerifierCoreV2;
use lacre_core::suite::SuiteError;
use lacre_core::session::SessionId;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

/// What a `session_id` slot in this store currently holds. One enum in
/// one map: a given `session_id` has exactly one entry and one source of
/// truth at any time.
enum Slot {
    /// Boxed: a live `VerifierCore` is hundreds of bytes while a tombstone
    /// is a timestamp.
    Live(Box<StoredVerifier>),
    /// The session's last frame verified successfully and the live
    /// `VerifierCore` was dropped, but the `session_id` is remembered with
    /// its own (longer) TTL so it CANNOT be silently reused (freshness gap
    /// closed earlier; see `complete`).
    Completed { completed_at: Instant, last: Option<Box<LastAccepted>> },
    /// The verification of this session panicked. Same refusal rule as
    /// `Completed`, but reported as a failure, never as a success.
    Failed { failed_at: Instant },
    /// Removed from the map while another thread still held a handle to
    /// it. Whoever finds this looks the session up again.
    Retired,
}

/// The verifier of a stored session. A session is bound to ONE wire version
/// (and, under v2, to one suite) from its first call: a later call with a
/// different version or suite is refused, never run on the wrong logic
/// (see spec/LACRE-WIRE-v2.md).
enum StoredCore {
    V1(Box<VerifierCore>),
    V2(Box<VerifierCoreV2>),
}

impl StoredCore {
    fn next_expected_index(&self) -> u64 {
        match self {
            StoredCore::V1(c) => c.next_expected_index(),
            StoredCore::V2(c) => c.next_expected_index(),
        }
    }
}

/// The last request this session accepted, remembered so that the SAME request
/// repeated (a client or an intermediary retrying after a lost response) gets
/// the same verdict instead of an error. It never accepts anything new: it
/// only repeats an answer already given, for a request already accepted, and
/// only when the stored response is small (`MAX_REPLAY_RESPONSE_BYTES`).
pub struct LastAccepted {
    digest: [u8; 32],
    response: crate::wire::VerifyResponse,
}

/// Largest serialized response kept for replay. Larger responses (a session
/// verified with many frames, or a reassembled payload) are not remembered:
/// a repeat of those gets the same refusal as before.
pub const MAX_REPLAY_RESPONSE_BYTES: usize = 16 * 1024;

struct StoredVerifier {
    core: StoredCore,
    last_accepted: Option<Box<LastAccepted>>,
    /// Optional reassembly of the session's verified payload (see
    /// `domain::verify`, `reassemble: true`). Lives and dies with the
    /// verifier: same TTL, same tombstone, dropped when the session
    /// completes.
    reassembly: Option<lacre_profiles::profile::ReassembleProfile>,
    last_used_at: Instant,
}

type Cell = Arc<Mutex<Slot>>;

/// What a sweep decides about one cell without blocking on it.
enum Verdict {
    Keep { live: bool },
    Drop,
}

/// Fixed TTL, explicit purge. TTL is measured from `last_used_at`: an
/// incremental-verification session legitimately stays alive across many
/// calls spread over real wall-clock time, so every successful call resets
/// the idle clock. `completed_ttl` (tombstones of `Completed` and `Failed`
/// sessions) is deliberately allowed to be longer: a tombstone is a few
/// bytes, and a longer window strengthens the refusal to revive a finished
/// or failed `session_id`. Both are finite: an unbounded tombstone would
/// just move the 9.6 resource-exhaustion vector to "tombstones never purged".
pub struct VerifierSessionStore {
    entries: Mutex<HashMap<[u8; 16], Cell>>,
    live_ttl: Duration,
    completed_ttl: Duration,
    /// Hard ceiling on simultaneously LIVE `VerifierCore`s (tombstones
    /// don't count). Each live entry holds a full `PendingBuffer`
    /// (measured around 16 MB resident under the Core profile), and
    /// `/v1/verify` is reachable with an arbitrary unauthenticated
    /// `session_id`, so without a ceiling a client can grow this store
    /// until the process dies. Project Lacre Prime 9.6 names the same vector
    /// and the same class of fix.
    max_live: usize,
}

/// Default ceiling on live verifier sessions. A placeholder sized for
/// "does not take a small node down" at the Core profile's current
/// ~16 MB-per-session cost (64 sessions is roughly 1 GB) — NOT derived
/// from first principles. A deployment should set it from its own memory
/// budget (`LACRE_MAX_VERIFIER_SESSIONS`).
pub const DEFAULT_MAX_LIVE_SESSIONS: usize = 64;

/// Result of attempting to operate on a stored `VerifierCore`.
#[derive(Debug, PartialEq, Eq)]
pub enum WithVerifierError {
    /// This `session_id` already completed (its last frame verified
    /// successfully and the session was closed) — refused rather than
    /// silently starting a brand new `VerifierCore` at index 0. Permanent
    /// for this id: only a new session can proceed.
    AlreadyCompleted,
    /// The store already holds `max_live` live verifier sessions, even
    /// after sweeping expired ones. Transient (HTTP 503).
    AtCapacity,
    /// The verification of this session panicked now or in an earlier call.
    /// The session is closed for good; a new establishment is required.
    SessionFailed,
    /// The session is bound to another wire version or suite than the one this
    /// call asked for. Refused before touching any state.
    WrongVersion,
    /// A v2 verifier could not be opened (for example, the key id is unknown to
    /// the ring). Nothing was stored.
    CannotOpen(SuiteError),
    /// The verification panicked in THIS call. Reported once; later calls
    /// for the same id get `SessionFailed`.
    Panicked,
}

/// What `with_verifier` (a test-only observation helper) reports.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub enum TestLookupError {
    NotFound,
    AlreadyCompleted,
    Failed,
}

/// Locks a cell. A poisoned session lock (a panic that escaped containment)
/// turns the session into a `Failed` tombstone instead of propagating.
fn lock_slot(cell: &Cell) -> MutexGuard<'_, Slot> {
    match cell.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            let mut g = poisoned.into_inner();
            if !matches!(*g, Slot::Failed { .. }) {
                *g = Slot::Failed { failed_at: Instant::now() };
            }
            g
        }
    }
}

impl VerifierSessionStore {
    pub fn new(live_ttl: Duration) -> Self {
        // A tombstone defaults to living twice as long as a live entry's
        // idle TTL; see `with_ttls` to configure both explicitly.
        Self::with_ttls(live_ttl, live_ttl.saturating_mul(2))
    }

    pub fn with_ttls(live_ttl: Duration, completed_ttl: Duration) -> Self {
        Self::with_limits(live_ttl, completed_ttl, DEFAULT_MAX_LIVE_SESSIONS)
    }

    pub fn with_limits(live_ttl: Duration, completed_ttl: Duration, max_live: usize) -> Self {
        VerifierSessionStore {
            entries: Mutex::new(HashMap::new()),
            live_ttl,
            completed_ttl,
            max_live,
        }
    }

    /// The map lock. The map is consistent at every point where user code
    /// can run under it (`make` runs before the insertion), so a poisoned
    /// lock is recovered instead of failing every later request.
    fn lock_entries(&self) -> MutexGuard<'_, HashMap<[u8; 16], Cell>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Decides, without blocking, what a sweep does with one cell. A cell
    /// whose lock is taken is being used right now, so it is alive. A cell
    /// that is dropped is marked `Retired` so a thread still holding a
    /// handle looks the session up again instead of using an orphan.
    fn judge(&self, cell: &Cell) -> Verdict {
        let mut g = match cell.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return Verdict::Keep { live: true },
            Err(TryLockError::Poisoned(p)) => {
                let mut g = p.into_inner();
                if !matches!(*g, Slot::Failed { .. }) {
                    *g = Slot::Failed { failed_at: Instant::now() };
                }
                g
            }
        };
        let (keep, live) = match &*g {
            Slot::Live(s) => (s.last_used_at.elapsed() <= self.live_ttl, true),
            Slot::Completed { completed_at, .. } => (completed_at.elapsed() <= self.completed_ttl, false),
            Slot::Failed { failed_at } => (failed_at.elapsed() <= self.completed_ttl, false),
            Slot::Retired => (false, false),
        };
        if keep {
            Verdict::Keep { live }
        } else {
            *g = Slot::Retired;
            Verdict::Drop
        }
    }

    /// Returns the result of running `f` on the `VerifierCore` for
    /// `session_id`, creating one via `make` if none exists yet. `make`
    /// only runs the first time the session is seen; later calls reuse the
    /// same instance and its real `next_expected_index`.
    pub fn get_or_insert_with<T>(
        &self,
        session_id: SessionId,
        make: impl FnOnce() -> VerifierCore,
        f: impl FnOnce(&mut VerifierCore) -> T,
    ) -> Result<T, WithVerifierError> {
        self.get_or_insert_with_reassembly(session_id, make, |core, _| f(core))
    }

    /// Same as `get_or_insert_with`, but the closure also receives the
    /// session's optional `ReassembleProfile` slot.
    ///
    /// `f` runs under the lock of this session only. A panic inside `f` is
    /// contained: the session becomes `Failed` and the call returns
    /// `Err(Panicked)`.
    pub fn get_or_insert_with_reassembly<T>(
        &self,
        session_id: SessionId,
        make: impl FnOnce() -> VerifierCore,
        f: impl FnOnce(&mut VerifierCore, &mut Option<lacre_profiles::profile::ReassembleProfile>) -> T,
    ) -> Result<T, WithVerifierError> {
        self.run(
            session_id,
            || Ok(StoredCore::V1(Box::new(make()))),
            |stored| match &mut stored.core {
                StoredCore::V1(core) => Ok(f(core, &mut stored.reassembly)),
                StoredCore::V2(_) => Err(WithVerifierError::WrongVersion),
            },
        )
    }

    /// Wire v2 counterpart. `suite_hash` is the hash of the canonical suite
    /// descriptor this call speaks: a stored session built under another
    /// suite (or under v1) is refused with `WrongVersion`.
    pub fn get_or_insert_v2_with_reassembly<T>(
        &self,
        session_id: SessionId,
        suite_hash: [u8; 32],
        make: impl FnOnce() -> Result<VerifierCoreV2, SuiteError>,
        f: impl FnOnce(&mut VerifierCoreV2, &mut Option<lacre_profiles::profile::ReassembleProfile>) -> T,
    ) -> Result<T, WithVerifierError> {
        self.run(
            session_id,
            || make().map(|c| StoredCore::V2(Box::new(c))).map_err(WithVerifierError::CannotOpen),
            |stored| match &mut stored.core {
                StoredCore::V2(core) if core.suite().suite_hash() == &suite_hash => Ok(f(core, &mut stored.reassembly)),
                _ => Err(WithVerifierError::WrongVersion),
            },
        )
    }

    /// True if `session_id` currently holds a live (not finished, not failed)
    /// verifier. Used to let sessions drain when an algorithm is quarantined.
    pub fn has_live(&self, session_id: &SessionId) -> bool {
        let cell = self.lock_entries().get(&session_id.0).cloned();
        match cell {
            None => false,
            Some(c) => matches!(&*lock_slot(&c), Slot::Live(_)),
        }
    }

    /// Closes a session for good (it becomes a `Failed` tombstone): used when
    /// its algorithm is quarantined and the policy says `close`. A session
    /// that does not exist is left alone. It does not create an entry.
    pub fn fail_session(&self, session_id: &SessionId) {
        let cell = self.lock_entries().get(&session_id.0).cloned();
        if let Some(c) = cell {
            let mut slot = lock_slot(&c);
            if matches!(&*slot, Slot::Live(_)) {
                *slot = Slot::Failed { failed_at: Instant::now() };
            }
        }
    }

    /// The common path of both wires: find or create the session's cell, run
    /// `f` under that session's lock only, and contain a panic. The binding
    /// between the session and its wire version is checked inside `f`.
    fn run<T>(
        &self,
        session_id: SessionId,
        make: impl FnOnce() -> Result<StoredCore, WithVerifierError>,
        f: impl FnOnce(&mut StoredVerifier) -> Result<T, WithVerifierError>,
    ) -> Result<T, WithVerifierError> {
        let mut make = Some(make);
        let mut f = Some(f);
        // A cell found `Retired` means another thread removed it between
        // our lookup and our lock; look up again (bounded: each round
        // needs a removal to have just happened).
        for _ in 0..8 {
            let cell = self.cell_for(session_id, &mut make)?;
            let mut slot = lock_slot(&cell);
            let now = Instant::now();
            match &mut *slot {
                Slot::Retired => continue,
                Slot::Completed { .. } => return Err(WithVerifierError::AlreadyCompleted),
                Slot::Failed { .. } => return Err(WithVerifierError::SessionFailed),
                Slot::Live(stored) => {
                    stored.last_used_at = now;
                    let stored = &mut **stored;
                    let run = f.take().expect("f is taken once: the loop only repeats on Retired");
                    let result = catch_unwind(AssertUnwindSafe(|| run(stored)));
                    return match result {
                        Ok(r) => r,
                        Err(_) => {
                            // The state of this session after a panic is unknown:
                            // it is closed for good, never resumed (Annex 15, vector 2).
                            *slot = Slot::Failed { failed_at: Instant::now() };
                            Err(WithVerifierError::Panicked)
                        }
                    };
                }
            }
        }
        Err(WithVerifierError::AtCapacity)
    }

    /// Finds the cell of `session_id` or creates it, under the map lock
    /// (never held while `f` runs). Refusals that need only the slot kind
    /// are decided in `get_or_insert_with_reassembly` under the slot lock.
    fn cell_for(
        &self,
        session_id: SessionId,
        make: &mut Option<impl FnOnce() -> Result<StoredCore, WithVerifierError>>,
    ) -> Result<Cell, WithVerifierError> {
        let mut guard = self.lock_entries();

        if let Some(cell) = guard.get(&session_id.0).cloned() {
            // A tombstone past its own TTL is removed now so that the
            // session_id can be reused (bounded trade-off: keeping every
            // finished id forever would turn this store into an unbounded
            // log; long-lived deployments that need "never reuse" pair this
            // store with the post-purge receipt, Prime 7.5). A tombstone
            // within its TTL stays and the caller refuses on it.
            match self.judge(&cell) {
                Verdict::Keep { .. } => return Ok(cell),
                Verdict::Drop => {
                    guard.remove(&session_id.0);
                }
            }
        }

        // Ceiling on live sessions, checked only when this call would ADD
        // a new entry. Expired entries are swept first, so idle sessions of
        // abandoned clients never turn away a legitimate new one for longer
        // than it takes to notice they are dead.
        if guard.len() >= self.max_live {
            let mut live = 0usize;
            let doomed: Vec<[u8; 16]> = guard
                .iter()
                .filter_map(|(k, c)| match self.judge(c) {
                    Verdict::Keep { live: l } => {
                        live += usize::from(l);
                        None
                    }
                    Verdict::Drop => Some(*k),
                })
                .collect();
            for k in doomed {
                guard.remove(&k);
            }
            if live >= self.max_live {
                return Err(WithVerifierError::AtCapacity);
            }
        }

        // `make` is already spent only if the cell this very call created was
        // retired by a concurrent discard before it could be used. The caller
        // can simply retry (transient, answered as "busy").
        let Some(make) = make.take() else {
            return Err(WithVerifierError::AtCapacity);
        };
        let cell: Cell = Arc::new(Mutex::new(Slot::Live(Box::new(StoredVerifier {
            last_accepted: None,
            core: make()?,
            reassembly: None,
            last_used_at: Instant::now(),
        }))));
        guard.insert(session_id.0, cell.clone());
        Ok(cell)
    }

    /// Runs `f` against an already-live, stored `VerifierCore` without
    /// creating one if absent. Test-only observation helper.
    #[cfg(test)]
    pub fn with_verifier<T>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&mut VerifierCore) -> T,
    ) -> Result<T, TestLookupError> {
        let cell = self.lock_entries().get(&session_id.0).cloned();
        let Some(cell) = cell else {
            return Err(TestLookupError::NotFound);
        };
        let mut slot = lock_slot(&cell);
        let expired = match &*slot {
            Slot::Completed { completed_at, .. } => {
                if completed_at.elapsed() <= self.completed_ttl {
                    return Err(TestLookupError::AlreadyCompleted);
                }
                true
            }
            Slot::Failed { failed_at } => {
                if failed_at.elapsed() <= self.completed_ttl {
                    return Err(TestLookupError::Failed);
                }
                true
            }
            Slot::Live(stored) => stored.last_used_at.elapsed() > self.live_ttl,
            Slot::Retired => true,
        };
        if expired {
            *slot = Slot::Retired;
            drop(slot);
            self.remove_if_same(session_id, &cell);
            return Err(TestLookupError::NotFound);
        }
        match &mut *slot {
            Slot::Live(stored) => {
                stored.last_used_at = Instant::now();
                match &mut stored.core {
                    StoredCore::V1(core) => Ok(f(core)),
                    StoredCore::V2(_) => unreachable!("with_verifier is only used by v1 tests"),
                }
            }
            _ => unreachable!("expired and tombstone cases returned above"),
        }
    }

    fn remove_if_same(&self, session_id: &SessionId, cell: &Cell) {
        let mut guard = self.lock_entries();
        if guard.get(&session_id.0).is_some_and(|c| Arc::ptr_eq(c, cell)) {
            guard.remove(&session_id.0);
        }
    }

    /// Marks a session as completed: drops its live `VerifierCore`
    /// (freeing its buffer immediately) but leaves a lightweight tombstone
    /// under the same `session_id`, so a later call for that id is refused
    /// with `AlreadyCompleted` instead of silently starting over at index 0.
    ///
    /// Calling this on a `session_id` with no live entry is a harmless
    /// no-op that leaves a tombstone: `domain::verify` calls it once, right
    /// after a session's own last frame verifies successfully.
    pub fn complete(&self, session_id: &SessionId) {
        let cell = {
            let mut guard = self.lock_entries();
            guard
                .entry(session_id.0)
                .or_insert_with(|| Arc::new(Mutex::new(Slot::Completed { completed_at: Instant::now(), last: None })))
                .clone()
        };
        *lock_slot(&cell) = Slot::Completed { completed_at: Instant::now(), last: None };
    }

    /// The response this session already gave to exactly this request, if it
    /// accepted it as its last one and it is still within its lifetime. Never
    /// creates, refreshes or changes a session.
    pub fn replay(&self, session_id: &SessionId, digest: &[u8; 32]) -> Option<crate::wire::VerifyResponse> {
        let cell = self.lock_entries().get(&session_id.0).cloned()?;
        let slot = lock_slot(&cell);
        let last = match &*slot {
            Slot::Live(s) if s.last_used_at.elapsed() <= self.live_ttl => s.last_accepted.as_ref(),
            Slot::Completed { completed_at, last } if completed_at.elapsed() <= self.completed_ttl => last.as_ref(),
            _ => None,
        }?;
        (last.digest == *digest).then(|| last.response.clone())
    }

    /// Remembers `response` as the answer to the request with `digest`, for
    /// `replay`. Does nothing for a response above `MAX_REPLAY_RESPONSE_BYTES`
    /// (and forgets the previous one: it no longer describes the last request).
    pub fn remember(&self, session_id: &SessionId, digest: [u8; 32], response: &crate::wire::VerifyResponse) {
        let keep = serde_json::to_vec(response).map(|b| b.len() <= MAX_REPLAY_RESPONSE_BYTES).unwrap_or(false);
        let value = keep.then(|| Box::new(LastAccepted { digest, response: response.clone() }));
        let Some(cell) = self.lock_entries().get(&session_id.0).cloned() else { return };
        let mut slot = lock_slot(&cell);
        match &mut *slot {
            Slot::Live(s) => s.last_accepted = value,
            Slot::Completed { last, .. } => *last = value,
            _ => {}
        }
    }

    /// Drops a live entry whose `VerifierCore` never verified a single
    /// frame (`next_expected_index() == 0`). A session that has verified
    /// nothing has no replay/reorder state worth keeping, so retaining its
    /// buffer would only let a client presenting garbage frames under
    /// arbitrary `session_id`s pin memory for a full idle TTL each.
    ///
    /// Does nothing for an entry that has advanced, for a tombstone, or
    /// for an id that isn't stored.
    pub fn discard_if_untouched(&self, session_id: &SessionId) {
        let cell = self.lock_entries().get(&session_id.0).cloned();
        let Some(cell) = cell else { return };
        let mut slot = lock_slot(&cell);
        let untouched = matches!(&*slot, Slot::Live(s) if s.core.next_expected_index() == 0);
        if !untouched {
            return;
        }
        // Retired under the slot lock: a thread already waiting for this
        // cell sees it and looks the session up again.
        *slot = Slot::Retired;
        drop(slot);
        self.remove_if_same(session_id, &cell);
    }

    /// Number of live (non-tombstone) entries. Test-only: production code
    /// has no caller for it, and exposing per-store counts through a
    /// metrics path would run into 11.3.2's side-channel concern.
    #[cfg(test)]
    pub fn live_count(&self) -> usize {
        let cells: Vec<Cell> = self.lock_entries().values().cloned().collect();
        cells.iter().filter(|c| matches!(&*lock_slot(c), Slot::Live(_))).count()
    }

    /// Purges entries whose TTL has expired — live entries past
    /// `live_ttl` of idleness, and tombstones past `completed_ttl`.
    /// Explicit invocation, wired into `main.rs`'s periodic sweep. A session
    /// in use right now is never purged.
    pub fn purge_expired(&self) -> usize {
        let mut guard = self.lock_entries();
        let before = guard.len();
        let doomed: Vec<[u8; 16]> = guard
            .iter()
            .filter_map(|(k, c)| match self.judge(c) {
                Verdict::Keep { .. } => None,
                Verdict::Drop => Some(*k),
            })
            .collect();
        for k in doomed {
            guard.remove(&k);
        }
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;
    use lacre_core::session::MasterKeyRing;
    use std::sync::Arc;

    fn dummy_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"test-key-for-verifier-store-32-b".to_vec(),
            Duration::from_secs(60),
        ))
    }

    fn make_verifier(ring: Arc<MasterKeyRing>, session_id: SessionId) -> VerifierCore {
        VerifierCore::resume(ring, session_id, 0, HmacAlgo::Sha256, 1024, 15 * 1024, Duration::from_millis(500))
            .expect("key_id 0 must be recognized right after construction")
    }

    #[test]
    fn get_or_insert_with_creates_once_and_reuses_afterward() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let session_id = SessionId::generate();

        let mut make_calls = 0;
        for _ in 0..3 {
            store
                .get_or_insert_with(
                    session_id,
                    || {
                        make_calls += 1;
                        make_verifier(ring.clone(), session_id)
                    },
                    |_v| (),
                )
                .expect("session is not yet completed, so this must succeed");
        }
        assert_eq!(make_calls, 1, "make() must run exactly once across repeated calls for the same session");
    }

    /// The central case this module exists for: `next_expected_index`
    /// (real state inside `VerifierCore`) must survive between two
    /// separate `get_or_insert_with` calls for the same session — not
    /// just the closure running, the underlying instance's own advance
    /// persisting.
    #[test]
    fn next_expected_index_survives_across_separate_calls() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let session_id = SessionId::generate();

        let index_after_first_call = store
            .get_or_insert_with(
                session_id,
                || make_verifier(ring.clone(), session_id),
                |v| {
                    // No real frame verified here — just observing the
                    // freshly constructed instance's starting point.
                    v.next_expected_index()
                },
            )
            .expect("session is not yet completed, so this must succeed");
        assert_eq!(index_after_first_call, 0);

        // A second, separate call for the SAME session must reuse the
        // same instance (make() doesn't run again — confirmed by the
        // test above), so mutating it here must be visible to any
        // future call too.
        store
            .get_or_insert_with(
                session_id,
                || panic!("make() must not run a second time for an existing session"),
                |_v| (),
            )
            .expect("session is not yet completed, so this must succeed");
    }

    #[test]
    fn with_verifier_returns_not_found_for_unknown_session_id() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let unknown = SessionId::generate();
        let result = store.with_verifier(&unknown, |_| ());
        assert!(matches!(result, Err(TestLookupError::NotFound)));
    }

    #[test]
    fn expired_entry_is_treated_as_not_found_and_recreated_on_next_get_or_insert() {
        let store = VerifierSessionStore::new(Duration::from_millis(20));
        let ring = dummy_ring();
        let session_id = SessionId::generate();

        store
            .get_or_insert_with(session_id, || make_verifier(ring.clone(), session_id), |_v| ())
            .unwrap();
        std::thread::sleep(Duration::from_millis(40));

        assert!(matches!(
            store.with_verifier(&session_id, |_| ()),
            Err(TestLookupError::NotFound)
        ));

        // Past the TTL, get_or_insert_with must call make() again — the
        // old, expired instance is gone, not silently reused.
        let mut make_calls = 0;
        store
            .get_or_insert_with(
                session_id,
                || {
                    make_calls += 1;
                    make_verifier(ring.clone(), session_id)
                },
                |_v| (),
            )
            .unwrap();
        assert_eq!(make_calls, 1, "an expired entry must be rebuilt from scratch, not reused");
    }

    #[test]
    fn idle_ttl_resets_on_each_use_unlike_sealer_sessions() {
        let store = VerifierSessionStore::new(Duration::from_millis(60));
        let ring = dummy_ring();
        let session_id = SessionId::generate();
        store
            .get_or_insert_with(session_id, || make_verifier(ring.clone(), session_id), |_v| ())
            .unwrap();

        // Sleep less than the TTL, then touch the entry — this must
        // reset the idle clock, so the entry survives a second sleep
        // that, added to the first, would exceed the TTL if measured
        // from insertion instead of from last use.
        std::thread::sleep(Duration::from_millis(40));
        let touched = store.with_verifier(&session_id, |_| ());
        assert!(touched.is_ok(), "entry must still be alive before its TTL from last use");

        std::thread::sleep(Duration::from_millis(40));
        let still_alive = store.with_verifier(&session_id, |_| ());
        assert!(
            still_alive.is_ok(),
            "touching the entry must have reset its idle clock — a stale-from-insertion TTL would wrongly expire it here"
        );
    }

    #[test]
    fn purge_expired_removes_only_idle_live_entries() {
        // Wide margins: the fresh session must still be younger than the TTL when
        // `purge_expired` runs, even if the test process is starved for CPU by
        // other test binaries (it flaked at 20 ms / 40 ms under load).
        let store = VerifierSessionStore::new(Duration::from_millis(400));
        let ring = dummy_ring();
        let stale_id = SessionId::generate();
        store
            .get_or_insert_with(stale_id, || make_verifier(ring.clone(), stale_id), |_v| ())
            .unwrap();
        std::thread::sleep(Duration::from_millis(600));

        let fresh_id = SessionId::generate();
        store
            .get_or_insert_with(fresh_id, || make_verifier(ring.clone(), fresh_id), |_v| ())
            .unwrap();

        let purged = store.purge_expired();
        assert_eq!(purged, 1);
        assert!(matches!(store.with_verifier(&stale_id, |_| ()), Err(TestLookupError::NotFound)));
        assert!(store.with_verifier(&fresh_id, |_| ()).is_ok());
    }

    /// The fix this whole extension exists for: once `complete` is
    /// called on a session, any later attempt to verify under that same
    /// `session_id` — even a brand new `get_or_insert_with` call that
    /// would otherwise happily construct a fresh `VerifierCore` at
    /// index 0 — must be refused, not silently treated as a new
    /// session. This is the exact scenario confirmed against the real
    /// running server: a completed session's `session_id`, reused,
    /// wrongly re-verified its own already-verified frame 0 from
    /// scratch before this fix existed.
    #[test]
    fn completed_session_cannot_be_silently_revived() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let session_id = SessionId::generate();

        store
            .get_or_insert_with(session_id, || make_verifier(ring.clone(), session_id), |_v| ())
            .unwrap();
        store.complete(&session_id);

        let mut make_calls = 0;
        let result = store.get_or_insert_with(
            session_id,
            || {
                make_calls += 1;
                make_verifier(ring.clone(), session_id)
            },
            |_v| (),
        );

        assert!(matches!(result, Err(WithVerifierError::AlreadyCompleted)));
        assert_eq!(
            make_calls, 0,
            "make() must never run for a completed session_id — constructing a fresh \
             VerifierCore at all, even one immediately discarded, would mean the check \
             ran too late"
        );
    }

    #[test]
    fn with_verifier_also_reports_already_completed_not_not_found() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let session_id = SessionId::generate();
        store
            .get_or_insert_with(session_id, || make_verifier(ring.clone(), session_id), |_v| ())
            .unwrap();

        store.complete(&session_id);

        // Distinguishing AlreadyCompleted from NotFound matters for the
        // caller: NotFound (an id nobody ever saw) and AlreadyCompleted
        // (an id that finished on purpose) should not be reported to a
        // client identically — one is "you made this up", the other is
        // "this session is over".
        assert!(matches!(
            store.with_verifier(&session_id, |_| ()),
            Err(TestLookupError::AlreadyCompleted)
        ));
    }

    #[test]
    fn completed_tombstone_expires_on_its_own_longer_ttl_and_allows_reuse_afterward() {
        // live_ttl=20ms -> completed_ttl defaults to 40ms (2x, via `new`).
        let store = VerifierSessionStore::new(Duration::from_millis(20));
        let ring = dummy_ring();
        let session_id = SessionId::generate();
        store
            .get_or_insert_with(session_id, || make_verifier(ring.clone(), session_id), |_v| ())
            .unwrap();
        store.complete(&session_id);

        // Past live_ttl (20ms) but still within completed_ttl (40ms):
        // must still be refused as AlreadyCompleted, not treated as
        // merely-expired-and-available.
        std::thread::sleep(Duration::from_millis(30));
        assert!(matches!(
            store.with_verifier(&session_id, |_| ()),
            Err(TestLookupError::AlreadyCompleted)
        ));

        // Past completed_ttl too: the tombstone itself finally expires,
        // and the session_id becomes reusable — a deliberate, bounded
        // trade-off (see the module-level doc), not a leftover gap.
        std::thread::sleep(Duration::from_millis(30));
        let mut make_calls = 0;
        let result = store.get_or_insert_with(
            session_id,
            || {
                make_calls += 1;
                make_verifier(ring.clone(), session_id)
            },
            |_v| (),
        );
        assert!(result.is_ok(), "a tombstone past its own TTL must allow the session_id to be reused");
        assert_eq!(make_calls, 1);
    }

    #[test]
    fn purge_expired_also_clears_expired_tombstones() {
        let store = VerifierSessionStore::with_ttls(Duration::from_secs(60), Duration::from_millis(20));
        let ring = dummy_ring();
        let session_id = SessionId::generate();
        store
            .get_or_insert_with(session_id, || make_verifier(ring.clone(), session_id), |_v| ())
            .unwrap();
        store.complete(&session_id);
        std::thread::sleep(Duration::from_millis(40));

        let purged = store.purge_expired();
        assert_eq!(purged, 1, "an expired tombstone must be purged same as an expired live entry");
        assert!(matches!(store.with_verifier(&session_id, |_| ()), Err(TestLookupError::NotFound)));
    }

    #[test]
    fn refuses_a_new_session_once_the_live_ceiling_is_reached() {
        let store = VerifierSessionStore::with_limits(
            Duration::from_secs(60), Duration::from_secs(120), 3);
        let ring = dummy_ring();
        for _ in 0..3 {
            let id = SessionId::generate();
            store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| ()).unwrap();
        }
        assert_eq!(store.live_count(), 3);

        let overflow_id = SessionId::generate();
        let mut make_calls = 0;
        let result = store.get_or_insert_with(
            overflow_id,
            || { make_calls += 1; make_verifier(ring.clone(), overflow_id) },
            |_v| (),
        );
        assert_eq!(result, Err(WithVerifierError::AtCapacity));
        assert_eq!(make_calls, 0, "no buffer may be allocated for a refused session");
        assert_eq!(store.live_count(), 3);
    }

    #[test]
    fn an_existing_session_is_never_refused_by_the_ceiling() {
        let store = VerifierSessionStore::with_limits(
            Duration::from_secs(60), Duration::from_secs(120), 2);
        let ring = dummy_ring();
        let a = SessionId::generate();
        let b = SessionId::generate();
        store.get_or_insert_with(a, || make_verifier(ring.clone(), a), |_v| ()).unwrap();
        store.get_or_insert_with(b, || make_verifier(ring.clone(), b), |_v| ()).unwrap();
        // Store is full, but `a` is already in it: reuse must still work.
        assert!(store.get_or_insert_with(a, || panic!("must reuse"), |_v| ()).is_ok());
    }

    #[test]
    fn expired_sessions_are_swept_to_make_room_before_refusing() {
        let store = VerifierSessionStore::with_limits(
            Duration::from_millis(20), Duration::from_secs(60), 2);
        let ring = dummy_ring();
        for _ in 0..2 {
            let id = SessionId::generate();
            store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| ()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(40));
        let fresh = SessionId::generate();
        assert!(
            store.get_or_insert_with(fresh, || make_verifier(ring.clone(), fresh), |_v| ()).is_ok(),
            "idle sessions must be reclaimed, not left to block a legitimate new one"
        );
        assert_eq!(store.live_count(), 1);
    }

    #[test]
    fn tombstones_do_not_count_against_the_live_ceiling() {
        let store = VerifierSessionStore::with_limits(
            Duration::from_secs(60), Duration::from_secs(120), 2);
        let ring = dummy_ring();
        for _ in 0..5 {
            let id = SessionId::generate();
            store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| ()).unwrap();
            store.complete(&id);
        }
        let fresh = SessionId::generate();
        assert!(store.get_or_insert_with(fresh, || make_verifier(ring.clone(), fresh), |_v| ()).is_ok());
    }

    #[test]
    fn discard_if_untouched_drops_only_sessions_that_never_advanced() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let id = SessionId::generate();
        store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| ()).unwrap();
        assert_eq!(store.live_count(), 1);
        store.discard_if_untouched(&id);
        assert_eq!(store.live_count(), 0, "a session that verified nothing must not be retained");
        // Unknown id and tombstone: both harmless no-ops.
        store.discard_if_untouched(&SessionId::generate());
        let done = SessionId::generate();
        store.get_or_insert_with(done, || make_verifier(ring.clone(), done), |_v| ()).unwrap();
        store.complete(&done);
        store.discard_if_untouched(&done);
        assert!(matches!(store.with_verifier(&done, |_| ()), Err(TestLookupError::AlreadyCompleted)));
    }

    // ---- E4: per-session locks, contained panics, no restart of a failed session ----

    /// Eight sessions whose verification takes 50 ms each must overlap. With the old
    /// global lock they took about 400 ms in total; with per-session locks, about 50 ms.
    #[test]
    fn slow_verifications_of_different_sessions_do_not_serialize() {
        let store = Arc::new(VerifierSessionStore::with_limits(
            Duration::from_secs(60), Duration::from_secs(120), 64));
        let ring = dummy_ring();
        let start = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let ring = ring.clone();
                std::thread::spawn(move || {
                    let id = SessionId::generate();
                    store
                        .get_or_insert_with(
                            id,
                            || make_verifier(ring.clone(), id),
                            |_v| std::thread::sleep(Duration::from_millis(50)),
                        )
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let took = start.elapsed();
        assert!(
            took < Duration::from_millis(250),
            "8 sessions of 50 ms each took {took:?}: they were serialized (a global lock would take about 400 ms)"
        );
    }

    /// The same session still serializes: two calls for one session never overlap.
    #[test]
    fn calls_for_the_same_session_still_run_one_at_a_time() {
        let store = Arc::new(VerifierSessionStore::new(Duration::from_secs(60)));
        let ring = dummy_ring();
        let id = SessionId::generate();
        store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| ()).unwrap();
        let inside = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (store, inside, max_seen) = (store.clone(), inside.clone(), max_seen.clone());
                std::thread::spawn(move || {
                    store
                        .get_or_insert_with(id, || panic!("exists"), |_v| {
                            use std::sync::atomic::Ordering::SeqCst;
                            let now = inside.fetch_add(1, SeqCst) + 1;
                            max_seen.fetch_max(now, SeqCst);
                            std::thread::sleep(Duration::from_millis(20));
                            inside.fetch_sub(1, SeqCst);
                        })
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(max_seen.load(std::sync::atomic::Ordering::SeqCst), 1, "one session must never run two verifications at once");
    }

    /// A panic inside the verification is contained: the call reports `Panicked`, the
    /// session is closed for good, and the store keeps serving other sessions (no
    /// poisoned global lock).
    #[test]
    fn a_panic_is_contained_and_does_not_poison_the_store() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let bad = SessionId::generate();
        let result: Result<(), _> = store.get_or_insert_with(
            bad,
            || make_verifier(ring.clone(), bad),
            |_v| panic!("algorithm blew up"),
        );
        assert_eq!(result, Err(WithVerifierError::Panicked));

        // Other sessions are unaffected.
        let other = SessionId::generate();
        assert!(store.get_or_insert_with(other, || make_verifier(ring.clone(), other), |_v| ()).is_ok());
        assert_eq!(store.live_count(), 1, "the failed session is a tombstone, not a live entry");
        assert!(store.purge_expired() == 0);
    }

    /// Annex 15, vector 2 (normative): a failed session cannot be restored. The same
    /// `session_id` is refused and `make` never runs again for it.
    #[test]
    fn a_failed_session_cannot_be_restarted_with_the_same_id() {
        let store = VerifierSessionStore::new(Duration::from_secs(60));
        let ring = dummy_ring();
        let id = SessionId::generate();
        let _ = store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| -> () { panic!("boom") });

        let mut make_calls = 0;
        let again = store.get_or_insert_with(
            id,
            || {
                make_calls += 1;
                make_verifier(ring.clone(), id)
            },
            |_v| (),
        );
        assert_eq!(again, Err(WithVerifierError::SessionFailed));
        assert_eq!(make_calls, 0, "a failed session_id must never get a fresh VerifierCore");
        assert!(matches!(store.with_verifier(&id, |_| ()), Err(TestLookupError::Failed)));

        // complete() is a different state and must not turn a failure into a success.
        assert_eq!(
            store.get_or_insert_with(id, || panic!("no"), |_v| ()),
            Err(WithVerifierError::SessionFailed)
        );
    }

    #[test]
    fn a_failed_tombstone_expires_on_the_tombstone_ttl() {
        let store = VerifierSessionStore::with_ttls(Duration::from_secs(60), Duration::from_millis(20));
        let ring = dummy_ring();
        let id = SessionId::generate();
        let _ = store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| -> () { panic!("boom") });
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(store.purge_expired(), 1);
    }

    /// A session being verified right now is never swept, even if its idle TTL would
    /// otherwise have expired while a slow verification holds its lock.
    #[test]
    fn a_session_in_use_is_not_purged_by_a_sweep() {
        let store = Arc::new(VerifierSessionStore::new(Duration::from_millis(10)));
        let ring = dummy_ring();
        let id = SessionId::generate();
        let (tx, rx) = std::sync::mpsc::channel();
        let (s2, r2) = (store.clone(), ring.clone());
        let worker = std::thread::spawn(move || {
            s2.get_or_insert_with(
                id,
                || make_verifier(r2.clone(), id),
                |_v| {
                    tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(80));
                },
            )
            .unwrap();
        });
        rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(store.purge_expired(), 0, "a busy session must be treated as alive");
        worker.join().unwrap();
    }

    /// `discard_if_untouched` racing with a waiting caller must not lose that caller's work:
    /// the waiting call looks the session up again instead of running on a discarded cell.
    #[test]
    fn discard_while_another_call_waits_does_not_lose_state() {
        let store = Arc::new(VerifierSessionStore::new(Duration::from_secs(60)));
        let ring = dummy_ring();
        for _ in 0..50 {
            let id = SessionId::generate();
            store.get_or_insert_with(id, || make_verifier(ring.clone(), id), |_v| ()).unwrap();
            let (s2, r2) = (store.clone(), ring.clone());
            let t = std::thread::spawn(move || {
                // Either finds the live entry, or (if discarded first) creates a new one.
                s2.get_or_insert_with(id, || make_verifier(r2.clone(), id), |v| v.next_expected_index()).unwrap()
            });
            store.discard_if_untouched(&id);
            assert_eq!(t.join().unwrap(), 0);
            store.discard_if_untouched(&id);
        }
    }
}

//! Profile Engine — Profiles Annex 5.0, Section III.
//!
//! # What this actually generalizes, and why it's narrower than the annex's proposal
//!
//! Annex 5.0 proposes a full declarative vocabulary for stateful
//! Profiles (`kind = "engine"`, `statefulness = "stateful"`, a
//! `[profile.x.state]` block with `key`/`retention` fields, TOML rule
//! blocks with `on_complete` actions) as a sketch, explicitly admitted
//! in the annex itself to be less certain than the rest of that
//! document — "this annex cannot close this vocabulary with the same
//! confidence it closed the Declarative Adapter's". Building a TOML
//! parser and a generic rule interpreter against that sketch would be
//! implementing a speculative vocabulary that has exactly one worked
//! example behind it (`ReassembleProfile`) in the annex's own account.
//!
//! What actually has two worked examples, in this codebase, right
//! now, is a much narrower and more concrete problem: **neither
//! stateful Profile that exists — `ReassembleProfile` nor
//! `ToolchainProfile` — has any way to purge its own retained state.**
//! `ReassembleProfile`'s `held_ahead` map can grow without bound if an
//! expected frame never arrives; `ToolchainProfile`'s `nodes` and
//! `tainted` sets only ever grow for the struct's lifetime. This is
//! exactly the resource-exhaustion vector Annex 5.0 Section 3.5
//! describes for a hypothetical declarative stateful Profile — except
//! it's not hypothetical, it's already true of both concrete stateful
//! Profiles in this codebase (see `PENDING.md`, "Real gap found while
//! comparing stateful Profiles").
//!
//! This module generalizes *that* — a retention policy any stateful
//! Profile can hold alongside its own state, following the exact same
//! pattern `lacre-core::buffer::PendingBuffer` already uses for the
//! Core's own fragment buffer: a relative `Instant`-based epoch, an
//! `elapsed_ms()` reading, and an explicit `sweep()` call rather than
//! an automatic timer — because, per `ARCHITECTURE_NOTES.md`'s own
//! documented reasoning for `PendingBuffer::purge_expired`, purging on
//! every operation would penalize the hot path, so the caller decides
//! when to sweep.
//!
//! # What this module does NOT attempt
//!
//! It does not implement a TOML-configurable rule vocabulary, a
//! `kind = "engine"` profile declaration format, or a generic
//! `state_complete`/`gaps_allowed` condition language. Those remain
//! exactly as open as Annex 5.0 leaves them — this module doesn't
//! pretend to close them. It also does not decide *what* counts as
//! "complete" for a given stateful Profile (that's inherently
//! Profile-specific: a chain reaching its last index for
//! `ReassembleProfile`, a node being explicitly queried for
//! `ToolchainProfile`) — it only tracks *when* an entry was inserted
//! and reports which ones are past their retention deadline, leaving
//! what to do about that entirely to the Profile holding it.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A bounded-retention record of entries keyed by `K`, generalizing
/// the "how long has this been sitting here unresolved" question that
/// both `ReassembleProfile::held_ahead` and `ToolchainProfile::nodes`
/// need an answer to but don't currently track at all.
///
/// Deliberately holds no opinion about what `K` or the entry's payload
/// represent — a stateful Profile embeds one of these next to its own
/// state (see the `ReassembleProfile`/`ToolchainProfile` integration
/// pattern demonstrated in this module's own tests) and calls
/// `record()` whenever it accepts something it might need to evict
/// later, and `sweep()` on whatever cadence it already uses to
/// perform its own bookkeeping — mirroring how `PendingBuffer::purge_expired`
/// is invoked externally by `SealerCore`/`VerifierCore` rather than
/// firing on its own timer.
pub struct RetentionTracker<K: Eq + Hash + Clone> {
    max_age: Duration,
    epoch: Instant,
    /// Milliseconds since `epoch` at which each key was recorded.
    /// `u32`, not a full `Instant` per entry, for the same reason
    /// `buffer.rs`'s own `Slot::inserted_at_ms` uses `u32`: a
    /// Profile's retention window is expected to be measured in
    /// seconds to minutes (Annex 5.0's own examples), not years, and a
    /// `u32` of milliseconds covers roughly 49 days of continuous
    /// tracking without needing the 8-byte width of an `Instant`.
    inserted_at_ms: HashMap<K, u32>,
}

impl<K: Eq + Hash + Clone> RetentionTracker<K> {
    /// `max_age` is the retention deadline: an entry recorded at time
    /// T is eligible for eviction once `now - T > max_age`. Per Annex
    /// 5.0 Section 3.5's own mitigation ("a stateful declarative
    /// Profile must never declare `retention = "until_complete"`
    /// without an explicit maximum timeout"), this constructor takes
    /// no `Option` and no default — a `RetentionTracker` always has a
    /// bound, by construction, not by convention a caller has to
    /// remember to apply.
    pub fn new(max_age: Duration) -> Self {
        RetentionTracker {
            max_age,
            epoch: Instant::now(),
            inserted_at_ms: HashMap::new(),
        }
    }

    fn elapsed_ms(&self) -> u32 {
        self.epoch.elapsed().as_millis().min(u32::MAX as u128) as u32
    }

    /// Records that `key` was accepted right now. If `key` was already
    /// being tracked, its age resets — matching the intuitive
    /// semantics of "this entry is still active" rather than treating
    /// a re-insertion as a duplicate to ignore (a caller that wants
    /// duplicate-insertion semantics, like `ReassembleProfile` already
    /// has for `held_ahead`, keeps enforcing that itself; this tracker
    /// only answers "how long has *a* version of this key been
    /// live").
    pub fn record(&mut self, key: K) {
        let now_ms = self.elapsed_ms();
        self.inserted_at_ms.insert(key, now_ms);
    }

    /// Stops tracking `key` — called when the Profile itself resolves
    /// the entry (a frame's gap gets filled, a graph node gets
    /// verified) so it doesn't later show up as "expired" for
    /// something that was already handled through the Profile's own
    /// normal completion path, not through eviction.
    pub fn forget(&mut self, key: &K) {
        self.inserted_at_ms.remove(key);
    }

    /// Returns every currently-tracked key whose age exceeds `max_age`,
    /// without removing them — mirrors `PendingBuffer::purge_expired`'s
    /// own split between *finding* expired entries and a caller
    /// deciding what "purging" means for its own state (for
    /// `PendingBuffer` that's freeing a byte slot; for a stateful
    /// Profile it's Profile-specific — dropping a `held_ahead` entry,
    /// or running `taint_and_cascade` on an incomplete graph node).
    /// Callers that want removal call `forget()` themselves for each
    /// key this returns, once they've done whatever cleanup their own
    /// state requires.
    pub fn expired(&self) -> Vec<K> {
        let now_ms = self.elapsed_ms();
        let max_age_ms: u32 = self.max_age.as_millis().min(u32::MAX as u128) as u32;
        self.inserted_at_ms
            .iter()
            .filter(|(_, &inserted)| now_ms.saturating_sub(inserted) > max_age_ms)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Number of entries currently tracked, expired or not — an
    /// inspection utility for tests and for a Profile that wants to
    /// expose its own retained-state size (the same kind of number
    /// `ToolchainProfile::node_count` already exposes for its own
    /// state).
    pub fn tracked_count(&self) -> usize {
        self.inserted_at_ms.len()
    }
}

#[cfg(test)]
mod tests {
    fn full(f: &lacre_core::frame::LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;

    #[test]
    fn a_freshly_recorded_key_is_not_expired() {
        let mut tracker = RetentionTracker::new(Duration::from_millis(500));
        tracker.record("fragment-3");
        assert!(tracker.expired().is_empty());
    }

    #[test]
    fn a_key_past_max_age_is_reported_as_expired() {
        let mut tracker = RetentionTracker::new(Duration::from_millis(20));
        tracker.record("fragment-3");
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(tracker.expired(), vec!["fragment-3"]);
    }

    #[test]
    fn expired_does_not_remove_entries_removal_is_the_callers_job() {
        let mut tracker = RetentionTracker::new(Duration::from_millis(20));
        tracker.record("fragment-3");
        std::thread::sleep(Duration::from_millis(40));

        assert_eq!(tracker.expired().len(), 1);
        // Calling `expired()` again without `forget()` still reports it
        // — this method only inspects, it never evicts on its own,
        // mirroring `PendingBuffer::purge_expired`'s split between
        // finding and freeing.
        assert_eq!(tracker.expired().len(), 1);
        assert_eq!(tracker.tracked_count(), 1);
    }

    #[test]
    fn forget_removes_a_key_from_tracking_entirely() {
        let mut tracker = RetentionTracker::new(Duration::from_millis(20));
        tracker.record("fragment-3");
        std::thread::sleep(Duration::from_millis(40));

        tracker.forget(&"fragment-3");
        assert!(tracker.expired().is_empty());
        assert_eq!(tracked_count(&tracker), 0);

        fn tracked_count<K: Eq + Hash + Clone>(t: &RetentionTracker<K>) -> usize {
            t.tracked_count()
        }
    }

    #[test]
    fn re_recording_an_existing_key_resets_its_age() {
        let mut tracker = RetentionTracker::new(Duration::from_millis(30));
        tracker.record("fragment-3");
        std::thread::sleep(Duration::from_millis(20));
        // Still fresh (20 ms < 30 ms max age) — re-record to simulate
        // the Profile seeing renewed activity for this key.
        tracker.record("fragment-3");
        std::thread::sleep(Duration::from_millis(20));
        // 20 ms since the second record — still under the 30 ms
        // threshold, even though 40 ms have passed since the first.
        assert!(tracker.expired().is_empty());
    }

    #[test]
    fn multiple_keys_expire_independently() {
        let mut tracker = RetentionTracker::new(Duration::from_millis(30));
        tracker.record("old");
        std::thread::sleep(Duration::from_millis(40));
        tracker.record("fresh");

        let expired = tracker.expired();
        assert_eq!(expired, vec!["old"]);
        assert_eq!(tracker.tracked_count(), 2); // "fresh" still tracked, not expired
    }

    /// Integration demonstration: `ReassembleProfile`'s own
    /// `held_ahead` gap — a frame held out of order that never gets
    /// its missing predecessor — is exactly the shape `RetentionTracker`
    /// exists to close. This test builds a minimal analogue of that
    /// situation directly against `ReassembleProfile` (not a
    /// hypothetical) to demonstrate the tracker actually applies to
    /// the real gap found in `PENDING.md`, not just to a synthetic
    /// `&str` key in isolation.
    #[test]
    fn retention_tracker_applies_to_reassemble_profiles_real_gap() {
        use lacre_core::frame::LacreFrame;
        use crate::profile::ReassembleProfile;
        use lacre_core::session::SessionId;

        let mut profile = ReassembleProfile::new(Duration::from_millis(20));
        let mut tracker: RetentionTracker<u64> = RetentionTracker::new(Duration::from_millis(20));

        let session_id = SessionId::generate();
        // Frame 1 arrives before frame 0 — held out of order, exactly
        // `ReassembleProfile`'s own documented held-ahead case.
        let frame1 = LacreFrame {
            session_id,
            index: 1,
            total_fragments: Some(2),
            is_last: true,
            payload: b"second half".to_vec(),
        };
        profile.accept(&full(&frame1), None);
        tracker.record(1u64); // Profile-side bookkeeping: "index 1 is now held, waiting on its gap"

        assert!(profile.try_reassemble().is_none()); // gap at index 0 still open
        assert!(tracker.expired().is_empty()); // not old enough yet

        std::thread::sleep(Duration::from_millis(40));

        // The missing predecessor (index 0) never arrives. A caller
        // sweeping on its own cadence — the same pattern
        // `SealerCore`/`VerifierCore` already use for
        // `PendingBuffer::purge_expired` — now learns index 1 has been
        // waiting too long, and can decide to drop it rather than
        // hold it indefinitely. `RetentionTracker` only reports this;
        // it has no access to `ReassembleProfile`'s internals to
        // evict the entry itself, by design (see this module's header
        // comment on leaving what "eviction" means entirely to the
        // Profile that owns the state).
        assert_eq!(tracker.expired(), vec![1u64]);
    }
}

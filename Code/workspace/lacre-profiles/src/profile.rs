//! Profiles — Chapter 7.3 of Project Lacre Prime.
//!
//! Extension components that operate on frames **already verified by
//! the Core**. Unlike the Core (invariant, 7.2), Profiles are not
//! expected to stay stable: they are the system's extensibility
//! surface. Each Profile declares `TOUCHES_PAYLOAD` (7.3.1) — whether
//! its function requires accessing the fragment's content, not just
//! its identity header.
//!
//! # ReassembleProfile: the first concrete Profile
//!
//! Reconstructs the complete payload from a sequence of already-
//! verified frames. This is the direct migration of what previously
//! lived inside `protocol::VerifierProtocol` (`pending_ahead`,
//! `verified_payloads`, `try_reassemble`) — the logic didn't change,
//! its location did: 8.1 is explicit that reassembly "doesn't belong
//! to the Core but to a specific Profile layer", so it's reclassified
//! as a Profile instead of part of the central verification flow.
//!
//! `TOUCHES_PAYLOAD = true`: it literally reconstructs content from
//! its fragments — that's the definition of touching the payload.
//!
//! # Retention (Annex 5.0, Profile Engine)
//!
//! `held_ahead` can grow without bound if a frame with a lower index
//! never arrives to fill the gap — a stateful Profile's own resource-
//! exhaustion vector, the same one `ToolchainProfile::nodes` had
//! before its own `RetentionTracker` integration (see
//! `PENDING.md`, "Real gap found while comparing stateful Profiles").
//! `sweep_expired` closes it here too, with the eviction semantics
//! that actually make sense *for this Profile*: a held-ahead frame
//! whose gap never fills can never be reassembled, no matter how long
//! it's kept — there's no "taint and cascade" concept in a linear
//! reassembly sequence the way there is in `ToolchainProfile`'s graph,
//! so eviction here means dropping the entry outright, freeing the
//! memory it was holding. This deliberate difference in what
//! "eviction" means between the two stateful Profiles is exactly why
//! `RetentionTracker` (see `profile_engine.rs`) only tracks *when*
//! something was recorded and leaves *what happens* to it entirely to
//! the Profile that owns the state.

use lacre_core::access::{AccessLevel, ContentAccess, ContentView, FullContent};
#[cfg(test)]
use lacre_core::frame::LacreFrame;
use crate::profile_engine::RetentionTracker;
use crate::transit_taxonomy::{self, NonNovelty, TransitIdentity};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

/// A Profile declares the level of content access it needs as a type. The
/// compiler then limits what it can reach: a Profile written against
/// `NoContent` is handed a view without byte accessors (see
/// `lacre_core::access`). `ACCESS` and `TOUCHES_PAYLOAD` are derived from
/// that one declaration, so they cannot disagree with it.
pub trait Profile {
    type Access: AccessLevel;
    const ACCESS: ContentAccess = <Self::Access as AccessLevel>::LEVEL;
    const TOUCHES_PAYLOAD: bool = <Self::Access as AccessLevel>::LEVEL.reads_bytes();
}

/// The view a Profile's entry points receive: its content, at the level it
/// declared. Writing the signatures with this alias ties each entry point to
/// the declaration, so lowering `type Access` stops the body from compiling
/// the moment it tries to read bytes it no longer declares.
pub type ViewOf<'a, P> = ContentView<'a, <P as Profile>::Access>;

/// A frame already verified by the Core, but that this Profile can't
/// incorporate into the reassembly yet because it arrived before an
/// earlier index. The Core already certified its integrity
/// (`verify_frame` already returned `Ok` before this frame gets here)
/// — what's missing isn't verification, it's arrival order for this
/// Profile's own purpose.
struct HeldFrame {
    payload: Vec<u8>,
    is_last: bool,
}

/// Reconstructs a complete payload from frames already verified by
/// `core::VerifierCore`. Never repeats any verification — assumes
/// everything it receives in `accept` already passed
/// `VerifierCore::verify_frame` successfully. Its only responsibility
/// is ordering and concatenating.
pub struct ReassembleProfile {
    verified_payloads: BTreeMap<u64, Vec<u8>>,
    /// Frames verified by the Core but that arrived at this Profile
    /// with a higher index than expected — can happen if the transport
    /// Adapter delivers frames to the Profile in a different order
    /// than the Core verified them in (e.g. transport-level
    /// parallelism). Held here, not in the Core.
    held_ahead: HashMap<u64, HeldFrame>,
    next_expected: u64,
    total_fragments: Option<u64>,
    reassembled: bool,
    /// See this module's header comment on retention. Every entry
    /// added to `held_ahead` is recorded here at the same time;
    /// forgotten the moment it's consumed by the reprocessing loop in
    /// `accept`, same as `ToolchainProfile` forgets a node the moment
    /// `verify_output` resolves it.
    retention: RetentionTracker<u64>,
}

impl Profile for ReassembleProfile {
    type Access = FullContent;
}

#[derive(Debug)]
pub enum AcceptOutcome {
    /// The frame was incorporated into the reassembled sequence.
    Accepted,
    /// Already incorporated before (index < next_expected) — see
    /// `NonNovelty` (Annex 6.0, Sub-problema 2) for why the failed
    /// fragment fell into this outcome, without this diagnosis
    /// changing the outcome itself. This is exactly the "diagnóstico,
    /// no una excepción al fallo cerrado" Annex 6.0 describes: the
    /// frame is discarded here unconditionally, same as before this
    /// field existed — a caller that ignores this field observes
    /// identical behavior to before it was added.
    DuplicateIgnored(NonNovelty),
    /// Arrived before its turn; held for later.
    HeldAhead,
}

impl ReassembleProfile {
    /// `max_held_age` bounds how long a held-ahead frame may wait for
    /// its gap to fill before `sweep_expired` is entitled to drop it.
    /// No default, no `Option` — same reasoning as
    /// `ToolchainProfile::new`'s own `max_node_age` parameter: per
    /// Annex 5.0 Section 3.5, a stateful Profile must never have an
    /// unbounded retention window available "by omission".
    pub fn new(max_held_age: Duration) -> Self {
        ReassembleProfile {
            verified_payloads: BTreeMap::new(),
            held_ahead: HashMap::new(),
            next_expected: 0,
            total_fragments: None,
            reassembled: false,
            retention: RetentionTracker::new(max_held_age),
        }
    }

    /// Incorporates a frame already verified by the Core. `frame` must
    /// have already passed `VerifierCore::verify_frame` successfully
    /// before reaching here — this method verifies nothing, it only
    /// orders.
    ///
    /// `transit_identity` is accepted so a caller whose Adapter DOES
    /// capture arrival metadata can pass it through — see
    /// `transit_taxonomy`'s own documentation for why this parameter
    /// does not yet change the classification result for any input
    /// this codebase's real Adapters produce today (neither
    /// `http_server.rs` nor `websocket_adapter.rs` captures it, so
    /// every real call site passes `None`).
    pub fn accept(
        &mut self,
        view: &ViewOf<'_, Self>,
        transit_identity: Option<&TransitIdentity>,
    ) -> AcceptOutcome {
        let header = view.header();
        let index = header.index;
        let is_last = header.is_last;
        if index < self.next_expected {
            // Look up what was actually recorded at this index — a
            // frame at an index below `next_expected` was necessarily
            // already chained into `verified_payloads` by a previous
            // call to `insert_one` (that's the definition of
            // `next_expected` having advanced past it), so this lookup
            // never panics on a missing entry for any index in this
            // range.
            let previously_accepted = self
                .verified_payloads
                .get(&index)
                .expect("an index below next_expected was already inserted into verified_payloads");
            let diagnosis =
                transit_taxonomy::classify(view, previously_accepted, transit_identity);
            return AcceptOutcome::DuplicateIgnored(diagnosis);
        }
        if index > self.next_expected {
            self.retention.record(index);
            self.held_ahead.insert(
                index,
                HeldFrame {
                    payload: view.content_bytes().to_vec(),
                    is_last,
                },
            );
            return AcceptOutcome::HeldAhead;
        }

        self.insert_one(index, view.content_bytes().to_vec(), is_last);

        // Chain-process any held frame that is now the next expected
        // one.
        while let Some(HeldFrame { payload, is_last }) = self.held_ahead.remove(&self.next_expected) {
            self.retention.forget(&self.next_expected);
            self.insert_one(self.next_expected, payload, is_last);
        }

        AcceptOutcome::Accepted
    }

    fn insert_one(&mut self, index: u64, payload: Vec<u8>, is_last: bool) {
        if is_last {
            self.total_fragments = Some(index + 1);
        }
        self.verified_payloads.insert(index, payload);
        self.next_expected = index + 1;
    }

    /// Evicts held-ahead frames whose gap has not filled within
    /// `max_held_age`. Unlike `ToolchainProfile::sweep_expired` — where
    /// an expired node is tainted so the failure propagates — a
    /// held-ahead frame here is simply dropped: there's no downstream
    /// node to cascade a failure to, only unreachable memory to free.
    /// Mirrors the same external-cadence pattern
    /// `PendingBuffer::purge_expired` and `ToolchainProfile::sweep_expired`
    /// both already use: never called automatically, always invoked by
    /// the caller on whatever schedule it already uses.
    ///
    /// Returns the indices that were evicted this sweep.
    pub fn sweep_expired(&mut self) -> Vec<u64> {
        let expired = self.retention.expired();
        for index in &expired {
            self.retention.forget(index);
            self.held_ahead.remove(index);
        }
        expired
    }

    /// Index the next in-order frame must have.
    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Bytes currently held: incorporated payloads plus frames held ahead.
    /// Lets a caller put a ceiling on a reassembly it does not trust to
    /// stay small.
    pub fn buffered_bytes(&self) -> usize {
        self.verified_payloads.values().map(Vec::len).sum::<usize>()
            + self.held_ahead.values().map(|h| h.payload.len()).sum::<usize>()
    }

    /// Diagnoses a frame whose index is below `next_expected` (one the
    /// Core refused as a duplicate/replay) WITHOUT touching any state:
    /// the same classification `accept` attaches to `DuplicateIgnored`,
    /// available to a caller that already knows the frame was rejected.
    /// `None` if the index is not one this Profile has incorporated.
    pub fn classify_duplicate(
        &self,
        view: &ViewOf<'_, Self>,
        transit_identity: Option<&TransitIdentity>,
    ) -> Option<NonNovelty> {
        let previous = self.verified_payloads.get(&view.header().index)?;
        Some(transit_taxonomy::classify(view, previous, transit_identity))
    }

    /// Reassembles the complete payload if the sequence is contiguous
    /// and complete; `None` if frames are still missing. Reassembles
    /// exactly once: calls after a success return `None`.
    pub fn try_reassemble(&mut self) -> Option<Vec<u8>> {
        if self.reassembled {
            return None;
        }
        let total = self.total_fragments?;
        if self.verified_payloads.len() as u64 != total {
            return None;
        }
        self.reassembled = true;
        Some(self.verified_payloads.values().flatten().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    fn full(f: &lacre_core::frame::LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;
    use lacre_core::core::{SealerCore, VerifierCore};
    use lacre_core::hmac_seal::HmacAlgo;
    use lacre_core::session::{MasterKeyRing, SessionId};
    use std::sync::Arc;

    fn test_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ))
    }

    /// A generous default so tests not about retention itself never
    /// have `sweep_expired` interfere with what they're actually
    /// checking — same convention used for `ToolchainProfile`'s tests.
    fn generous_retention() -> Duration {
        Duration::from_secs(3600)
    }

    /// Real end-to-end flow: the Core seals and verifies, the Profile
    /// reassembles — confirming the layer separation actually works
    /// end to end, not just in isolation.
    #[test]
    fn core_verifies_then_profile_reassembles() {
        let ring = test_ring();
        let mut sealer = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
        );
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

        let original = b"the quick brown fox jumps over the lazy dog".to_vec();
        let sealed = sealer.seal_payload(&original, 8).unwrap();

        let mut profile = ReassembleProfile::new(generous_retention());
        for (frame, seal) in sealed {
            verifier
                .verify_frame(&frame, ring.active_key_id(), &seal, None)
                .expect("the Core must verify every frame");
            let outcome = profile.accept(&full(&frame), None);
            assert!(matches!(outcome, AcceptOutcome::Accepted));
        }

        let reassembled = profile.try_reassemble().expect("complete sequence");
        assert_eq!(reassembled, original);
        assert!(profile.try_reassemble().is_none());
    }

    #[test]
    fn out_of_order_frames_are_held_then_chained() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(2),
            is_last: false,
            payload: b"first".to_vec(),
        };
        let frame1 = LacreFrame {
            session_id: sid,
            index: 1,
            total_fragments: Some(2),
            is_last: true,
            payload: b"second".to_vec(),
        };

        let mut profile = ReassembleProfile::new(generous_retention());
        assert!(matches!(
            profile.accept(&full(&frame1), None),
            AcceptOutcome::HeldAhead
        ));
        assert!(matches!(
            profile.accept(&full(&frame0), None),
            AcceptOutcome::Accepted
        ));

        let reassembled = profile.try_reassemble().expect("complete sequence");
        assert_eq!(reassembled, b"firstsecond".to_vec());
    }

    #[test]
    fn duplicate_frame_is_ignored() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"only".to_vec(),
        };

        let mut profile = ReassembleProfile::new(generous_retention());
        assert!(matches!(
            profile.accept(&full(&frame0), None),
            AcceptOutcome::Accepted
        ));
        // Same content resent at an already-resolved index: per
        // `transit_taxonomy`'s own honest scope, this is reported as
        // `SameContentUnclearOrigin` (not asserted as `Duplicate`
        // specifically) because no `TransitIdentity` was supplied to
        // distinguish a legitimate resend from a malicious replay —
        // see this profile's `accept` and `transit_taxonomy`'s own
        // documentation for why.
        match profile.accept(&full(&frame0), None) {
            AcceptOutcome::DuplicateIgnored(diagnosis) => {
                assert_eq!(diagnosis, NonNovelty::SameContentUnclearOrigin);
            }
            other => panic!("expected DuplicateIgnored, got a different AcceptOutcome variant: {other:?}"),
        }
    }

    /// A frame arriving at an already-resolved index with DIFFERENT
    /// content — Annex 6.0's own `NewMessage` case (a session
    /// collision, not a resend) — must be diagnosed as such, not
    /// conflated with the ordinary duplicate case above.
    #[test]
    fn colliding_frame_with_different_content_is_diagnosed_as_new_message() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"original content".to_vec(),
        };
        let colliding_frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"different content, same index".to_vec(),
        };

        let mut profile = ReassembleProfile::new(generous_retention());
        profile.accept(&full(&frame0), None);

        match profile.accept(&full(&colliding_frame0), None) {
            AcceptOutcome::DuplicateIgnored(diagnosis) => {
                assert_eq!(diagnosis, NonNovelty::NewMessage);
            }
            other => panic!("expected DuplicateIgnored, got a different AcceptOutcome variant: {other:?}"),
        }
    }

    #[test]
    fn reassembly_refuses_while_gap_remains() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(3),
            is_last: false,
            payload: b"aaaa".to_vec(),
        };
        let frame2 = LacreFrame {
            session_id: sid,
            index: 2,
            total_fragments: Some(3),
            is_last: true,
            payload: b"cccc".to_vec(),
        };

        let mut profile = ReassembleProfile::new(generous_retention());
        profile.accept(&full(&frame0), None);
        profile.accept(&full(&frame2), None); // stays HeldAhead, index 1 is missing

        assert!(profile.try_reassemble().is_none());
    }

    /// Streaming: frames with total_fragments=None (as produced by
    /// SealerCore::seal_chunk, see core.rs) until the is_last marker
    /// arrives. The Profile must not attempt to reassemble while the
    /// total is unknown, not even after accepting several consecutive
    /// gap-free frames.
    #[test]
    fn streaming_frames_with_unknown_total_do_not_reassemble_early() {
        let sid = SessionId::generate();
        let token1 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: None, // unknown, as in real streaming
            is_last: false,
            payload: b"The".to_vec(),
        };
        let token2 = LacreFrame {
            session_id: sid,
            index: 1,
            total_fragments: None,
            is_last: false,
            payload: b" sky".to_vec(),
        };
        let token3 = LacreFrame {
            session_id: sid,
            index: 2,
            total_fragments: None,
            is_last: true, // only now is the stream known to have ended
            payload: b" is blue".to_vec(),
        };

        let mut profile = ReassembleProfile::new(generous_retention());
        profile.accept(&full(&token1), None);
        // After the first token, total_fragments isn't even known yet
        // — nothing should be reassemblable so far.
        assert!(profile.try_reassemble().is_none());

        profile.accept(&full(&token2), None);
        assert!(profile.try_reassemble().is_none());

        profile.accept(&full(&token3), None);
        let reassembled = profile
            .try_reassemble()
            .expect("is_last on the third token must enable reassembly");
        assert_eq!(reassembled, b"The sky is blue".to_vec());
    }

    /// `sweep_expired` closes the real gap found while comparing this
    /// Profile against `ToolchainProfile` (see `PENDING.md`): a frame
    /// held ahead whose gap never fills would otherwise sit in
    /// `held_ahead` forever. A frame arriving after the sweep already
    /// evicted its slot is treated as a fresh out-of-order arrival —
    /// `retention` and `held_ahead` are kept in lockstep, so there's
    /// no stale bookkeeping left behind for an index that was already
    /// evicted.
    #[test]
    fn sweep_expired_drops_an_abandoned_held_ahead_frame() {
        let mut profile = ReassembleProfile::new(Duration::from_millis(20));
        let sid = SessionId::generate();
        let frame1 = LacreFrame {
            session_id: sid,
            index: 1,
            total_fragments: Some(2),
            is_last: true,
            payload: b"second".to_vec(),
        };

        assert!(matches!(profile.accept(&full(&frame1), None), AcceptOutcome::HeldAhead));

        std::thread::sleep(Duration::from_millis(40));

        let evicted = profile.sweep_expired();
        assert_eq!(evicted, vec![1u64]);

        // The gap at index 0 arriving now can never complete the
        // original sequence, because index 1's payload was dropped —
        // demonstrated by feeding index 0 and confirming reassembly
        // still doesn't happen the way it would have before eviction.
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(2),
            is_last: false,
            payload: b"first".to_vec(),
        };
        profile.accept(&full(&frame0), None);
        assert!(profile.try_reassemble().is_none());
    }

    /// A frame that gets chained into the sequence before its
    /// retention deadline must never show up as expired afterward —
    /// `retention.forget` inside `accept`'s reprocessing loop is what
    /// prevents a later sweep from evicting a slot that was already
    /// consumed.
    #[test]
    fn sweep_expired_does_not_affect_a_frame_already_chained_in() {
        let mut profile = ReassembleProfile::new(Duration::from_millis(20));
        let sid = SessionId::generate();
        let frame1 = LacreFrame {
            session_id: sid,
            index: 1,
            total_fragments: Some(2),
            is_last: true,
            payload: b"second".to_vec(),
        };
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(2),
            is_last: false,
            payload: b"first".to_vec(),
        };

        profile.accept(&full(&frame1), None); // held ahead
        profile.accept(&full(&frame0), None); // fills the gap, chains frame 1 in too

        std::thread::sleep(Duration::from_millis(40));

        let evicted = profile.sweep_expired();
        assert!(evicted.is_empty());
        // The sequence is complete and unaffected by the sweep.
        assert_eq!(
            profile.try_reassemble(),
            Some(b"firstsecond".to_vec())
        );
    }
}

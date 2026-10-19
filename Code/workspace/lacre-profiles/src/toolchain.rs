//! Tool-Chain Integrity — Profiles Annex 4.0.
//!
//! # What this is, precisely
//!
//! Every Profile documented before this module (`ReassembleProfile`
//! included) verifies a single-hop transit or a linear sequence of
//! fragments: each frame has, at most, one predecessor. Annex 4.0
//! identifies a case that shape doesn't cover: an agent's reasoning
//! episode that invokes several tools — some of them in parallel — and
//! combines their responses in a later step. That combining step
//! depends on more than one source. The resulting structure isn't a
//! chain; it's a directed acyclic graph (DAG) with nodes that can have
//! multiple parents.
//!
//! This module is the first reference implementation of that
//! mechanism — the `Toolchain` profile from Family XXI, so far only
//! specified in Annex 4.0. It was `[PA]` (Open Problem) in the annex
//! itself: no code existed before this module.
//!
//! # What this module does NOT do (and why)
//!
//! It does not fragment, does not seal with the Core's own HMAC, does
//! not purge network sessions. Every graph node (`ChainNode`) is built
//! from a `LacreFrame` that must have already passed
//! `VerifierCore::verify_frame` successfully — exactly the same
//! precondition `ReassembleProfile::accept` already requires. This
//! module never re-verifies the Core's HMAC; it only adds a second
//! sealing layer (Δᵥ) on top of content whose byte-level integrity the
//! Core has already certified, in direct application of Axiom A7
//! (content visibility boundary), without touching anything in
//! `core.rs`.
//!
//! # The chain seal Δᵥ
//!
//! Δᵥ = HMAC(fᵥ ∥ {Δ_p : p ∈ parents(v)} ∥ S_chain, k)
//!
//! Reuses `hmac_seal::seal_fragment` — the same primitive the Core
//! already uses for δᵢ — instead of writing a new HMAC construction.
//! The "fragment" being sealed is the deterministic concatenation of:
//! the node's content + the Δ seals of each parent, in declaration
//! order. `S_chain` plays, for this graph, the same role Sᵢ plays for
//! a linear Core session: it ties the seal to an episode context, so a
//! Δᵥ computed in one episode never verifies in another even if the
//! content and the parents match.
//!
//! # Fail-closed, in cascade
//!
//! Invalidating a node isn't limited to that node: it propagates
//! forward through every path that depends on it, transitively
//! invalidating any descendant — including the output node, even if
//! its own Δᵥ verifies in isolation. This is the literal application
//! of Axiom A4 to a graph structure, not a new extension of the axiom.

use crate::profile::ViewOf;
#[cfg(test)]
use lacre_core::frame::LacreFrame;
use lacre_core::hmac_seal::{seal_fragment, verify_fragment, HmacAlgo, Seal};
use crate::profile_engine::RetentionTracker;
use lacre_core::session::SessionKey;
use std::collections::{HashMap, HashSet};

/// Identifier of a node within a reasoning episode. Deliberately
/// opaque (`String`, not a sequential numeric index like
/// `LacreFrame::index`): unlike a fragment in a linear session, a node
/// in this graph has no natural position in a sequence — "the node
/// that queried the market price" isn't the second or third of
/// anything, it's a vertex with its own name inside an episode.
pub type NodeId = String;

/// A node already incorporated into the graph, with its chain seal
/// already computed and verified at insertion time (see
/// `ToolchainProfile::add_node`).
#[derive(Debug, Clone)]
struct ChainNode {
    parents: Vec<NodeId>,
    chain_seal: Seal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ToolchainError {
    /// A declared parent doesn't exist in the graph yet. Corresponds
    /// to "a declared parent doesn't exist in the session's record"
    /// from the Formal Model chapter of Annex 4.0 — treated as a
    /// verification failure of the node that declares it, never as a
    /// deferred insertion waiting for the parent to show up later
    /// (that would be silent reordering, exactly what Δᵥ exists to
    /// prevent).
    UnknownParent(NodeId),
    /// A node with this identifier already exists in the episode. A
    /// second attempt to declare the same node is not treated as an
    /// update — the graph is append-only, same as `ReceiptLog`
    /// (Section 7.5 of Project Lacre Prime).
    DuplicateNode(NodeId),
    /// The node declares a parent that, at some earlier point in this
    /// same episode, already failed its own verification or that of
    /// one of its ancestors. Fail-closed in cascade: this node is
    /// rejected without even recomputing its own Δᵥ, because its
    /// ancestry is already known to be compromised.
    TaintedParent(NodeId),
}

/// Result of verifying an episode's output node: success with the
/// traversal order used, or the first node in the ancestry whose
/// verification failed — never an opaque failure without naming which
/// hop was compromised (Annex 4.0, "What Toolchain Integrity DOES
/// solve": the failure propagates "visibly and by name").
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationOutcome {
    Valid,
    /// The named node doesn't verify: either its own recomputed Δᵥ
    /// doesn't match the one received, or it references a
    /// nonexistent parent.
    Invalid { failed_node: NodeId },
}

/// Extension Profile that builds and verifies a directed acyclic graph
/// of reasoning nodes within a single episode. `TOUCHES_PAYLOAD =
/// true`: just like `ReassembleProfile`, it operates directly on each
/// frame's content in order to compute Δᵥ.
///
/// This is a stateful Profile (in the sense of Annex 5.0, Section
/// 3.2): its decision about a node depends, essentially, on nodes
/// already incorporated into the same episode — their chain seals,
/// declared as parents. It cannot be expressed in the stateless
/// vocabulary of the Rule Engine from Annex 2.0, for the same reason
/// `ReassembleProfile` can't be either.
pub struct ToolchainProfile {
    algo: HmacAlgo,
    key: SessionKey,
    /// S_chain: fixed episode context, analogous to the Core's own Sᵢ
    /// but constant throughout the whole episode instead of evolving
    /// per fragment — the graph, not a linear sequence, is what ties
    /// each node's position, so S_chain only needs to distinguish one
    /// episode from another, not a position within it.
    chain_context: Vec<u8>,
    nodes: HashMap<NodeId, ChainNode>,
    /// Nodes marked compromised by an explicit decision (`taint_and_cascade`, used
    /// by `sweep_expired` for nodes that outlived their retention window, and by
    /// insertion of a node that declares a bad parent), plus their descendants. Once
    /// tainted, a node stays tainted: there's no transition back to valid within the
    /// same episode. `verify_output` does NOT add to this set: a verification whose
    /// supplied content does not match is a result, not a state change.
    tainted: HashSet<NodeId>,
    /// Closes the resource-exhaustion gap documented in `PENDING.md`
    /// ("Real gap found while comparing stateful Profiles"): without
    /// this, `nodes` grows for the lifetime of the struct with no way
    /// to bound how long an episode can be kept open. Every node is
    /// recorded here at insertion and forgotten once it's resolved via
    /// `verify_output` — see `sweep_expired` for what happens to a
    /// node that's neither resolved nor forgotten before its
    /// retention deadline.
    retention: RetentionTracker<NodeId>,
    /// How many `verify_output` calls returned `Invalid` in this episode.
    /// Not a taint (a failed verification still has no side effect on the
    /// recorded graph): it is a counter the caller can use to stop a
    /// party that holds only the verify capability from probing the
    /// episode with guessed contents indefinitely.
    failed_verifications: u32,
}

impl crate::profile::Profile for ToolchainProfile {
    type Access = lacre_core::access::FullContent;
}

impl ToolchainProfile {
    /// `episode_id` identifies the reasoning episode — the equivalent,
    /// for this Profile, of `SessionId` for a Core session. Two
    /// episodes with different `episode_id` never produce the same Δᵥ
    /// for the same content and the same parents, for exactly the
    /// same reason Sᵢ prevents reusing a seal from one session in
    /// another.
    ///
    /// `max_node_age` bounds how long a node may sit in the graph
    /// without being resolved by `verify_output` before
    /// `sweep_expired` is entitled to taint it. There is no default
    /// and no `Option` — per Annex 5.0 Section 3.5's own mitigation, a
    /// stateful Profile must never have an unbounded retention window
    /// available "by omission".
    pub fn new(algo: HmacAlgo, key: SessionKey, episode_id: &[u8], max_node_age: std::time::Duration) -> Self {
        ToolchainProfile {
            algo,
            key,
            chain_context: episode_id.to_vec(),
            nodes: HashMap::new(),
            tainted: HashSet::new(),
            failed_verifications: 0,
            retention: RetentionTracker::new(max_node_age),
        }
    }

    /// Computes Δᵥ for a node given its content and its parents'
    /// seals, in declaration order. Deterministic: the same content
    /// with the same parents in the same order always produces the
    /// same Δᵥ within the same episode — a necessary condition for an
    /// independent verifier to be able to recompute it.
    fn compute_chain_seal(&self, content: &[u8], parent_seals: &[Seal]) -> Seal {
        let mut material = Vec::with_capacity(content.len() + parent_seals.len() * 32);
        material.extend_from_slice(content);
        for seal in parent_seals {
            material.extend_from_slice(&seal.0);
        }
        seal_fragment(self.algo, &self.key, &material, &self.chain_context)
    }

    /// Incorporates a root node (no parents) into the episode.
    /// Corresponds, in the Annex 4.0 example, to the agent's initial
    /// prompt.
    ///
    /// `frame` must have already been verified by `VerifierCore` —
    /// this method does not repeat that verification, same as
    /// `ReassembleProfile::accept`.
    pub fn add_root(
        &mut self,
        node_id: impl Into<NodeId>,
        view: &ViewOf<'_, Self>,
    ) -> Result<Seal, ToolchainError> {
        self.add_node(node_id, view, &[])
    }

    /// Incorporates a node with one or more declared parents. Returns
    /// the computed Δᵥ if the insertion is valid.
    ///
    /// Fail-closed, without exception: if any declared parent doesn't
    /// exist in the graph, or if any parent is already marked as
    /// compromised (directly, or by inheritance from one of its own
    /// ancestors), this node is rejected and marks itself as
    /// compromised — it is never inserted with partial validity.
    pub fn add_node(
        &mut self,
        node_id: impl Into<NodeId>,
        view: &ViewOf<'_, Self>,
        parent_ids: &[NodeId],
    ) -> Result<Seal, ToolchainError> {
        let node_id = node_id.into();

        if self.nodes.contains_key(&node_id) || self.tainted.contains(&node_id) {
            return Err(ToolchainError::DuplicateNode(node_id));
        }

        // Check the existence and health of every parent BEFORE
        // touching the graph's state — so a failed insertion leaves
        // no partial side effects.
        let mut parent_seals = Vec::with_capacity(parent_ids.len());
        for parent_id in parent_ids {
            if self.tainted.contains(parent_id) {
                self.tainted.insert(node_id.clone());
                return Err(ToolchainError::TaintedParent(parent_id.clone()));
            }
            match self.nodes.get(parent_id) {
                Some(parent_node) => parent_seals.push(parent_node.chain_seal),
                None => {
                    self.tainted.insert(node_id.clone());
                    return Err(ToolchainError::UnknownParent(parent_id.clone()));
                }
            }
        }

        let chain_seal = self.compute_chain_seal(view.content_bytes(), &parent_seals);
        self.retention.record(node_id.clone());
        self.nodes.insert(
            node_id,
            ChainNode {
                parents: parent_ids.to_vec(),
                chain_seal,
            },
        );
        Ok(chain_seal)
    }

    /// Evicts nodes that have sat in the graph, neither resolved via
    /// `verify_output` nor otherwise removed, for longer than the
    /// `max_node_age` given to `new`. Unlike `RetentionTracker::expired`
    /// on its own (which only inspects), this method decides what
    /// eviction means *for this specific Profile*: an expired node is
    /// tainted — fail-closed, per Axiom A4 — rather than silently
    /// dropped, because a node an agent never followed up on could
    /// otherwise leave a descendant's ancestry silently incomplete.
    /// Mirrors the split `PENDING.md`'s Toolchain section documents
    /// for `PendingBuffer::purge_expired`: a caller invokes this on
    /// whatever cadence it already uses for its own bookkeeping, it is
    /// never called automatically on every operation.
    ///
    /// Returns the node IDs that were evicted this sweep, for the
    /// caller's own observability if it wants it.
    pub fn sweep_expired(&mut self) -> Vec<NodeId> {
        let expired = self.retention.expired();
        for node_id in &expired {
            self.retention.forget(node_id);
            self.taint_and_cascade(node_id);
        }
        expired
    }

    /// Explicitly marks a node as compromised, propagating the mark
    /// forward to every already-incorporated node that depends on it,
    /// directly or transitively. Used when an external verifier
    /// detects, by some other means, that an already-accepted node's
    /// content didn't really correspond to what its source produced
    /// (for example: a Δᵥ received from an external source doesn't
    /// match the recomputed one — see `verify_output`).
    ///
    /// Implemented iteratively with an explicit stack rather than
    /// recursively: a recursive version would recurse once per level
    /// of the descendant chain, and a sufficiently deep or wide
    /// episode graph (nothing prevents an agent's reasoning episode
    /// from having a very long chain of tool calls) could exhaust the
    /// call stack — turning a graph-shape problem into a process
    /// crash instead of a `Result`, which would itself violate the
    /// fail-closed spirit this whole mechanism exists to uphold. See
    /// `a_long_linear_chain_verifies_without_stack_overflow` in the
    /// test module below for the empirical depth (tens of thousands of
    /// levels) at which a comparable recursive implementation actually
    /// aborts on this machine's default stack size.
    fn taint_and_cascade(&mut self, node_id: &NodeId) {
        let mut stack = vec![node_id.clone()];
        while let Some(current) = stack.pop() {
            if !self.tainted.insert(current.clone()) {
                continue; // already tainted, don't repeat the traversal
            }
            let children: Vec<NodeId> = self
                .nodes
                .iter()
                .filter(|(_, n)| n.parents.contains(&current))
                .map(|(id, _)| id.clone())
                .collect();
            stack.extend(children);
        }
    }

    /// Walks the graph backward from `output_node`, recomputing Δᵥ for
    /// every reachable node and comparing it against the value already
    /// recorded at insertion time. Returns the first node whose
    /// verification fails, named explicitly — never an opaque failure
    /// over the whole episode.
    ///
    /// This models the case of a verifier that receives the complete
    /// graph *after* it was built (for example, for post-hoc
    /// auditing): it recomputes each Δᵥ independently instead of
    /// trusting the ones each `ChainNode` carries, exactly like
    /// `VerifierCore::verify_frame` recomputes δᵢ instead of trusting
    /// the one carried by the frame.
    ///
    /// Implemented iteratively (explicit post-order traversal with a
    /// work stack), for the same stack-safety reason as
    /// `taint_and_cascade` above, plus one real efficiency gain a
    /// recursive version wouldn't have for free: a `verified` memo
    /// table means a node with two children that both depend on it
    /// (the diamond shape from the tests) gets recomputed exactly
    /// once per call to `verify_output`, not once per path that
    /// reaches it.
    pub fn verify_output(
        &mut self,
        output_node: &NodeId,
        contents: &HashMap<NodeId, Vec<u8>>,
    ) -> VerificationOutcome {
        // Memo of nodes already resolved during this call: Some(seal)
        // if valid (the seal is what a child needs to build its own
        // material), None if invalid. Keeps a diamond-shaped ancestry
        // from being walked twice and gives the iterative version the
        // same short-circuit-on-first-failure behavior the recursive
        // version had.
        let mut resolved: HashMap<NodeId, Option<Seal>> = HashMap::new();
        // Explicit post-order work stack. `false` entries mean "expand
        // this node's parents onto the stack first"; `true` entries
        // mean "this node's parents are already resolved, compute
        // this node now".
        let mut work: Vec<(NodeId, bool)> = vec![(output_node.clone(), false)];
        let mut first_failure: Option<NodeId> = None;

        while let Some((current, ready)) = work.pop() {
            if resolved.contains_key(&current) {
                continue;
            }
            // Persisted taint is checked on the second (post-order)
            // visit, so the reported `failed_node` is the root-most
            // failing node (its ancestors were resolved first), not
            // whichever tainted descendant the walk met first.
            if ready && self.tainted.contains(&current) {
                resolved.insert(current.clone(), None);
                if first_failure.is_none() {
                    first_failure = Some(current);
                }
                continue;
            }
            let node = match self.nodes.get(&current) {
                Some(n) => n.clone(),
                None => {
                    resolved.insert(current.clone(), None);
                    if first_failure.is_none() {
                        first_failure = Some(current);
                    }
                    continue;
                }
            };

            if !ready {
                // First visit: push this node back for a second visit
                // once its parents are resolved, then push the parents
                // themselves. Post-order via a two-phase marker,
                // avoiding recursion entirely.
                work.push((current.clone(), true));
                for parent_id in &node.parents {
                    if !resolved.contains_key(parent_id) {
                        work.push((parent_id.clone(), false));
                    }
                }
                continue;
            }

            // Second visit: every parent has been resolved by now.
            let mut all_parents_valid = true;
            let mut parent_seals = Vec::with_capacity(node.parents.len());
            for parent_id in &node.parents {
                match resolved.get(parent_id) {
                    Some(Some(seal)) => parent_seals.push(*seal),
                    _ => {
                        all_parents_valid = false;
                        break;
                    }
                }
            }

            if !all_parents_valid {
                resolved.insert(current.clone(), None);
                if first_failure.is_none() {
                    first_failure = Some(current);
                }
                continue;
            }

            let content = match contents.get(&current) {
                Some(c) => c,
                None => {
                    resolved.insert(current.clone(), None);
                    if first_failure.is_none() {
                        first_failure = Some(current);
                    }
                    continue;
                }
            };

            // `verify_fragment` (constant-time comparison) operates on
            // the same logical "fragment" that `compute_chain_seal`
            // builds: the node's content concatenated with its
            // parents' seals, in that order. Passing just `content` is
            // not enough — that would completely ignore the parent
            // dependency that is the whole reason this mechanism
            // exists, and would accept a node whose own content is
            // correct but whose declared ancestry was swapped out
            // without touching `content` at all. (This is exactly the
            // bug the first draft of this function had: it called
            // `verify_fragment` with `content` alone, so any node with
            // more than one parent — the diamond-shaped-graph test —
            // failed immediately, because the recomputed material
            // never included the parent seals in the first place.)
            let mut material = Vec::with_capacity(content.len() + parent_seals.len() * 32);
            material.extend_from_slice(content);
            for seal in &parent_seals {
                material.extend_from_slice(&seal.0);
            }
            let matches = verify_fragment(
                self.algo,
                &self.key,
                &material,
                &self.chain_context,
                &Seal(node.chain_seal.0),
            );

            if matches {
                // A node that verifies successfully no longer needs
                // eviction tracking: its ancestry is now confirmed, so
                // a later `sweep_expired` should not be able to taint
                // it just for having existed a long time — retention
                // only ever applies to nodes still *unresolved*.
                self.retention.forget(&current);
                resolved.insert(current.clone(), Some(node.chain_seal));
            } else {
                resolved.insert(current.clone(), None);
                if first_failure.is_none() {
                    first_failure = Some(current);
                }
            }
        }

        match first_failure {
            None => VerificationOutcome::Valid,
            Some(failed_node) => {
                self.failed_verifications = self.failed_verifications.saturating_add(1);
                VerificationOutcome::Invalid { failed_node }
            }
        }
    }

    /// Number of `verify_output` calls that came back `Invalid`.
    pub fn failed_verifications(&self) -> u32 {
        self.failed_verifications
    }

    /// Number of nodes incorporated into the graph, without
    /// distinguishing valid from compromised ones. Inspection utility
    /// for tests and for a future Adapter that wants to report an
    /// episode's size.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_tainted(&self, node_id: &NodeId) -> bool {
        self.tainted.contains(node_id)
    }
}

#[cfg(test)]
mod tests {
    fn full(f: &lacre_core::frame::LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;
    use lacre_core::session::{MasterKeyRing, SessionId};
    use std::time::Duration;

    fn test_key() -> SessionKey {
        let ring = MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        );
        ring.derive_for_sealing(&SessionId::generate())
    }

    fn frame_with(payload: &[u8]) -> LacreFrame {
        LacreFrame {
            session_id: SessionId::generate(),
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: payload.to_vec(),
        }
    }

    /// The Annex 4.0 case: a root node (prompt), two children in
    /// parallel (market price, news), and a combining node with two
    /// parents. The whole graph must verify.
    #[test]
    fn diamond_shaped_graph_with_two_parents_verifies() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-1", Duration::from_secs(3600));

        tc.add_root("prompt", &full(&frame_with(b"sell BTC if the price goes up"))).unwrap();
        tc.add_node("market_price", &full(&frame_with(b"BTC=65000")), &["prompt".into()])
            .unwrap();
        tc.add_node("news", &full(&frame_with(b"no relevant events")), &["prompt".into()])
            .unwrap();
        tc.add_node(
            "recommendation",
            &full(&frame_with(b"sell: favorable price, no news risk")),
            &["market_price".into(), "news".into()],
        )
        .unwrap();

        let mut contents = HashMap::new();
        contents.insert("prompt".to_string(), b"sell BTC if the price goes up".to_vec());
        contents.insert("market_price".to_string(), b"BTC=65000".to_vec());
        contents.insert("news".to_string(), b"no relevant events".to_vec());
        contents.insert(
            "recommendation".to_string(),
            b"sell: favorable price, no news risk".to_vec(),
        );

        let outcome = tc.verify_output(&"recommendation".to_string(), &contents);
        assert_eq!(outcome, VerificationOutcome::Valid);
    }

    /// The exact motivating example from Annex 4.0: the market price
    /// is tampered with after sealing. The final recommendation, which
    /// depends on it, must fail — and the node named as responsible
    /// must be the market price, not the recommendation, and not an
    /// opaque "the episode doesn't verify".
    #[test]
    fn tampered_intermediate_node_is_detected_and_named() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-2", Duration::from_secs(3600));

        tc.add_root("prompt", &full(&frame_with(b"sell BTC if the price goes up"))).unwrap();
        tc.add_node("market_price", &full(&frame_with(b"BTC=65000")), &["prompt".into()])
            .unwrap();
        tc.add_node(
            "recommendation",
            &full(&frame_with(b"sell based on BTC=65000")),
            &["market_price".into()],
        )
        .unwrap();

        // The attacker alters the price AFTER sealing (simulated: the
        // content presented for verification is no longer what was
        // sealed).
        let mut contents = HashMap::new();
        contents.insert("prompt".to_string(), b"sell BTC if the price goes up".to_vec());
        contents.insert("market_price".to_string(), b"BTC=999999".to_vec()); // tampered
        contents.insert(
            "recommendation".to_string(),
            b"sell based on BTC=65000".to_vec(),
        );

        let outcome = tc.verify_output(&"recommendation".to_string(), &contents);
        assert_eq!(
            outcome,
            VerificationOutcome::Invalid {
                failed_node: "market_price".to_string()
            }
        );
    }

    /// Fail-closed in cascade: if an intermediate node fails, the
    /// output node is invalidated even though its own Δᵥ, computed
    /// over untampered content, is perfectly correct in isolation.
    #[test]
    fn invalidation_cascades_even_when_output_seal_itself_is_locally_correct() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-3", Duration::from_secs(3600));

        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();
        tc.add_node("intermediate_data", &full(&frame_with(b"original-value")), &["prompt".into()])
            .unwrap();
        tc.add_node(
            "output",
            &full(&frame_with(b"conclusion based on original-value")),
            &["intermediate_data".into()],
        )
        .unwrap();

        let mut contents = HashMap::new();
        contents.insert("prompt".to_string(), b"context".to_vec());
        contents.insert("intermediate_data".to_string(), b"TAMPERED-value".to_vec());
        contents.insert(
            "output".to_string(),
            b"conclusion based on original-value".to_vec(),
        );

        let outcome = tc.verify_output(&"output".to_string(), &contents);
        assert_eq!(
            outcome,
            VerificationOutcome::Invalid {
                failed_node: "intermediate_data".to_string()
            }
        );
        // The output node is reported invalid in this call even though its own
        // content never changed (cascade within the verification) ...
        // ... but the failed verification is a result, not a state change: nothing
        // is stored, so presenting wrong content cannot poison the episode.
        assert!(!tc.is_tainted(&"output".to_string()));
        assert!(!tc.is_tainted(&"intermediate_data".to_string()));
    }

    /// Fraudulent merge: a combining node declares a parent that was
    /// never actually part of the episode.
    #[test]
    fn declaring_a_nonexistent_parent_is_rejected_at_insertion() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-4", Duration::from_secs(3600));
        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();

        let result = tc.add_node(
            "combination",
            &full(&frame_with(b"combined result")),
            &["prompt".into(), "nonexistent_source".into()],
        );

        assert_eq!(
            result,
            Err(ToolchainError::UnknownParent("nonexistent_source".to_string()))
        );
        // The failed attempt doesn't leave the node half-inserted.
        assert_eq!(tc.node_count(), 1); // only "prompt"
        assert!(tc.is_tainted(&"combination".to_string()));
    }

    /// A node that declares an already-compromised parent is rejected
    /// immediately, without even computing its own Δᵥ — verified
    /// indirectly by confirming it never gets added to the graph
    /// (node_count doesn't grow).
    #[test]
    fn node_declaring_a_tainted_parent_is_rejected_without_computing_its_own_seal() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-5", Duration::from_secs(3600));
        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();

        // Force a manual taint on an existing node other than "prompt".
        tc.add_node("intermediate", &full(&frame_with(b"data")), &["prompt".into()])
            .unwrap();
        tc.taint_and_cascade(&"intermediate".to_string());

        let result = tc.add_node(
            "dependent",
            &full(&frame_with(b"depends on the compromised intermediate node")),
            &["intermediate".into()],
        );

        assert_eq!(
            result,
            Err(ToolchainError::TaintedParent("intermediate".to_string()))
        );
        assert_eq!(tc.node_count(), 2); // prompt, intermediate — not "dependent"
    }

    /// Determinism: the same content with the same parents in the same
    /// order, in the same episode, always produces the same Δᵥ — a
    /// necessary condition for an independent verifier to be able to
    /// recompute it without ambiguity.
    #[test]
    fn chain_seal_is_deterministic_for_same_content_and_parents() {
        let key = test_key();
        let mut tc1 = ToolchainProfile::new(HmacAlgo::Sha256, key.clone(), b"episode-6", Duration::from_secs(3600));
        let mut tc2 = ToolchainProfile::new(HmacAlgo::Sha256, key, b"episode-6", Duration::from_secs(3600));

        let seal1 = tc1.add_root("prompt", &full(&frame_with(b"content"))).unwrap();
        let seal2 = tc2.add_root("prompt", &full(&frame_with(b"content"))).unwrap();

        assert_eq!(seal1.0, seal2.0);
    }

    /// Two different episodes (different `episode_id`) never produce
    /// the same Δᵥ for identical content — analogous to why Sᵢ
    /// prevents reusing a seal from one session in another.
    #[test]
    fn different_episodes_produce_different_chain_seals_for_identical_content() {
        let key = test_key();
        let mut tc1 = ToolchainProfile::new(HmacAlgo::Sha256, key.clone(), b"episode-A", Duration::from_secs(3600));
        let mut tc2 = ToolchainProfile::new(HmacAlgo::Sha256, key, b"episode-B", Duration::from_secs(3600));

        let seal1 = tc1.add_root("prompt", &full(&frame_with(b"content"))).unwrap();
        let seal2 = tc2.add_root("prompt", &full(&frame_with(b"content"))).unwrap();

        assert_ne!(seal1.0, seal2.0);
    }

    /// An episode cannot declare two nodes with the same identifier —
    /// the graph is append-only.
    #[test]
    fn duplicate_node_id_is_rejected() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-7", Duration::from_secs(3600));
        tc.add_root("prompt", &full(&frame_with(b"content"))).unwrap();

        let result = tc.add_root("prompt", &full(&frame_with(b"other content")));
        assert_eq!(result, Err(ToolchainError::DuplicateNode("prompt".to_string())));
    }

    /// Reordering: the same set of parents declared in a different
    /// order produces a different Δᵥ — `{Δ_p}` is an ORDERED sequence
    /// per Annex 4.0's formal model, not an order-independent
    /// mathematical set. Same key, same episode: two combinations with
    /// parents in different order must produce different seals.
    #[test]
    fn parent_order_matters_within_the_same_keyed_episode() {
        let key = test_key();
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, key, b"episode-9", Duration::from_secs(3600));

        tc.add_root("a", &full(&frame_with(b"content-a"))).unwrap();
        tc.add_root("b", &full(&frame_with(b"content-b"))).unwrap();

        let seal_ab = tc
            .add_node("combined-ab", &full(&frame_with(b"combined")), &["a".into(), "b".into()])
            .unwrap();
        let seal_ba = tc
            .add_node("combined-ba", &full(&frame_with(b"combined")), &["b".into(), "a".into()])
            .unwrap();

        assert_ne!(seal_ab.0, seal_ba.0);
    }

    /// A cycle is structurally impossible to construct through this
    /// API, and this test exists to demonstrate that rather than just
    /// assert it in a comment: `add_node` requires every declared
    /// parent to already exist in `self.nodes` (see the `UnknownParent`
    /// check above) before the current node is inserted. Since a node
    /// can only ever declare parents that were inserted strictly
    /// before it, there is no sequence of insertions that can produce
    /// a node reachable from itself — the graph is a DAG by
    /// construction, not by a separate cycle-detection pass. Attempting
    /// to declare a node as its own parent (the simplest possible
    /// cycle) fails with `UnknownParent`, because the node doesn't
    /// exist yet at the moment it would need to reference itself.
    #[test]
    fn a_node_cannot_declare_itself_as_its_own_parent() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-cycle-1", Duration::from_secs(3600));

        let result = tc.add_node("self_referential", &full(&frame_with(b"data")), &["self_referential".into()]);

        assert_eq!(
            result,
            Err(ToolchainError::UnknownParent("self_referential".to_string()))
        );
        assert_eq!(tc.node_count(), 0);
    }

    /// Same property, one level removed: A is inserted, B declares A
    /// as its parent (fine, A already exists) — but A can never be
    /// retroactively amended to declare B as *its* parent, because
    /// there is no "amend an existing node" operation in this API at
    /// all. The only way to attempt a longer cycle is a fresh
    /// insertion, and a fresh insertion of a node that would complete
    /// a cycle always references, as one of its declared parents, a
    /// node that — by the time the cycle would close — hasn't been
    /// inserted yet under that identifier. This test exercises that
    /// with an explicit attempt.
    #[test]
    fn a_longer_cycle_is_impossible_because_closing_it_requires_an_unknown_parent() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-cycle-2", Duration::from_secs(3600));

        tc.add_root("a", &full(&frame_with(b"content-a"))).unwrap();
        tc.add_node("b", &full(&frame_with(b"content-b")), &["a".into()]).unwrap();

        // Attempting to close the cycle a -> b -> a by inserting a NEW
        // node under the id "a" that declares "b" as a parent doesn't
        // amend the existing "a" — it's rejected outright as a
        // duplicate, which is itself a second, independent reason a
        // cycle can never be constructed here.
        let result = tc.add_node("a", &full(&frame_with(b"content-a-again")), &["b".into()]);
        assert_eq!(result, Err(ToolchainError::DuplicateNode("a".to_string())));
    }

    /// The concrete reason `verify_output` and `taint_and_cascade` are
    /// implemented iteratively rather than recursively: a long chain
    /// of tool calls (nothing in the mechanism forbids it — Annex
    /// 4.0's own examples describe multi-step reasoning episodes) must
    /// verify without blowing the call stack. This isn't a
    /// theoretical concern — a small standalone reproduction with a
    /// comparable amount of per-frame local state (a `Vec` and a
    /// `HashMap` per level, similar in shape to `material` and
    /// `parent_seals` in this function) reliably aborts with a real
    /// stack overflow (`SIGABRT`, not a `Result`) somewhere between
    /// 20,000 and 50,000 levels of recursion on this machine's default
    /// stack size. This test builds a chain at that same order of
    /// magnitude and confirms the iterative version verifies it
    /// correctly — direct evidence, not just an argument in a comment.
    #[test]
    fn a_long_linear_chain_verifies_without_stack_overflow() {
        let key = test_key();
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, key, b"episode-deep-chain", Duration::from_secs(3600));
        let mut contents = HashMap::new();

        let depth = 50_000;
        let mut previous: Option<NodeId> = None;
        for i in 0..depth {
            let id = format!("node-{i}");
            let content = format!("content-{i}").into_bytes();
            let parents: Vec<NodeId> = previous.iter().cloned().collect();
            tc.add_node(id.clone(), &full(&frame_with(&content)), &parents).unwrap();
            contents.insert(id.clone(), content);
            previous = Some(id);
        }

        let output = previous.unwrap();
        assert_eq!(tc.verify_output(&output, &contents), VerificationOutcome::Valid);
    }

    /// Same depth, but the very first node in the chain is tampered
    /// with — confirming the iterative traversal still walks all the
    /// way back and names the correct culprit, not just "somewhere in
    /// this long chain something failed". Uses a smaller depth than
    /// the test above purely to keep this specific test fast; the
    /// stack-safety property itself is already demonstrated at 50,000
    /// by the previous test.
    #[test]
    fn a_long_linear_chain_still_names_the_root_cause_when_the_first_node_is_tampered() {
        let key = test_key();
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, key, b"episode-deep-chain-tampered", Duration::from_secs(3600));
        let mut contents = HashMap::new();

        let depth = 2_000;
        let mut previous: Option<NodeId> = None;
        for i in 0..depth {
            let id = format!("node-{i}");
            let content = format!("content-{i}").into_bytes();
            let parents: Vec<NodeId> = previous.iter().cloned().collect();
            tc.add_node(id.clone(), &full(&frame_with(&content)), &parents).unwrap();
            contents.insert(id.clone(), content);
            previous = Some(id);
        }

        // Tamper with the root node's presented content only.
        contents.insert("node-0".to_string(), b"tampered-root-content".to_vec());

        let output = previous.unwrap();
        assert_eq!(
            tc.verify_output(&output, &contents),
            VerificationOutcome::Invalid {
                failed_node: "node-0".to_string()
            }
        );
    }

    /// `sweep_expired` closes the exact resource-exhaustion gap this
    /// integration exists for: a node inserted but never resolved via
    /// `verify_output` (imagine an agent that opened a tool call and
    /// never followed up on it) doesn't sit in `nodes` forever. Once
    /// its retention deadline passes, a sweep taints it — and, per
    /// fail-closed-in-cascade, taints any node that already declared
    /// it as a parent, even though that descendant's own content was
    /// never touched.
    #[test]
    fn sweep_expired_taints_an_abandoned_node_and_cascades_to_its_children() {
        let mut tc = ToolchainProfile::new(
            HmacAlgo::Sha256,
            test_key(),
            b"episode-sweep",
            Duration::from_millis(20),
        );

        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();
        // "abandoned_tool_call" is inserted but its result is never
        // checked via verify_output — the agent moved on without it.
        tc.add_node("abandoned_tool_call", &full(&frame_with(b"never followed up")), &["prompt".into()])
            .unwrap();
        tc.add_node(
            "downstream",
            &full(&frame_with(b"depends on the abandoned call")),
            &["abandoned_tool_call".into()],
        )
        .unwrap();

        assert!(!tc.is_tainted(&"abandoned_tool_call".to_string()));
        assert!(!tc.is_tainted(&"downstream".to_string()));

        std::thread::sleep(Duration::from_millis(40));

        let evicted = tc.sweep_expired();
        assert!(evicted.contains(&"abandoned_tool_call".to_string()));
        assert!(tc.is_tainted(&"abandoned_tool_call".to_string()));
        // Cascades to the descendant, exactly like a content tamper
        // would — an abandoned dependency is treated with the same
        // fail-closed severity as a verification failure, not
        // silently forgotten.
        assert!(tc.is_tainted(&"downstream".to_string()));
    }

    /// A node that finishes verifying successfully before its
    /// retention deadline must never show up as expired afterward —
    /// `retention.forget` inside `verify_output`'s success path is
    /// what prevents a later sweep from tainting an already-confirmed
    /// node just because a lot of wall-clock time passed since it was
    /// inserted.
    #[test]
    fn sweep_expired_does_not_taint_a_node_already_resolved_by_verify_output() {
        let mut tc = ToolchainProfile::new(
            HmacAlgo::Sha256,
            test_key(),
            b"episode-sweep-resolved",
            Duration::from_millis(20),
        );

        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();
        let mut contents = HashMap::new();
        contents.insert("prompt".to_string(), b"context".to_vec());

        assert_eq!(
            tc.verify_output(&"prompt".to_string(), &contents),
            VerificationOutcome::Valid
        );

        std::thread::sleep(Duration::from_millis(40));

        let evicted = tc.sweep_expired();
        assert!(evicted.is_empty());
        assert!(!tc.is_tainted(&"prompt".to_string()));
    }

    /// End-to-end integration: `SealerCore` seals, `VerifierCore`
    /// verifies, and only THEN does `ToolchainProfile` incorporate the
    /// frames into the graph — confirming this Profile respects the
    /// same boundary `ReassembleProfile` already demonstrates in
    /// `profile.rs` (`core_verifies_then_profile_reassembles`): it
    /// never operates on content the Core hasn't certified first.
    #[test]
    fn core_verifies_then_toolchain_builds_and_verifies_the_graph() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use std::sync::Arc;

        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ));

        // Three "hops" of an episode, each sealed and verified by the
        // Core independently, as if each one arrived from a different
        // tool invoked by the agent.
        let mut sealer = SealerCore::open(ring.clone(), HmacAlgo::Sha256, 256, 10, Duration::from_millis(500));
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            256,
            10,
            Duration::from_millis(500),
        )
        .unwrap();

        let prompt = b"sell BTC if the price goes up".to_vec();
        let market_price = b"BTC=65000".to_vec();
        let recommendation = b"sell: favorable price".to_vec();

        let mut verified_frames = Vec::new();
        for payload in [&prompt, &market_price, &recommendation] {
            let sealed = sealer.seal_payload(payload, 256).unwrap();
            assert_eq!(sealed.len(), 1, "each hop fits in a single frame in this test");
            let (frame, seal) = &sealed[0];
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, None)
                .expect("the Core must verify each hop before Toolchain sees it");
            verified_frames.push(frame.clone());
        }

        // At this point, the Core has already certified the three
        // frames separately. ToolchainProfile now organizes them as a
        // graph — its own key session, independent of the Core's,
        // because Δᵥ is a different sealing layer than δᵢ.
        let tc_key = ring.derive_for_sealing(&SessionId::generate());
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, tc_key, b"integration-episode", Duration::from_secs(3600));

        tc.add_root("prompt", &full(&verified_frames[0])).unwrap();
        tc.add_node("market_price", &full(&verified_frames[1]), &["prompt".into()])
            .unwrap();
        tc.add_node(
            "recommendation",
            &full(&verified_frames[2]),
            &["market_price".into()],
        )
        .unwrap();

        let mut contents = HashMap::new();
        contents.insert("prompt".to_string(), prompt);
        contents.insert("market_price".to_string(), market_price);
        contents.insert("recommendation".to_string(), recommendation);

        assert_eq!(
            tc.verify_output(&"recommendation".to_string(), &contents),
            VerificationOutcome::Valid
        );
    }

    /// A verification with wrong content must not poison the
    /// recorded graph. The honest verification that follows still succeeds and the
    /// agent can keep building on the same nodes.
    #[test]
    fn a_failed_verification_does_not_poison_the_episode() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-rsk3", Duration::from_secs(3600));
        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();
        tc.add_node("data", &full(&frame_with(b"value")), &["prompt".into()]).unwrap();
        tc.add_node("output", &full(&frame_with(b"conclusion")), &["data".into()]).unwrap();

        let honest: HashMap<String, Vec<u8>> = [
            ("prompt", &b"context"[..]), ("data", &b"value"[..]), ("output", &b"conclusion"[..]),
        ].into_iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect();
        let mut forged = honest.clone();
        forged.insert("data".to_string(), b"X".to_vec());

        assert_eq!(
            tc.verify_output(&"output".to_string(), &forged),
            VerificationOutcome::Invalid { failed_node: "data".to_string() }
        );
        // Repeating the bad call changes nothing either.
        assert_eq!(
            tc.verify_output(&"output".to_string(), &forged),
            VerificationOutcome::Invalid { failed_node: "data".to_string() }
        );
        assert_eq!(tc.verify_output(&"output".to_string(), &honest), VerificationOutcome::Valid);
        assert!(tc.add_node("next", &full(&frame_with(b"more")), &["output".into()]).is_ok());
    }

    /// The other half of the design: what IS recorded as compromised (expiry, explicit
    /// taint) still fails closed in a later verification, even with honest content.
    #[test]
    fn an_explicitly_tainted_node_still_fails_verification_with_honest_content() {
        let mut tc = ToolchainProfile::new(HmacAlgo::Sha256, test_key(), b"episode-rsk3b", Duration::from_secs(3600));
        tc.add_root("prompt", &full(&frame_with(b"context"))).unwrap();
        tc.add_node("data", &full(&frame_with(b"value")), &["prompt".into()]).unwrap();
        tc.add_node("output", &full(&frame_with(b"conclusion")), &["data".into()]).unwrap();
        tc.taint_and_cascade(&"data".to_string());
        let honest: HashMap<String, Vec<u8>> = [
            ("prompt", &b"context"[..]), ("data", &b"value"[..]), ("output", &b"conclusion"[..]),
        ].into_iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect();
        assert_eq!(
            tc.verify_output(&"output".to_string(), &honest),
            VerificationOutcome::Invalid { failed_node: "data".to_string() }
        );
    }
}

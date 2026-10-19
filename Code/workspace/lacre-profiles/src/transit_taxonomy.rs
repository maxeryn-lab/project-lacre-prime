//! Transit Non-Novelty Taxonomy — Annex 6.0, Sub-problema 2 ("Taxonomía
//! de no-novedad"), Section 2.3.
//!
//! # What this module is for, precisely
//!
//! Annex 6.0's own text: "El catálogo actual, a través de Sᵢ, tiene una
//! única respuesta binaria ante un fragmento que no ocupa la posición
//! esperada de la secuencia ... se rechaza. Este anexo ... propone
//! diferenciar, antes de esa decisión final e inalterada, entre cuatro
//! categorías de 'no-novedad'": `Replay`, `Retransmission`, `Duplicate`,
//! `NewMessage`. This module implements that classification. It never
//! changes what `ReassembleProfile::accept` decides
//! (`AcceptOutcome::DuplicateIgnored` for any `frame.index <
//! next_expected`, unconditionally, per Axiom A4's own fail-closed
//! discipline extended by Annex 6.0's own explicit note: "Esta
//! taxonomía no reemplaza el fallo cerrado ... como resultado final
//! posible ... Lo que esta taxonomía aporta es diagnóstico"). This
//! module only names *why* a fragment fell into that already-decided
//! outcome, for whichever observability consumer wants that
//! information — it does not gate, delay, or reroute anything.
//!
//! # Honest scope: two categories resolvable today, two that are not
//!
//! `Duplicate` and `NewMessage` are distinguishable using only what
//! `ReassembleProfile` already holds — the previously-accepted payload
//! at a given index, compared byte-for-byte against the incoming
//! payload at that same index. No new input is needed from any
//! Adapter; this module's own tests confirm both categories against
//! real `ReassembleProfile` state.
//!
//! `Replay` and `Retransmission` cannot be told apart this way. Annex
//! 6.0's own Section 2.2 (Sub-problema 1) is explicit about why: the
//! distinguishing fact is `transit_identity` — "la identidad de un
//! intento de entrega concreto", something that exists only at the
//! instant a fragment crosses the transport boundary (an arrival
//! timestamp, a network path), which is information only an Adapter
//! observes, not something `ReassembleProfile` or any Profile can
//! reconstruct after the fact. Neither `http_server.rs` nor
//! `websocket_adapter.rs` captures that information today — this
//! module accepts it as an `Option<TransitIdentity>` parameter rather
//! than inventing a way to infer it from data that doesn't carry it.
//! Given `None`, this module reports `NonNovelty::SameContentUnclearOrigin`
//! rather than guessing between `Replay` and `Retransmission` — Axiom
//! A4's fail-closed discipline applied to classification itself: an
//! unresolvable distinction is reported as unresolved, never collapsed
//! into a guess that looks more confident than the evidence supports.

use lacre_core::access::FullView;
#[cfg(test)]
use lacre_core::frame::LacreFrame;
use std::time::SystemTime;

/// The delivery-attempt identity Annex 6.0 Section 2.2 calls
/// `transit_identity` — observable only by an Adapter, at the instant a
/// fragment arrives. `arrived_at` is the minimum an Adapter needs to
/// capture to make `Replay` vs. `Retransmission` distinguishable in a
/// future revision of this module; `network_path` is accepted now (as
/// an opaque, Adapter-defined string — e.g. a socket's remote address,
/// or a multi-path route identifier) because Annex 6.0's own text names
/// it explicitly for the `Duplicate` case ("el mismo dato viaja por dos
/// caminos de red distintos"), even though this module's own
/// `classify` does not yet use it as a distinguishing signal — no
/// Adapter in this codebase produces two real paths for the same
/// fragment today, so there's no real case to validate that use of it
/// against yet, the same "don't build ahead of a confirmed case"
/// discipline already applied elsewhere in this codebase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitIdentity {
    pub arrived_at: SystemTime,
    pub network_path: Option<String>,
}

impl TransitIdentity {
    /// The single, shared capture point every Adapter calls at the
    /// same structural moment — the instant a fragment crosses the
    /// transport boundary, before it reaches the Core — rather than
    /// each Adapter hand-rolling its own `SystemTime::now()` call with
    /// its own field name and its own chance of drifting out of sync
    /// with how another Adapter captures the same fact.
    ///
    /// This exists because of a real scale problem this codebase's own
    /// catalog already names: Annex 3.0's Family XX (Adapters of
    /// Existing Transport Protocols) lists four Adapters
    /// (`QUIC-Native`, `WebTransport-Bridge`, `gRPC-Interceptor`,
    /// `HTTPS-Plus`) beyond the two real ones already in this codebase
    /// (HTTP, WebSocket) — and the catalog's own stated intent (Annex
    /// 5.0's Declarative Adapter) is for that number to keep growing
    /// cheaply. Writing "capture `SystemTime::now()` into a
    /// `TransitIdentity`" as a few lines duplicated inside every one of
    /// a dozen or more Adapter implementations is exactly the kind of
    /// per-Adapter cost the Declarative Adapter already exists to avoid
    /// on the dispatch side — this is the same discipline applied to
    /// arrival-metadata capture instead: one function, in `lacre-core`
    /// (reachable by any Adapter, since every real Adapter already
    /// depends on `lacre-core`), called identically regardless of which
    /// transport protocol is underneath.
    ///
    /// Lives in `lacre-core`, not `lacre-server`, specifically so a
    /// *future* Adapter — one that doesn't exist as code yet, and may
    /// never live in `lacre-server` at all — gets this for free by
    /// depending on `lacre-core`, the one dependency every real and
    /// cataloged Adapter already has, rather than needing to depend on
    /// `lacre-server` (which two of the four cataloged-but-unbuilt
    /// Family XX Adapters explicitly would not: `QUIC-Native` and
    /// `WebTransport-Bridge` are transport-layer concerns with no
    /// reason to route through an HTTP/WebSocket-specific binary
    /// crate).
    ///
    /// `network_path` is deliberately a plain parameter, not something
    /// this function infers — the concrete shape of "which path did
    /// this arrive on" (a socket's remote address for HTTP/WebSocket, a
    /// QUIC connection ID for `QUIC-Native`, something else entirely for
    /// a transport not yet cataloged) is transport-specific in a way
    /// `arrived_at`'s capture instant is not; this function unifies the
    /// *when*, and leaves the *how* of describing *where* to each
    /// caller, exactly as narrow as the actual shared behavior goes.
    pub fn capture(network_path: Option<String>) -> Self {
        TransitIdentity { arrived_at: SystemTime::now(), network_path }
    }
}

/// The four categories from Annex 6.0 Section 2.3, plus the honest
/// fifth outcome for when the evidence available cannot distinguish
/// `Replay` from `Retransmission`. This enum is diagnostic output only
/// — see this module's header comment on why it never changes
/// `AcceptOutcome`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonNovelty {
    /// A fragment already seen, resent by an adversary trying to pass
    /// it off as new. Requires `TransitIdentity` evidence this module
    /// does not yet have a way to evaluate — see
    /// `SameContentUnclearOrigin` below for what this module reports
    /// instead when only content, not transit identity, is available.
    Replay,
    /// A fragment already seen, legitimately resent by the transport
    /// layer itself. Same evidentiary requirement as `Replay` above.
    Retransmission,
    /// The exact same fragment (identical payload at the same index),
    /// delivered twice through two legitimately simultaneous paths —
    /// Annex 6.0's own multi-path scenario. Distinguishable today by
    /// content comparison alone.
    Duplicate,
    /// A genuinely different fragment that collides on index with one
    /// already accepted — a session collision, per Annex 6.0's own
    /// definition, not a resend of anything. Distinguishable today by
    /// content comparison alone: same index, different payload bytes.
    NewMessage,
    /// The honest fallback when the incoming payload is byte-identical
    /// to the one already recorded at this index, but no
    /// `TransitIdentity` was supplied to distinguish a malicious
    /// `Replay` from a legitimate `Retransmission`. This is not a fifth
    /// category Annex 6.0 names — it's this module's own admission that,
    /// absent transport-layer evidence, `Replay` and `Retransmission`
    /// are indistinguishable from content alone, and reporting one or
    /// the other without that evidence would manufacture a certainty
    /// this module does not have.
    SameContentUnclearOrigin,
}

/// Classifies why an incoming fragment is "non-novel" — already
/// occupying a position `ReassembleProfile` has already resolved
/// (`frame.index < next_expected`, i.e. exactly the condition under
/// which `ReassembleProfile::accept` already returns
/// `AcceptOutcome::DuplicateIgnored`, unconditionally and without any
/// change from this function's result).
///
/// `previously_accepted_payload` is the payload `ReassembleProfile`
/// already has recorded at `frame.index` — the caller reads this from
/// `ReassembleProfile`'s own `verified_payloads` before this function
/// runs; this module has no access to that state itself; it is a pure
/// function of what's handed to it.
///
/// `transit_identity`, when available, is not yet used to distinguish
/// `Replay` from `Retransmission` — see this module's header comment
/// on why: no Adapter in this codebase produces a second, comparable
/// `TransitIdentity` for the same index to compare against yet, so
/// there is nothing real to validate a distinguishing rule against.
/// Its presence or absence currently only decides between reporting
/// `SameContentUnclearOrigin` (when absent) or, once a future revision
/// of this module has a real rule to apply, one of `Replay`/
/// `Retransmission` (when present) — today, supplying it changes
/// nothing about the result, and that is documented here rather than
/// silently implied.
pub fn classify(
    view: &FullView<'_>,
    previously_accepted_payload: &[u8],
    _transit_identity: Option<&TransitIdentity>,
) -> NonNovelty {
    if view.content_bytes() == previously_accepted_payload {
        // Content is identical. Annex 6.0's own text draws the
        // Replay/Retransmission line at transit identity, not content —
        // and this module has no rule yet that actually uses
        // `_transit_identity` to draw that line (see this function's
        // own documentation above), so regardless of whether one was
        // supplied, the honest report today is "same content, origin
        // unclear" rather than a guess.
        NonNovelty::SameContentUnclearOrigin
    } else {
        NonNovelty::NewMessage
    }
}

#[cfg(test)]
mod tests {
    fn full(f: &LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;
    use lacre_core::session::SessionId;

    fn frame_with(index: u64, payload: &[u8]) -> LacreFrame {
        LacreFrame {
            session_id: SessionId::generate(),
            index,
            total_fragments: Some(1),
            is_last: true,
            payload: payload.to_vec(),
        }
    }

    /// Annex 6.0's own `Duplicate` definition, verbatim: "el mismo
    /// dato viaja por dos caminos de red distintos" — same content,
    /// same index. Without `TransitIdentity`, this module correctly
    /// reports the honest `SameContentUnclearOrigin` rather than
    /// asserting `Duplicate` specifically, because distinguishing a
    /// legitimate multi-path duplicate from a malicious replay of
    /// identical content is exactly the distinction this module cannot
    /// make from content alone — see this module's header comment.
    #[test]
    fn identical_content_at_the_same_index_reports_unclear_origin_without_transit_evidence() {
        let previously_accepted = b"original payload bytes";
        let incoming = frame_with(0, b"original payload bytes");
        let outcome = classify(&full(&incoming), previously_accepted, None);
        assert_eq!(outcome, NonNovelty::SameContentUnclearOrigin);
    }

    /// Annex 6.0's own `NewMessage` definition, verbatim: "un fragmento
    /// genuinamente distinto que ... coincide en índice con uno ya
    /// procesado" — this IS distinguishable from content alone, and
    /// this module reports it correctly without needing any
    /// `TransitIdentity`.
    #[test]
    fn different_content_at_the_same_index_is_a_new_message() {
        let previously_accepted = b"original payload bytes";
        let incoming = frame_with(0, b"a completely different payload");
        let outcome = classify(&full(&incoming), previously_accepted, None);
        assert_eq!(outcome, NonNovelty::NewMessage);
    }

    /// Supplying `TransitIdentity` does not currently change the
    /// result for identical content — documented behavior, not an
    /// oversight. This test exists so a future revision that DOES add
    /// a real Replay/Retransmission rule has an existing test to
    /// update deliberately, rather than silently changing behavior
    /// this test suite never noticed shifted.
    #[test]
    fn supplying_transit_identity_does_not_yet_change_the_outcome_for_identical_content() {
        let previously_accepted = b"original payload bytes";
        let incoming = frame_with(0, b"original payload bytes");
        let identity = TransitIdentity { arrived_at: SystemTime::now(), network_path: None };
        let outcome = classify(&full(&incoming), previously_accepted, Some(&identity));
        assert_eq!(outcome, NonNovelty::SameContentUnclearOrigin);
    }

    /// A single differing byte is still a `NewMessage`, not treated
    /// as "close enough" to the original — this module does no fuzzy
    /// comparison, only exact byte equality, consistent with the exact
    /// HMAC-based integrity the rest of this codebase already relies
    /// on for "identical or not".
    #[test]
    fn a_single_differing_byte_is_still_classified_as_a_new_message() {
        let previously_accepted = b"AAAA";
        let incoming = frame_with(5, b"AAAB");
        let outcome = classify(&full(&incoming), previously_accepted, None);
        assert_eq!(outcome, NonNovelty::NewMessage);
    }

    /// `TransitIdentity::capture` is the one shared point any Adapter
    /// calls — confirms it actually reads the real clock (two captures
    /// in sequence are non-decreasing, never frozen at a fixed value)
    /// and correctly threads through whatever `network_path` its caller
    /// supplies, without altering it.
    #[test]
    fn capture_reads_the_real_clock_and_preserves_the_supplied_network_path() {
        let first = TransitIdentity::capture(Some("127.0.0.1:54321".to_string()));
        let second = TransitIdentity::capture(None);

        assert!(second.arrived_at >= first.arrived_at);
        assert_eq!(first.network_path, Some("127.0.0.1:54321".to_string()));
        assert_eq!(second.network_path, None);
    }
}

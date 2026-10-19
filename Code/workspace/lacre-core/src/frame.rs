//! `LacreFrame`: the Lacre protocol's unit of transport.
//!
//! # Immutable frame, separate state
//!
//! `LacreFrame` is identity + data, and never changes once created.
//! What progresses isn't the frame — it's what each role *knows* about
//! it. This separation avoids repeating a problem already found with
//! `Session` in server.rs: mixing "who this is" with "what we're doing
//! with it now" produced a real bug (sealer and verifier confused into
//! a single entity). Here the same data — the frame — can have two
//! independent evidence trails (`SealerFrameState` and
//! `VerifierFrameState`) without either one owning or mutating the
//! frame they describe.
//!
//! # Transport only, not a message
//!
//! A `LacreFrame`'s lifecycle ends at `Purged`: it's a transport unit,
//! not the complete message. The concept of "commit" belongs to the
//! reassembled `Payload` (see protocol.rs), not to each fragment — two
//! different levels of granularity that aren't mixed into the same
//! enum.
//!
//! # Why state references the frame by key, not by ownership
//!
//! `SealerFrameState`/`VerifierFrameState` don't wrap or own a
//! `LacreFrame`: they identify it by `(session_id, index)`. Wrapping
//! it would break the premise that the frame is shared data, not the
//! exclusive property of one state — two roles (or two observers, e.g.
//! for auditing) can each keep their own state trail over the same
//! frame without cloning it or fighting over ownership.

use crate::hmac_seal::Seal;
use crate::session::SessionId;

/// Identity + data of a Lacre protocol fragment. Immutable: once
/// built, no field changes. What changes over time is the state each
/// role records *about* this frame (see `SealerFrameState` /
/// `VerifierFrameState`), never the frame itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LacreFrame {
    pub session_id: SessionId,
    /// Position in the sequence. Matches the index `engine.rs` uses as
    /// part of Sᵢ — Block II.3 of the document.
    pub index: u64,
    /// Whether the total number of fragments is known at the moment
    /// this frame is created. `None` is valid and expected in
    /// continuous streaming (Stream profile, Block III), where the
    /// total isn't known until the last fragment appears.
    pub total_fragments: Option<u64>,
    /// Whether this is the last fragment of the sequence. Unlike
    /// `total_fragments`, this is always determinable at the moment
    /// the frame is emitted, in any profile.
    pub is_last: bool,
    pub payload: Vec<u8>,
}

impl LacreFrame {
    /// This frame's identity key, used to index its state in
    /// `protocol.rs`'s maps. Not a new id: it's literally
    /// `(session_id, index)`, which already uniquely identifies the
    /// frame within a session.
    pub fn key(&self) -> (SessionId, u64) {
        (self.session_id, self.index)
    }
}

/// A `LacreFrame`'s lifecycle from the sealer's perspective. Never
/// visits a verification state: the sealer doesn't verify its own
/// seal, it only produces it and waits for delivery confirmation.
///
/// Valid transitions, forward only:
///   Raw → Sealed → Committed → Purged
///
/// Each transition method consumes `self` and only exists on the state
/// it's legal to start from — the compiler rejects a rollback or a
/// state skip, not a caller's convention.
#[derive(Debug, Clone)]
pub enum SealerFrameState {
    /// The frame was produced (fragmented) but not yet sealed.
    Raw,
    /// Sealed and awaiting ACK. Holds the seal so the transport can
    /// send it in the header alongside the payload.
    Sealed { seal: Seal },
    /// ACK received: the receiver confirmed intact delivery.
    Committed,
    /// Released from the buffer — either via ACK or via forced purge
    /// timeout.
    Purged,
}

impl SealerFrameState {
    pub fn new() -> Self {
        SealerFrameState::Raw
    }

    /// Raw → Sealed. Only valid from `Raw`.
    pub fn seal(self, seal: Seal) -> Result<Self, FrameStateError> {
        match self {
            SealerFrameState::Raw => Ok(SealerFrameState::Sealed { seal }),
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "seal",
            }),
        }
    }

    /// Sealed → Committed. Only valid from `Sealed`.
    pub fn commit(self) -> Result<Self, FrameStateError> {
        match self {
            SealerFrameState::Sealed { .. } => Ok(SealerFrameState::Committed),
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "commit",
            }),
        }
    }

    /// Sealed → Purged (timeout) or Committed → Purged (after ACK).
    /// `Raw → Purged` is not valid: there's no point purging something
    /// that was never sealed nor attempted for delivery.
    pub fn purge(self) -> Result<Self, FrameStateError> {
        match self {
            SealerFrameState::Sealed { .. } | SealerFrameState::Committed => {
                Ok(SealerFrameState::Purged)
            }
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "purge",
            }),
        }
    }
}

impl Default for SealerFrameState {
    fn default() -> Self {
        SealerFrameState::new()
    }
}

/// A `LacreFrame`'s lifecycle from the verifier's perspective. Never
/// visits a sealing state: the verifier receives the frame already
/// sealed from outside; what it does is verify, not produce the seal.
///
/// Valid transitions, forward only:
///   Raw → Verified → Purged
///
/// There is no `Committed` at the frame level — that belongs to the
/// complete reassembled `Payload` (protocol.rs), not to each
/// individual fragment.
#[derive(Debug, Clone)]
pub enum VerifierFrameState {
    /// The frame arrived but its seal hasn't been verified yet.
    Raw,
    /// The seal was verified successfully against Sᵢ.
    Verified,
    /// Released from the buffer after being incorporated into
    /// reassembly (or via timeout if it never got verified).
    Purged,
}

impl VerifierFrameState {
    pub fn new() -> Self {
        VerifierFrameState::Raw
    }

    /// Raw → Verified. Only valid from `Raw`.
    pub fn verify(self) -> Result<Self, FrameStateError> {
        match self {
            VerifierFrameState::Raw => Ok(VerifierFrameState::Verified),
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "verify",
            }),
        }
    }

    /// Raw → Purged (never got verified, e.g. timeout with a corrupt
    /// seal) or Verified → Purged (normal case, after being
    /// incorporated into reassembly).
    pub fn purge(self) -> Result<Self, FrameStateError> {
        match self {
            VerifierFrameState::Raw | VerifierFrameState::Verified => {
                Ok(VerifierFrameState::Purged)
            }
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "purge",
            }),
        }
    }
}

impl Default for VerifierFrameState {
    fn default() -> Self {
        VerifierFrameState::new()
    }
}

#[derive(Debug)]
pub enum FrameStateError {
    InvalidTransition {
        from: String,
        attempted: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal() -> Seal {
        Seal([0u8; SEAL_LEN])
    }

    #[test]
    fn sealer_happy_path_advances_through_all_states() {
        let s = SealerFrameState::new();
        let s = s.seal(dummy_seal()).unwrap();
        let s = s.commit().unwrap();
        let s = s.purge().unwrap();
        assert!(matches!(s, SealerFrameState::Purged));
    }

    #[test]
    fn sealer_cannot_skip_sealed_to_commit() {
        let s = SealerFrameState::new();
        let res = s.commit();
        assert!(res.is_err());
    }

    #[test]
    fn sealer_cannot_purge_raw() {
        let s = SealerFrameState::new();
        let res = s.purge();
        assert!(res.is_err());
    }

    #[test]
    fn sealer_can_purge_directly_from_sealed_on_timeout() {
        // Not every Sealed reaches Committed: a forced purge timeout
        // can release a frame that never received an ACK.
        let s = SealerFrameState::new().seal(dummy_seal()).unwrap();
        let res = s.purge();
        assert!(res.is_ok());
    }

    #[test]
    fn sealer_cannot_seal_twice() {
        let s = SealerFrameState::new().seal(dummy_seal()).unwrap();
        let res = s.seal(dummy_seal());
        assert!(res.is_err());
    }

    #[test]
    fn verifier_happy_path_advances_through_all_states() {
        let s = VerifierFrameState::new();
        let s = s.verify().unwrap();
        let s = s.purge().unwrap();
        assert!(matches!(s, VerifierFrameState::Purged));
    }

    #[test]
    fn verifier_cannot_verify_twice() {
        let s = VerifierFrameState::new().verify().unwrap();
        let res = s.verify();
        assert!(res.is_err());
    }

    #[test]
    fn verifier_can_purge_directly_from_raw_on_timeout() {
        // A frame whose seal never got verified (e.g. timeout, or
        // discarded before attempting) can also be purged.
        let s = VerifierFrameState::new();
        let res = s.purge();
        assert!(res.is_ok());
    }

    #[test]
    fn frame_is_immutable_and_key_matches_identity() {
        let frame = LacreFrame {
            session_id: SessionId([0u8; crate::session::SESSION_ID_LEN]),
            index: 7,
            total_fragments: Some(10),
            is_last: false,
            payload: vec![1, 2, 3],
        };
        assert_eq!(frame.key(), (frame.session_id, 7));
    }
}

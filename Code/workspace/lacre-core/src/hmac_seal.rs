//! Per-fragment seal generation and verification.
//!
//! δᵢ = HMAC(fᵢ ∥ Sᵢ, k)
//!
//! Supports SHA-256 (Core profile, de facto standard) and Blake3
//! (Lite/Lightning profiles, faster on CPU). The algorithm choice is a
//! profile parameter, not a code decision.
//!
//! Sᵢ (session state) is passed as an explicit parameter rather than
//! stored as a mutable field: this forces the caller to consciously
//! decide which state corresponds to each fragment, instead of
//! trusting that the object was updated correctly in the previous
//! step.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::session::SessionKey;

pub const SEAL_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgo {
    Sha256,
    Blake3,
}

/// A fragment's seal: always 32 bytes, regardless of algorithm. The
/// algorithm used travels separately (in the profile's header), not
/// inside the seal itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seal(pub [u8; SEAL_LEN]);

/// Generates δᵢ = HMAC(fᵢ ∥ Sᵢ, k) for a given fragment.
///
/// `session_state` is Sᵢ: the session state at step i. It's
/// concatenated with the fragment before applying HMAC, so a seal
/// valid for position i is not valid for position j ≠ i, even if the
/// fragment's content is identical (covers reordering/substitution,
/// see Block IV.1 of the specification).
pub fn seal_fragment(
    algo: HmacAlgo,
    key: &SessionKey,
    fragment: &[u8],
    session_state: &[u8],
) -> Seal {
    match algo {
        HmacAlgo::Sha256 => seal_sha256(key, fragment, session_state),
        HmacAlgo::Blake3 => seal_blake3(key, fragment, session_state),
    }
}

/// Verifies δᵢ against a received fragment. Constant-time comparison:
/// comparing the recomputed HMAC against the received one with `==`
/// leaks timing information a remote attacker could exploit to forge
/// the seal byte by byte. This isn't in the original specification
/// document and is the kind of detail that separates a design that's
/// correct on paper from an implementation that's genuinely secure.
pub fn verify_fragment(
    algo: HmacAlgo,
    key: &SessionKey,
    fragment: &[u8],
    session_state: &[u8],
    received: &Seal,
) -> bool {
    let expected = seal_fragment(algo, key, fragment, session_state);
    expected.0.ct_eq(&received.0).into()
}

fn seal_sha256(key: &SessionKey, fragment: &[u8], session_state: &[u8]) -> Seal {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(fragment);
    mac.update(session_state);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; SEAL_LEN];
    out.copy_from_slice(&result);
    Seal(out)
}

fn seal_blake3(key: &SessionKey, fragment: &[u8], session_state: &[u8]) -> Seal {
    // blake3::keyed_hash requires a key of exactly 32 bytes.
    // SESSION_KEY_LEN is already 32, so this never fails in practice,
    // but we make it explicit rather than silencing it with a
    // truncation.
    let key_bytes: [u8; 32] = key
        .as_bytes()
        .try_into()
        .expect("SessionKey always has SESSION_KEY_LEN=32 bytes");
    let mut hasher = blake3::Hasher::new_keyed(&key_bytes);
    hasher.update(fragment);
    hasher.update(session_state);
    let result = hasher.finalize();
    Seal(*result.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{MasterKeyRing, SessionId};
    use std::time::Duration;

    fn test_key() -> SessionKey {
        let ring = MasterKeyRing::new(0, b"test-master-key-minimum-32-bytes-".to_vec(), Duration::from_secs(60));
        let sid = SessionId::generate();
        ring.derive_for_sealing(&sid)
    }

    #[test]
    fn valid_seal_verifies_sha256() {
        let key = test_key();
        let fragment = b"fragment content";
        let state = b"session-state-step-3";
        let seal = seal_fragment(HmacAlgo::Sha256, &key, fragment, state);
        assert!(verify_fragment(HmacAlgo::Sha256, &key, fragment, state, &seal));
    }

    #[test]
    fn valid_seal_verifies_blake3() {
        let key = test_key();
        let fragment = b"fragment content";
        let state = b"session-state-step-3";
        let seal = seal_fragment(HmacAlgo::Blake3, &key, fragment, state);
        assert!(verify_fragment(HmacAlgo::Blake3, &key, fragment, state, &seal));
    }

    /// Block IV test 1: altered fragment, unmodified seal.
    #[test]
    fn altered_fragment_fails_verification() {
        let key = test_key();
        let original = b"fragment content".to_vec();
        let state = b"session-state-step-3";
        let seal = seal_fragment(HmacAlgo::Sha256, &key, &original, state);

        let mut tampered = original.clone();
        tampered[0] ^= 0x01; // flips a single bit

        assert!(!verify_fragment(HmacAlgo::Sha256, &key, &tampered, state, &seal));
    }

    /// Reordering: same content, different session state (position).
    #[test]
    fn same_fragment_different_session_state_fails() {
        let key = test_key();
        let fragment = b"identical content";
        let seal_at_step_3 = seal_fragment(HmacAlgo::Sha256, &key, fragment, b"state-step-3");

        assert!(!verify_fragment(
            HmacAlgo::Sha256,
            &key,
            fragment,
            b"state-step-7",
            &seal_at_step_3
        ));
    }

    /// Block IV test 2: fragment forged without knowing the key.
    #[test]
    fn forged_seal_without_key_fails() {
        let key = test_key();
        let fragment = b"fragment content";
        let state = b"session-state-step-3";

        // Attacker without the key: uses a plain hash (no HMAC component).
        let fake = blake3::hash(fragment).as_bytes().to_owned();
        let forged_seal = Seal(fake);

        assert!(!verify_fragment(HmacAlgo::Sha256, &key, fragment, state, &forged_seal));
        assert!(!verify_fragment(HmacAlgo::Blake3, &key, fragment, state, &forged_seal));
    }

    #[test]
    fn different_algo_families_are_incompatible() {
        // A seal generated with Blake3 must not verify under SHA-256
        // and vice versa: confirms the algorithm must be negotiated
        // explicitly per profile and cannot be inferred from the seal
        // itself.
        let key = test_key();
        let fragment = b"content";
        let state = b"state";
        let seal_blake3 = seal_fragment(HmacAlgo::Blake3, &key, fragment, state);
        assert!(!verify_fragment(HmacAlgo::Sha256, &key, fragment, state, &seal_blake3));
    }
}

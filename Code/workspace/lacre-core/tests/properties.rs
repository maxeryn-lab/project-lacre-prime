//! Property tests (E3) for the state chain, sealing and verification.
//!
//! Each property is checked against an independent model written in this file
//! from the specification (spec/LACRE-WIRE-v1.md §3–§8), using only the raw
//! HMAC/HKDF/BLAKE3 primitives — not the Core's own code paths.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use lacre_core::core::{CoreError, SealerCore, VerifierCore};
use lacre_core::hmac_seal::{HmacAlgo, Seal};
use lacre_core::receipt::derive_receipt;
use lacre_core::session::{MasterKeyRing, SessionId};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

fn hm(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Independent model of the whole chain: (seal, receipt) per fragment.
fn model(algo: HmacAlgo, ikm: &[u8], sid: &[u8; 16], frags: &[Vec<u8>]) -> Vec<([u8; 32], [u8; 32])> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(sid), ikm).expand(b"lacre-core/v1/session-key", &mut key).unwrap();
    let mut st = hm(&key, &[sid, b"lacre-core/v1/initial-state"]);
    let mut out = vec![];
    for f in frags {
        let seal: [u8; 32] = match algo {
            HmacAlgo::Sha256 => hm(&key, &[f, &st]),
            HmacAlgo::Blake3 => {
                let mut buf = f.clone();
                buf.extend_from_slice(&st);
                blake3::keyed_hash(&key, &buf).into()
            }
        };
        out.push((seal, Sha256::digest(seal).into()));
        st = hm(&key, &[&st, f]);
    }
    out
}

fn algo_strategy() -> impl Strategy<Value = HmacAlgo> {
    prop_oneof![Just(HmacAlgo::Sha256), Just(HmacAlgo::Blake3)]
}

#[derive(Debug, Clone)]
struct Case {
    algo: HmacAlgo,
    ikm: Vec<u8>,
    sid: [u8; 16],
    payload: Vec<u8>,
    slot: usize,
}

fn case() -> impl Strategy<Value = Case> {
    (
        algo_strategy(),
        prop::collection::vec(any::<u8>(), 16..64),
        any::<[u8; 16]>(),
        prop::collection::vec(any::<u8>(), 0..600),
        1usize..200,
    )
        .prop_map(|(algo, ikm, sid, payload, slot)| Case { algo, ikm, sid, payload, slot })
}

fn ring(c: &Case) -> Arc<MasterKeyRing> {
    Arc::new(MasterKeyRing::new(0, c.ikm.clone(), Duration::from_secs(60)))
}

fn sealed(c: &Case) -> Vec<(lacre_core::frame::LacreFrame, Seal)> {
    let mut s = SealerCore::open_with_session_key(ring(c), SessionId(c.sid), c.algo, c.slot, 4096, Duration::from_secs(60));
    s.seal_payload(&c.payload, c.slot).unwrap()
}

fn verifier(c: &Case) -> VerifierCore {
    VerifierCore::resume(ring(c), SessionId(c.sid), 0, c.algo, c.slot, 4096, Duration::from_secs(60)).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The Core's seals and receipts equal the independent model's, for any key, session, payload and slot size.
    #[test]
    fn chain_equals_the_independent_model(c in case()) {
        let out = sealed(&c);
        let frags: Vec<Vec<u8>> = out.iter().map(|(f, _)| f.payload.clone()).collect();
        // the fragments are exactly the slot-sized cuts of the payload (one empty frame for an empty payload)
        let cut: Vec<Vec<u8>> = if c.payload.is_empty() { vec![vec![]] } else { c.payload.chunks(c.slot).map(|x| x.to_vec()).collect() };
        prop_assert_eq!(&frags, &cut);
        prop_assert_eq!(frags.concat(), c.payload.clone());
        let m = model(c.algo, &c.ikm, &c.sid, &frags);
        for ((frame, seal), (ms, mr)) in out.iter().zip(m) {
            prop_assert_eq!(seal.0, ms);
            prop_assert_eq!(derive_receipt(seal).0, mr);
            prop_assert_eq!(frame.session_id.0, c.sid);
        }
    }

    /// Whatever a sealer produces, a verifier accepts in order; frame metadata is coherent.
    #[test]
    fn sealed_sequences_verify_and_metadata_is_coherent(c in case()) {
        let out = sealed(&c);
        let n = out.len() as u64;
        let mut v = verifier(&c);
        for (i, (frame, seal)) in out.iter().enumerate() {
            prop_assert_eq!(frame.index, i as u64);
            prop_assert_eq!(frame.total_fragments, Some(n));
            prop_assert_eq!(frame.is_last, i as u64 == n - 1);
            prop_assert!(v.verify_frame(frame, 0, seal, None).is_ok());
        }
        prop_assert_eq!(v.next_expected_index(), n);
    }

    /// Where the sender cuts the payload does not matter: seal_chunk over the same cuts gives the same seals.
    #[test]
    fn streaming_and_batch_sealing_agree(c in case()) {
        let out = sealed(&c);
        let mut s = SealerCore::open_with_session_key(ring(&c), SessionId(c.sid), c.algo, c.slot, 4096, Duration::from_secs(60));
        for (i, (frame, seal)) in out.iter().enumerate() {
            let (f2, s2) = s.seal_chunk(frame.payload.clone(), i == out.len() - 1).unwrap();
            prop_assert_eq!(s2.0, seal.0);
            // streaming never claims a total, numbers frames consecutively, and passes is_last through
            prop_assert_eq!(f2.total_fragments, None);
            prop_assert_eq!(f2.index, i as u64);
            prop_assert_eq!(f2.is_last, i == out.len() - 1);
        }
    }

    /// Any single-bit change to a payload or a seal is detected, consumes nothing, and the genuine frame still verifies after.
    #[test]
    fn any_single_bit_flip_is_detected_without_consuming_state(
        c in case(), pick in any::<prop::sample::Index>(), bit in 0usize..8, flip_seal in any::<bool>(), bit_idx in any::<prop::sample::Index>()
    ) {
        let out = sealed(&c);
        let k = pick.index(out.len());
        let mut v = verifier(&c);
        for (frame, seal) in &out[..k] {
            prop_assert!(v.verify_frame(frame, 0, seal, None).is_ok());
        }
        let (frame, seal) = &out[k];
        let (mut f2, mut s2) = (frame.clone(), *seal);
        if flip_seal || f2.payload.is_empty() {
            s2.0[bit_idx.index(32)] ^= 1 << bit;
        } else {
            let i = bit_idx.index(f2.payload.len());
            f2.payload[i] ^= 1 << bit;
        }
        prop_assert!(matches!(v.verify_frame(&f2, 0, &s2, None), Err(CoreError::SealMismatch)));
        prop_assert_eq!(v.next_expected_index(), k as u64);
        prop_assert!(v.verify_frame(frame, 0, seal, None).is_ok());
        prop_assert_eq!(v.next_expected_index(), k as u64 + 1);
    }

    /// Ordering: every frame presented out of position is refused with the exact expected/received pair, and nothing advances.
    #[test]
    fn out_of_order_and_replayed_frames_are_refused_exactly(c in case(), a in any::<prop::sample::Index>(), b in any::<prop::sample::Index>()) {
        let out = sealed(&c);
        let mut v = verifier(&c);
        let upto = a.index(out.len() + 1); // verify the first `upto` frames
        for (frame, seal) in &out[..upto] {
            prop_assert!(v.verify_frame(frame, 0, seal, None).is_ok());
        }
        let j = b.index(out.len());
        let (frame, seal) = &out[j];
        let r = v.verify_frame(frame, 0, seal, None);
        if j == upto {
            prop_assert!(r.is_ok());
        } else {
            match r {
                Err(CoreError::OutOfSequence { expected, received }) => {
                    prop_assert_eq!(expected, upto as u64);
                    prop_assert_eq!(received, j as u64);
                    prop_assert_eq!(v.next_expected_index(), upto as u64);
                }
                other => prop_assert!(false, "expected OutOfSequence, got {:?}", other),
            }
        }
    }

    /// Chain binding: a seal is valid only at its own position — swapping the seals of two different fragments never verifies.
    #[test]
    fn a_seal_is_bound_to_its_position_and_content(c in case()) {
        let out = sealed(&c);
        prop_assume!(out.len() >= 2);
        let mut v = verifier(&c);
        let (f0, _) = &out[0];
        let (_, s1) = &out[1];
        prop_assert!(matches!(v.verify_frame(f0, 0, s1, None), Err(CoreError::SealMismatch)));
    }

    /// Session isolation: the same payload under another session id (or another master key) gives different seals and does not verify.
    #[test]
    fn sessions_are_isolated(c in case(), other_sid in any::<[u8; 16]>(), other_ikm in prop::collection::vec(any::<u8>(), 16..64)) {
        prop_assume!(other_sid != c.sid);
        let out = sealed(&c);
        let c2 = Case { sid: other_sid, ..c.clone() };
        let out2 = sealed(&c2);
        prop_assert_ne!(out[0].1 .0, out2[0].1 .0);
        let mut v2 = verifier(&c2);
        prop_assert!(v2.verify_frame(&out[0].0, 0, &out[0].1, None).is_err());
        prop_assume!(other_ikm != c.ikm);
        let c3 = Case { ikm: other_ikm, ..c.clone() };
        let mut v3 = verifier(&c3);
        prop_assert!(matches!(v3.verify_frame(&out[0].0, 0, &out[0].1, None), Err(CoreError::SealMismatch)));
    }

    /// An unknown key_id never verifies (no silent fallback), whatever the frame.
    #[test]
    fn unknown_key_ids_are_refused(c in case(), kid in 1u8..=255) {
        let out = sealed(&c);
        let mut v = verifier(&c);
        prop_assert!(matches!(v.verify_frame(&out[0].0, kid, &out[0].1, None), Err(CoreError::UnknownKeyId)));
        prop_assert_eq!(v.next_expected_index(), 0);
    }
}

//! Wire v2 behaviour: round trips for several families, tampering, crossed
//! algorithms, mismatched suites, key separation and the memory budget.
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use lacre_core::access::Provenance;
use lacre_core::core::CoreError;
use lacre_core::core_v2::{BufferSpec, SealerCoreV2, VerifierCoreV2};
use lacre_core::session::MasterKeyRing;
use lacre_core::suite::{SealTag, SuiteError, ValidatedSuite, MAX_TAG_LEN};

const T: Duration = Duration::from_secs(5);
const CAP: usize = usize::MAX;

fn pair(suite: ValidatedSuite) -> (SealerCoreV2, VerifierCoreV2) {
    let ring = ring();
    let s = SealerCoreV2::open_with_session_id(ring.clone(), sid(5), suite.clone(), BufferSpec::new(64, 16, T, CAP)).unwrap();
    let v = VerifierCoreV2::resume(ring, sid(5), 0, suite, BufferSpec::new(64, 16, T, CAP)).unwrap();
    (s, v)
}

fn every_suite() -> Vec<(&'static str, ValidatedSuite)> {
    vec![
        ("hmac-sha256", sha256_suite()),
        ("hmac-sha512", sha512_suite()),
        ("xof-16", xof_suite(16)),
        ("xof-128 (1024 bits)", xof_suite(128)),
        ("xof-1024 (limit)", xof_suite(1024)),
    ]
}

#[test]
fn every_family_round_trips_a_multi_fragment_payload() {
    for (name, suite) in every_suite() {
        let tag_len = suite.tag_len();
        let (mut s, mut v) = pair(suite);
        let payload: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        let sealed = s.seal_payload(&payload).unwrap();
        assert_eq!(sealed.len(), 4, "{name}");
        let mut rebuilt = vec![];
        for (frame, tag) in &sealed {
            assert_eq!(tag.len(), tag_len, "{name}");
            v.verify_frame(frame, s.key_id(), tag).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            rebuilt.extend_from_slice(&frame.payload);
            assert!(s.ack(frame.index));
        }
        assert_eq!(rebuilt, payload, "{name}");
        assert_eq!(s.pending_count(), 0, "{name}");
    }
}

#[test]
fn a_one_mebibyte_fragment_is_sealed_and_verified() {
    let ring = ring();
    let suite = sha512_suite();
    let mut s = SealerCoreV2::open_with_session_id(ring.clone(), sid(1), suite.clone(), BufferSpec::new(1 << 20, 1, T, CAP)).unwrap();
    let mut v = VerifierCoreV2::resume(ring, sid(1), 0, suite, BufferSpec::new(1 << 20, 1, T, CAP)).unwrap();
    let (frame, tag) = s.seal_chunk(vec![0xAB; 1 << 20], true).unwrap();
    v.verify_frame(&frame, 0, &tag).unwrap();
}

#[test]
fn tampering_fails_closed_and_leaves_the_state_unchanged() {
    for (name, suite) in every_suite() {
        let (mut s, mut v) = pair(suite);
        let sealed = s.seal_payload(&[1u8; 130]).unwrap();
        let (f0, t0) = &sealed[0];
        // Altered payload.
        let mut bad = f0.clone();
        bad.payload[0] ^= 1;
        assert!(matches!(v.verify_frame(&bad, 0, t0), Err(CoreError::SealMismatch)), "{name}");
        // Every single-bit change of the tag.
        for byte in 0..t0.len().min(16) {
            let mut b = t0.as_bytes().to_vec();
            b[byte] ^= 0x80;
            let t = SealTag::new(b).unwrap();
            assert!(matches!(v.verify_frame(f0, 0, &t), Err(CoreError::SealMismatch)), "{name} byte {byte}");
        }
        // Truncated and extended tags.
        let short = SealTag::new(t0.as_bytes()[..t0.len() - 1].to_vec());
        if let Ok(short) = short {
            assert!(matches!(v.verify_frame(f0, 0, &short), Err(CoreError::SealMismatch)), "{name} truncated");
        }
        let mut long = t0.as_bytes().to_vec();
        long.push(0);
        if let Ok(long) = SealTag::new(long) {
            assert!(matches!(v.verify_frame(f0, 0, &long), Err(CoreError::SealMismatch)), "{name} extended");
        }
        // After all the failures the genuine frames still verify, in order.
        assert_eq!(v.next_expected_index(), 0, "{name}");
        for (f, t) in &sealed {
            v.verify_frame(f, 0, t).unwrap();
        }
    }
}

#[test]
fn order_replay_and_substitution_are_rejected() {
    let (mut s, mut v) = pair(sha256_suite());
    let sealed = s.seal_payload(&[9u8; 130]).unwrap();
    assert!(matches!(
        v.verify_frame(&sealed[1].0, 0, &sealed[1].1),
        Err(CoreError::OutOfSequence { expected: 0, received: 1 })
    ));
    v.verify_frame(&sealed[0].0, 0, &sealed[0].1).unwrap();
    assert!(matches!(
        v.verify_frame(&sealed[0].0, 0, &sealed[0].1),
        Err(CoreError::OutOfSequence { expected: 1, received: 0 })
    ), "replay");
    // Identical content at another position carries a different tag.
    let (mut s2, _) = pair(sha256_suite());
    let (_, a) = s2.seal_chunk(vec![5; 8], false).unwrap();
    let (_, b) = s2.seal_chunk(vec![5; 8], false).unwrap();
    assert_ne!(a, b);
}

#[test]
fn a_tag_from_one_algorithm_never_verifies_under_another() {
    // Same output length on purpose: hmac-sha256 (32 B) against an XOF at 32 B.
    let (mut s_a, _) = pair(sha256_suite());
    let (_, mut v_b) = pair(xof_suite(32));
    let (frame, tag) = s_a.seal_chunk(vec![1, 2, 3], true).unwrap();
    assert_eq!(tag.len(), 32);
    assert!(matches!(v_b.verify_frame(&frame, 0, &tag), Err(CoreError::SealMismatch)));
    // Different lengths: refused before any computation.
    let (_, mut v_c) = pair(sha512_suite());
    assert!(matches!(v_c.verify_frame(&frame, 0, &tag), Err(CoreError::SealMismatch)));
}

#[test]
fn a_different_suite_at_the_verifier_fails_at_the_first_frame() {
    // Same algorithm, same tag length; only the declared signature scheme
    // differs in the descriptor. Different hash, different keys, no agreement.
    let with_sig = suite_for(Arc::new(HmacSha256Ref), vec![], Some("ed25519"));
    let ring = ring();
    let mut s = SealerCoreV2::open_with_session_id(ring.clone(), sid(3), sha256_suite(), BufferSpec::new(64, 4, T, CAP)).unwrap();
    let mut v = VerifierCoreV2::resume_signed(ring, sid(3), 0, with_sig, BufferSpec::new(64, 4, T, CAP), &vault_public()).unwrap();
    let (frame, tag) = s.seal_chunk(vec![7; 10], true).unwrap();
    assert!(matches!(v.verify_frame(&frame, 0, &tag), Err(CoreError::SealMismatch)));
    // Different XOF length is a different descriptor too.
    let (mut s16, _) = pair(xof_suite(16));
    let (_, mut v32) = pair(xof_suite(32));
    let (f, t) = s16.seal_chunk(vec![1], true).unwrap();
    assert!(matches!(v32.verify_frame(&f, 0, &t), Err(CoreError::SealMismatch)));
}

#[test]
fn keys_are_separated_by_purpose_suite_and_session() {
    let ring = ring();
    let a = sha256_suite();
    let b = sha512_suite();
    let k = |suite: &ValidatedSuite, sid_byte: u8| {
        ring.derive_v2_for_sealing(&sid(sid_byte), suite.suite_hash(), suite.key_len()).unwrap()
    };
    let ka = k(&a, 1);
    assert_ne!(ka.seal.as_bytes(), ka.chain.as_bytes(), "seal key and chain key differ");
    assert_eq!(ka.seal.as_bytes().len(), a.key_len());
    assert_eq!(ka.chain.as_bytes().len(), 32);
    assert_ne!(ka.seal.as_bytes(), k(&a, 2).seal.as_bytes(), "other session");
    assert_ne!(&ka.seal.as_bytes()[..32], &k(&b, 1).seal.as_bytes()[..32], "other suite");
    assert_ne!(ka.chain.as_bytes(), k(&b, 1).chain.as_bytes(), "chain key also binds the suite");
    // And no v2 key equals the v1 session key of the same session.
    let v1 = ring.derive_for_sealing(&sid(1));
    assert_ne!(v1.as_bytes(), ka.seal.as_bytes());
    assert_ne!(v1.as_bytes(), ka.chain.as_bytes());
}

#[test]
fn unknown_and_foreign_key_ids_are_told_apart() {
    let mut r = MasterKeyRing::new(0, b"test-master-key-minimum-32-bytes-".to_vec(), T);
    r.rotate(1, b"second-master-key-minimum-32-bytes".to_vec());
    let ring = Arc::new(r);
    let suite = sha256_suite();
    // Sealed under the active key (1); a verifier resumed under the retiring key 0 cannot agree.
    let mut s = SealerCoreV2::open_with_session_id(ring.clone(), sid(8), suite.clone(), BufferSpec::new(64, 4, T, CAP)).unwrap();
    assert_eq!(s.key_id(), 1);
    let (frame, tag) = s.seal_chunk(vec![1], true).unwrap();
    let mut v = VerifierCoreV2::resume(ring.clone(), sid(8), 1, suite.clone(), BufferSpec::new(64, 4, T, CAP)).unwrap();
    assert!(matches!(v.verify_frame(&frame, 9, &tag), Err(CoreError::UnknownKeyId)));
    assert!(matches!(v.verify_frame(&frame, 0, &tag), Err(CoreError::SealMismatch)), "known but not this session's");
    v.verify_frame(&frame, 1, &tag).unwrap();
    assert_eq!(
        VerifierCoreV2::resume(ring, sid(8), 9, suite, BufferSpec::new(64, 4, T, CAP)).err(),
        Some(SuiteError::UnknownKeyId)
    );
}

#[test]
fn the_memory_budget_is_refused_before_allocating() {
    let suite = xof_suite(1024);
    let ring = ring();
    // 15 360 slots of 1 KiB plus 1 KiB tags each = 30 MiB; a 15 MiB cap refuses it.
    let r = SealerCoreV2::open(ring.clone(), suite.clone(), BufferSpec::new(1024, 15 * 1024, T, 15 * 1024 * 1024));
    assert!(matches!(r, Err(SuiteError::MemoryBudgetExceeded { .. })));
    let r = VerifierCoreV2::resume(ring.clone(), sid(1), 0, suite.clone(), BufferSpec::new(1024, 15 * 1024, T, 15 * 1024 * 1024));
    assert!(matches!(r, Err(SuiteError::MemoryBudgetExceeded { .. })));
    // The same session with a 32-byte tag fits.
    assert!(SealerCoreV2::open(ring.clone(), sha256_suite(), BufferSpec::new(1024, 15 * 1024, T, 16 * 1024 * 1024)).is_ok());
    // An absurd slot count is an overflow error, not a huge allocation.
    assert!(matches!(
        SealerCoreV2::open(ring, suite, BufferSpec::new(1024, usize::MAX / 1024, T, CAP)),
        Err(SuiteError::MemoryBudgetExceeded { .. })
    ));
}

#[test]
fn a_verified_view_comes_from_the_core_with_core_provenance() {
    let (mut s, mut v) = pair(sha256_suite());
    let (frame, tag) = s.seal_chunk(b"hello".to_vec(), true).unwrap();
    let verified = v.verify_frame_view(&frame, 0, &tag).unwrap();
    assert_eq!(verified.view::<lacre_core::access::FullContent>().provenance(), Provenance::CoreVerified);
    let (frame2, tag2) = s.seal_chunk(b"x".to_vec(), true).unwrap();
    let mut bad = tag2.as_bytes().to_vec();
    bad[0] ^= 1;
    assert!(v.verify_frame_view(&frame2, 0, &SealTag::new(bad).unwrap()).is_err(), "no view without verification");
}

#[test]
fn acknowledged_and_expired_fragments_are_purged() {
    let ring = ring();
    let mut s = SealerCoreV2::open_with_session_id(ring, sid(2), sha256_suite(), BufferSpec::new(64, 4, Duration::from_millis(20), CAP))
    .unwrap();
    let (f0, _) = s.seal_chunk(vec![1; 8], false).unwrap();
    let _ = s.seal_chunk(vec![2; 8], false).unwrap();
    assert_eq!(s.pending_count(), 2);
    assert!(s.ack(f0.index));
    assert!(!s.ack(f0.index), "a duplicate ACK is a no-op");
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(s.purge_expired(), 1);
    assert_eq!(s.pending_count(), 0);
}

#[test]
fn the_tag_limit_is_the_documented_one() {
    assert_eq!(MAX_TAG_LEN, 1024);
    assert!(SealTag::new(vec![0; MAX_TAG_LEN]).is_ok());
    assert!(SealTag::new(vec![0; MAX_TAG_LEN + 1]).is_err());
}

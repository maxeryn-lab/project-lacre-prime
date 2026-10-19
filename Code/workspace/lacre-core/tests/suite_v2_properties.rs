//! Properties of wire v2 over random inputs.
mod common;

use common::*;
use lacre_core::core_v2::{BufferSpec, SealerCoreV2, VerifierCoreV2};
use lacre_core::core::CoreError;
use lacre_core::suite::{SealTag, ValidatedSuite};
use proptest::prelude::*;
use std::time::Duration;

fn suite_by(i: usize, xof_len: u16) -> ValidatedSuite {
    match i % 3 {
        0 => sha256_suite(),
        1 => sha512_suite(),
        _ => xof_suite(xof_len),
    }
}

fn pair(suite: ValidatedSuite, slot: usize, sid_byte: u8) -> (SealerCoreV2, VerifierCoreV2) {
    let ring = ring();
    let spec = BufferSpec::new(slot, 1024, Duration::from_secs(5), usize::MAX);
    (
        SealerCoreV2::open_with_session_id(ring.clone(), sid(sid_byte), suite.clone(), spec).unwrap(),
        VerifierCoreV2::resume(ring, sid(sid_byte), 0, suite, spec).unwrap(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn any_payload_round_trips_under_any_family_and_tag_length(
        payload in proptest::collection::vec(any::<u8>(), 0..700),
        slot in 1usize..96,
        which in 0usize..3,
        xof_len in 16u16..=1024,
        sid_byte in any::<u8>(),
    ) {
        let (mut s, mut v) = pair(suite_by(which, xof_len), slot, sid_byte);
        let mut rebuilt = vec![];
        for (f, t) in s.seal_payload(&payload).unwrap() {
            v.verify_frame(&f, s.key_id(), &t).unwrap();
            rebuilt.extend_from_slice(&f.payload);
        }
        prop_assert_eq!(rebuilt, payload);
    }

    #[test]
    fn any_single_bit_change_in_payload_or_tag_is_rejected(
        payload in proptest::collection::vec(any::<u8>(), 1..200),
        which in 0usize..3,
        xof_len in 16u16..=300,
        bit in any::<usize>(),
        in_tag in any::<bool>(),
    ) {
        let (mut s, mut v) = pair(suite_by(which, xof_len), 256, 7);
        let (frame, tag) = s.seal_chunk(payload, true).unwrap();
        let (mut frame2, mut tag_bytes) = (frame.clone(), tag.as_bytes().to_vec());
        if in_tag {
            let b = bit % (tag_bytes.len() * 8);
            tag_bytes[b / 8] ^= 1 << (b % 8);
        } else {
            let b = bit % (frame2.payload.len() * 8);
            frame2.payload[b / 8] ^= 1 << (b % 8);
        }
        let r = v.verify_frame(&frame2, 0, &SealTag::new(tag_bytes).unwrap());
        prop_assert!(matches!(r, Err(CoreError::SealMismatch)));
        // The genuine frame still verifies afterwards: a failure changed nothing.
        prop_assert!(v.verify_frame(&frame, 0, &tag).is_ok());
    }

    #[test]
    fn tags_differ_across_sessions_positions_and_algorithms(
        data in proptest::collection::vec(any::<u8>(), 0..64),
        a in any::<u8>(), b in any::<u8>(),
    ) {
        prop_assume!(a != b);
        let (mut s1, _) = pair(sha256_suite(), 128, a);
        let (mut s2, _) = pair(sha256_suite(), 128, b);
        let (_, t1) = s1.seal_chunk(data.clone(), false).unwrap();
        let (_, t2) = s2.seal_chunk(data.clone(), false).unwrap();
        prop_assert_ne!(t1.clone(), t2, "other session");
        let (_, t1b) = s1.seal_chunk(data.clone(), false).unwrap();
        prop_assert_ne!(t1.clone(), t1b, "other position");
        let (mut s3, _) = pair(xof_suite(32), 128, a);
        let (_, t3) = s3.seal_chunk(data, false).unwrap();
        prop_assert_ne!(t1, t3, "other algorithm, same length");
    }
}

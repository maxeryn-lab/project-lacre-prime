//! `VerifierCore::verify_frame_view` hands out a `VerifiedFrame` only after
//! the same verification as `verify_frame`, and a failed verification hands
//! out nothing.

use lacre_core::access::{ContentAccess, DerivedContent, FullContent, NoContent, Provenance};
use lacre_core::core::{CoreError, SealerCore, VerifierCore};
use lacre_core::hmac_seal::{HmacAlgo, Seal};
use lacre_core::session::{MasterKeyRing, SessionId};
use std::sync::Arc;
use std::time::Duration;

fn pair() -> (SealerCore, VerifierCore) {
    let ring = Arc::new(MasterKeyRing::new(0, b"verified-view-test-master-key-32!".to_vec(), Duration::from_secs(60)));
    let sid = SessionId([5u8; 16]);
    let sealer = SealerCore::open_with_session_key(
        ring.clone(), sid, HmacAlgo::Sha256, 8, 8, Duration::from_secs(60),
    );
    let verifier = VerifierCore::resume(ring, sid, 0, HmacAlgo::Sha256, 8, 8, Duration::from_secs(60))
        .expect("resume");
    (sealer, verifier)
}

#[test]
fn a_verified_frame_gives_each_level_exactly_its_accessor() {
    let (mut sealer, mut verifier) = pair();
    let out = sealer.seal_payload(b"hello", 8).unwrap();
    let (frame, seal) = &out[0];
    let verified = verifier.verify_frame_view(frame, 0, seal, None).expect("verifies");

    let none = verified.view::<NoContent>();
    assert_eq!(none.level(), ContentAccess::None);
    assert_eq!(none.provenance(), Provenance::CoreVerified);
    assert_eq!(none.header().payload_len, 5);

    assert_eq!(verified.view::<DerivedContent>().derived_bytes(), b"hello");
    assert_eq!(verified.view::<FullContent>().content_bytes(), b"hello");
    assert_eq!(verified.header().index, 0);
}

#[test]
fn a_bad_seal_produces_no_verified_frame() {
    let (mut sealer, mut verifier) = pair();
    let out = sealer.seal_payload(b"hello", 8).unwrap();
    let (frame, seal) = &out[0];
    let mut bad = *seal;
    bad.0[0] ^= 1;
    let err = verifier.verify_frame_view(frame, 0, &Seal(bad.0), None).unwrap_err();
    assert!(matches!(err, CoreError::SealMismatch));
}

#[test]
fn an_out_of_sequence_frame_produces_no_verified_frame() {
    let (mut sealer, mut verifier) = pair();
    let out = sealer.seal_payload(b"hello world!!", 8).unwrap();
    assert!(out.len() >= 2);
    let (f1, s1) = &out[1];
    let err = verifier.verify_frame_view(f1, 0, s1, None).unwrap_err();
    assert!(matches!(err, CoreError::OutOfSequence { expected: 0, received: 1 }));
}

//! Signature schemes and Vault in wire v2 (stage E5), at the Core's contract.
//! The scheme is a test reference (`Ed25519Ref`); the Core names none.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use lacre_core::core::CoreError;
use lacre_core::core_v2::{BufferSpec, SealerCoreV2, VerifierCoreV2};
use lacre_core::suite::{
    derive_receipt_v2, SealMac, SignInput, SignatureScheme, Status, SuiteDescriptor, SuiteError, ValidatedSuite,
    MAX_SIGNATURE_KEY_LEN, MAX_SIGNATURE_LEN,
};

const T: Duration = Duration::from_secs(5);
const CAP: usize = 1 << 20;

fn spec() -> BufferSpec {
    BufferSpec::new(64, 8, T, CAP)
}

fn signing_pair(session: u8) -> (SealerCoreV2, VerifierCoreV2) {
    let s = SealerCoreV2::open_signed(ring(), Some(sid(session)), signed_suite(), spec(), &vault_secret()).unwrap();
    let v = VerifierCoreV2::resume_signed(ring(), sid(session), s.key_id(), signed_suite(), spec(), &vault_public()).unwrap();
    (s, v)
}

#[test]
fn a_signed_session_round_trips_and_the_signature_has_the_declared_length() {
    let (mut s, mut v) = signing_pair(1);
    for i in 0..3u8 {
        let (frame, tag) = s.seal_chunk(vec![i; 20], i == 2).unwrap();
        let sig = s.sign_for(frame.index, &tag).unwrap();
        assert_eq!(sig.len(), 64);
        v.verify_frame_signed(&frame, 0, &tag, Some(&sig)).unwrap();
    }
    assert_eq!(v.next_expected_index(), 3);
}

#[test]
fn the_signature_is_mandatory_under_a_suite_that_names_a_scheme() {
    let (mut s, mut v) = signing_pair(2);
    let (frame, tag) = s.seal_chunk(vec![1; 10], true).unwrap();
    assert!(matches!(v.verify_frame(&frame, 0, &tag), Err(CoreError::VaultSignatureMismatch)));
    assert!(matches!(v.verify_frame_signed(&frame, 0, &tag, None), Err(CoreError::VaultSignatureMismatch)));
    assert_eq!(v.next_expected_index(), 0, "a refusal leaves the state untouched");
    let sig = s.sign_for(0, &tag).unwrap();
    v.verify_frame_signed(&frame, 0, &tag, Some(&sig)).unwrap();
}

#[test]
fn a_signature_is_refused_under_a_suite_without_a_scheme() {
    let ring = ring();
    let mut s = SealerCoreV2::open_with_session_id(ring.clone(), sid(3), sha256_suite(), spec()).unwrap();
    let mut v = VerifierCoreV2::resume(ring, sid(3), 0, sha256_suite(), spec()).unwrap();
    let (frame, tag) = s.seal_chunk(vec![1; 10], true).unwrap();
    assert!(matches!(v.verify_frame_signed(&frame, 0, &tag, Some(&[0u8; 64])), Err(CoreError::VaultSignatureMismatch)));
    v.verify_frame_signed(&frame, 0, &tag, None).unwrap();
}

#[test]
fn altered_truncated_extended_or_foreign_signatures_are_refused_without_advancing() {
    let (mut s, mut v) = signing_pair(4);
    let (frame, tag) = s.seal_chunk(vec![9; 10], true).unwrap();
    let good = s.sign_for(0, &tag).unwrap();
    let mut flipped = good.clone();
    flipped[0] ^= 1;
    let mut tail = good.clone();
    tail[63] ^= 0x80;
    let mut longer = good.clone();
    longer.push(0);
    for bad in [flipped, tail, good[..63].to_vec(), longer, vec![], vec![0u8; 64]] {
        assert!(
            matches!(v.verify_frame_signed(&frame, 0, &tag, Some(&bad)), Err(CoreError::VaultSignatureMismatch)),
            "len {}", bad.len()
        );
        assert_eq!(v.next_expected_index(), 0);
    }
    v.verify_frame_signed(&frame, 0, &tag, Some(&good)).unwrap();
}

#[test]
fn a_signature_does_not_travel_between_sessions_indices_or_keys() {
    let (mut s5, _) = signing_pair(5);
    let (mut s6, mut v6) = signing_pair(6);
    let (f5, t5) = s5.seal_chunk(vec![1; 10], false).unwrap();
    let (f6, t6) = s6.seal_chunk(vec![1; 10], false).unwrap();
    let sig5 = s5.sign_for(0, &t5).unwrap();
    // another session
    assert!(matches!(v6.verify_frame_signed(&f6, 0, &t6, Some(&sig5)), Err(CoreError::VaultSignatureMismatch)));
    // another index: the right tag and signature of index 0 presented as index 1's
    let (_, t6b) = s6.seal_chunk(vec![2; 10], true).unwrap();
    let sig6_idx1 = s6.sign_for(1, &t6b).unwrap();
    let sig6_idx0 = s6.sign_for(0, &t6).unwrap();
    v6.verify_frame_signed(&f6, 0, &t6, Some(&sig6_idx0)).unwrap();
    assert_ne!(sig6_idx0, sig6_idx1);
    let _ = f5;
    // another key
    let other = [7u8; 32];
    let mut s7 = SealerCoreV2::open_signed(ring(), Some(sid(7)), signed_suite(), spec(), &other).unwrap();
    let mut v7 = VerifierCoreV2::resume_signed(ring(), sid(7), 0, signed_suite(), spec(), &vault_public()).unwrap();
    let (f7, t7) = s7.seal_chunk(vec![1; 10], true).unwrap();
    let sig7 = s7.sign_for(0, &t7).unwrap();
    assert!(matches!(v7.verify_frame_signed(&f7, 0, &t7, Some(&sig7)), Err(CoreError::VaultSignatureMismatch)));
}

#[test]
fn the_signature_covers_the_suite_and_the_tag_length() {
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];
    let sid = [3u8; 16];
    let tag = [4u8; 32];
    let base = SignInput::new(&h1, &sid, 0, &tag).to_vec();
    assert_ne!(base, SignInput::new(&h2, &sid, 0, &tag).to_vec(), "suite hash");
    assert_ne!(base, SignInput::new(&h1, &[9u8; 16], 0, &tag).to_vec(), "session");
    assert_ne!(base, SignInput::new(&h1, &sid, 1, &tag).to_vec(), "index");
    assert_ne!(base, SignInput::new(&h1, &sid, 0, &tag[..31]).to_vec(), "tag length");
    assert!(base.starts_with(b"lacre/v2/vault-sig"));
    // exact layout: domain, suite_hash, session_id, index, len, tag
    let want = [&b"lacre/v2/vault-sig"[..], &h1, &sid, &0u64.to_be_bytes(), &32u64.to_be_bytes(), &tag].concat();
    assert_eq!(base, want);
}

#[test]
fn opening_without_the_matching_key_or_scheme_fails_closed() {
    // a suite that names a scheme cannot be opened as unsigned, nor resumed as unsigned
    assert!(matches!(
        SealerCoreV2::open_with_session_id(ring(), sid(8), signed_suite(), spec()),
        Err(SuiteError::SignatureSchemeMismatch)
    ));
    assert!(matches!(
        VerifierCoreV2::resume(ring(), sid(8), 0, signed_suite(), spec()),
        Err(SuiteError::SignatureSchemeMismatch)
    ));
    // a suite without scheme cannot be opened as signed
    assert!(matches!(
        SealerCoreV2::open_signed(ring(), Some(sid(8)), sha256_suite(), spec(), &vault_secret()),
        Err(SuiteError::SignatureSchemeMismatch)
    ));
    assert!(matches!(
        VerifierCoreV2::resume_signed(ring(), sid(8), 0, sha256_suite(), spec(), &vault_public()),
        Err(SuiteError::SignatureSchemeMismatch)
    ));
    // keys of the wrong length
    assert!(matches!(
        SealerCoreV2::open_signed(ring(), Some(sid(8)), signed_suite(), spec(), &[1u8; 31]),
        Err(SuiteError::SignatureKeyInvalid)
    ));
    assert!(matches!(
        VerifierCoreV2::resume_signed(ring(), sid(8), 0, signed_suite(), spec(), &[1u8; 33]),
        Err(SuiteError::SignatureKeyInvalid)
    ));
}

#[test]
fn a_descriptor_and_its_scheme_must_agree() {
    let mac: Arc<dyn SealMac> = Arc::new(HmacSha256Ref);
    let named = SuiteDescriptor::new("hmac-sha256", vec![], Some("ed25519")).unwrap();
    let other = SuiteDescriptor::new("hmac-sha256", vec![], Some("ed448")).unwrap();
    let none = SuiteDescriptor::new("hmac-sha256", vec![], None).unwrap();
    let sc = || Some(Arc::new(Ed25519Ref) as Arc<dyn SignatureScheme>);
    assert!(ValidatedSuite::with_signature(named.clone(), mac.clone(), sc()).is_ok());
    assert!(matches!(ValidatedSuite::with_signature(other, mac.clone(), sc()), Err(SuiteError::SignatureSchemeMismatch)));
    assert!(matches!(ValidatedSuite::with_signature(none, mac.clone(), sc()), Err(SuiteError::SignatureSchemeMismatch)));
    assert!(matches!(ValidatedSuite::with_signature(named.clone(), mac.clone(), None), Err(SuiteError::SignatureSchemeMismatch)));
    assert!(matches!(ValidatedSuite::new(named, mac), Err(SuiteError::SignatureSchemeMismatch)));
}

struct BadScheme {
    sig_len: usize,
    out_len: usize,
    pk_len: usize,
}
impl SignatureScheme for BadScheme {
    fn id(&self) -> &'static str { "ed25519" }
    fn status(&self) -> Status { Status::Experimental }
    fn security_bits(&self) -> u16 { 0 }
    fn public_key_len(&self) -> usize { self.pk_len }
    fn secret_key_len(&self) -> usize { 32 }
    fn signature_len(&self) -> usize { self.sig_len }
    fn public_from_secret(&self, _s: &[u8]) -> Option<Vec<u8>> { Some(vec![0; self.pk_len]) }
    fn sign(&self, _s: &[u8], _i: &SignInput<'_>) -> Vec<u8> { vec![1; self.out_len] }
    fn verify(&self, _p: &[u8], _i: &SignInput<'_>, _s: &[u8]) -> bool { true }
}

#[test]
fn declared_lengths_are_bounded_and_a_scheme_that_returns_the_wrong_length_is_refused() {
    let mac: Arc<dyn SealMac> = Arc::new(HmacSha256Ref);
    let d = || SuiteDescriptor::new("hmac-sha256", vec![], Some("ed25519")).unwrap();
    let with = |b: BadScheme| ValidatedSuite::with_signature(d(), mac.clone(), Some(Arc::new(b)));
    assert!(matches!(with(BadScheme { sig_len: 0, out_len: 0, pk_len: 32 }), Err(SuiteError::SignatureLenOutOfRange(0))));
    assert!(matches!(
        with(BadScheme { sig_len: MAX_SIGNATURE_LEN + 1, out_len: 0, pk_len: 32 }),
        Err(SuiteError::SignatureLenOutOfRange(_))
    ));
    assert!(matches!(with(BadScheme { sig_len: 64, out_len: 64, pk_len: 0 }), Err(SuiteError::SignatureKeyLenOutOfRange(0))));
    assert!(matches!(
        with(BadScheme { sig_len: 64, out_len: 64, pk_len: MAX_SIGNATURE_KEY_LEN + 1 }),
        Err(SuiteError::SignatureKeyLenOutOfRange(_))
    ));
    assert!(with(BadScheme { sig_len: MAX_SIGNATURE_LEN, out_len: MAX_SIGNATURE_LEN, pk_len: 32 }).is_ok());
    assert!(with(BadScheme { sig_len: 64, out_len: 64, pk_len: MAX_SIGNATURE_KEY_LEN }).is_ok());
    // a scheme that declares 64 and returns 63: the sealer refuses to release it
    let suite = with(BadScheme { sig_len: 64, out_len: 63, pk_len: 32 }).unwrap();
    let mut s = SealerCoreV2::open_signed(ring(), Some(sid(9)), suite, spec(), &[1u8; 32]).unwrap();
    let (_, tag) = s.seal_chunk(vec![1; 5], true).unwrap();
    assert!(matches!(s.sign_for(0, &tag), Err(CoreError::VaultSignatureMismatch)));
}

#[test]
fn an_unsigned_sealer_cannot_sign() {
    let mut s = SealerCoreV2::open_with_session_id(ring(), sid(10), sha256_suite(), spec()).unwrap();
    let (_, tag) = s.seal_chunk(vec![1; 5], true).unwrap();
    assert!(matches!(s.sign_for(0, &tag), Err(CoreError::VaultSignatureMismatch)));
    assert!(s.receipts().is_none());
}

#[test]
fn receipts_are_recorded_before_the_purge_and_only_for_signing_sessions() {
    let (mut s, _) = signing_pair(11);
    let (_, t0) = s.seal_chunk(vec![1; 5], false).unwrap();
    let (_, t1) = s.seal_chunk(vec![2; 5], true).unwrap();
    assert_eq!(s.receipts().unwrap().len(), 0);
    assert!(s.ack(0));
    assert!(!s.ack(0), "a duplicate ACK is not pending and issues no second receipt");
    assert!(s.ack(1));
    let r = s.receipts().unwrap();
    assert_eq!(r.len(), 2);
    let h = *signed_suite().suite_hash();
    assert_eq!(r[0].receipt.0, derive_receipt_v2(&h, 0, t0.as_bytes()));
    assert_eq!(r[1].receipt.0, derive_receipt_v2(&h, 1, t1.as_bytes()));
    assert_eq!(r[0].fragment_index, 0);
    // the receipt depends on the suite, the index and the tag
    assert_ne!(derive_receipt_v2(&h, 0, t0.as_bytes()), derive_receipt_v2(&h, 1, t0.as_bytes()));
    assert_ne!(derive_receipt_v2(&h, 0, t0.as_bytes()), derive_receipt_v2(&[0u8; 32], 0, t0.as_bytes()));
    assert_ne!(derive_receipt_v2(&h, 0, t0.as_bytes()), derive_receipt_v2(&h, 0, t1.as_bytes()));
    // an unsigned session issues none
    let mut u = SealerCoreV2::open_with_session_id(ring(), sid(12), sha256_suite(), spec()).unwrap();
    u.seal_chunk(vec![1; 5], true).unwrap();
    assert!(u.ack(0));
    assert!(u.receipts().is_none());
}

#[test]
fn a_different_signature_scheme_in_the_descriptor_changes_every_key() {
    // The descriptor names the scheme, so a verifier expecting another scheme derives other keys.
    let named = signed_suite();
    let plain = sha256_suite();
    assert_ne!(named.suite_hash(), plain.suite_hash());
}

#[test]
fn the_core_demands_the_declared_length_even_from_a_scheme_that_accepts_anything() {
    // BadScheme::verify answers `true` to everything: only the Core's own length
    // check can stop a signature of the wrong size.
    let mac: Arc<dyn SealMac> = Arc::new(HmacSha256Ref);
    let suite = || {
        let d = SuiteDescriptor::new("hmac-sha256", vec![], Some("ed25519")).unwrap();
        ValidatedSuite::with_signature(d, mac.clone(), Some(Arc::new(BadScheme { sig_len: 64, out_len: 64, pk_len: 32 }))).unwrap()
    };
    let mut s = SealerCoreV2::open_signed(ring(), Some(sid(30)), suite(), spec(), &[1u8; 32]).unwrap();
    let key_id = s.key_id();
    let (f, t) = s.seal_chunk(vec![1; 5], true).unwrap();
    let mut v = VerifierCoreV2::resume_signed(ring(), sid(30), key_id, suite(), spec(), &[0u8; 32]).unwrap();
    for len in [0usize, 1, 63, 65, 128] {
        assert!(
            matches!(v.verify_frame_signed(&f, key_id, &t, Some(&vec![1u8; len])), Err(CoreError::VaultSignatureMismatch)),
            "a {len}-byte signature must be refused"
        );
    }
    assert_eq!(v.next_expected_index(), 0, "the refusals did not advance the session");
    v.verify_frame_signed(&f, key_id, &t, Some(&[1u8; 64])).unwrap();
}

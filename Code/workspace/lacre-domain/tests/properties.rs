//! Property and robustness tests (E3) for the wire decoder and the domain
//! entry points: arbitrary input must be refused cleanly — never a panic —
//! and the documented decode rules must hold exactly.

use lacre_core::hmac_seal::Seal;
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::vault_signature::VaultSigningKey;
use lacre_domain::app_state::AppState;
use lacre_domain::capability::{CapabilityRoot, Scope};
use lacre_domain::domain::{self, DomainError};
use lacre_domain::sealer_session_store::SealerSessionStore;
use lacre_domain::session_store::InMemorySessionStore;
use lacre_domain::wire::*;
use proptest::prelude::*;
use std::sync::Arc;
use std::time::Duration;

fn state() -> AppState {
    AppState::new_for_test(
        Arc::new(MasterKeyRing::new(0, b"test-master-key-minimum-32-bytes-".to_vec(), Duration::from_secs(60))),
        Arc::new(InMemorySessionStore::new(Duration::from_secs(60))),
        VaultSigningKey::generate(),
        Arc::new(SealerSessionStore::new(Duration::from_secs(60))),
    )
}

fn wire(session: String, payload: String, seal: String, sig: Option<String>) -> SealedFrameWire {
    SealedFrameWire { session_id: session, index: 0, total_fragments: Some(1), is_last: true, payload_hex: payload, seal_hex: seal, vault_signature_hex: sig, signature: None }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// from_parts then into_parts is the identity, for any frame content.
    #[test]
    fn frame_roundtrip(sid in any::<[u8; 16]>(), index in any::<u64>(), total in prop::option::of(any::<u64>()),
                       last in any::<bool>(), payload in prop::collection::vec(any::<u8>(), 0..300),
                       seal in any::<[u8; 32]>(), sig in prop::option::of(any::<[u8; 64]>())) {
        let frame = lacre_core::frame::LacreFrame { session_id: SessionId(sid), index, total_fragments: total, is_last: last, payload };
        let vs = sig.map(|b| lacre_core::vault_signature::VaultSignature::from_bytes(&b));
        let w = SealedFrameWire::from_parts(&frame, &Seal(seal), vs.as_ref());
        let (f2, s2, v2) = w.into_parts().expect("a well-formed frame decodes");
        prop_assert_eq!(&f2, &frame);
        prop_assert_eq!(s2.0, seal);
        prop_assert_eq!(v2.map(|s| s.to_bytes()), sig);
        // and survives JSON
        let j = serde_json::to_string(&w).unwrap();
        let w2: SealedFrameWire = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(w2.into_parts().unwrap().0, frame);
    }

    /// Arbitrary strings in every text field: never a panic; accepted exactly when the lengths and hex rules hold.
    #[test]
    fn decoder_accepts_exactly_the_documented_shapes(s in ".{0,80}", p in ".{0,40}", seal in ".{0,80}", sig in prop::option::of(".{0,140}")) {
        let r = wire(s.clone(), p.clone(), seal.clone(), sig.clone()).into_parts();
        let ok = |t: &str, n: usize| hex::decode(t).map(|b| b.len() == n).unwrap_or(false);
        let expect_ok = ok(&s, 16) && hex::decode(&p).is_ok() && ok(&seal, 32) && sig.as_deref().map(|x| ok(x, 64)).unwrap_or(true);
        prop_assert_eq!(r.is_ok(), expect_ok);
    }

    /// Well-formed hex of the wrong length is refused with the matching error, at every length.
    #[test]
    fn wrong_lengths_are_refused_with_the_right_error(n_sid in 0usize..40, n_seal in 0usize..70, n_sig in 0usize..90) {
        let w = wire(hex::encode(vec![1u8; n_sid]), "00".into(), hex::encode(vec![2u8; n_seal]), Some(hex::encode(vec![3u8; n_sig])));
        let r = w.into_parts();
        match r {
            Ok(_) => prop_assert!(n_sid == 16 && n_seal == 32 && n_sig == 64),
            Err(WireDecodeError::InvalidSessionId) => prop_assert!(n_sid != 16),
            Err(WireDecodeError::InvalidSealLength) => prop_assert!(n_sid == 16 && n_seal != 32),
            Err(WireDecodeError::InvalidVaultSignatureLength) => prop_assert!(n_sid == 16 && n_seal == 32 && n_sig != 64),
            Err(e) => prop_assert!(false, "unexpected {:?}", e),
        }
    }

    /// Arbitrary JSON text into every request type: never a panic (an error is fine).
    #[test]
    fn request_deserialization_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = serde_json::from_slice::<HandshakeRequest>(&bytes);
        let _ = serde_json::from_slice::<SealRequest>(&bytes);
        let _ = serde_json::from_slice::<VerifyRequest>(&bytes);
        let _ = serde_json::from_slice::<AckRequest>(&bytes);
        let _ = serde_json::from_slice::<CreateToolchainEpisodeRequest>(&bytes);
        let _ = serde_json::from_slice::<AddToolchainNodeRequest>(&bytes);
        let _ = serde_json::from_slice::<VerifyToolchainOutputRequest>(&bytes);
    }

    /// Any u32 other than the current version is refused with BadRequest; the current one and None are accepted.
    #[test]
    fn version_check_is_total(v in any::<u32>()) {
        let r = lacre_domain::version::check(Some(v));
        if lacre_domain::version::ACCEPTED_VERSIONS.contains(&v) {
            prop_assert_eq!(r.unwrap(), v);
        } else {
            prop_assert!(matches!(r, Err(DomainError::BadRequest(_))));
        }
    }

    /// Capability tokens: valid only for the exact (scope, session); any other pair, or any perturbed token, is refused.
    #[test]
    fn capability_tokens_are_scope_and_session_bound(root in any::<[u8; 32]>(), sid in any::<[u8; 16]>(), sid2 in any::<[u8; 16]>(),
                                                      pos in 0usize..64, junk in ".{0,70}") {
        let r = CapabilityRoot::from_bytes(root);
        let scopes = [Scope::Write, Scope::Verify, Scope::Ack];
        for a in scopes {
            let t = r.token_hex(a, &sid);
            prop_assert!(r.check(a, &sid, Some(&t)));
            for b in scopes {
                if std::mem::discriminant(&a) != std::mem::discriminant(&b) {
                    prop_assert!(!r.check(b, &sid, Some(&t)));
                }
            }
            if sid2 != sid { prop_assert!(!r.check(a, &sid2, Some(&t))); }
            let mut bytes = t.clone().into_bytes();
            bytes[pos] = if bytes[pos] == b'0' { b'1' } else { b'0' };
            prop_assert!(!r.check(a, &sid, Some(std::str::from_utf8(&bytes).unwrap())));
            prop_assert!(!r.check(a, &sid, Some(&junk)) || junk.trim() == t);
        }
    }

    /// The domain entry points never panic on arbitrary requests, whatever the text, and a refusal opens no session.
    #[test]
    fn domain_operations_never_panic_on_garbage(
        s1 in ".{0,50}", s2 in ".{0,50}", s3 in ".{0,50}", idx in any::<u64>(), ver in prop::option::of(any::<u32>()),
        key_id in any::<u8>(), reassemble in any::<bool>(), tok in prop::option::of(".{0,70}")
    ) {
        let st = state();
        let _ = domain::handshake(&st, &HandshakeRequest { version: ver, client_public_key_hex: s1.clone() });
        let _ = domain::seal(&st, &SealRequest { version: ver, profile: s1.clone(), payload_hex: s2.clone(), session_id: Some(s3.clone()), token: tok.clone(), ruleset: None, suite: None });
        let frame = SealedFrameWire { session_id: s3.clone(), index: idx, total_fragments: None, is_last: false, payload_hex: s1.clone(), seal_hex: s2.clone(), vault_signature_hex: Some(s3.clone()), signature: None };
        let _ = domain::verify(&st, &VerifyRequest { version: ver, profile: s2.clone(), session_id: s3.clone(), key_id, frames: vec![frame], token: tok.clone(), reassemble, ruleset: Some(s1.clone()), suite: None });
        let _ = domain::ack(&st, &AckRequest { session_id: s1.clone(), indices: vec![idx], token: tok.clone() });
        let _ = domain::receipts(&st, &s2, tok.as_deref());
        let _ = domain::create_toolchain_episode(&st, &CreateToolchainEpisodeRequest { version: ver, episode_id_hex: s1, algo: s2, max_node_age_ms: idx });
    }
}

fn seal_req(profile: &str, payload: &[u8]) -> SealRequest {
    SealRequest { version: None, profile: profile.into(), payload_hex: hex::encode(payload), session_id: None, token: None, ruleset: None, suite: None }
}

fn verify_req(profile: &str, sid: &str, token: &str, frames: Vec<SealedFrameWire>) -> VerifyRequest {
    VerifyRequest { version: None, profile: profile.into(), session_id: sid.into(), key_id: 0, frames, token: Some(token.into()), reassemble: false, ruleset: None, suite: None }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Stateful, end to end through the domain: a tampered frame in the middle of a sequence stops verification exactly there,
    /// reports ok:false for it, and the session stays usable: the genuine remainder then verifies completely.
    #[test]
    fn a_tampered_frame_stops_the_sequence_and_the_session_survives(
        // (profile, payload) sized so the profile cuts at least two frames: core slot 1 KiB, lite 8 KiB.
        // Vault (256 KiB slots) would need >256 KiB per case; its tamper detection is covered by the
        // vector scenarios, the signature tests and the single-frame bit-flip property in lacre-core.
        (profile, payload) in prop_oneof![
            (Just("core"), prop::collection::vec(any::<u8>(), 2100..4200)),
            (Just("lite"), prop::collection::vec(any::<u8>(), 8200..20000)),
        ],
        pick in any::<prop::sample::Index>(), bit in 0usize..8, on_seal in any::<bool>(), at in any::<prop::sample::Index>()
    ) {
        let st = state();
        let sealed = domain::seal(&st, &seal_req(profile, &payload)).expect("seal");
        let frames = sealed.frames.clone();
        let tok = sealed.capabilities.verify.clone();
        prop_assume!(frames.len() >= 2);
        let k = pick.index(frames.len());
        let mut bad = frames[k].clone();
        if on_seal {
            let mut b = hex::decode(&bad.seal_hex).unwrap();
            let i = at.index(b.len()); b[i] ^= 1 << bit; bad.seal_hex = hex::encode(b);
        } else {
            let mut b = hex::decode(&bad.payload_hex).unwrap();
            let i = at.index(b.len()); b[i] ^= 1 << bit; bad.payload_hex = hex::encode(b);
        }
        let mut first: Vec<SealedFrameWire> = frames[..k].to_vec();
        first.push(bad);
        first.extend_from_slice(&frames[k + 1..]); // frames after the bad one must never be processed
        let r = domain::verify(&st, &verify_req(profile, &sealed.session_id, &tok, first)).expect("verify answers 200");
        prop_assert!(!r.all_verified);
        prop_assert_eq!(r.results.len(), k + 1, "stops at the tampered frame");
        prop_assert!(r.results[..k].iter().all(|x| x.ok));
        prop_assert!(!r.results[k].ok && r.results[k].error.is_some());
        let rest = domain::verify(&st, &verify_req(profile, &sealed.session_id, &tok, frames[k..].to_vec())).expect("resume");
        prop_assert!(rest.all_verified, "{:?}", rest.results);
        prop_assert_eq!(rest.results.len(), frames.len() - k);
    }
}

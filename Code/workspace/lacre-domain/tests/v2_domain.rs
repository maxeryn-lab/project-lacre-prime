//! Wire v2 at the domain level (E4): version rules, validation order, policy
//! re-evaluation, session binding, quarantine and panic containment, using
//! test-only algorithms (the Core does not know them: flexibility demo).

use lacre_core::session::MasterKeyRing;
use lacre_core::suite::{CostClass, OutputKind, SealInput, SealMac, Status};
use lacre_core::vault_signature::VaultSigningKey;
use lacre_domain::app_state::AppState;
use lacre_domain::domain::{self, DomainError};
use lacre_domain::seal_policy::{SealRegistry, SealRuntime};
use lacre_domain::sealer_session_store::SealerSessionStore;
use lacre_domain::session_store::InMemorySessionStore;
use lacre_domain::wire::*;
use std::sync::Arc;
use std::time::Duration;

/// The two tests that flip `FLAKY_ON` hold this guard, so they never overlap.
static FLAKY_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
static FLAKY_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct Toy {
    id: &'static str,
    status: Status,
    output: OutputKind,
    panics: bool,
    cost: CostClass,
}
impl SealMac for Toy {
    fn id(&self) -> &'static str { self.id }
    fn status(&self) -> Status { self.status }
    fn cost(&self) -> CostClass { self.cost }
    fn security_bits(&self) -> u16 { 128 }
    fn key_len(&self) -> usize { 32 }
    fn output(&self) -> OutputKind { self.output }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        if self.panics || (self.id == "toy-flaky" && FLAKY_ON.load(std::sync::atomic::Ordering::SeqCst)) {
            panic!("toy algorithm failure");
        }
        let mut acc = key.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        for part in input.parts() {
            for b in part {
                acc = acc.wrapping_mul(31).wrapping_add(*b);
            }
        }
        for (i, o) in out.iter_mut().enumerate() {
            *o = acc.wrapping_add(i as u8);
        }
    }
}

fn registry() -> SealRegistry {
    let t = |id, status, output, panics| Arc::new(Toy { id, status, output, panics, cost: CostClass::Light }) as Arc<dyn SealMac>;
    SealRegistry::new(vec![
        t("toy-fixed", Status::Standard, OutputKind::Fixed(32), false),
        t("toy-xof", Status::Standard, OutputKind::Xof { min: 16, max: 1024 }, false),
        t("toy-panic", Status::Standard, OutputKind::Fixed(32), true),
        t("toy-flaky", Status::Standard, OutputKind::Fixed(32), false),
        t("toy-other", Status::Standard, OutputKind::Fixed(32), false),
        Arc::new(Toy { id: "toy-heavy", status: Status::Standard, output: OutputKind::Fixed(32), panics: false, cost: CostClass::Heavy }),
        Arc::new(Toy { id: "toy-xof32", status: Status::Standard, output: OutputKind::Xof { min: 16, max: 1024 }, panics: false, cost: CostClass::Light }),
    ])
    .unwrap()
}

fn policy(extra: &str) -> String {
    format!(
        r#"{{"wire_versions":[1,2],"max_session_memory_bytes":33554432{extra},"algorithms":[
        {{"id":"toy-fixed","expect_status":"standard","profiles":["lite","core"],"max_cost":"light"}},
        {{"id":"toy-xof","expect_status":"standard","profiles":["core"],"tag_len_bytes":{{"min":16,"max":64}},"max_cost":"light"}},
        {{"id":"toy-panic","expect_status":"standard","profiles":["lite"],"max_cost":"light"}},
        {{"id":"toy-flaky","expect_status":"standard","profiles":["lite"],"max_cost":"light"}},
        {{"id":"toy-other","expect_status":"standard","profiles":["lite"],"max_cost":"light"}},
        {{"id":"toy-heavy","expect_status":"standard","profiles":["lite"],"max_cost":"heavy"}},
        {{"id":"toy-xof32","expect_status":"standard","profiles":["core"],"tag_len_bytes":{{"min":32,"max":64}},"max_cost":"light"}}]}}"#
    )
}

fn state_with(extra: &str) -> (AppState, Arc<SealRuntime>) {
    let rt = Arc::new(SealRuntime::from_json(registry(), &policy(extra)).unwrap());
    let st = AppState::new_for_test(
        Arc::new(MasterKeyRing::new(0, b"test-master-key-minimum-32-bytes-".to_vec(), Duration::from_secs(60))),
        Arc::new(InMemorySessionStore::new(Duration::from_secs(60))),
        VaultSigningKey::generate(),
        Arc::new(SealerSessionStore::new(Duration::from_secs(60))),
    )
    .with_seal_runtime(rt.clone());
    (st, rt)
}

fn suite(seal: &str, tag: Option<u32>) -> SuiteWire {
    SuiteWire { seal: seal.to_string(), tag_len_bytes: tag, signature: None }
}

fn seal_req(version: Option<u32>, profile: &str, payload: &[u8], s: Option<SuiteWire>) -> SealRequest {
    SealRequest {
        version,
        profile: profile.to_string(),
        payload_hex: hex::encode(payload),
        session_id: None,
        token: None,
        ruleset: None,
        suite: s,
    }
}

fn verify_req(version: Option<u32>, profile: &str, sealed: &SealResponse, s: Option<SuiteWire>) -> VerifyRequest {
    VerifyRequest {
        version,
        profile: profile.to_string(),
        session_id: sealed.session_id.clone(),
        key_id: 0,
        frames: sealed.frames.clone(),
        token: Some(sealed.capabilities.verify.clone()),
        reassemble: true,
        ruleset: None,
        suite: s,
    }
}

fn bad(e: DomainError) -> bool { matches!(e, DomainError::BadRequest(_)) }

#[test]
fn v2_roundtrip_with_algorithms_the_core_never_heard_of() {
    let (st, _) = state_with("");
    for (seal, tag, profile, len) in [("toy-fixed", None, "lite", 32usize), ("toy-xof", Some(16), "core", 16), ("toy-xof", Some(64), "core", 64)] {
        let s = suite(seal, tag);
        let sealed = domain::seal(&st, &seal_req(Some(2), profile, b"hola lacre", Some(s.clone()))).unwrap();
        assert_eq!(sealed.version, 2);
        assert_eq!(sealed.suite.as_ref(), Some(&s));
        assert_eq!(sealed.suite_hash_hex.as_ref().unwrap().len(), 64);
        assert_eq!(sealed.frames[0].seal_hex.len(), len * 2);
        let v = domain::verify(&st, &verify_req(Some(2), profile, &sealed, Some(s))).unwrap();
        assert!(v.all_verified);
        assert_eq!(v.version, 2);
        assert_eq!(v.payload_hex.as_deref(), Some(hex::encode(b"hola lacre").as_str()));
    }
}

#[test]
fn multi_frame_payload_roundtrips() {
    let (st, _) = state_with("");
    let payload = vec![0xAB; 20_000]; // lite slot is 8 KiB: 3 frames
    let s = suite("toy-fixed", None);
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", &payload, Some(s.clone()))).unwrap();
    assert_eq!(sealed.frames.len(), 3);
    let v = domain::verify(&st, &verify_req(Some(2), "lite", &sealed, Some(s))).unwrap();
    assert!(v.all_verified);
    assert_eq!(v.payload_hex.unwrap(), hex::encode(payload));
}

#[test]
fn version_rules_never_reinterpret() {
    let (st, _) = state_with("");
    let s = suite("toy-fixed", None);
    // v2 without suite
    assert!(bad(domain::seal(&st, &seal_req(Some(2), "lite", b"x", None)).unwrap_err()));
    // suite under v1 and with no version
    assert!(bad(domain::seal(&st, &seal_req(Some(1), "lite", b"x", Some(s.clone()))).unwrap_err()));
    assert!(bad(domain::seal(&st, &seal_req(None, "lite", b"x", Some(s.clone()))).unwrap_err()));
    // unknown versions
    for v in [0u32, 3, 99] {
        assert!(bad(domain::seal(&st, &seal_req(Some(v), "lite", b"x", Some(s.clone()))).unwrap_err()));
    }
    // omission is v1, as ever
    let r = domain::seal(&st, &seal_req(None, "lite", b"x", None)).unwrap();
    assert_eq!(r.version, 1);
    assert!(r.suite.is_none());
}

#[test]
fn without_a_policy_v2_is_disabled() {
    let st = AppState::new_for_test(
        Arc::new(MasterKeyRing::new(0, b"test-master-key-minimum-32-bytes-".to_vec(), Duration::from_secs(60))),
        Arc::new(InMemorySessionStore::new(Duration::from_secs(60))),
        VaultSigningKey::generate(),
        Arc::new(SealerSessionStore::new(Duration::from_secs(60))),
    );
    assert!(bad(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-fixed", None)))).unwrap_err()));
    assert!(domain::seal(&st, &seal_req(None, "lite", b"x", None)).is_ok());
}

#[test]
fn explicit_version_required_when_the_policy_says_so() {
    let (st, _) = state_with(r#","allow_implicit_version":false"#);
    assert!(bad(domain::seal(&st, &seal_req(None, "lite", b"x", None)).unwrap_err()));
    assert!(domain::seal(&st, &seal_req(Some(1), "lite", b"x", None)).is_ok());
}

#[test]
fn validation_order_and_no_state_left_behind() {
    let (st, _) = state_with("");
    // 400: unknown algorithm, fixed with tag, xof without tag, vault, unknown profile
    for (p, s) in [
        ("lite", suite("nope", None)),
        ("lite", suite("toy-fixed", Some(32))),
        ("core", suite("toy-xof", None)),
        ("vault", suite("toy-fixed", None)),
        ("zzz", suite("toy-fixed", None)),
    ] {
        assert!(bad(domain::seal(&st, &seal_req(Some(2), p, b"x", Some(s))).unwrap_err()), "{p}");
    }
    // 403: known to the registry, not allowed for this profile / tag range
    assert!(matches!(domain::seal(&st, &seal_req(Some(2), "core", b"x", Some(suite("toy-panic", None)))).unwrap_err(), DomainError::Forbidden(_)));
    assert!(matches!(domain::seal(&st, &seal_req(Some(2), "core", b"x", Some(suite("toy-xof", Some(128))))).unwrap_err(), DomainError::Forbidden(_)));
    assert!(matches!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-xof", Some(16))))).unwrap_err(), DomainError::Forbidden(_)));
    // 422 memory budget before allocation
    let (small, _) = state_with("");
    let rt = Arc::new(
        SealRuntime::from_json(
            registry(),
            &policy("").replace("33554432", "1024"),
        )
        .unwrap(),
    );
    let small = AppState::new_for_test(
        small.key_ring().clone(),
        small.handshake_sessions().clone(),
        VaultSigningKey::generate(),
        Arc::new(SealerSessionStore::new(Duration::from_secs(60))),
    )
    .with_seal_runtime(rt);
    assert!(matches!(domain::seal(&small, &seal_req(Some(2), "lite", b"x", Some(suite("toy-fixed", None)))).unwrap_err(), DomainError::Unprocessable(_)));
}

#[test]
fn a_session_is_bound_to_its_first_suite() {
    let (st, _) = state_with("");
    let s = suite("toy-fixed", None);
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", &vec![5u8; 20_000], Some(s.clone()))).unwrap();
    // the first batch (frame 0) opens the session bound to `toy-fixed`
    let mut first = verify_req(Some(2), "lite", &sealed, Some(s.clone()));
    first.frames.truncate(1);
    assert!(domain::verify(&st, &first).unwrap().results[0].ok);
    // the rest under ANOTHER allowed suite: refused, not reinterpreted
    let mut rest = verify_req(Some(2), "lite", &sealed, Some(suite("toy-other", None)));
    rest.frames.remove(0);
    assert!(bad(domain::verify(&st, &rest).unwrap_err()));
    // and the same session under v1 is refused too
    let mut v1 = verify_req(Some(1), "lite", &sealed, None);
    v1.frames.remove(0);
    assert!(bad(domain::verify(&st, &v1).unwrap_err()));
    // the session is intact: the right suite still finishes it
    let mut ok = verify_req(Some(2), "lite", &sealed, Some(s));
    ok.frames.remove(0);
    assert!(domain::verify(&st, &ok).unwrap().all_verified);
}

#[test]
fn a_session_that_panicked_is_a_tombstone_never_restored() {
    use std::sync::atomic::Ordering::SeqCst;
    let _g = FLAKY_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    let (st, _) = state_with("");
    let s = suite("toy-flaky", None);
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", b"abc", Some(s.clone()))).unwrap();
    FLAKY_ON.store(true, SeqCst);
    let e = domain::verify(&st, &verify_req(Some(2), "lite", &sealed, Some(s.clone()))).unwrap_err();
    FLAKY_ON.store(false, SeqCst);
    assert!(matches!(e, DomainError::Internal(_)), "{e:?}");
    // the algorithm works again, but the failed session is not restorable
    let again = domain::verify(&st, &verify_req(Some(2), "lite", &sealed, Some(s)));
    assert!(matches!(again, Err(DomainError::BadRequest(_))), "{again:?}");
}

#[test]
fn policy_tightening_and_quarantine_apply_to_open_sessions() {
    let (st, rt) = state_with("");
    let s = suite("toy-fixed", None);
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", b"abc", Some(s.clone()))).unwrap();
    rt.quarantine_now("toy-fixed");
    // new seals refused
    assert!(matches!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(s.clone()))).unwrap_err(), DomainError::Forbidden(_)));
    // verify refused and the session is closed (default on_quarantine = close)
    assert!(matches!(domain::verify(&st, &verify_req(Some(2), "lite", &sealed, Some(s))).unwrap_err(), DomainError::Forbidden(_)));
    // time does not reactivate
    assert!(rt.is_quarantined("toy-fixed"));
}

#[test]
fn drain_lets_a_session_that_is_already_open_finish() {
    let (st, rt) = state_with(r#","on_quarantine":"drain""#);
    let s = suite("toy-fixed", None);
    let payload = vec![1u8; 20_000];
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", &payload, Some(s.clone()))).unwrap();
    let mut first = verify_req(Some(2), "lite", &sealed, Some(s.clone()));
    first.frames.truncate(1);
    assert!(domain::verify(&st, &first).unwrap().results[0].ok);
    rt.quarantine_now("toy-fixed");
    let mut rest = verify_req(Some(2), "lite", &sealed, Some(s.clone()));
    rest.frames.remove(0);
    let v = domain::verify(&st, &rest).unwrap();
    assert!(v.all_verified, "an open session drains");
    // a session that was never opened is refused
    let sealed2 = domain::seal(&st, &seal_req(Some(2), "lite", b"zz", Some(suite("toy-other", None)))).unwrap();
    let _ = sealed2;
    assert!(matches!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(s))).unwrap_err(), DomainError::Forbidden(_)));
}

#[test]
fn a_panicking_algorithm_is_a_generic_500_and_gets_quarantined() {
    let (st, rt) = state_with(r#","quarantine_after_panics":2"#);
    let s = suite("toy-panic", None);
    for _ in 0..2 {
        let e = domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(s.clone()))).unwrap_err();
        match e {
            DomainError::Internal(m) => assert!(!m.contains("toy algorithm failure"), "no internals in the message"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }
    assert!(rt.is_quarantined("toy-panic"));
    assert!(matches!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(s))).unwrap_err(), DomainError::Forbidden(_)));
    // others keep working
    assert!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-fixed", None)))).is_ok());
}

#[test]
fn v1_is_untouched_by_a_v2_policy() {
    let (st, _) = state_with("");
    let sealed = domain::seal(&st, &seal_req(Some(1), "lite", b"v1 sigue igual", None)).unwrap();
    assert_eq!(sealed.version, 1);
    assert_eq!(sealed.frames[0].seal_hex.len(), 64);
    let v = domain::verify(&st, &verify_req(None, "lite", &sealed, None)).unwrap();
    assert!(v.all_verified);
}

#[test]
fn tag_length_range_has_a_minimum_and_a_maximum() {
    let (st, _) = state_with("");
    // allowed 32..=64: the Core accepts 16 and 128 for this algorithm, the policy does not
    for n in [16u32, 31, 65, 128] {
        let e = domain::seal(&st, &seal_req(Some(2), "core", b"x", Some(suite("toy-xof32", Some(n))))).unwrap_err();
        assert!(matches!(e, DomainError::Forbidden(_)), "{n}: {e:?}");
    }
    for n in [32u32, 48, 64] {
        assert!(domain::seal(&st, &seal_req(Some(2), "core", b"x", Some(suite("toy-xof32", Some(n))))).is_ok(), "{n}");
    }
}

#[test]
fn quarantine_in_close_mode_ends_the_open_session() {
    let (st, rt) = state_with("");
    let s = suite("toy-fixed", None);
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", &vec![9u8; 20_000], Some(s.clone()))).unwrap();
    let sid = lacre_domain::wire::session_id_from_hex(&sealed.session_id).unwrap();
    let mut first = verify_req(Some(2), "lite", &sealed, Some(s.clone()));
    first.frames.truncate(1);
    domain::verify(&st, &first).unwrap();
    assert!(st.verifier_sessions().has_live(&sid));
    rt.quarantine_now("toy-fixed");
    let mut rest = verify_req(Some(2), "lite", &sealed, Some(s));
    rest.frames.remove(0);
    assert!(matches!(domain::verify(&st, &rest).unwrap_err(), DomainError::Forbidden(_)));
    assert!(!st.verifier_sessions().has_live(&sid), "close means the session is gone, not merely refused");
}

#[test]
fn drain_never_opens_a_session_that_was_not_open() {
    let (st, rt) = state_with(r#","on_quarantine":"drain""#);
    let s = suite("toy-fixed", None);
    let sealed = domain::seal(&st, &seal_req(Some(2), "lite", b"abc", Some(s.clone()))).unwrap();
    let sid = lacre_domain::wire::session_id_from_hex(&sealed.session_id).unwrap();
    rt.quarantine_now("toy-fixed");
    let e = domain::verify(&st, &verify_req(Some(2), "lite", &sealed, Some(s))).unwrap_err();
    assert!(matches!(e, DomainError::Forbidden(_)), "{e:?}");
    assert!(!st.verifier_sessions().has_live(&sid), "a refused call leaves no session behind");
}

#[test]
fn a_heavy_algorithm_needs_a_heavy_place_only_when_the_operator_configured_one() {
    use lacre_domain::admission::AdmissionGate;
    let (st, _) = state_with("");
    // no admission configured: heavy runs
    assert!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-heavy", None)))).is_ok());
    let gate = AdmissionGate::new(None, Some(1));
    let st = st.with_admission(gate.clone());
    let held = gate.try_admit_heavy().unwrap();
    let e = domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-heavy", None)))).unwrap_err();
    assert!(matches!(e, DomainError::Unavailable(_)), "{e:?}");
    // a light algorithm does not need a heavy place
    assert!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-fixed", None)))).is_ok());
    drop(held);
    assert!(domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-heavy", None)))).is_ok());
    assert_eq!(gate.running_heavy(), 0, "the heavy place is released when the operation ends");
}

#[test]
fn the_500_says_nothing_about_the_algorithm_or_the_panic() {
    let (st, _) = state_with("");
    let e = domain::seal(&st, &seal_req(Some(2), "lite", b"x", Some(suite("toy-panic", None)))).unwrap_err();
    let DomainError::Internal(m) = e else { panic!("expected Internal") };
    assert_eq!(m, "internal error while sealing");
}

#[test]
fn panics_during_verify_count_toward_quarantine_too() {
    use std::sync::atomic::Ordering::SeqCst;
    let _g = FLAKY_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    let (st, rt) = state_with(r#","quarantine_after_panics":2"#);
    let s = suite("toy-flaky", None);
    for _ in 0..2 {
        let sealed = domain::seal(&st, &seal_req(Some(2), "lite", b"abc", Some(s.clone()))).unwrap();
        FLAKY_ON.store(true, SeqCst);
        let e = domain::verify(&st, &verify_req(Some(2), "lite", &sealed, Some(s.clone()))).unwrap_err();
        FLAKY_ON.store(false, SeqCst);
        assert!(matches!(e, DomainError::Internal(_)), "{e:?}");
    }
    assert!(rt.is_quarantined("toy-flaky"));
}

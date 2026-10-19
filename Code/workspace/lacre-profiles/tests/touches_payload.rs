//! E4 — `touches_payload` made mechanically verifiable (Prime 7.3.1).
//!
//! What is checked here, and what is not:
//!  * every Profile type in the crate declares `TOUCHES_PAYLOAD` and is listed
//!    in the registry (source scan — adding a Profile without declaring it fails);
//!  * the exact set of content-touching Profiles is pinned (changing a
//!    declaration requires changing this test: it is a review gate);
//!  * a declaration of `true` carries a justification;
//!  * `assert_content_blind` is the mechanical check for a `false` declaration,
//!    proven by a positive and a negative control (no real Profile declares
//!    `false` today);
//!  * witnesses: each `true` Profile really does depend on the content.

use lacre_core::access::{ContentAccess, DerivedContent, FullContent, NoContent};
use lacre_core::frame::LacreFrame;
use lacre_core::session::SessionId;
use lacre_profiles::certifier::{CertifierConfig, RequiredPattern};
use lacre_profiles::declaration::{content_touching, DECLARATIONS};
use lacre_profiles::profile::{AcceptOutcome, Profile, ReassembleProfile};
use std::collections::HashSet;
use std::time::Duration;

fn src(name: &str) -> String {
    std::fs::read_to_string(format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"))).expect("source file")
}

fn all_sources() -> Vec<(String, String)> {
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    let mut v = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().map(|x| x == "rs").unwrap_or(false) {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            v.push((name.clone(), src(&name)));
        }
    }
    v
}

/// Production code of a source file: everything before its `#[cfg(test)] mod`.
/// A bare `#[cfg(test)] use` earlier in the file must not end the scan.
fn production_code(text: &str) -> &str {
    text.split("#[cfg(test)]\nmod ").next().unwrap()
}

fn full(f: &LacreFrame) -> lacre_core::access::FullView<'_> {
    lacre_core::access::ContentView::caller_supplied(f)
}

fn frame(payload: &[u8], index: u64, total: u64) -> LacreFrame {
    LacreFrame { session_id: SessionId([9; 16]), index, total_fragments: Some(total), is_last: index + 1 == total, payload: payload.to_vec() }
}

#[test]
fn every_profile_type_declares_touches_payload_and_is_in_the_registry() {
    let struct_re = regex::Regex::new(r"(?m)^pub struct (\w*Profile)\b").unwrap();
    let registry = src("declaration.rs");
    let mut found = HashSet::new();
    for (file, text) in all_sources() {
        if file == "declaration.rs" {
            continue;
        }
        for c in struct_re.captures_iter(&text) {
            let name = c[1].to_string();
            let impl_re = regex::Regex::new(&format!(r"impl\s+(crate::profile::)?Profile\s+for\s+{name}\b")).unwrap();
            let declared = all_sources().iter().any(|(_, t)| impl_re.is_match(t));
            assert!(declared, "{name} ({file}) does not implement Profile (no TOUCHES_PAYLOAD declaration)");
            assert!(
                registry.contains(&format!("declare::<{name}>")),
                "{name} ({file}) is missing from declaration::DECLARATIONS"
            );
            found.insert(name);
        }
    }
    // The registry has no entries for types that do not exist, and one entry per type.
    assert_eq!(found.len(), DECLARATIONS.len(), "types found: {found:?}");
}

#[test]
fn registry_names_are_unique_and_true_entries_are_justified() {
    let mut names = HashSet::new();
    for d in DECLARATIONS {
        assert!(names.insert(d.name), "duplicate name {}", d.name);
        if d.touches_payload {
            assert!(d.justification.trim().len() >= 20, "{}: a `true` declaration needs a real justification", d.name);
        }
    }
}

#[test]
fn the_set_of_content_touching_profiles_is_pinned() {
    // Review gate: any change to this list is a change to the node's neutrality surface.
    assert_eq!(content_touching(), vec!["certifier", "guardian", "reassemble", "rule-engine", "toolchain"]);
}

#[test]
fn registry_values_come_from_the_type_constants() {
    use lacre_profiles::certifier::CertifierProfile;
    use lacre_profiles::toolchain::ToolchainProfile;
    let by = |n: &str| DECLARATIONS.iter().find(|d| d.name == n).unwrap().touches_payload;
    assert_eq!(by("reassemble"), ReassembleProfile::TOUCHES_PAYLOAD);
    assert_eq!(by("toolchain"), ToolchainProfile::TOUCHES_PAYLOAD);
    assert_eq!(by("certifier"), CertifierProfile::TOUCHES_PAYLOAD);
}

/// The mechanical check for a Profile that declares `touches_payload = false`:
/// its outcome must be identical for any content. Panics otherwise.
fn assert_content_blind<P: Profile>(run: impl Fn(&[u8]) -> String) {
    if P::TOUCHES_PAYLOAD {
        return; // nothing to prove: it admits to touching content
    }
    // Same length on purpose: the length of a fragment is part of the header
    // (the Core needs it to size its buffer), so only the bytes may vary.
    let samples: [&[u8]; 5] = [
        &[0u8; 32],
        &[b'a'; 32],
        b"{\"order_id\": 1, \"x\": \"00000000\"}",
        b"LA-000000000001-AAAAAAAA-AAAA-AA",
        &[0xff; 32],
    ];
    assert!(samples.iter().all(|s| s.len() == 32), "samples must have the same length");
    let first = run(samples[0]);
    for s in &samples[1..] {
        assert_eq!(run(s), first, "declares touches_payload=false but its outcome depends on the content");
    }
}

struct BlindOk;
impl Profile for BlindOk {
    type Access = NoContent;
}
struct LiarPeeks;
impl Profile for LiarPeeks {
    type Access = NoContent;
}
struct HonestPeeks;
impl Profile for HonestPeeks {
    type Access = FullContent;
}

#[test]
fn control_a_blind_profile_passes_the_check() {
    assert_content_blind::<BlindOk>(|_| "ok".to_string());
}

#[test]
#[should_panic(expected = "outcome depends on the content")]
fn control_a_profile_that_lies_about_being_blind_is_caught() {
    assert_content_blind::<LiarPeeks>(|c| format!("first={:?}", c.first()));
}

#[test]
fn control_a_profile_that_admits_touching_content_is_not_asked_to_be_blind() {
    assert_content_blind::<HonestPeeks>(|c| format!("first={:?}", c.first()));
}

#[test]
fn witness_reassemble_returns_the_content_of_its_frames() {
    let mut r = ReassembleProfile::new(Duration::from_secs(5));
    assert!(matches!(r.accept(&full(&frame(b"hello ", 0, 2)), None), AcceptOutcome::Accepted));
    assert!(matches!(r.accept(&full(&frame(b"world", 1, 2)), None), AcceptOutcome::Accepted));
    assert_eq!(r.try_reassemble().as_deref(), Some(&b"hello world"[..]));
}

#[test]
fn witness_certifier_outcome_depends_on_the_payload() {
    let c = CertifierConfig::new().require(RequiredPattern::new("LA-[0-9]{4}")).build().unwrap();
    let content = lacre_profiles::rule_engine::StructuredContent::new();
    let yes = format!("{:?}", c.evaluate(&full(&frame(b"xx LA-1234 yy", 0, 1)), &content).unwrap());
    let no = format!("{:?}", c.evaluate(&full(&frame(b"xx nothing yy", 0, 1)), &content).unwrap());
    assert_ne!(yes, no);
}

// ---------------------------------------------------------------------------
// Content access by type (spec §13): the level is a type, and the compiler
// limits what a Profile's entry point can reach.
// ---------------------------------------------------------------------------

#[test]
fn every_declaration_agrees_with_its_type_and_with_the_boolean() {
    use lacre_profiles::certifier::CertifierProfile;
    use lacre_profiles::guardian::GuardianProfile;
    use lacre_profiles::rule_engine::RuleEngineProfile;
    use lacre_profiles::toolchain::ToolchainProfile;
    let by = |n: &str| *DECLARATIONS.iter().find(|d| d.name == n).unwrap();
    assert_eq!(by("reassemble").access, ReassembleProfile::ACCESS);
    assert_eq!(by("toolchain").access, ToolchainProfile::ACCESS);
    assert_eq!(by("rule-engine").access, RuleEngineProfile::ACCESS);
    assert_eq!(by("guardian").access, GuardianProfile::ACCESS);
    assert_eq!(by("certifier").access, CertifierProfile::ACCESS);
    for d in DECLARATIONS {
        assert_eq!(d.touches_payload, d.access.reads_bytes(), "{}: boolean and level disagree", d.name);
        if d.access.reads_bytes() {
            assert!(d.justification.trim().len() >= 20, "{}: reading bytes needs a justification", d.name);
        }
    }
}

#[test]
fn the_access_level_of_every_profile_is_pinned() {
    // Review gate, like the set above: lowering or raising a level is a change
    // to the node's neutrality surface and must change this list.
    let mut got: Vec<(&str, ContentAccess)> = DECLARATIONS.iter().map(|d| (d.name, d.access)).collect();
    got.sort_by_key(|(n, _)| *n);
    assert_eq!(
        got,
        vec![
            ("certifier", ContentAccess::Full),
            ("guardian", ContentAccess::Full),
            ("reassemble", ContentAccess::Full),
            ("rule-engine", ContentAccess::Full),
            ("toolchain", ContentAccess::Full),
        ]
    );
}

#[test]
fn a_source_file_may_only_use_the_accessor_its_declared_level_allows() {
    // The accessors are the only way to reach bytes from a view, so a scan of
    // who calls them is an audit of who reads content, and at which level.
    for (file, text) in all_sources() {
        let code: String = production_code(&text).lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        if code.contains(".content_bytes(") {
            assert!(code.contains("FullContent") || code.contains("FullView"), "{file} reads full content but declares no FullContent access");
        }
        if code.contains(".derived_bytes(") {
            assert!(code.contains("DerivedContent"), "{file} reads derived bytes but declares no DerivedContent access");
        }
    }
}

#[test]
fn no_profile_source_builds_a_view_from_a_raw_frame_in_production_code() {
    // `caller_supplied` is for endpoints that evaluate bytes the Core did not
    // verify, and those live in the domain, not in the Profiles.
    for (file, text) in all_sources() {
        let code = production_code(&text);
        for l in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
            assert!(!l.contains("caller_supplied"), "{file}: a Profile must not fabricate its own view: {l}");
        }
    }
}

/// A Profile of level `None`: its entry point is typed so that it only ever
/// receives a view without byte accessors.
struct HeaderOnly;
impl Profile for HeaderOnly {
    type Access = NoContent;
}
impl HeaderOnly {
    fn evaluate(&self, view: &lacre_core::access::ContentView<'_, NoContent>) -> u64 {
        view.header().index + view.header().payload_len as u64
    }
}

/// A Profile of level `Derived`: it reads a proof, never the datum.
struct ProofChecker;
impl Profile for ProofChecker {
    type Access = DerivedContent;
}
impl ProofChecker {
    fn evaluate(&self, view: &lacre_core::access::ContentView<'_, DerivedContent>) -> bool {
        view.derived_bytes().first() == Some(&1)
    }
}

#[test]
fn witness_a_none_profile_decides_from_the_header_alone() {
    assert!(!std::hint::black_box(HeaderOnly::TOUCHES_PAYLOAD));
    assert_eq!(HeaderOnly::ACCESS, ContentAccess::None);
    let f1 = frame(b"AAAA", 2, 3);
    let f2 = frame(b"BBBB", 2, 3);
    let v1 = lacre_core::access::ContentView::<NoContent>::caller_supplied(&f1);
    let v2 = lacre_core::access::ContentView::<NoContent>::caller_supplied(&f2);
    assert_eq!(HeaderOnly.evaluate(&v1), HeaderOnly.evaluate(&v2));
    // And the generic check agrees: the outcome is identical for any content.
    assert_content_blind::<HeaderOnly>(|c| {
        let f = frame(c, 0, 1);
        HeaderOnly.evaluate(&lacre_core::access::ContentView::<NoContent>::caller_supplied(&f)).to_string()
    });
}

#[test]
fn witness_a_derived_profile_reads_bytes_but_is_declared_as_derived() {
    assert!(std::hint::black_box(ProofChecker::TOUCHES_PAYLOAD), "derived access reads bytes, so the boolean is true");
    assert_eq!(ProofChecker::ACCESS, ContentAccess::Derived);
    let good = frame(&[1, 9, 9], 0, 1);
    let bad = frame(&[0, 9, 9], 0, 1);
    assert!(ProofChecker.evaluate(&lacre_core::access::ContentView::<DerivedContent>::caller_supplied(&good)));
    assert!(!ProofChecker.evaluate(&lacre_core::access::ContentView::<DerivedContent>::caller_supplied(&bad)));
}

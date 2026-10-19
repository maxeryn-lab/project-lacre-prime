//! Structural guarantees of the wire v2 contract, read from the sources:
//! the Core does not know the catalogue, only the Core compares tags, and
//! wire v1 is frozen.

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../Cargo.toml");

fn src(name: &str) -> String {
    std::fs::read_to_string(format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Production code: before the test module, comment lines dropped.
fn production(text: &str) -> String {
    let cut = text.find("#[cfg(test)]\nmod ").unwrap_or(text.len());
    text[..cut].lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
}

fn all_sources() -> Vec<(String, String)> {
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "rs").then(|| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read_to_string(&p).unwrap()))
        })
        .collect()
}

#[test]
fn the_core_does_not_know_the_seal_catalogue() {
    assert!(!MANIFEST.contains("lacre-seals"), "lacre-core must not depend on the catalogue");
    for (file, text) in all_sources() {
        let code = production(&text);
        for forbidden in ["lacre_seals", "lacre-seals", "dlopen", "libloading", "Library::new"] {
            assert!(!code.contains(forbidden), "{file} mentions `{forbidden}`");
        }
    }
}

#[test]
fn the_seal_trait_has_no_verify_so_only_the_core_compares_tags() {
    let suite = production(&src("suite.rs"));
    let start = suite.find("pub trait SealMac").expect("trait SealMac");
    let body = &suite[start..start + suite[start..].find("\n}\n").unwrap()];
    assert!(!body.contains("fn verify"), "SealMac must not offer verify: {body}");
    assert!(body.contains("fn mac("), "SealMac computes, nothing else");
}

#[test]
fn tags_are_compared_in_constant_time_and_only_through_seal_tag_matches() {
    let suite = production(&src("suite.rs"));
    assert!(suite.contains("ct_eq"), "SealTag::matches must use subtle's ct_eq");
    let v2 = production(&src("core_v2.rs"));
    assert!(v2.contains(".matches("), "the v2 verifier compares through SealTag::matches");
    for l in v2.lines() {
        let squeezed: String = l.split_whitespace().collect();
        assert!(
            !(squeezed.contains("expected==") || squeezed.contains("==expected") || squeezed.contains("tag==") || squeezed.contains("==tag")
                || squeezed.contains("expected!=") || squeezed.contains("!=expected")),
            "tag bytes compared with ==/!=: {l}"
        );
    }
}

#[test]
fn the_core_builds_the_output_buffer_and_the_algorithm_does_not_choose_its_length() {
    let v2 = production(&src("core_v2.rs"));
    assert!(v2.contains("vec![0u8; suite.tag_len()]"), "the output buffer is sized by the suite");
    // The trait gives the algorithm a slice it must fill, never a length to choose.
    let suite = production(&src("suite.rs"));
    assert!(suite.contains("fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]);"));
}

#[test]
fn wire_v1_vectors_are_frozen_byte_for_byte() {
    let bytes = std::fs::read(format!("{}/../spec/vectors/wire-v1.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let hash = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        hash, "5d09bb4628543632a3c8f0dee883d1c474bad7aceff3822878702959ec94ab3a",
        "spec/vectors/wire-v1.json changed: wire v1 is frozen (see spec/LACRE-WIRE-v2.md)"
    );
}

#[test]
fn the_v1_modules_do_not_import_the_v2_ones() {
    for f in ["core.rs", "hmac_seal.rs", "frame.rs", "receipt.rs", "vault_signature.rs", "session_handshake.rs"] {
        let code = production(&src(f));
        for v2 in ["crate::suite", "crate::core_v2", "SealMac", "SuiteDescriptor"] {
            assert!(!code.contains(v2), "v1 module {f} references v2 item `{v2}`");
        }
    }
}

//! The third-party algorithm passes Lacre's conformance suite with vectors from
//! an independent implementation (Python).

use std::sync::Arc;

use hmac_sha3_256_seal::HmacSha3_256;
use lacre_core::suite::SealMac;
use lacre_seal_conformance::{check_catalogue, check_seal_mac, Kat, Options};

fn kats() -> Vec<Kat> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, c)| {
            Kat::from_hex(
                &format!("hmac-sha3-256 caso {i}"),
                c["key_hex"].as_str().unwrap(),
                c["fragment_hex"].as_str().unwrap(),
                c["state_hex"].as_str().unwrap(),
                c["tag_hex"].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn passes_the_conformance_suite() {
    let rep = check_seal_mac(Arc::new(HmacSha3_256), &kats(), &Options::default());
    assert!(rep.passed(), "{}", rep.summary());
}

#[test]
fn is_consistent_next_to_the_whole_catalogue() {
    // The third party coexists with Lacre's catalogue: distinct ids, no alias of another algorithm.
    let mut entries: Vec<(Arc<dyn SealMac>, Vec<Kat>)> = vec![(Arc::new(HmacSha3_256), kats())];
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../workspace/spec/vectors/seals-v2.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for m in lacre_seals_all() {
        let id = m.id();
        let k: Vec<Kat> = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["seal_id"] == id)
            .map(|c| {
                Kat::from_hex(id, c["key_hex"].as_str().unwrap(), c["fragment_hex"].as_str().unwrap(), c["state_hex"].as_str().unwrap(), c["tag_hex"].as_str().unwrap()).unwrap()
            })
            .collect();
        entries.push((m, k));
    }
    let rep = check_catalogue(&entries, &Options::default());
    assert!(rep.passed(), "{}", rep.summary());
}

fn lacre_seals_all() -> Vec<Arc<dyn SealMac>> {
    lacre_seals::all()
}

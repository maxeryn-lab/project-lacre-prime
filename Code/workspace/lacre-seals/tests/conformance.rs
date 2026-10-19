//! The catalogue passes the conformance suite, with vectors produced by
//! implementations other than the ones the adapters wrap
//! (`Tools/gen_seal_vectors.py`).

use std::sync::Arc;

use lacre_core::suite::SealMac;
use lacre_seal_conformance::{check_catalogue, check_seal_mac, Kat, Options};

fn kats_for(id: &str) -> Vec<Kat> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/seals-v2.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let kats: Vec<Kat> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["seal_id"] == id)
        .map(|c| {
            Kat::from_hex(
                &format!("{id} len {} frag {}", c["tag_len"], c["fragment_hex"].as_str().unwrap().len() / 2),
                c["key_hex"].as_str().unwrap(),
                c["fragment_hex"].as_str().unwrap(),
                c["state_hex"].as_str().unwrap(),
                c["tag_hex"].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert!(!kats.is_empty(), "no vectors for {id}");
    kats
}

#[test]
fn every_algorithm_of_the_catalogue_passes_the_suite() {
    for m in lacre_seals::all() {
        let id = m.id();
        let rep = check_seal_mac(m.clone(), &kats_for(id), &Options::default());
        assert!(rep.passed(), "{id}:\n{}", rep.summary());
    }
}

#[test]
fn the_whole_catalogue_is_consistent_as_a_registry() {
    let entries: Vec<(Arc<dyn SealMac>, Vec<Kat>)> =
        lacre_seals::all().into_iter().map(|m| { let k = kats_for(m.id()); (m, k) }).collect();
    let rep = check_catalogue(&entries, &Options::default());
    assert!(rep.passed(), "{}", rep.summary());
}

#[test]
fn ids_are_unique_and_lookup_works() {
    let all = lacre_seals::all();
    let mut ids: Vec<_> = all.iter().map(|m| m.id()).collect();
    let n = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), n);
    for m in &all {
        assert_eq!(lacre_seals::find(m.id()).unwrap().id(), m.id());
    }
    assert!(lacre_seals::find("nope").is_none());
}

#[test]
fn statuses_match_the_decisions() {
    use lacre_core::suite::Status::*;
    for m in lacre_seals::all() {
        let want = match m.id() {
            "kmac256" => Experimental,
            "hmac-sha1" => Legacy,
            _ => Standard,
        };
        assert_eq!(m.status(), want, "{}", m.id());
    }
    // SHA-1 exists only behind the feature.
    assert_eq!(lacre_seals::find("hmac-sha1").is_some(), cfg!(feature = "legacy-seals"));
}

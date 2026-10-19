//! Known-answer vectors for wire v2 (spec/vectors/suite-v2.json), produced by
//! an independent Python implementation (Tools/gen_suite_vectors.py).
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use lacre_core::core_v2::{BufferSpec, SealerCoreV2, VerifierCoreV2};
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::suite::{SealInput, SealMac, SealTag, SignatureScheme, SuiteDescriptor, ValidatedSuite};
use serde_json::Value;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/suite-v2.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h(v: &Value) -> Vec<u8> { hex::decode(v.as_str().unwrap()).unwrap() }

fn mac_for(id: &str) -> Arc<dyn SealMac> {
    match id {
        "hmac-sha256" => Arc::new(HmacSha256Ref),
        "hmac-sha512" => Arc::new(HmacSha512Ref),
        "blake3-keyed-xof" => Arc::new(Blake3XofRef),
        other => panic!("vector for unknown algorithm {other}"),
    }
}

fn suite_of(c: &Value) -> ValidatedSuite {
    let sig = c["signature"].as_str();
    let d = SuiteDescriptor::new(c["seal_id"].as_str().unwrap(), h(&c["params_hex"]), sig).unwrap();
    let scheme: Option<Arc<dyn SignatureScheme>> = sig.map(|_| Arc::new(Ed25519Ref) as Arc<dyn SignatureScheme>);
    ValidatedSuite::with_signature(d, mac_for(c["seal_id"].as_str().unwrap()), scheme).unwrap()
}

#[test]
fn descriptor_and_hash_match_the_independent_implementation() {
    let doc = load();
    for c in doc["cases"].as_array().unwrap() {
        let s = suite_of(c);
        assert_eq!(s.descriptor().canonical(), h(&c["descriptor_hex"]), "{}", c["name"]);
        assert_eq!(s.suite_hash().to_vec(), h(&c["suite_hash_hex"]), "{}", c["name"]);
        // And the parser returns the same descriptor from those bytes.
        assert_eq!(&SuiteDescriptor::parse(&h(&c["descriptor_hex"])).unwrap(), s.descriptor());
        assert_eq!(s.tag_len(), c["tag_len"].as_u64().unwrap() as usize);
    }
}

#[test]
fn derived_keys_match_the_independent_implementation() {
    let doc = load();
    let ring = MasterKeyRing::new(0, h(&doc["ikm_hex"]), Duration::from_secs(60));
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&h(&doc["session_id_hex"]));
    for c in doc["cases"].as_array().unwrap() {
        let s = suite_of(c);
        let keys = ring.derive_v2_for_sealing(&SessionId(sid), s.suite_hash(), s.key_len()).unwrap();
        assert_eq!(keys.seal.as_bytes(), h(&c["seal_key_hex"]).as_slice(), "{}", c["name"]);
        assert_eq!(keys.chain.as_bytes(), h(&c["chain_key_hex"]).as_slice(), "{}", c["name"]);
    }
}

#[test]
fn seal_inputs_and_tags_match_the_independent_implementation() {
    let doc = load();
    for c in doc["cases"].as_array().unwrap() {
        let s = suite_of(c);
        let key = h(&c["seal_key_hex"]);
        for f in c["frames"].as_array().unwrap() {
            let fragment = h(&f["fragment_hex"]);
            let state: [u8; 32] = h(&f["state_hex"]).try_into().unwrap();
            let input = SealInput::new(&fragment, &state);
            assert_eq!(input.to_vec(), h(&f["seal_input_hex"]), "{} frame {}", c["name"], f["index"]);
            let mut out = vec![0u8; s.tag_len()];
            s.mac().mac(&key, &input, &mut out);
            assert_eq!(out, h(&f["tag_hex"]), "{} frame {}", c["name"], f["index"]);
        }
    }
}

#[test]
fn the_v2_cores_reproduce_the_vectors_end_to_end() {
    let doc = load();
    let ring = Arc::new(MasterKeyRing::new(0, h(&doc["ikm_hex"]), Duration::from_secs(60)));
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&h(&doc["session_id_hex"]));
    for c in doc["cases"].as_array().unwrap() {
        let spec = || BufferSpec::new(1024, 8, Duration::from_secs(5), usize::MAX);
        let signed = c["signature"].as_str().is_some();
        let (mut sealer, mut verifier) = if signed {
            (
                SealerCoreV2::open_signed(ring.clone(), Some(SessionId(sid)), suite_of(c), spec(), &vault_secret()).unwrap(),
                VerifierCoreV2::resume_signed(ring.clone(), SessionId(sid), 0, suite_of(c), spec(), &vault_public()).unwrap(),
            )
        } else {
            (
                SealerCoreV2::open_with_session_id(ring.clone(), SessionId(sid), suite_of(c), spec()).unwrap(),
                VerifierCoreV2::resume(ring.clone(), SessionId(sid), 0, suite_of(c), spec()).unwrap(),
            )
        };
        let frames = c["frames"].as_array().unwrap();
        for (i, f) in frames.iter().enumerate() {
            let (frame, tag) = sealer.seal_chunk(h(&f["fragment_hex"]), i + 1 == frames.len()).unwrap();
            assert_eq!(tag.as_bytes(), h(&f["tag_hex"]).as_slice(), "{} frame {}", c["name"], i);
            let expected = SealTag::new(h(&f["tag_hex"])).unwrap();
            let sig = signed.then(|| sealer.sign_for(frame.index, &expected).unwrap());
            verifier.verify_frame_signed(&frame, sealer.key_id(), &expected, sig.as_deref()).unwrap();
            sealer.ack(frame.index);
        }
    }
}

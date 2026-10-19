//! Ed25519 and the v2 receipt against vectors produced by an independent
//! implementation (`Tools/gen_sign_vectors.py`: Python, OpenSSL).

use lacre_core::suite::{derive_receipt_v2, SignInput, SignatureScheme};
use lacre_seals::signatures::Ed25519;
use serde_json::Value;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/signatures-v2.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn h(v: &Value) -> Vec<u8> { hex::decode(v.as_str().unwrap()).unwrap() }

#[test]
fn ed25519_reproduces_the_independent_vectors() {
    let doc = load();
    let secret = h(&doc["secret_hex"]);
    let public = h(&doc["public_hex"]);
    let suite_hash: [u8; 32] = h(&doc["suite_hash_hex"]).try_into().unwrap();
    let sid: [u8; 16] = h(&doc["session_id_hex"]).try_into().unwrap();
    assert_eq!(Ed25519.public_from_secret(&secret).unwrap(), public);
    for c in doc["cases"].as_array().unwrap() {
        let index = c["index"].as_u64().unwrap();
        let tag = h(&c["tag_hex"]);
        let input = SignInput::new(&suite_hash, &sid, index, &tag);
        assert_eq!(input.to_vec(), h(&c["sign_input_hex"]), "input {index}");
        let sig = Ed25519.sign(&secret, &input);
        assert_eq!(sig, h(&c["signature_hex"]), "signature {index}");
        assert!(Ed25519.verify(&public, &input, &sig));
        assert_eq!(derive_receipt_v2(&suite_hash, index, &tag).to_vec(), h(&c["receipt_hex"]), "receipt {index}");
        // Any single-bit change of signature or input must be refused.
        let mut bad = sig.clone();
        bad[10] ^= 1;
        assert!(!Ed25519.verify(&public, &input, &bad));
        let other = SignInput::new(&suite_hash, &sid, index + 1, &tag);
        assert!(!Ed25519.verify(&public, &other, &sig));
        assert!(!Ed25519.verify(&public, &input, &sig[..63]));
    }
}

#[test]
fn malformed_keys_and_lengths_are_refused_not_panicked() {
    let tag = [1u8; 32];
    let input = SignInput::new(&[0u8; 32], &[0u8; 16], 0, &tag);
    assert!(!Ed25519.verify(&[0u8; 31], &input, &[0u8; 64]));
    assert!(!Ed25519.verify(&[0u8; 32], &input, &[0u8; 65]));
    assert!(Ed25519.public_from_secret(&[0u8; 31]).is_none());
}

#[test]
fn the_catalogue_lists_it_and_finds_it() {
    assert_eq!(lacre_seals::signatures().len(), 1);
    assert!(lacre_seals::find_signature("ed25519").is_some());
    assert!(lacre_seals::find_signature("nope").is_none());
}

//! Known-answer tests for the Lacre wire format v1 (spec/LACRE-WIRE-v1.md).
//!
//! The vectors in `spec/vectors/wire-v1.json` were produced by
//! `Tools/gen_vectors.py`, an independent implementation (Python: hashlib,
//! hmac, cryptography, blake3) that shares no code with this crate. Every
//! test here recomputes the value with the Core and compares it byte for byte.

use lacre_core::core::{CoreError, SealerCore, VerifierCore};
use lacre_core::frame::LacreFrame;
use lacre_core::hmac_seal::{HmacAlgo, Seal};
use lacre_core::receipt::derive_receipt;
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::vault_signature::{VaultSignature, VaultSigningKey};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

const VECTORS: &str = include_str!("../../spec/vectors/wire-v1.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors file is valid JSON")
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))).expect("hex")
}

fn arr<const N: usize>(v: &Value, k: &str) -> [u8; N] {
    hx(v, k).try_into().unwrap_or_else(|_| panic!("{k}: wrong length"))
}

fn algo_of(c: &Value) -> HmacAlgo {
    match c["algo"].as_str().unwrap() {
        "sha256" => HmacAlgo::Sha256,
        "blake3" => HmacAlgo::Blake3,
        other => panic!("unknown algo {other}"),
    }
}

fn ring(c: &Value) -> Arc<MasterKeyRing> {
    Arc::new(MasterKeyRing::new(
        c["key_id"].as_u64().unwrap() as u8,
        hx(c, "ikm_hex"),
        Duration::from_secs(60),
    ))
}

fn chain<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no chain {name}"))
}

fn sealer(c: &Value) -> SealerCore {
    let slot = c["slot_size"].as_u64().unwrap() as usize;
    SealerCore::open_with_session_key(
        ring(c),
        SessionId(arr(c, "session_id_hex")),
        algo_of(c),
        slot,
        c["frames"].as_array().unwrap().len() + 1,
        Duration::from_secs(60),
    )
}

#[test]
fn the_file_declares_protocol_version_1_and_the_constants() {
    let v = vectors();
    assert_eq!(v["format"], "lacre-wire-vectors");
    assert_eq!(v["protocol_version"], 1);
    assert_eq!(v["constants"]["seal_len"], 32);
    assert_eq!(v["constants"]["session_id_len"], 16);
    assert_eq!(v["constants"]["session_key_len"], 32);
    assert_eq!(v["constants"]["vault_signature_len"], 64);
}

#[test]
fn session_key_derivation_matches_the_vectors() {
    let v = vectors();
    for case in v["key_derivation"].as_array().unwrap() {
        let r = MasterKeyRing::new(0, hx(case, "ikm_hex"), Duration::from_secs(60));
        let sid = SessionId(arr(case, "session_id_hex"));
        assert_eq!(
            r.derive_for_sealing(&sid).as_bytes(),
            &hx(case, "session_key_hex")[..],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn x25519_shared_secret_feeds_hkdf_as_the_vectors_say() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let v = vectors();
    let h = &v["handshake"];
    let client = StaticSecret::from(arr::<32>(h, "client_private_hex"));
    let server = StaticSecret::from(arr::<32>(h, "server_private_hex"));
    assert_eq!(PublicKey::from(&client).as_bytes(), &arr::<32>(h, "client_public_hex"));
    assert_eq!(PublicKey::from(&server).as_bytes(), &arr::<32>(h, "server_public_hex"));
    let shared = client.diffie_hellman(&PublicKey::from(&server));
    assert_eq!(shared.as_bytes(), &arr::<32>(h, "shared_secret_hex"));
    let r = MasterKeyRing::new(0, shared.as_bytes().to_vec(), Duration::from_secs(60));
    let sid = SessionId(arr(h, "session_id_hex"));
    assert_eq!(r.derive_for_sealing(&sid).as_bytes(), &hx(h, "session_key_hex")[..]);
}

#[test]
fn the_sealer_reproduces_every_chain_in_the_vectors() {
    let v = vectors();
    for c in v["chains"].as_array().unwrap() {
        let slot = c["slot_size"].as_u64().unwrap() as usize;
        let frames = c["frames"].as_array().unwrap();
        let out = sealer(c).seal_payload(&hx(c, "payload_hex"), slot).expect("seal_payload");
        assert_eq!(out.len(), frames.len(), "{}: frame count", c["name"]);
        for (i, ((frame, seal), want)) in out.iter().zip(frames).enumerate() {
            assert_eq!(frame.index, want["index"].as_u64().unwrap(), "{} #{i}", c["name"]);
            assert_eq!(frame.total_fragments, Some(want["total_fragments"].as_u64().unwrap()));
            assert_eq!(frame.is_last, want["is_last"].as_bool().unwrap());
            assert_eq!(frame.payload, hx(want, "payload_hex"), "{} #{i} payload", c["name"]);
            assert_eq!(seal.0.to_vec(), hx(want, "seal_hex"), "{} #{i} seal", c["name"]);
            assert_eq!(derive_receipt(seal).0.to_vec(), hx(want, "receipt_hex"), "{} #{i} receipt", c["name"]);
        }
    }
}

#[test]
fn streaming_seal_chunk_gives_the_same_seals_as_seal_payload() {
    // The seal depends only on (key, fragment, state): where the payload was
    // cut must not change a single byte.
    let v = vectors();
    for c in v["chains"].as_array().unwrap() {
        let mut s = sealer(c);
        for want in c["frames"].as_array().unwrap() {
            let last = want["is_last"].as_bool().unwrap();
            let (_, seal) = s.seal_chunk(hx(want, "payload_hex"), last).expect("seal_chunk");
            assert_eq!(seal.0.to_vec(), hx(want, "seal_hex"), "{}", c["name"]);
        }
    }
}

fn tamper(name: &str, c: &Value, v: &Value, frame: &mut LacreFrame, seal: &mut Seal) {
    match name {
        "flip_payload_byte_0" => frame.payload[0] ^= 0x01,
        "seal_of_frame_1" => seal.0 = arr(&c["frames"][1], "seal_hex"),
        t if t.starts_with("seal_from_chain:") => {
            let mut p = t.split(':').skip(1);
            let cn = p.next().unwrap();
            let idx = p.next().unwrap().parse::<usize>().unwrap();
            seal.0 = arr(&chain(v, cn)["frames"][idx], "seal_hex");
        }
        other => panic!("unknown tamper {other}"),
    }
}

#[test]
fn the_verifier_reaches_the_verdicts_in_the_scenarios() {
    let v = vectors();
    for sc in v["scenarios"].as_array().unwrap() {
        let c = chain(&v, sc["chain"].as_str().unwrap());
        let slot = c["slot_size"].as_u64().unwrap() as usize;
        let mut ver = VerifierCore::resume(
            ring(c),
            SessionId(arr(c, "session_id_hex")),
            c["key_id"].as_u64().unwrap() as u8,
            algo_of(c),
            slot,
            4,
            Duration::from_secs(60),
        )
        .expect("resume");
        for (n, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let fv = &c["frames"][step["frame"].as_u64().unwrap() as usize];
            let mut frame = LacreFrame {
                session_id: SessionId(arr(c, "session_id_hex")),
                index: fv["index"].as_u64().unwrap(),
                total_fragments: Some(fv["total_fragments"].as_u64().unwrap()),
                is_last: fv["is_last"].as_bool().unwrap(),
                payload: hx(fv, "payload_hex"),
            };
            let mut seal = Seal(arr(fv, "seal_hex"));
            if let Some(t) = step["tamper"].as_str() {
                tamper(t, c, &v, &mut frame, &mut seal);
            }
            let key_id = step["key_id"].as_u64().unwrap_or(c["key_id"].as_u64().unwrap()) as u8;
            let got = ver.verify_frame(&frame, key_id, &seal, None);
            let want = step["expect"].as_str().unwrap();
            let ctx = format!("{} / paso {n}", sc["name"]);
            match (want, got) {
                ("ok", Ok(())) => {}
                ("SealMismatch", Err(CoreError::SealMismatch)) => {}
                ("UnknownKeyId", Err(CoreError::UnknownKeyId)) => {}
                (w, Err(CoreError::OutOfSequence { expected, received })) if w.starts_with("OutOfSequence:") => {
                    assert_eq!(w, format!("OutOfSequence:{expected}:{received}"), "{ctx}");
                }
                (w, g) => panic!("{ctx}: esperado {w}, obtenido {g:?}"),
            }
        }
    }
}

#[test]
fn vault_signatures_match_rfc8032_and_verify() {
    let v = vectors();
    let t = &v["vault"];
    let sk = VaultSigningKey::from_bytes(&arr(t, "seed_hex"));
    assert_eq!(sk.verifying_key().to_bytes(), arr::<32>(t, "public_key_hex"));
    let seal = Seal(arr(t, "signed_seal_hex"));
    let sig = sk.sign_seal(&seal);
    assert_eq!(sig.to_bytes().to_vec(), hx(t, "signature_hex"));
    assert!(sk
        .verifying_key()
        .verify_seal(&seal, &VaultSignature::from_bytes(&arr(t, "signature_hex"))));
    let mut other = seal;
    other.0[0] ^= 1;
    assert!(!sk.verifying_key().verify_seal(&other, &sig));
}

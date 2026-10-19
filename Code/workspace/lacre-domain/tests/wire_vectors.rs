//! Known-answer tests for the capability tokens of wire format v1
//! (spec/LACRE-WIRE-v1.md §Capabilities). Vectors come from the independent
//! generator `Tools/gen_vectors.py`.

use lacre_domain::capability::{CapabilityRoot, Scope};
use serde_json::Value;

const VECTORS: &str = include_str!("../../spec/vectors/wire-v1.json");

#[test]
fn capability_tokens_match_the_vectors() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let c = &v["capability"];
    let root: [u8; 32] = hex::decode(c["root_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let sid: [u8; 16] = hex::decode(c["session_id_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let r = CapabilityRoot::from_bytes(root);
    for (name, scope) in [("write", Scope::Write), ("verify", Scope::Verify), ("ack", Scope::Ack)] {
        let want = c[name].as_str().unwrap();
        assert_eq!(r.token_hex(scope, &sid), want, "scope {name}");
        assert!(r.check(scope, &sid, Some(want)));
    }
    // A token is valid for its scope only, and for its session only.
    let w = c["write"].as_str().unwrap();
    assert!(!r.check(Scope::Verify, &sid, Some(w)));
    assert!(!r.check(Scope::Write, &[8u8; 16], Some(w)));
    assert!(!r.check(Scope::Write, &sid, None));
}

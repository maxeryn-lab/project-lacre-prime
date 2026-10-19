//! Wire v2 over the real HTTP router with the real catalogue, plus the
//! concurrency behaviour with an algorithm that is slow or panics.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use lacre_core::suite::{CostClass, OutputKind, SealInput, SealMac, Status};
use lacre_domain::seal_policy::SealRegistry;
use lacre_server::compose::{build_registry, compose};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

fn router_with(registry: SealRegistry, env: &[(&str, &str)], files: &[(&str, &str)]) -> axum::Router {
    let env: HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let files: HashMap<String, String> = files.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let (state, _) = compose(
        lacre_adapter_http::build_default_state(),
        registry,
        &|k| env.get(k).cloned(),
        &|p| files.get(p).cloned().ok_or_else(|| "missing".to_string()),
    )
    .unwrap();
    lacre_adapter_http::build_router_with_state(state)
}

async fn post(router: &axum::Router, path: &str, body: Value) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, json, headers)
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn seal_body(profile: &str, payload: &[u8], suite: Value) -> Value {
    json!({"version":2,"profile":profile,"payload_hex":hex::encode(payload),"suite":suite})
}

fn verify_body(profile: &str, sealed: &Value, suite: Value) -> Value {
    json!({"version":2,"profile":profile,"session_id":sealed["session_id"],"key_id":0,
           "frames":sealed["frames"],"token":sealed["capabilities"]["verify"],"reassemble":true,"suite":suite})
}

#[tokio::test]
async fn the_six_standard_algorithms_roundtrip_over_http() {
    let router = router_with(build_registry(), &[("LACRE_SEAL_POLICY", "preset:standard")], &[]);
    let cases: Vec<(&str, Option<u32>)> = vec![
        ("hmac-sha256", None),
        ("hmac-sha512", None),
        ("hmac-sha3-512", None),
        ("blake2b-keyed", None),
        ("aes-cmac", None),
        ("blake3-keyed-xof", Some(16)),
        ("blake3-keyed-xof", Some(32)),
        ("blake3-keyed-xof", Some(64)),
    ];
    for (id, tag) in cases {
        let mut suite = json!({"seal": id});
        if let Some(t) = tag {
            suite["tag_len_bytes"] = json!(t);
        }
        for payload in [b"un fragmento".to_vec(), vec![7u8; 5000]] {
            let (st, sealed, _) = post(&router, "/v1/seal", seal_body("core", &payload, suite.clone())).await;
            assert_eq!(st, StatusCode::OK, "{id}: {sealed}");
            assert_eq!(sealed["version"], 2);
            assert_eq!(sealed["suite"]["seal"], id);
            let (st, v, _) = post(&router, "/v1/verify", verify_body("core", &sealed, suite.clone())).await;
            assert_eq!(st, StatusCode::OK, "{id}: {v}");
            assert_eq!(v["all_verified"], true, "{id}");
            assert_eq!(v["payload_hex"], hex::encode(&payload));
        }
    }
}

#[tokio::test]
async fn without_a_policy_v2_is_refused_and_v1_still_works() {
    let router = router_with(build_registry(), &[], &[]);
    let (st, _, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"hmac-sha256"}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, r, _) = post(&router, "/v1/seal", json!({"profile":"lite","payload_hex":"6162"})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(r["version"], 1);
}

#[tokio::test]
async fn sha1_is_compiled_or_not_but_never_allowed_by_the_preset() {
    let router = router_with(build_registry(), &[("LACRE_SEAL_POLICY", "preset:standard")], &[]);
    let (st, _, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"hmac-sha1"}))).await;
    // not compiled: unknown algorithm (400); compiled: not in the policy (403)
    if cfg!(feature = "legacy-seals") {
        assert_eq!(st, StatusCode::FORBIDDEN);
    } else {
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn discovery_is_off_unless_the_policy_turns_it_on() {
    let off = router_with(build_registry(), &[("LACRE_SEAL_POLICY", "preset:standard")], &[]);
    assert_eq!(get(&off, "/v1/seal-algorithms").await.0, StatusCode::NOT_FOUND);
    let policy = r#"{"wire_versions":[1,2],"max_session_memory_bytes":33554432,"expose_discovery":true,
        "algorithms":[{"id":"hmac-sha256","expect_status":"standard","profiles":["lite","core"],"max_cost":"light"}]}"#;
    let on = router_with(build_registry(), &[("LACRE_SEAL_POLICY", "p.json")], &[("p.json", policy)]);
    let (st, body) = get(&on, "/v1/seal-algorithms").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["algorithms"][0]["id"], "hmac-sha256");
    // nothing about load or quarantine
    assert!(!body.to_string().contains("quarantine"));
}

// ---- concurrency ----

struct Slow {
    millis: u64,
    panics: bool,
}
impl SealMac for Slow {
    fn id(&self) -> &'static str { if self.panics { "boom" } else { "slow" } }
    fn status(&self) -> Status { Status::Standard }
    fn cost(&self) -> CostClass { CostClass::Light }
    fn security_bits(&self) -> u16 { 128 }
    fn key_len(&self) -> usize { 32 }
    fn output(&self) -> OutputKind { OutputKind::Fixed(32) }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        if self.panics {
            panic!("secret internal detail");
        }
        std::thread::sleep(std::time::Duration::from_millis(self.millis));
        let mut acc = key.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        for part in input.parts() {
            for b in part {
                acc = acc.wrapping_mul(31).wrapping_add(*b);
            }
        }
        out.fill(acc);
    }
}

const SLOW_POLICY: &str = r#"{"wire_versions":[1,2],"max_session_memory_bytes":33554432,"quarantine_after_panics":2,
  "algorithms":[
   {"id":"slow","expect_status":"standard","profiles":["lite"],"max_cost":"light"},
   {"id":"boom","expect_status":"standard","profiles":["lite"],"max_cost":"light"}]}"#;

fn slow_registry(millis: u64) -> SealRegistry {
    SealRegistry::new(vec![
        Arc::new(Slow { millis, panics: false }) as Arc<dyn SealMac>,
        Arc::new(Slow { millis, panics: true }),
    ])
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_sessions_do_not_serialize_each_other() {
    let router = router_with(slow_registry(300), &[("LACRE_SEAL_POLICY", "p.json")], &[("p.json", SLOW_POLICY)]);
    let start = std::time::Instant::now();
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let r = router.clone();
            tokio::spawn(async move { post(&r, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await.0 })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    // 8 x 300 ms in series would be 2.4 s
    assert!(start.elapsed() < std::time::Duration::from_millis(1500), "took {:?}", start.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_admission_gate_answers_503_with_retry_after_and_recovers() {
    let router = router_with(
        slow_registry(400),
        &[("LACRE_SEAL_POLICY", "p.json"), ("LACRE_MAX_INFLIGHT", "2")],
        &[("p.json", SLOW_POLICY)],
    );
    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let r = router.clone();
            tokio::spawn(async move { post(&r, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await })
        })
        .collect();
    let mut ok = 0;
    let mut busy = 0;
    for t in tasks {
        let (st, _, headers) = t.await.unwrap();
        match st {
            StatusCode::OK => ok += 1,
            StatusCode::SERVICE_UNAVAILABLE => {
                assert_eq!(headers.get("retry-after").unwrap(), "1");
                busy += 1;
            }
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(ok + busy, 6);
    assert!(ok >= 2 && busy >= 1, "ok={ok} busy={busy}");
    // places were released
    let (st, _, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_algorithm_is_500_without_internals_then_quarantined() {
    let router = router_with(slow_registry(1), &[("LACRE_SEAL_POLICY", "p.json")], &[("p.json", SLOW_POLICY)]);
    for _ in 0..2 {
        let (st, body, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"boom"}))).await;
        assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.to_string().contains("secret"));
    }
    let (st, _, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"boom"}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "quarantined after 2 panics");
    let (st, _, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await;
    assert_eq!(st, StatusCode::OK, "other algorithms keep working");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_configured_deadline_answers_504_and_none_means_no_504() {
    let with = router_with(
        slow_registry(500),
        &[("LACRE_SEAL_POLICY", "p.json"), ("LACRE_REQUEST_DEADLINE_MS", "100")],
        &[("p.json", SLOW_POLICY)],
    );
    let (st, _, _) = post(&with, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await;
    assert_eq!(st, StatusCode::GATEWAY_TIMEOUT);
    let without = router_with(slow_registry(300), &[("LACRE_SEAL_POLICY", "p.json")], &[("p.json", SLOW_POLICY)]);
    let (st, _, _) = post(&without, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_place_is_held_for_the_whole_computation_not_only_until_it_starts() {
    let router = router_with(
        slow_registry(600),
        &[("LACRE_SEAL_POLICY", "p.json"), ("LACRE_MAX_INFLIGHT", "2")],
        &[("p.json", SLOW_POLICY)],
    );
    let running: Vec<_> = (0..2)
        .map(|_| {
            let r = router.clone();
            tokio::spawn(async move { post(&r, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await.0 })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await; // both are inside the algorithm now
    let (st, _, headers) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "two places are still running work");
    assert_eq!(headers.get("retry-after").unwrap(), "1");
    for t in running {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    let (st, _, _) = post(&router, "/v1/seal", seal_body("lite", b"x", json!({"seal":"slow"}))).await;
    assert_eq!(st, StatusCode::OK, "released once the computation ended");
}

// ---------------------------------------------------------------- vault v2 (E5)

const VAULT_POLICY: &str = r#"{"wire_versions":[1,2],"max_session_memory_bytes":33554432,
  "algorithms":[
   {"id":"hmac-sha256","expect_status":"standard","profiles":["lite","core","vault"],"max_cost":"light"}],
  "signatures":[{"id":"ed25519","expect_status":"standard"}]}"#;

fn vault_router() -> axum::Router {
    router_with(build_registry(), &[("LACRE_SEAL_POLICY", "p.json")], &[("p.json", VAULT_POLICY)])
}

fn vault_suite() -> Value {
    json!({"seal":"hmac-sha256","signature":"ed25519"})
}

async fn post_auth(router: &axum::Router, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn vault_v2_signs_every_frame_and_verification_requires_the_signature() {
    let router = vault_router();
    let payload = vec![9u8; 600_000]; // several fragments
    let (st, sealed, _) = post(&router, "/v1/seal", seal_body("vault", &payload, vault_suite())).await;
    assert_eq!(st, StatusCode::OK, "{sealed}");
    let frames = sealed["frames"].as_array().unwrap();
    assert!(frames.len() > 1);
    for f in frames {
        assert_eq!(f["signature"]["scheme"], "ed25519");
        assert_eq!(f["signature"]["sig_hex"].as_str().unwrap().len(), 128);
        assert!(f.get("vault_signature_hex").is_none_or(|v| v.is_null()));
    }

    // A signature of another frame, and a missing one, are refused without advancing.
    let mut swapped = sealed.clone();
    let sig1 = frames[1]["signature"].clone();
    swapped["frames"][0]["signature"] = sig1;
    let (st, v, _) = post(&router, "/v1/verify", verify_body("vault", &swapped, vault_suite())).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["all_verified"], false, "{v}");

    let mut unsigned = sealed.clone();
    unsigned["frames"][0]["signature"] = Value::Null;
    let (_, v, _) = post(&router, "/v1/verify", verify_body("vault", &unsigned, vault_suite())).await;
    assert_eq!(v["all_verified"], false, "{v}");

    // The honest frames still verify afterwards: the refusals left the state untouched.
    let (st, v, _) = post(&router, "/v1/verify", verify_body("vault", &sealed, vault_suite())).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["all_verified"], true, "{v}");
    assert_eq!(v["payload_hex"], hex::encode(&payload));
}

#[tokio::test]
async fn vault_v2_ack_records_v2_receipts_for_this_session_only() {
    let router = vault_router();
    let (_, sealed, _) = post(&router, "/v1/seal", seal_body("vault", b"auditable", vault_suite())).await;
    let sid = sealed["session_id"].clone();
    let idx = sealed["frames"][0]["index"].clone();
    let (st, ack) = post_auth(
        &router,
        "/v1/ack",
        sealed["capabilities"]["ack"].as_str().unwrap(),
        json!({"session_id": sid, "indices": [idx]}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{ack}");
    assert_eq!(ack["all_acknowledged"], true);
    assert_eq!(ack["total_receipts"], 1);
    let (st, r, _) = post(&router, "/v1/receipts", json!({"session_id": sid, "token": sealed["capabilities"]["write"]})).await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(r["entries"][0]["receipt_hex"].as_str().unwrap().len(), 64);

    // A non-vault v2 session keeps nothing for ack: there is no receipt to give.
    let (_, core, _) = post(&router, "/v1/seal", seal_body("core", b"x", json!({"seal":"hmac-sha256"}))).await;
    let ack = core["capabilities"].get("ack").and_then(Value::as_str).unwrap_or("");
    let (st, _) = post_auth(&router, "/v1/ack", ack, json!({"session_id": core["session_id"], "indices": [0]})).await;
    assert_ne!(st, StatusCode::OK, "a non-signing v2 session has nothing to acknowledge");
}

#[tokio::test]
async fn the_vault_signature_rules_are_explicit_over_http() {
    let router = vault_router();
    // vault without a scheme, a scheme outside vault, an unknown scheme: 400
    for (profile, suite) in [
        ("vault", json!({"seal":"hmac-sha256"})),
        ("core", vault_suite()),
        ("vault", json!({"seal":"hmac-sha256","signature":"nope"})),
    ] {
        let (st, body, _) = post(&router, "/v1/seal", seal_body(profile, b"x", suite.clone())).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{profile} {suite}: {body}");
    }
    // a frame must not mix the v1 field into v2
    let (_, sealed, _) = post(&router, "/v1/seal", seal_body("vault", b"x", vault_suite())).await;
    let mut mixed = sealed.clone();
    mixed["frames"][0]["vault_signature_hex"] = json!("00".repeat(64));
    let (_, v, _) = post(&router, "/v1/verify", verify_body("vault", &mixed, vault_suite())).await;
    assert_eq!(v["all_verified"], false, "{v}");
    // a signature under another scheme's name is refused by name
    let mut renamed = sealed.clone();
    renamed["frames"][0]["signature"]["scheme"] = json!("other");
    let (_, v, _) = post(&router, "/v1/verify", verify_body("vault", &renamed, vault_suite())).await;
    assert_eq!(v["all_verified"], false, "{v}");
}

#[tokio::test]
async fn a_policy_that_allows_vault_without_a_scheme_does_not_load_and_v1_vault_is_unchanged() {
    let no_sig = VAULT_POLICY.replace(r#""signatures":[{"id":"ed25519","expect_status":"standard"}]"#, r#""signatures":[]"#);
    assert_ne!(no_sig, VAULT_POLICY);
    let env: HashMap<String, String> = [("LACRE_SEAL_POLICY".to_string(), "p.json".to_string())].into();
    let files: HashMap<String, String> = [("p.json".to_string(), no_sig)].into();
    let r = compose(
        lacre_adapter_http::build_default_state(),
        build_registry(),
        &|k| env.get(k).cloned(),
        &|p| files.get(p).cloned().ok_or_else(|| "missing".to_string()),
    );
    assert!(r.is_err());

    // Wire v1 under the vault profile, on a node that also speaks v2.
    let router = vault_router();
    let (st, sealed, _) = post(&router, "/v1/seal", json!({"profile":"vault","payload_hex":hex::encode(b"v1")})).await;
    assert_eq!(st, StatusCode::OK, "{sealed}");
    assert!(sealed["frames"][0]["vault_signature_hex"].is_string());
    assert!(sealed["frames"][0].get("signature").is_none());
    let body = json!({"profile":"vault","session_id":sealed["session_id"],"key_id":0,"frames":sealed["frames"],
                      "token":sealed["capabilities"]["verify"],"reassemble":true});
    let (st, v, _) = post(&router, "/v1/verify", body).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["all_verified"], true, "{v}");
}

// ---------------------------------------------------------------- parts

#[tokio::test]
async fn parts_under_wire_v2_verify_for_every_standard_algorithm_and_for_vault() {
    let standard = router_with(build_registry(), &[("LACRE_SEAL_POLICY", "preset:standard")], &[]);
    let signed = vault_router();
    let cases: Vec<(&axum::Router, &str, Value)> = vec![
        (&standard, "core", json!({"seal":"hmac-sha256"})),
        (&standard, "core", json!({"seal":"blake3-keyed-xof","tag_len_bytes":32})),
        (&standard, "lite", json!({"seal":"aes-cmac"})),
        (&signed, "vault", vault_suite()),
    ];
    for (router, profile, suite) in cases {
        let original: Vec<u8> = (0..7000u32).map(|i| (i % 253) as u8).collect();
        let (st, open, _) = post(router, "/v1/seal/open", json!({"version":2,"profile":profile,"suite":suite})).await;
        assert_eq!(st, StatusCode::OK, "{suite}: {open}");
        assert_eq!(open["version"], 2);
        assert_eq!(open["suite"]["seal"], suite["seal"]);
        let wt = open["capabilities"]["write"].clone();
        let mut frames: Vec<Value> = vec![];
        let pieces: Vec<&[u8]> = original.chunks(2500).collect();
        for (i, piece) in pieces.iter().enumerate() {
            let body = json!({"session_id":open["session_id"],"token":wt,"part_index":i,"payload_hex":hex::encode(piece),"is_last":i + 1 == pieces.len()});
            let (st, part, _) = post(router, "/v1/seal/part", body.clone()).await;
            assert_eq!(st, StatusCode::OK, "{suite} part {i}: {part}");
            // a retry of the same part is the same answer
            let (_, again, _) = post(router, "/v1/seal/part", body).await;
            assert_eq!(part["frames"], again["frames"], "{suite} part {i}");
            frames.extend(part["frames"].as_array().unwrap().iter().cloned());
        }
        if profile == "vault" {
            assert!(frames.iter().all(|f| f["signature"]["scheme"] == "ed25519"), "every frame of a part is signed");
        }
        let sealed = json!({"session_id":open["session_id"],"frames":frames,"capabilities":{"verify":open["capabilities"]["verify"]}});
        let (st, v, _) = post(router, "/v1/verify", verify_body(profile, &sealed, suite.clone())).await;
        assert_eq!(st, StatusCode::OK, "{suite}: {v}");
        assert_eq!(v["all_verified"], true, "{suite}: {v}");
        assert_eq!(v["payload_hex"], hex::encode(&original), "{suite}");
    }
}

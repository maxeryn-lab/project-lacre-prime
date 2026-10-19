//! Composition of wire v2 for the node: registry (from the catalogue compiled
//! into this binary), explicit policy, optional admission and deadline.
//!
//! Nothing here has a default value that limits or enables anything: without
//! `LACRE_SEAL_POLICY` the node speaks wire v1 only, and a limit that was not
//! configured does not exist (the startup log says so).

use lacre_domain::admission::AdmissionGate;
use lacre_domain::app_state::AppState;
use lacre_domain::seal_policy::{SealRegistry, SealRuntime};
use std::sync::Arc;
use std::time::Duration;

/// Reads the environment through `get`, so it can be tested without touching
/// the process environment. Returns the state plus the lines for the startup log.
pub fn compose(
    state: AppState,
    registry: SealRegistry,
    get: &dyn Fn(&str) -> Option<String>,
    read_file: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(AppState, Vec<String>), String> {
    let mut state = state;
    let mut log = Vec::new();

    match get("LACRE_SEAL_POLICY") {
        None => log.push("wire v2: disabled (no LACRE_SEAL_POLICY): this node speaks version 1 only".to_string()),
        Some(spec) => {
            let runtime = if spec == "preset:standard" {
                SealRuntime::preset_standard(registry).map_err(|e| format!("LACRE_SEAL_POLICY: {e}"))?
            } else {
                let json = read_file(&spec).map_err(|e| format!("LACRE_SEAL_POLICY: cannot read `{spec}`: {e}"))?;
                SealRuntime::from_json(registry, &json).map_err(|e| format!("LACRE_SEAL_POLICY `{spec}`: {e}"))?
            };
            log.push(format!(
                "wire v2: policy `{spec}`, wire versions {:?}, session memory ceiling {} bytes, discovery {}, on quarantine: {:?}",
                runtime.wire_versions(),
                runtime.max_session_memory_bytes(),
                if runtime.expose_discovery() { "on" } else { "off" },
                runtime.on_quarantine(),
            ));
            state = state.with_seal_runtime(Arc::new(runtime));
        }
    }

    let max_inflight = positive(get, "LACRE_MAX_INFLIGHT")?;
    let max_heavy = positive(get, "LACRE_MAX_HEAVY")?;
    if max_inflight.is_some() || max_heavy.is_some() {
        log.push(format!(
            "admission: running operations {}, heavy operations {}",
            max_inflight.map_or("no limit configured".to_string(), |n| n.to_string()),
            max_heavy.map_or("no limit configured".to_string(), |n| n.to_string()),
        ));
        state = state.with_admission(AdmissionGate::new(max_inflight, max_heavy));
    } else {
        log.push("admission: no limit configured (operations are not limited by this node)".to_string());
    }

    match positive(get, "LACRE_REQUEST_DEADLINE_MS")? {
        Some(ms) => {
            log.push(format!("request deadline: {ms} ms"));
            state = state.with_request_deadline(Duration::from_millis(ms as u64));
        }
        None => log.push("request deadline: none configured".to_string()),
    }
    match positive(get, "LACRE_MAX_BODY_BYTES")? {
        Some(n) => {
            log.push(format!("request body limit: {n} bytes (configured)"));
            state = state.with_max_body_bytes(n);
        }
        None => log.push(format!(
            "request body limit: {} bytes (default; set LACRE_MAX_BODY_BYTES to change it)",
            state.max_body_bytes()
        )),
    }
    match positive(get, "LACRE_WS_PING_SECS")? {
        Some(n) => {
            log.push(format!("websocket ping: every {n} s (configured)"));
            state = state.with_ws_ping_interval(Duration::from_secs(n as u64));
        }
        None => log.push(format!(
            "websocket ping: every {} s (default; set LACRE_WS_PING_SECS to change it)",
            state.ws_ping_interval().as_secs()
        )),
    }
    Ok((state, log))
}

/// A variable that, if present, must be a positive integer. A bad value stops
/// the node: configuration is attack surface, so it is never silently ignored.
fn positive(get: &dyn Fn(&str) -> Option<String>, var: &str) -> Result<Option<usize>, String> {
    match get(var) {
        None => Ok(None),
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => Ok(Some(n)),
            _ => Err(format!("{var} must be a positive integer, got `{raw}`")),
        },
    }
}

/// The registry of this build: every algorithm and signature scheme compiled into `lacre-seals`.
pub fn build_registry() -> SealRegistry {
    SealRegistry::new(lacre_seals::all())
        .and_then(|r| r.with_signatures(lacre_seals::signatures()))
        .expect("the catalogue has unique ids")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn state() -> AppState {
        lacre_adapter_http::build_default_state()
    }
    fn run(env: &[(&str, &str)], files: &[(&str, &str)]) -> Result<(AppState, Vec<String>), String> {
        let env: HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let files: HashMap<String, String> = files.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        compose(
            state(),
            build_registry(),
            &|k| env.get(k).cloned(),
            &|p| files.get(p).cloned().ok_or_else(|| "no such file".to_string()),
        )
    }

    #[test]
    fn with_nothing_configured_v2_is_off_and_nothing_is_limited() {
        let (st, log) = run(&[], &[]).unwrap();
        assert!(st.seal_runtime().is_none() && st.admission().is_none() && st.request_deadline().is_none());
        assert!(log.iter().any(|l| l.contains("disabled")));
        assert!(log.iter().any(|l| l.contains("no limit configured")));
    }

    #[test]
    fn the_standard_preset_is_an_explicit_choice() {
        let (st, _) = run(&[("LACRE_SEAL_POLICY", "preset:standard")], &[]).unwrap();
        assert!(st.seal_runtime().is_some());
    }

    #[test]
    fn a_bad_policy_or_bad_numbers_stop_the_node() {
        assert!(run(&[("LACRE_SEAL_POLICY", "/no/such")], &[]).is_err());
        assert!(run(&[("LACRE_SEAL_POLICY", "p.json")], &[("p.json", "{not json")]).is_err());
        assert!(run(&[("LACRE_MAX_INFLIGHT", "0")], &[]).is_err());
        assert!(run(&[("LACRE_MAX_HEAVY", "x")], &[]).is_err());
        assert!(run(&[("LACRE_REQUEST_DEADLINE_MS", "-5")], &[]).is_err());
        assert!(run(&[("LACRE_MAX_BODY_BYTES", "0")], &[]).is_err());
        assert!(run(&[("LACRE_MAX_BODY_BYTES", "2m")], &[]).is_err());
        assert!(run(&[("LACRE_WS_PING_SECS", "0")], &[]).is_err());
        assert!(run(&[("LACRE_WS_PING_SECS", "fast")], &[]).is_err());
    }

    #[test]
    fn the_websocket_ping_is_explicit_in_both_cases() {
        let (st, log) = run(&[], &[]).unwrap();
        assert_eq!(st.ws_ping_interval(), Duration::from_secs(25));
        assert!(log.iter().any(|l| l.contains("websocket ping: every 25 s (default")));
        let (st, log) = run(&[("LACRE_WS_PING_SECS", "1")], &[]).unwrap();
        assert_eq!(st.ws_ping_interval(), Duration::from_secs(1));
        assert!(log.iter().any(|l| l.contains("websocket ping: every 1 s (configured)")));
    }

    #[test]
    fn the_body_limit_is_explicit_in_both_cases() {
        let (st, log) = run(&[], &[]).unwrap();
        assert_eq!(st.max_body_bytes(), 2_097_152);
        assert!(log.iter().any(|l| l.contains("request body limit: 2097152 bytes (default")));
        let (st, log) = run(&[("LACRE_MAX_BODY_BYTES", "4096")], &[]).unwrap();
        assert_eq!(st.max_body_bytes(), 4096);
        assert!(log.iter().any(|l| l.contains("request body limit: 4096 bytes (configured)")));
    }

    #[test]
    fn limits_exist_only_when_configured() {
        let (st, _) = run(&[("LACRE_MAX_INFLIGHT", "4"), ("LACRE_REQUEST_DEADLINE_MS", "250")], &[]).unwrap();
        assert!(st.admission().is_some());
        assert_eq!(st.request_deadline(), Some(Duration::from_millis(250)));
    }

    #[test]
    fn without_the_feature_sha1_is_not_even_in_the_registry() {
        #[cfg(not(feature = "legacy-seals"))]
        assert!(build_registry().get("hmac-sha1").is_none());
    }
}

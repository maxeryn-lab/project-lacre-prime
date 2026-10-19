//! Wire v2 on the server: seal registry, operator policy, algorithm
//! quarantine (see spec/LACRE-WIRE-v2.md).
//!
//! # Compiled is not authorized
//!
//! The registry holds what the binary CONTAINS. The policy says what the
//! operator ALLOWS. A seal algorithm is usable only if it is in both, and
//! each entry of the policy says what it expects: if the catalogue's status
//! of an algorithm differs from the status the operator wrote, the policy
//! does not load (it guards against silent drift).
//!
//! # The policy is configuration, and configuration is attack surface
//!
//! (Annex 5.0, 2.5 and 3.5.) It is validated when loaded and rejected on
//! any inconsistency; a policy never loads with a warning. Required limits
//! have no default value. Without an explicit policy the node speaks
//! wire v1 only. The registry is a composition: `lacre-domain` does not
//! depend on any catalogue crate, so the binary that assembles the node
//! decides which algorithms exist.
//!
//! # What this module does not do
//!
//! It does not cancel a running algorithm and it does not promise
//! availability. The Core is synchronous. Admission and concurrency limits
//! are the operator's (see `admission.rs`), and richer admission is a
//! Profile (Annex 15, vector 1).

use crate::domain::DomainError;
use crate::profile_config::ProfileName;
use crate::wire::SuiteWire;
use lacre_core::suite::{
    check_memory_budget, xof_params, CostClass, OutputKind, SealMac, SignatureScheme, Status, SuiteDescriptor,
    SuiteError, ValidatedSuite, MAX_TAG_LEN,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

/// Wire versions this binary knows. The policy selects among them.
pub const KNOWN_WIRE_VERSIONS: &[u32] = &[1, 2];

/// Profiles that can speak wire v2. `vault` needs a signature scheme, so the
/// policy may allow it only if it also lists at least one (E5).
const V2_PROFILES: &[&str] = &["lite", "core", "vault"];

/// Why a policy was refused when loading. The text names the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "seal policy refused: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

fn refuse<T>(msg: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError(msg.into()))
}

/// The algorithms the binary contains, by id. Ids are unique.
pub struct SealRegistry {
    by_id: HashMap<&'static str, Arc<dyn SealMac>>,
    signatures: HashMap<&'static str, Arc<dyn SignatureScheme>>,
}

impl SealRegistry {
    pub fn new(algorithms: Vec<Arc<dyn SealMac>>) -> Result<Self, PolicyError> {
        let mut by_id = HashMap::new();
        for a in algorithms {
            let id = a.id();
            if by_id.insert(id, a).is_some() {
                return refuse(format!("registry contains the id `{id}` twice"));
            }
        }
        Ok(SealRegistry { by_id, signatures: HashMap::new() })
    }

    /// Adds the signature schemes the binary contains (E5). Ids are unique.
    pub fn with_signatures(mut self, schemes: Vec<Arc<dyn SignatureScheme>>) -> Result<Self, PolicyError> {
        for sc in schemes {
            let id = sc.id();
            if self.signatures.insert(id, sc).is_some() {
                return refuse(format!("registry contains the signature scheme `{id}` twice"));
            }
        }
        Ok(self)
    }

    pub fn get_signature(&self, id: &str) -> Option<&Arc<dyn SignatureScheme>> {
        self.signatures.get(id)
    }

    pub fn signature_ids(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.signatures.keys().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn SealMac>> {
        self.by_id.get(id)
    }

    pub fn ids(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.by_id.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

fn yes() -> bool {
    true
}

/// What the operator says to do when an algorithm goes into quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnQuarantine {
    /// Sessions that use the algorithm are closed for good. The default:
    /// if draining is not justified, the session is closed (Annex 13, 10.4).
    #[default]
    Close,
    /// Sessions already open may finish (until their idle TTL); no new
    /// session may start with the algorithm.
    Drain,
}

/// Tag length range, in BYTES.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRange {
    pub min: usize,
    pub max: usize,
}

/// One allowed algorithm. Every field is required except `tag_len_bytes`,
/// which is required for XOF algorithms and forbidden for fixed-length ones.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmEntry {
    pub id: String,
    /// `standard`, `experimental` or `legacy`: the status the operator
    /// expects. A different catalogue status means the policy does not load.
    pub expect_status: String,
    pub profiles: Vec<String>,
    #[serde(default)]
    pub tag_len_bytes: Option<TagRange>,
    /// `light`, `standard` or `heavy`: the most expensive class admitted.
    pub max_cost: String,
}

/// One allowed signature scheme (vault profile).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub id: String,
    /// The status the operator expects; a different catalogue status means
    /// the policy does not load.
    pub expect_status: String,
}

/// The policy file, as written by the operator.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Wire versions this node accepts. Required.
    pub wire_versions: Vec<u32>,
    /// Whether an absent `version` means v1. Kept `true` by default because
    /// frozen v1 clients omit it; `false` demands an explicit version.
    #[serde(default = "yes")]
    pub allow_implicit_version: bool,
    /// Third of the three switches that unlock a legacy algorithm.
    #[serde(default)]
    pub allow_legacy: bool,
    /// Serve the algorithm listing (`GET /v1/seal-algorithms`). Off by default:
    /// the listing fingerprints the deployment.
    #[serde(default)]
    pub expose_discovery: bool,
    /// Memory one session may need, in BYTES: `slot_count x (slot_size + tag_len)`
    /// must fit. Required; a deployment property, not a protocol one.
    pub max_session_memory_bytes: usize,
    /// Panics of one algorithm before it goes into quarantine. Absent means
    /// no automatic quarantine.
    #[serde(default)]
    pub quarantine_after_panics: Option<u32>,
    #[serde(default)]
    pub on_quarantine: OnQuarantine,
    /// Ids the operator orders into quarantine from the first request. Each
    /// must be an algorithm the policy lists. Leaving quarantine means
    /// restarting with a policy that no longer names it here.
    #[serde(default)]
    pub quarantined_at_start: Vec<String>,
    pub algorithms: Vec<AlgorithmEntry>,
    /// Signature schemes the operator allows. Absent means none: the `vault`
    /// profile is then not available under wire v2.
    #[serde(default)]
    pub signatures: Vec<SignatureEntry>,
}

fn cost_rank(c: CostClass) -> u8 {
    match c {
        CostClass::Light => 0,
        CostClass::Standard => 1,
        CostClass::Heavy => 2,
    }
}

fn parse_cost(s: &str) -> Option<u8> {
    match s {
        "light" => Some(0),
        "standard" => Some(1),
        "heavy" => Some(2),
        _ => None,
    }
}

struct Entry {
    mac: Arc<dyn SealMac>,
    profiles: Vec<ProfileName>,
    tag_range: Option<(usize, usize)>,
    max_cost: u8,
}

struct Policy {
    wire_versions: Vec<u32>,
    allow_implicit_version: bool,
    allow_legacy: bool,
    expose_discovery: bool,
    max_session_memory_bytes: usize,
    quarantine_after_panics: Option<u32>,
    on_quarantine: OnQuarantine,
    entries: HashMap<String, Entry>,
    signatures: HashMap<String, Arc<dyn SignatureScheme>>,
}

#[derive(Default)]
struct Quarantine {
    panics: HashMap<String, u32>,
    quarantined: HashSet<String>,
}

/// Registry + validated policy + quarantine state. Shared by every request.
pub struct SealRuntime {
    registry: SealRegistry,
    policy: Policy,
    quarantine: Mutex<Quarantine>,
    /// Where policy and quarantine events go (the server log by default).
    /// Events never carry payloads, keys or session ids (A3).
    events: Box<dyn Fn(&str) + Send + Sync>,
}

impl std::fmt::Debug for SealRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealRuntime")
            .field("wire_versions", &self.policy.wire_versions)
            .field("algorithms", &self.policy.entries.len())
            .finish()
    }
}

/// A suite that passed every check of steps 3 to 5 of the validation order.
pub struct ResolvedSuite {
    pub suite: ValidatedSuite,
    pub cost: CostClass,
}

impl SealRuntime {
    /// Validates `file` against `registry`. Every inconsistency is a refusal.
    pub fn new(registry: SealRegistry, file: PolicyFile) -> Result<Self, PolicyError> {
        if file.wire_versions.is_empty() {
            return refuse("`wire_versions` is empty: the node would accept nothing");
        }
        let mut seen_versions = HashSet::new();
        for v in &file.wire_versions {
            if !KNOWN_WIRE_VERSIONS.contains(v) {
                return refuse(format!("wire version {v} is not known to this binary (known: {KNOWN_WIRE_VERSIONS:?})"));
            }
            if !seen_versions.insert(*v) {
                return refuse(format!("wire version {v} appears twice"));
            }
        }
        if file.max_session_memory_bytes == 0 {
            return refuse("`max_session_memory_bytes` must be greater than zero");
        }
        if file.quarantine_after_panics == Some(0) {
            return refuse("`quarantine_after_panics` of 0 would quarantine every algorithm at the start");
        }
        let v2_enabled = file.wire_versions.contains(&2);
        if v2_enabled && file.algorithms.is_empty() {
            return refuse("wire version 2 is enabled but no algorithm is allowed");
        }

        let mut signatures: HashMap<String, Arc<dyn SignatureScheme>> = HashMap::new();
        for sg in &file.signatures {
            let id = sg.id.as_str();
            if signatures.contains_key(id) {
                return refuse(format!("signature scheme `{id}` appears twice"));
            }
            let Some(scheme) = registry.get_signature(id) else {
                return refuse(format!("signature scheme `{id}` is not in this binary's registry"));
            };
            let real = scheme.status().name();
            if sg.expect_status != real {
                return refuse(format!(
                    "signature scheme `{id}`: the policy expects status `{}` but the catalogue says `{real}`",
                    sg.expect_status
                ));
            }
            if scheme.status() == Status::Legacy && !file.allow_legacy {
                return refuse(format!("signature scheme `{id}` is legacy and `allow_legacy` is not true"));
            }
            signatures.insert(sg.id.clone(), scheme.clone());
        }

        let mut entries = HashMap::new();
        for a in &file.algorithms {
            let id = a.id.as_str();
            if entries.contains_key(id) {
                return refuse(format!("algorithm `{id}` appears twice"));
            }
            let Some(mac) = registry.get(id) else {
                return refuse(format!("algorithm `{id}` is not in this binary's registry"));
            };
            let real = mac.status().name();
            if a.expect_status != real {
                return refuse(format!(
                    "algorithm `{id}`: the policy expects status `{}` but the catalogue says `{real}`",
                    a.expect_status
                ));
            }
            if mac.status() == Status::Legacy && !file.allow_legacy {
                return refuse(format!("algorithm `{id}` is legacy and `allow_legacy` is not true"));
            }
            let Some(max_cost) = parse_cost(&a.max_cost) else {
                return refuse(format!("algorithm `{id}`: `max_cost` must be light, standard or heavy"));
            };
            if cost_rank(mac.cost()) > max_cost {
                return refuse(format!("algorithm `{id}` costs more than the `max_cost` allowed for it: it could never run"));
            }
            if a.profiles.is_empty() {
                return refuse(format!("algorithm `{id}`: `profiles` is empty"));
            }
            let mut profiles = Vec::new();
            for p in &a.profiles {
                if !V2_PROFILES.contains(&p.as_str()) {
                    return refuse(format!("algorithm `{id}`: profile `{p}` cannot speak wire v2 in this version"));
                }
                if p == "vault" && signatures.is_empty() {
                    return refuse(format!(
                        "algorithm `{id}`: profile `vault` needs a signature scheme and the policy lists none in `signatures`"
                    ));
                }
                let name = ProfileName::from_header_value(p).expect("V2_PROFILES are real profile names");
                if profiles.contains(&name) {
                    return refuse(format!("algorithm `{id}`: profile `{p}` appears twice"));
                }
                profiles.push(name);
            }
            let tag_range = match (mac.output(), a.tag_len_bytes) {
                (OutputKind::Fixed(_), Some(_)) => {
                    return refuse(format!("algorithm `{id}` has a fixed tag length: `tag_len_bytes` is not allowed"));
                }
                (OutputKind::Fixed(_), None) => None,
                (OutputKind::Xof { .. }, None) => {
                    return refuse(format!("algorithm `{id}` is XOF: `tag_len_bytes` {{min,max}} is required"));
                }
                (OutputKind::Xof { min: lo, max: hi }, Some(r)) => {
                    if r.min == 0 || r.min > r.max || r.max > MAX_TAG_LEN || r.min < lo || r.max > hi {
                        return refuse(format!(
                            "algorithm `{id}`: `tag_len_bytes` {}..={} is outside what the algorithm produces ({lo}..={hi} bytes) or the Core ceiling ({MAX_TAG_LEN})",
                            r.min, r.max
                        ));
                    }
                    Some((r.min, r.max))
                }
            };
            entries.insert(a.id.clone(), Entry { mac: mac.clone(), profiles, tag_range, max_cost });
        }

        for id in &file.quarantined_at_start {
            if !entries.contains_key(id) {
                return refuse(format!("`quarantined_at_start` names `{id}`, which the policy does not list"));
            }
        }
        let quarantine = Quarantine { panics: HashMap::new(), quarantined: file.quarantined_at_start.iter().cloned().collect() };

        let at_start: Vec<String> = file.quarantined_at_start.clone();
        let rt = SealRuntime {
            registry,
            policy: Policy {
                wire_versions: file.wire_versions,
                allow_implicit_version: file.allow_implicit_version,
                allow_legacy: file.allow_legacy,
                expose_discovery: file.expose_discovery,
                max_session_memory_bytes: file.max_session_memory_bytes,
                quarantine_after_panics: file.quarantine_after_panics,
                on_quarantine: file.on_quarantine,
                entries,
                signatures,
            },
            quarantine: Mutex::new(quarantine),
            events: Box::new(|line| eprintln!("{line}")),
        };
        for id in at_start {
            rt.emit(format!("seal policy: algorithm `{id}` is in quarantine by operator order since startup"));
        }
        Ok(rt)
    }

    /// Replaces the destination of policy and quarantine events.
    pub fn with_event_sink(mut self, sink: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.events = Box::new(sink);
        self
    }

    fn emit(&self, line: String) {
        (self.events)(&line);
    }

    pub fn from_json(registry: SealRegistry, json: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile =
            serde_json::from_str(json).map_err(|e| PolicyError(format!("the policy file does not parse: {e}")))?;
        Self::new(registry, file)
    }

    /// The `standard` preset: an explicit choice by the operator, never a
    /// silent default. It allows the standard algorithms of the registry on
    /// profiles `lite` and `core`; XOF tags from 16 to 64 bytes; at most
    /// 32 MiB per session. Experimental and legacy algorithms are not in it.
    pub fn preset_standard(registry: SealRegistry) -> Result<Self, PolicyError> {
        let mut algorithms = Vec::new();
        for id in registry.ids() {
            let mac = registry.get(id).expect("id came from the registry");
            // The preset admits up to `standard` cost: a heavy algorithm would
            // make its own entry impossible to run, so it is not in the preset.
            if mac.status() != Status::Standard || cost_rank(mac.cost()) > 1 {
                continue;
            }
            let tag_len_bytes = match mac.output() {
                OutputKind::Fixed(_) => None,
                OutputKind::Xof { min, max } => Some(TagRange { min: min.max(16), max: max.min(64) }),
            };
            algorithms.push(AlgorithmEntry {
                id: id.to_string(),
                expect_status: "standard".to_string(),
                profiles: vec!["lite".to_string(), "core".to_string()],
                tag_len_bytes,
                max_cost: "standard".to_string(),
            });
        }
        Self::new(
            registry,
            PolicyFile {
                wire_versions: vec![1, 2],
                allow_implicit_version: true,
                allow_legacy: false,
                expose_discovery: false,
                max_session_memory_bytes: 32 * 1024 * 1024,
                quarantine_after_panics: None,
                on_quarantine: OnQuarantine::Close,
                quarantined_at_start: Vec::new(),
                algorithms,
                signatures: Vec::new(),
            },
        )
    }

    // ---- what the version rules need ----

    pub fn wire_versions(&self) -> &[u32] {
        &self.policy.wire_versions
    }
    pub fn allow_implicit_version(&self) -> bool {
        self.policy.allow_implicit_version
    }
    pub fn expose_discovery(&self) -> bool {
        self.policy.expose_discovery
    }
    pub fn on_quarantine(&self) -> OnQuarantine {
        self.policy.on_quarantine
    }
    pub fn max_session_memory_bytes(&self) -> usize {
        self.policy.max_session_memory_bytes
    }

    // ---- steps 3 to 5 of the validation order ----

    /// Builds and checks the suite a request names.
    ///
    /// Step 3 (400): the suite is well formed and the Core accepts it.
    /// Step 4 (403): the policy allows it for this profile, tag length and
    /// cost, it is not in quarantine, and a legacy algorithm has all three
    /// switches. Step 5 (422): the buffers fit `max_session_memory_bytes`,
    /// checked BEFORE anything is allocated.
    pub fn resolve(&self, wire: &SuiteWire, profile: ProfileName) -> Result<ResolvedSuite, DomainError> {
        self.resolve_with(wire, profile, true)
    }

    /// Like `resolve`, but ignores quarantine: only for draining sessions that
    /// were already open when the algorithm was quarantined.
    pub fn resolve_draining(&self, wire: &SuiteWire, profile: ProfileName) -> Result<ResolvedSuite, DomainError> {
        self.resolve_with(wire, profile, false)
    }

    fn resolve_with(&self, wire: &SuiteWire, profile: ProfileName, check_quarantine: bool) -> Result<ResolvedSuite, DomainError> {
        // The vault profile signs, every other profile does not: the rule is
        // explicit, never inferred (E5 design, section 3).
        match (profile == ProfileName::Vault, wire.signature.as_deref()) {
            (true, None) => {
                return Err(DomainError::BadRequest(
                    "profile `vault` requires `suite.signature` to name a signature scheme".to_string(),
                ));
            }
            (false, Some(_)) => {
                return Err(DomainError::BadRequest(
                    "`suite.signature` must be null: only profile `vault` signs".to_string(),
                ));
            }
            _ => {}
        }
        let scheme = match wire.signature.as_deref() {
            None => None,
            Some(id) => {
                let Some(scheme) = self.registry.get_signature(id) else {
                    return Err(DomainError::BadRequest(format!("unknown signature scheme: {id}")));
                };
                Some(scheme.clone())
            }
        };
        let Some(mac) = self.registry.get(&wire.seal) else {
            return Err(DomainError::BadRequest(format!("unknown seal algorithm: {}", wire.seal)));
        };
        let params = match (mac.output(), wire.tag_len_bytes) {
            (OutputKind::Fixed(_), Some(_)) => {
                return Err(DomainError::BadRequest(format!(
                    "`suite.tag_len_bytes` is not allowed for `{}`: its tag length is fixed",
                    wire.seal
                )));
            }
            (OutputKind::Fixed(_), None) => Vec::new(),
            (OutputKind::Xof { .. }, None) => {
                return Err(DomainError::BadRequest(format!(
                    "`suite.tag_len_bytes` is required for `{}`",
                    wire.seal
                )));
            }
            (OutputKind::Xof { .. }, Some(n)) => {
                let n = u16::try_from(n).map_err(|_| {
                    DomainError::BadRequest("`suite.tag_len_bytes` is out of range".to_string())
                })?;
                xof_params(n)
            }
        };
        let descriptor = SuiteDescriptor::new(&wire.seal, params, wire.signature.as_deref())
            .map_err(|e| DomainError::BadRequest(describe_suite_error(&e)))?;
        let suite = ValidatedSuite::with_signature(descriptor, mac.clone(), scheme)
            .map_err(|e| DomainError::BadRequest(describe_suite_error(&e)))?;

        // Step 4: policy.
        let forbidden = |why: &str| DomainError::Forbidden(format!("seal algorithm `{}` is not allowed here: {why}", wire.seal));
        let Some(entry) = self.policy.entries.get(&wire.seal) else {
            return Err(forbidden("the node's policy does not list it"));
        };
        if mac.status() == Status::Legacy && !self.policy.allow_legacy {
            return Err(forbidden("it is legacy and the policy does not allow legacy algorithms"));
        }
        if check_quarantine && self.is_quarantined(&wire.seal) {
            return Err(forbidden("it is in quarantine"));
        }
        if !entry.profiles.contains(&profile) {
            return Err(forbidden("the policy does not allow it for this profile"));
        }
        if let Some((lo, hi)) = entry.tag_range {
            let n = suite.tag_len();
            if n < lo || n > hi {
                return Err(forbidden("the tag length is outside the range the policy allows"));
            }
        }
        if cost_rank(mac.cost()) > entry.max_cost {
            return Err(forbidden("its cost class exceeds what the policy admits"));
        }
        if let Some(sig_id) = wire.signature.as_deref() {
            if !self.policy.signatures.contains_key(sig_id) {
                return Err(DomainError::Forbidden(format!(
                    "signature scheme `{sig_id}` is not allowed here: the node's policy does not list it"
                )));
            }
        }

        // Step 5: memory, before any allocation.
        let cfg = profile.config();
        check_memory_budget(cfg.slot_size, cfg.slot_count, suite.tag_len(), self.policy.max_session_memory_bytes).map_err(
            |e| match e {
                SuiteError::MemoryBudgetExceeded { required, cap } => DomainError::Unprocessable(format!(
                    "the session would need {required} bytes of buffers; this node allows {cap} bytes per session"
                )),
                other => DomainError::BadRequest(describe_suite_error(&other)),
            },
        )?;

        Ok(ResolvedSuite { cost: mac.cost(), suite })
    }

    // ---- quarantine ----

    fn lock_q(&self) -> MutexGuard<'_, Quarantine> {
        self.quarantine.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_quarantined(&self, id: &str) -> bool {
        self.lock_q().quarantined.contains(id)
    }

    /// Records one panic of `id`. At `quarantine_after_panics` panics the
    /// algorithm enters quarantine and stays there until the node restarts:
    /// it never leaves by itself, by time or by luck. Returns whether this
    /// call put it into quarantine (so the caller can log it once).
    pub fn record_panic(&self, id: &str) -> bool {
        let Some(limit) = self.policy.quarantine_after_panics else { return false };
        let mut q = self.lock_q();
        if q.quarantined.contains(id) {
            return false;
        }
        let n = q.panics.entry(id.to_string()).or_insert(0);
        *n += 1;
        let n = *n;
        if n >= limit {
            q.quarantined.insert(id.to_string());
            drop(q);
            self.emit(format!(
                "seal policy: algorithm `{id}` entered quarantine after {n} panics (on_quarantine: {:?}); it stays out until a restart with a policy that names it again",
                self.policy.on_quarantine
            ));
            return true;
        }
        drop(q);
        self.emit(format!("seal policy: algorithm `{id}` panicked ({n} of {limit} before quarantine)"));
        false
    }

    /// Operator order, at startup: put `id` into quarantine now.
    pub fn quarantine_now(&self, id: &str) {
        let newly = self.lock_q().quarantined.insert(id.to_string());
        if newly {
            self.emit(format!("seal policy: algorithm `{id}` put into quarantine by operator order"));
        }
    }

    // ---- discovery (only when the policy exposes it) ----

    /// The listing for `GET /v1/seal-algorithms`, or `None` if the operator
    /// did not turn discovery on. Reports what the policy allows; it is not a
    /// negotiation and exposes no load or quarantine state.
    pub fn discovery(&self) -> Option<serde_json::Value> {
        if !self.policy.expose_discovery {
            return None;
        }
        let mut ids: Vec<&String> = self.policy.entries.keys().collect();
        ids.sort();
        let algorithms: Vec<serde_json::Value> = ids
            .into_iter()
            .map(|id| {
                let e = &self.policy.entries[id];
                let output = match e.mac.output() {
                    OutputKind::Fixed(n) => serde_json::json!({ "fixed_bytes": n }),
                    OutputKind::Xof { min, max } => serde_json::json!({ "xof_bytes": { "min": min, "max": max } }),
                };
                serde_json::json!({
                    "id": id,
                    "status": e.mac.status().name(),
                    "cost": match e.mac.cost() { CostClass::Light => "light", CostClass::Standard => "standard", CostClass::Heavy => "heavy" },
                    "security_bits": e.mac.security_bits(),
                    "output": output,
                    "profiles": e.profiles.iter().map(|p| p.as_header_value()).collect::<Vec<_>>(),
                    "tag_len_bytes": e.tag_range.map(|(lo, hi)| serde_json::json!({ "min": lo, "max": hi })),
                })
            })
            .collect();
        let mut doc = serde_json::json!({ "wire_versions": self.policy.wire_versions, "algorithms": algorithms });
        if !self.policy.signatures.is_empty() {
            let mut sids: Vec<&String> = self.policy.signatures.keys().collect();
            sids.sort();
            doc["signatures"] = sids
                .into_iter()
                .map(|id| {
                    let sc = &self.policy.signatures[id];
                    serde_json::json!({ "id": id, "status": sc.status().name(), "security_bits": sc.security_bits(), "signature_len_bytes": sc.signature_len() })
                })
                .collect();
        }
        Some(doc)
    }
}

/// Stable text for a suite error. Never exposes internal `Debug` output.
pub fn describe_suite_error(e: &SuiteError) -> String {
    match e {
        SuiteError::InvalidId => "invalid algorithm id".to_string(),
        SuiteError::DescriptorMalformed | SuiteError::DescriptorTooLarge => "the suite descriptor is not valid".to_string(),
        SuiteError::UnsupportedVersion(_) => "unsupported suite version".to_string(),
        SuiteError::UnsupportedKdf | SuiteError::UnsupportedChain => "unsupported key derivation or chain suite".to_string(),
        SuiteError::IdMismatch => "the suite does not match the algorithm".to_string(),
        SuiteError::KeyLenOutOfRange(_) => "the algorithm's key length is outside the Core limits".to_string(),
        SuiteError::TagLenOutOfRange(_) => "the tag length is outside what the algorithm can produce".to_string(),
        SuiteError::ParamsInvalid => "the suite parameters are not valid for this algorithm".to_string(),
        SuiteError::MemoryBudgetExceeded { .. } => "the session buffers exceed the memory budget".to_string(),
        SuiteError::UnknownKeyId => "key_id not recognized in the server's ring".to_string(),
        SuiteError::KeyDerivationFailed => "key derivation failed".to_string(),
        SuiteError::SignatureSchemeMismatch => "the suite's signature scheme does not match the scheme object".to_string(),
        SuiteError::SignatureLenOutOfRange(_) => "the signature length is outside the Core limits".to_string(),
        SuiteError::SignatureKeyLenOutOfRange(_) => "the signature key length is outside the Core limits".to_string(),
        SuiteError::SignatureKeyInvalid => "the signature key is not valid for this scheme".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::suite::SealInput;

    /// A tiny, test-only algorithm: not secure, only shaped like one.
    struct Toy {
        id: &'static str,
        status: Status,
        cost: CostClass,
        output: OutputKind,
    }
    impl SealMac for Toy {
        fn id(&self) -> &'static str {
            self.id
        }
        fn status(&self) -> Status {
            self.status
        }
        fn cost(&self) -> CostClass {
            self.cost
        }
        fn security_bits(&self) -> u16 {
            128
        }
        fn key_len(&self) -> usize {
            32
        }
        fn output(&self) -> OutputKind {
            self.output
        }
        fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
            let mut acc = key.iter().fold(0u8, |a, b| a.wrapping_add(*b));
            for part in input.parts() {
                for b in part {
                    acc = acc.wrapping_mul(31).wrapping_add(*b);
                }
            }
            for (i, o) in out.iter_mut().enumerate() {
                *o = acc.wrapping_add(i as u8);
            }
        }
    }

    fn registry() -> SealRegistry {
        SealRegistry::new(vec![
            Arc::new(Toy { id: "toy-fixed", status: Status::Standard, cost: CostClass::Light, output: OutputKind::Fixed(32) }),
            Arc::new(Toy { id: "toy-xof", status: Status::Standard, cost: CostClass::Standard, output: OutputKind::Xof { min: 16, max: 1024 } }),
            Arc::new(Toy { id: "toy-heavy", status: Status::Standard, cost: CostClass::Heavy, output: OutputKind::Fixed(32) }),
            Arc::new(Toy { id: "toy-exp", status: Status::Experimental, cost: CostClass::Light, output: OutputKind::Fixed(32) }),
            Arc::new(Toy { id: "toy-legacy", status: Status::Legacy, cost: CostClass::Light, output: OutputKind::Fixed(20) }),
        ])
        .unwrap()
    }

    fn policy_json(extra: &str, algs: &str) -> String {
        format!(
            r#"{{"wire_versions":[1,2],"max_session_memory_bytes":33554432{extra},"algorithms":[{algs}]}}"#
        )
    }

    const FIXED: &str = r#"{"id":"toy-fixed","expect_status":"standard","profiles":["lite","core"],"max_cost":"light"}"#;
    const XOF: &str = r#"{"id":"toy-xof","expect_status":"standard","profiles":["core"],"tag_len_bytes":{"min":16,"max":64},"max_cost":"standard"}"#;

    fn runtime(extra: &str, algs: &str) -> Result<SealRuntime, PolicyError> {
        SealRuntime::from_json(registry(), &policy_json(extra, algs))
    }

    fn wire(seal: &str, tag: Option<u32>) -> SuiteWire {
        SuiteWire { seal: seal.to_string(), tag_len_bytes: tag, signature: None }
    }

    // ---- loading refuses every inconsistency ----

    #[test]
    fn a_good_policy_loads() {
        assert!(runtime("", &format!("{FIXED},{XOF}")).is_ok());
    }

    #[test]
    fn unknown_fields_in_the_policy_are_refused() {
        assert!(SealRuntime::from_json(registry(), r#"{"wire_versions":[1],"max_session_memory_bytes":1,"algorithms":[],"typo":1}"#).is_err());
    }

    #[test]
    fn quarantine_transitions_are_logged_without_payloads_or_keys() {
        use std::sync::{Arc as A, Mutex as M};
        let log = A::new(M::new(Vec::<String>::new()));
        let sink = log.clone();
        let rt = runtime(r#","quarantine_after_panics":2"#, &format!("{FIXED},{XOF}"))
            .unwrap()
            .with_event_sink(move |l| sink.lock().unwrap().push(l.to_string()));
        assert!(!rt.record_panic("toy-fixed"));
        assert!(rt.record_panic("toy-fixed"));
        rt.quarantine_now("toy-xof");
        rt.quarantine_now("toy-xof"); // already there: no second line
        let lines = log.lock().unwrap().clone();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains("panicked (1 of 2"));
        assert!(lines[1].contains("entered quarantine after 2 panics"));
        assert!(lines[2].contains("`toy-xof`") && lines[2].contains("operator order"));
    }

    #[test]
    fn the_operator_can_order_quarantine_from_the_start_and_only_for_listed_ids() {
        let rt = runtime(r#","quarantined_at_start":["toy-fixed"]"#, FIXED).unwrap();
        assert!(rt.is_quarantined("toy-fixed"));
        assert!(runtime(r#","quarantined_at_start":["toy-xof"]"#, FIXED).is_err(), "not listed in the policy");
        assert!(runtime(r#","quarantined_at_start":["nope"]"#, FIXED).is_err());
    }

    #[test]
    fn required_limits_have_no_default() {
        // no max_session_memory_bytes
        assert!(SealRuntime::from_json(registry(), r#"{"wire_versions":[1],"algorithms":[]}"#).is_err());
        // no wire_versions
        assert!(SealRuntime::from_json(registry(), r#"{"max_session_memory_bytes":1,"algorithms":[]}"#).is_err());
        // an XOF entry without its tag range
        let xof_no_range = r#"{"id":"toy-xof","expect_status":"standard","profiles":["core"],"max_cost":"standard"}"#;
        assert!(runtime("", xof_no_range).is_err());
    }

    #[test]
    fn a_policy_that_names_an_unregistered_algorithm_does_not_load() {
        let e = r#"{"id":"nope","expect_status":"standard","profiles":["core"],"max_cost":"light"}"#;
        assert!(runtime("", e).unwrap_err().0.contains("not in this binary's registry"));
    }

    #[test]
    fn a_status_that_differs_from_the_catalogue_does_not_load() {
        let e = r#"{"id":"toy-exp","expect_status":"standard","profiles":["core"],"max_cost":"light"}"#;
        assert!(runtime("", e).unwrap_err().0.contains("expects status"));
    }

    #[test]
    fn legacy_needs_its_status_written_and_allow_legacy() {
        let e = r#"{"id":"toy-legacy","expect_status":"legacy","profiles":["core"],"max_cost":"light"}"#;
        assert!(runtime("", e).is_err(), "legacy without allow_legacy must not load");
        assert!(runtime(r#","allow_legacy":true"#, e).is_ok());
        let wrong = r#"{"id":"toy-legacy","expect_status":"standard","profiles":["core"],"max_cost":"light"}"#;
        assert!(runtime(r#","allow_legacy":true"#, wrong).is_err(), "legacy must be written as legacy");
    }

    #[test]
    fn a_fixed_length_algorithm_forbids_a_tag_range_and_xof_ranges_must_fit() {
        let fixed_with_range = r#"{"id":"toy-fixed","expect_status":"standard","profiles":["core"],"tag_len_bytes":{"min":16,"max":32},"max_cost":"light"}"#;
        assert!(runtime("", fixed_with_range).is_err());
        for range in [r#"{"min":0,"max":8}"#, r#"{"min":32,"max":16}"#, r#"{"min":8,"max":64}"#, r#"{"min":16,"max":2048}"#] {
            let e = format!(r#"{{"id":"toy-xof","expect_status":"standard","profiles":["core"],"tag_len_bytes":{range},"max_cost":"standard"}}"#);
            assert!(runtime("", &e).is_err(), "range {range} must be refused");
        }
    }

    #[test]
    fn vault_cannot_be_allowed_under_v2_and_costs_must_fit() {
        let vault = r#"{"id":"toy-fixed","expect_status":"standard","profiles":["vault"],"max_cost":"light"}"#;
        assert!(runtime("", vault).is_err());
        let too_cheap = r#"{"id":"toy-heavy","expect_status":"standard","profiles":["core"],"max_cost":"standard"}"#;
        assert!(runtime("", too_cheap).unwrap_err().0.contains("could never run"));
    }

    #[test]
    fn versions_must_be_known_unique_and_not_empty() {
        let mk = |v: &str| SealRuntime::from_json(registry(), &format!(r#"{{"wire_versions":{v},"max_session_memory_bytes":1,"algorithms":[]}}"#));
        assert!(mk("[]").is_err());
        assert!(mk("[3]").is_err());
        assert!(mk("[1,1]").is_err());
        assert!(mk("[1]").is_ok(), "v1 only needs no algorithms");
        assert!(mk("[2]").is_err(), "v2 without algorithms would accept nothing");
    }

    #[test]
    fn zero_memory_and_zero_panic_limit_are_refused_and_duplicates_too() {
        assert!(SealRuntime::from_json(registry(), r#"{"wire_versions":[1],"max_session_memory_bytes":0,"algorithms":[]}"#).is_err());
        assert!(runtime(r#","quarantine_after_panics":0"#, FIXED).is_err());
        assert!(runtime("", &format!("{FIXED},{FIXED}")).is_err());
    }

    // ---- resolve: 400 / 403 / 422, in that order ----

    #[test]
    fn resolve_accepts_what_the_policy_allows() {
        let rt = runtime("", &format!("{FIXED},{XOF}")).unwrap();
        let r = rt.resolve(&wire("toy-fixed", None), ProfileName::Lite).unwrap();
        assert_eq!(r.suite.tag_len(), 32);
        let r = rt.resolve(&wire("toy-xof", Some(48)), ProfileName::Core).unwrap();
        assert_eq!(r.suite.tag_len(), 48);
    }

    #[test]
    fn malformed_suites_are_400_not_403() {
        let rt = runtime("", &format!("{FIXED},{XOF}")).unwrap();
        for (w, why) in [
            (wire("nope", None), "unknown id"),
            (wire("toy-fixed", Some(32)), "tag_len on a fixed algorithm"),
            (wire("toy-xof", None), "XOF without tag_len"),
            (wire("toy-xof", Some(70000)), "tag_len beyond u16"),
            (wire("toy-xof", Some(4)), "tag_len below the algorithm's minimum"),
            (SuiteWire { seal: "toy-fixed".into(), tag_len_bytes: None, signature: Some("ed25519".into()) }, "signature"),
        ] {
            let e = rt.resolve(&w, ProfileName::Core).err().unwrap_or_else(|| panic!("{why} must fail"));
            assert!(matches!(e, DomainError::BadRequest(_)), "{why}: {e:?}");
        }
    }

    #[test]
    fn compiled_is_not_authorized() {
        // toy-exp and toy-legacy exist in the registry but the policy does not list them.
        let rt = runtime("", FIXED).unwrap();
        for id in ["toy-exp", "toy-xof", "toy-heavy"] {
            let tag = (id == "toy-xof").then_some(32);
            assert!(matches!(rt.resolve(&wire(id, tag), ProfileName::Core), Err(DomainError::Forbidden(_))), "{id}");
        }
        assert!(matches!(rt.resolve(&wire("toy-legacy", None), ProfileName::Core), Err(DomainError::Forbidden(_))));
    }

    #[test]
    fn profile_and_tag_range_are_enforced() {
        let rt = runtime("", &format!("{FIXED},{XOF}")).unwrap();
        // XOF entry allows only `core`
        assert!(matches!(rt.resolve(&wire("toy-xof", Some(32)), ProfileName::Lite), Err(DomainError::Forbidden(_))));
        // and only 16..=64 bytes
        assert!(matches!(rt.resolve(&wire("toy-xof", Some(65)), ProfileName::Core), Err(DomainError::Forbidden(_))));
        assert!(rt.resolve(&wire("toy-xof", Some(16)), ProfileName::Core).is_ok());
        assert!(rt.resolve(&wire("toy-xof", Some(64)), ProfileName::Core).is_ok());
        // vault without a signature scheme is a malformed request, not a policy question
        assert!(matches!(rt.resolve(&wire("toy-fixed", None), ProfileName::Vault), Err(DomainError::BadRequest(_))));
    }

    // ---- signature schemes and the vault profile (E5) ----

    struct ToySig {
        status: Status,
        id: &'static str,
    }
    impl SignatureScheme for ToySig {
        fn id(&self) -> &'static str {
            self.id
        }
        fn status(&self) -> Status {
            self.status
        }
        fn security_bits(&self) -> u16 {
            0
        }
        fn public_key_len(&self) -> usize {
            32
        }
        fn secret_key_len(&self) -> usize {
            32
        }
        fn signature_len(&self) -> usize {
            32
        }
        fn public_from_secret(&self, secret: &[u8]) -> Option<Vec<u8>> {
            Some(secret.to_vec())
        }
        fn sign(&self, _: &[u8], _: &lacre_core::suite::SignInput<'_>) -> Vec<u8> {
            vec![0; 32]
        }
        fn verify(&self, _: &[u8], _: &lacre_core::suite::SignInput<'_>, _: &[u8]) -> bool {
            false
        }
    }

    const SIG: &str = r#","signatures":[{"id":"toy-sig","expect_status":"standard"}]"#;
    const VAULT_FIXED: &str = r#"{"id":"toy-fixed","expect_status":"standard","profiles":["lite","core","vault"],"max_cost":"light"}"#;

    fn signed_runtime(extra: &str, algs: &str) -> Result<SealRuntime, PolicyError> {
        let reg = registry().with_signatures(vec![Arc::new(ToySig { status: Status::Standard, id: "toy-sig" })]).unwrap();
        SealRuntime::from_json(reg, &policy_json(extra, algs))
    }

    fn vault_wire(sig: Option<&str>) -> SuiteWire {
        SuiteWire { seal: "toy-fixed".into(), tag_len_bytes: None, signature: sig.map(str::to_string) }
    }

    #[test]
    fn vault_in_a_policy_needs_a_listed_signature_scheme() {
        assert!(signed_runtime("", VAULT_FIXED).unwrap_err().0.contains("signature scheme"));
        assert!(signed_runtime(SIG, VAULT_FIXED).is_ok());
    }

    #[test]
    fn the_signature_list_is_validated_like_the_algorithms() {
        let unknown = r#","signatures":[{"id":"nope","expect_status":"standard"}]"#;
        assert!(signed_runtime(unknown, FIXED).unwrap_err().0.contains("registry"));
        let wrong = r#","signatures":[{"id":"toy-sig","expect_status":"experimental"}]"#;
        assert!(signed_runtime(wrong, FIXED).unwrap_err().0.contains("expects status"));
        let twice = r#","signatures":[{"id":"toy-sig","expect_status":"standard"},{"id":"toy-sig","expect_status":"standard"}]"#;
        assert!(signed_runtime(twice, FIXED).unwrap_err().0.contains("twice"));
    }

    #[test]
    fn vault_signs_and_every_other_profile_does_not() {
        let rt = signed_runtime(SIG, VAULT_FIXED).unwrap();
        let ok = rt.resolve(&vault_wire(Some("toy-sig")), ProfileName::Vault).unwrap();
        assert!(ok.suite.signature_scheme().is_some());
        let bad = |w: SuiteWire, p| matches!(rt.resolve(&w, p), Err(DomainError::BadRequest(_)));
        assert!(bad(vault_wire(None), ProfileName::Vault), "vault without a scheme");
        assert!(bad(vault_wire(Some("toy-sig")), ProfileName::Core), "core with a scheme");
        assert!(bad(vault_wire(Some("toy-sig")), ProfileName::Lite), "lite with a scheme");
        assert!(bad(vault_wire(Some("nope")), ProfileName::Vault), "scheme the binary does not contain");
        assert!(rt.resolve(&vault_wire(None), ProfileName::Core).is_ok());
    }

    #[test]
    fn a_compiled_scheme_the_policy_does_not_list_is_forbidden() {
        // Two schemes are compiled in; the policy lists only one, and vault is allowed
        // for the algorithm, so the ONLY thing that can refuse the other is the list.
        let reg = registry()
            .with_signatures(vec![
                Arc::new(ToySig { status: Status::Standard, id: "toy-sig" }),
                Arc::new(ToySig { status: Status::Standard, id: "toy-other" }),
            ])
            .unwrap();
        let rt = SealRuntime::from_json(reg, &policy_json(SIG, VAULT_FIXED)).unwrap();
        assert!(rt.resolve(&vault_wire(Some("toy-sig")), ProfileName::Vault).is_ok());
        assert!(matches!(rt.resolve(&vault_wire(Some("toy-other")), ProfileName::Vault), Err(DomainError::Forbidden(_))));
    }

    #[test]
    fn discovery_lists_signature_schemes_only_when_the_policy_has_them() {
        let with = signed_runtime(&format!(r#"{SIG},"expose_discovery":true"#), VAULT_FIXED).unwrap();
        assert_eq!(with.discovery().unwrap()["signatures"][0]["id"], "toy-sig");
        let without = runtime(r#","expose_discovery":true"#, FIXED).unwrap();
        assert!(without.discovery().unwrap().get("signatures").is_none());
    }

    #[test]
    fn the_memory_budget_is_checked_with_the_tag_length_before_allocation() {
        // core: 15360 slots x (1024 + tag). With 16 MiB the 1024-byte tag does not fit.
        let xof = r#"{"id":"toy-xof","expect_status":"standard","profiles":["core"],"tag_len_bytes":{"min":16,"max":1024},"max_cost":"standard"}"#;
        let rt = SealRuntime::from_json(
            registry(),
            &format!(r#"{{"wire_versions":[2],"max_session_memory_bytes":16777216,"algorithms":[{xof}]}}"#),
        )
        .unwrap();
        assert!(rt.resolve(&wire("toy-xof", Some(16)), ProfileName::Core).is_ok());
        assert!(matches!(rt.resolve(&wire("toy-xof", Some(1024)), ProfileName::Core), Err(DomainError::Unprocessable(_))));
    }

    // ---- quarantine ----

    #[test]
    fn quarantine_is_off_without_a_limit_and_never_lifts_by_itself() {
        let rt = runtime("", FIXED).unwrap();
        for _ in 0..100 {
            assert!(!rt.record_panic("toy-fixed"));
        }
        assert!(rt.resolve(&wire("toy-fixed", None), ProfileName::Core).is_ok());

        let rt = runtime(r#","quarantine_after_panics":3"#, FIXED).unwrap();
        assert!(!rt.record_panic("toy-fixed"));
        assert!(!rt.record_panic("toy-fixed"));
        assert!(rt.record_panic("toy-fixed"), "the third panic puts it into quarantine, reported once");
        assert!(!rt.record_panic("toy-fixed"));
        assert!(matches!(rt.resolve(&wire("toy-fixed", None), ProfileName::Core), Err(DomainError::Forbidden(_))));
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(rt.is_quarantined("toy-fixed"), "time does not reactivate an algorithm");
    }

    #[test]
    fn an_operator_order_quarantines_immediately() {
        let rt = runtime("", FIXED).unwrap();
        rt.quarantine_now("toy-fixed");
        assert!(matches!(rt.resolve(&wire("toy-fixed", None), ProfileName::Core), Err(DomainError::Forbidden(_))));
    }

    // ---- discovery is opt-in ----

    #[test]
    fn discovery_exists_only_when_the_operator_turns_it_on() {
        assert!(runtime("", FIXED).unwrap().discovery().is_none());
        let rt = runtime(r#","expose_discovery":true"#, &format!("{FIXED},{XOF}")).unwrap();
        let d = rt.discovery().unwrap();
        assert_eq!(d["wire_versions"], serde_json::json!([1, 2]));
        let ids: Vec<_> = d["algorithms"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["toy-fixed", "toy-xof"]);
        assert!(!d.to_string().contains("quarantine"), "no load or quarantine state is exposed");
    }

    #[test]
    fn the_standard_preset_is_explicit_and_leaves_out_experimental_and_legacy() {
        let rt = SealRuntime::preset_standard(registry()).unwrap();
        assert!(rt.resolve(&wire("toy-fixed", None), ProfileName::Core).is_ok());
        assert!(rt.resolve(&wire("toy-xof", Some(64)), ProfileName::Lite).is_ok());
        assert!(matches!(rt.resolve(&wire("toy-xof", Some(65)), ProfileName::Core), Err(DomainError::Forbidden(_))));
        assert!(matches!(rt.resolve(&wire("toy-exp", None), ProfileName::Core), Err(DomainError::Forbidden(_))));
        assert!(matches!(rt.resolve(&wire("toy-legacy", None), ProfileName::Core), Err(DomainError::Forbidden(_))));
        // toy-heavy has Standard status but Heavy cost: the preset caps cost at `standard`.
        assert!(matches!(rt.resolve(&wire("toy-heavy", None), ProfileName::Core), Err(DomainError::Forbidden(_))));
    }
}

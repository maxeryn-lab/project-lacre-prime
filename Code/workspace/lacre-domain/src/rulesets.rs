//! Named rule sets — the live route to the Rule Engine, Guardian and
//! Certifier (`lacre-profiles`).
//!
//! Those three were library code with no way in from a request. Here a
//! *deployment* (not the caller) defines named rule sets, loaded once at
//! startup from a JSON file (`LACRE_RULESETS_FILE`); a request only picks
//! one by name (`"ruleset": "orders"`). The caller never supplies a rule
//! or a regex, so it cannot make the server compile or run a pattern of
//! its choosing, and a malformed rule set stops the server at startup
//! (fail at load, not at runtime — Annex 5.0).
//!
//! File shape (kinds map to the Annex 2.0 Profiles):
//! ```json
//! { "orders": {"kind": "guardian",
//!              "fields": [{"name": "order_id", "type": "integer", "digits": 8},
//!                         {"name": "customer", "type": "string"}]},
//!   "ids":    {"kind": "certifier",
//!              "patterns": [{"pattern": "LA-[0-9]{12}", "occurrences_min": 1}]},
//!   "mixed":  {"kind": "engine",
//!              "rules": [{"id": "amount", "on_fail": "quarantine",
//!                         "field": "amount", "type": "integer"},
//!                        {"id": "tag", "on_fail": "pass_with_flag",
//!                         "pattern": "urgent", "occurrences_min": 1}]} }
//! ```
//! A payload is read as a flat JSON object: integer, string, boolean and
//! array-of-those fields are visible to `FieldCheck`; anything else
//! (null, float, nested object) is simply absent, so a rule that needs it
//! fails closed. A payload that is not a JSON object has no fields.
use lacre_core::access::{ContentView, FullContent, Provenance};
use lacre_core::frame::LacreFrame;
use lacre_core::session::SessionId;
use lacre_profiles::certifier::{CertifierConfig, RequiredPattern};
use lacre_profiles::guardian::{GuardianConfig, RequiredField};
use lacre_profiles::rule_engine::{
    Condition, FieldType, JsonValue, OnFail, Rule, RuleEngineProfile, RuleOutcome, Statefulness,
    StructuredContent,
};
use serde::Deserialize;
use std::collections::HashMap;

/// Which Annex 2.0 Profile a rule set is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetKind {
    Guardian,
    Certifier,
    Engine,
}

impl RuleSetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleSetKind::Guardian => "guardian",
            RuleSetKind::Certifier => "certifier",
            RuleSetKind::Engine => "engine",
        }
    }
}

enum Built {
    Guardian(lacre_profiles::guardian::GuardianProfile),
    Certifier(lacre_profiles::certifier::CertifierProfile),
    Engine(RuleEngineProfile),
}

/// One built rule set.
pub struct RuleSet {
    kind: RuleSetKind,
    built: Built,
}

/// Result of evaluating a payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub outcome: &'static str,
    pub failing_rule_id: Option<String>,
}

impl Evaluation {
    /// `true` when the payload may proceed (passed, or passed with a flag).
    pub fn proceeds(&self) -> bool {
        matches!(self.outcome, "passed" | "passed_with_flag")
    }
}

impl RuleSet {
    pub fn kind(&self) -> RuleSetKind {
        self.kind
    }

    /// Evaluates a whole payload. `Err` is a fail-closed evaluation
    /// error (for example a Certifier pattern over non-UTF-8 bytes).
    pub fn evaluate(&self, payload: &[u8]) -> Result<Evaluation, String> {
        self.evaluate_as(payload, Provenance::CallerSupplied)
    }

    /// Same as `evaluate`, saying where the bytes come from: the view the
    /// rules receive carries it (`CallerSupplied` for bytes nobody verified,
    /// `Reassembled` for a payload rebuilt from Core-verified frames).
    pub fn evaluate_as(&self, payload: &[u8], provenance: Provenance) -> Result<Evaluation, String> {
        let frame = LacreFrame {
            session_id: SessionId([0u8; 16]),
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: payload.to_vec(),
        };
        let view = match provenance {
            Provenance::Reassembled => ContentView::<FullContent>::reassembled(&frame),
            _ => ContentView::<FullContent>::caller_supplied(&frame),
        };
        let content = structured_content(payload);
        let outcome = match &self.built {
            Built::Guardian(g) => g.evaluate(&view, &content),
            Built::Certifier(c) => c.evaluate(&view, &content),
            Built::Engine(e) => e.evaluate(&view, &content),
        }
        .map_err(|e| e.to_string())?;
        Ok(match outcome {
            RuleOutcome::Passed => Evaluation { outcome: "passed", failing_rule_id: None },
            RuleOutcome::Rejected { failing_rule_id } => {
                Evaluation { outcome: "rejected", failing_rule_id: Some(failing_rule_id) }
            }
            RuleOutcome::Quarantined { failing_rule_id } => {
                Evaluation { outcome: "quarantined", failing_rule_id: Some(failing_rule_id) }
            }
            RuleOutcome::PassedWithFlag { failing_rule_id } => {
                Evaluation { outcome: "passed_with_flag", failing_rule_id: Some(failing_rule_id) }
            }
        })
    }
}

/// Flat JSON object → the Rule Engine's `StructuredContent`.
pub fn structured_content(payload: &[u8]) -> StructuredContent {
    let mut content = StructuredContent::new();
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return content;
    };
    for (name, value) in map {
        if let Some(v) = to_json_value(&value) {
            content = content.with_field(name, v);
        }
    }
    content
}

fn to_json_value(v: &serde_json::Value) -> Option<JsonValue> {
    match v {
        serde_json::Value::Bool(b) => Some(JsonValue::Boolean(*b)),
        serde_json::Value::Number(n) => n.as_i64().map(JsonValue::Integer),
        serde_json::Value::String(s) => Some(JsonValue::String(s.clone())),
        serde_json::Value::Array(items) => {
            items.iter().map(to_json_value).collect::<Option<Vec<_>>>().map(JsonValue::Array)
        }
        _ => None,
    }
}

/// The deployment's rule sets by name.
#[derive(Default)]
pub struct RuleSets {
    sets: HashMap<String, RuleSet>,
}

impl RuleSets {
    pub fn empty() -> Self {
        RuleSets::default()
    }

    pub fn get(&self, name: &str) -> Option<&RuleSet> {
        self.sets.get(name)
    }

    pub fn names(&self) -> Vec<&str> {
        let mut n: Vec<&str> = self.sets.keys().map(String::as_str).collect();
        n.sort_unstable();
        n
    }

    pub fn len(&self) -> usize {
        self.sets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Builds the registry from the JSON text of a rule-set file.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let specs: HashMap<String, Spec> =
            serde_json::from_str(text).map_err(|e| format!("rule-set file is not valid: {e}"))?;
        let mut sets = HashMap::new();
        for (name, spec) in specs {
            let set = spec.build().map_err(|e| format!("rule set `{name}`: {e}"))?;
            sets.insert(name, set);
        }
        Ok(RuleSets { sets })
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Spec {
    Guardian { fields: Vec<FieldSpec> },
    Certifier { patterns: Vec<PatternSpec> },
    Engine { rules: Vec<RuleSpec> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldSpec {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    digits: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternSpec {
    pattern: String,
    #[serde(default = "one")]
    occurrences_min: u32,
}

fn one() -> u32 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    id: String,
    #[serde(default = "reject")]
    on_fail: String,
    // FieldCheck
    #[serde(default)]
    field: Option<String>,
    #[serde(default, rename = "type")]
    ty: Option<String>,
    #[serde(default)]
    digits: Option<u32>,
    // PatternMatch
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    occurrences_min: Option<u32>,
}

fn reject() -> String {
    "reject".to_string()
}

fn field_type(s: &str) -> Result<FieldType, String> {
    match s {
        "integer" => Ok(FieldType::Integer),
        "string" => Ok(FieldType::String),
        "boolean" => Ok(FieldType::Boolean),
        "array" => Ok(FieldType::Array),
        other => Err(format!("unknown field type `{other}` (integer, string, boolean, array)")),
    }
}

impl Spec {
    fn build(self) -> Result<RuleSet, String> {
        match self {
            Spec::Guardian { fields } => {
                let mut cfg = GuardianConfig::new();
                for f in fields {
                    let mut rf = RequiredField::new(f.name, field_type(&f.ty)?);
                    if let Some(d) = f.digits {
                        rf = rf.with_digits(d);
                    }
                    cfg = cfg.require(rf);
                }
                let built = cfg.build().map_err(|e| e.to_string())?;
                Ok(RuleSet { kind: RuleSetKind::Guardian, built: Built::Guardian(built) })
            }
            Spec::Certifier { patterns } => {
                let mut cfg = CertifierConfig::new();
                for p in patterns {
                    cfg = cfg.require(RequiredPattern::new(p.pattern).occurring_at_least(p.occurrences_min));
                }
                let built = cfg.build().map_err(|e| e.to_string())?;
                Ok(RuleSet { kind: RuleSetKind::Certifier, built: Built::Certifier(built) })
            }
            Spec::Engine { rules } => {
                let mut out = Vec::with_capacity(rules.len());
                for r in rules {
                    let on_fail = match r.on_fail.as_str() {
                        "reject" => OnFail::Reject,
                        "quarantine" => OnFail::Quarantine,
                        "pass_with_flag" => OnFail::PassWithFlag,
                        other => return Err(format!("rule `{}`: unknown on_fail `{other}`", r.id)),
                    };
                    let condition = match (r.field, r.pattern) {
                        (Some(field), None) => Condition::FieldCheck {
                            field,
                            expected_type: field_type(r.ty.as_deref().ok_or_else(|| format!("rule `{}`: a field rule needs `type`", r.id))?)?,
                            digits: r.digits,
                        },
                        (None, Some(pattern)) => Condition::PatternMatch {
                            pattern,
                            occurrences_min: r.occurrences_min.unwrap_or(1),
                        },
                        _ => return Err(format!("rule `{}`: give either `field` (+`type`) or `pattern`, not both or neither", r.id)),
                    };
                    out.push(Rule { id: r.id, condition, on_fail });
                }
                let built = RuleEngineProfile::new(Statefulness::Stateless, out).map_err(|e| e.to_string())?;
                Ok(RuleSet { kind: RuleSetKind::Engine, built: Built::Engine(built) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"{
      "orders": {"kind":"guardian","fields":[{"name":"order_id","type":"integer","digits":8},{"name":"customer","type":"string"}]},
      "ids": {"kind":"certifier","patterns":[{"pattern":"LA-[0-9]{12}","occurrences_min":1}]},
      "mixed": {"kind":"engine","rules":[
          {"id":"amount","on_fail":"quarantine","field":"amount","type":"integer"},
          {"id":"tag","on_fail":"pass_with_flag","pattern":"urgent","occurrences_min":1}]}
    }"#;

    fn sets() -> RuleSets {
        RuleSets::from_json(FILE).unwrap()
    }

    #[test]
    fn guardian_passes_a_complete_record_and_rejects_by_rule_name() {
        let s = sets();
        let g = s.get("orders").unwrap();
        assert_eq!(g.kind(), RuleSetKind::Guardian);
        let ok = g.evaluate(br#"{"order_id":12345678,"customer":"ana"}"#).unwrap();
        assert_eq!(ok.outcome, "passed");
        let missing = g.evaluate(br#"{"order_id":12345678}"#).unwrap();
        assert_eq!((missing.outcome, missing.failing_rule_id.as_deref()), ("rejected", Some("required_field_customer")));
        let digits = g.evaluate(br#"{"order_id":1234,"customer":"ana"}"#).unwrap();
        assert_eq!(digits.failing_rule_id.as_deref(), Some("required_field_order_id"));
        let wrong_type = g.evaluate(br#"{"order_id":"12345678","customer":"ana"}"#).unwrap();
        assert_eq!(wrong_type.outcome, "rejected");
    }

    #[test]
    fn a_payload_that_is_not_a_json_object_has_no_fields_so_guardian_fails_closed() {
        let g = sets();
        let g = g.get("orders").unwrap();
        for bad in [&b"not json"[..], b"[1,2]", b"42", b"\"s\"", b"", b"{\"order_id\":null,\"customer\":null}", b"{\"order_id\":1.5,\"customer\":{}}"] {
            assert_eq!(g.evaluate(bad).unwrap().outcome, "rejected", "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn certifier_counts_a_real_regex_and_fails_closed_on_non_utf8() {
        let s = sets();
        let c = s.get("ids").unwrap();
        assert_eq!(c.evaluate(b"ref LA-123456789012 ok").unwrap().outcome, "passed");
        assert_eq!(c.evaluate(b"ref LA-12 short").unwrap().outcome, "rejected");
        assert!(c.evaluate(&[0xff, 0xfe, 0x00]).is_err(), "non-UTF-8 must be an error, not zero matches");
    }

    #[test]
    fn engine_supports_quarantine_and_pass_with_flag() {
        let s = sets();
        let e = s.get("mixed").unwrap();
        let q = e.evaluate(br#"{"amount":"x","note":"urgent"}"#).unwrap();
        assert_eq!((q.outcome, q.proceeds()), ("quarantined", false));
        let f = e.evaluate(br#"{"amount":5,"note":"calm"}"#).unwrap();
        assert_eq!((f.outcome, f.failing_rule_id.as_deref(), f.proceeds()), ("passed_with_flag", Some("tag"), true));
        let p = e.evaluate(br#"{"amount":5,"note":"urgent"}"#).unwrap();
        assert_eq!(p.outcome, "passed");
    }

    #[test]
    fn a_bad_file_is_refused_at_load() {
        for bad in [
            "not json",
            r#"{"x":{"kind":"nope"}}"#,
            r#"{"x":{"kind":"guardian","fields":[{"name":"a","type":"float"}]}}"#,
            r#"{"x":{"kind":"certifier","patterns":[{"pattern":"("}]}}"#,
            r#"{"x":{"kind":"engine","rules":[{"id":"a","field":"f"}]}}"#,
            r#"{"x":{"kind":"engine","rules":[{"id":"a","field":"f","type":"string","pattern":"p"}]}}"#,
            r#"{"x":{"kind":"engine","rules":[{"id":"a","on_fail":"explode","pattern":"p"}]}}"#,
            r#"{"x":{"kind":"engine","rules":[{"id":"a","pattern":"p"},{"id":"a","pattern":"q"}]}}"#,
            r#"{"x":{"kind":"guardian","fields":[],"extra":1}}"#,
        ] {
            assert!(RuleSets::from_json(bad).is_err(), "accepted: {bad}");
        }
    }
}

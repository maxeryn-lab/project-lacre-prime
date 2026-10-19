//! Rule Engine — Profiles Annex 5.0, Section III.3 ("El vocabulario del
//! Motor de Perfiles para Profiles sin estado"), completing what
//! `profile_engine.rs` deliberately left open when it built only
//! `RetentionTracker`.
//!
//! # What `profile_engine.rs` built, and what it explicitly didn't
//!
//! `profile_engine.rs`'s own header comment is explicit: it generalizes
//! retention (how long a stateful Profile may hold an entry before
//! purging it), not rule evaluation. At the time that module was
//! written, no Family X Profile (Guardian, Certifier, Sanitizer,
//! Redactor — Annex 2.0) existed in code, so there was nothing real to
//! validate a rule vocabulary against; building one anyway would have
//! been exactly the kind of speculation this project's own epistemic
//! discipline exists to prevent (`DECISIONS.md`: "the normative
//! document follows implementation, not the other way around").
//!
//! This module is that validation. It exists because `GuardianProfile`
//! (see `guardian.rs`) was the first real Family X Profile in this
//! codebase, and it is expressed *as* a `RuleEngineProfile`
//! configuration rather than as its own hand-written struct — the
//! actual test of Annex 2.0's own claim (Section "Un catálogo de
//! condiciones reutilizables, no una regla por Profile") that Guardian,
//! Certifier, Sanitizer, and Redactor share enough structure to be
//! four configurations of one interpreter instead of four codebases.
//! `CertifierProfile` (see `certifier.rs`) is the second, and the
//! first to actually exercise `Condition::PatternMatch` against a real
//! regular expression rather than only Guardian's `FieldCheck`.
//!
//! # Regex: added when Certifier, not Guardian, needed it for real
//!
//! `Condition::PatternMatch` originally matched only literal byte
//! substrings — enough to compile and pass its own tests, but not
//! enough to evaluate Annex 2.0's own Certifier example verbatim
//! (`"LA-[0-9]{12}-[A-F0-9-]{36}"`, a real regular expression with
//! character classes and quantifiers). That gap was documented
//! honestly rather than hidden when it was first built, and closed
//! only once Certifier — a second real Family X Profile, not a
//! hypothetical one — actually needed it: this module now depends on
//! the `regex` crate (see `lacre-core/Cargo.toml`'s own comment on
//! that dependency), and `PatternMatch` evaluates against real regular
//! expressions, compiled once at `RuleEngineProfile::new` (so a
//! malformed pattern fails at configuration-load time, not the first
//! time a fragment happens to hit that rule) and re-compiled per
//! evaluation call thereafter (see `count_pattern_occurrences`'s own
//! documentation for why, and for the deliberate choice to fail closed
//! on a non-UTF-8 payload rather than silently report zero matches).
//!
//! # Vocabulary scope: the full closed set from Annex 2.0, not just
//! what Guardian alone needs
//!
//! Annex 2.0's own rule block names seven condition fields as the
//! closed vocabulary for the first version of the Rule Engine: `exists`,
//! `type`, `digits`, `pattern`, `occurrences_min`, `pattern_list`,
//! `match`. Building only `exists`/`type` (the minimum Guardian alone
//! needs) would leave the next Profile (Certifier, which needs
//! `pattern`/`occurrences_min`) hitting the exact same gap this module
//! exists to close — so every field from that closed vocabulary is
//! implemented here, even though `GuardianProfile` only exercises a
//! subset of it. `pattern_list` (a named, pre-registered set of
//! heuristics — Annex 2.0's own example is
//! `"heuristicas_inyeccion_v3"`) is deliberately NOT implemented as an
//! open string-to-regex-set lookup here: Annex 2.0 never specifies
//! where such a named list is registered or by whom, and building a
//! registry for a name with no real content behind it yet would be the
//! same kind of unanchored speculation this module exists to avoid.
//! `pattern_list` parses as a `Condition` variant (so a caller CAN
//! declare it and the value round-trips), but evaluating it against a
//! fragment returns `RuleError::UnregisteredPatternList` rather than
//! silently treating an unknown list as an empty one — fail-closed
//! (Axiom A4) applied to an unimplemented condition, not a silent
//! pass.
//!
//! # `on_fail`: all three values from Annex 2.0, including quarantine
//!
//! Annex 2.0 specifies three `on_fail` values: `reject` (Axiom A4,
//! fail-closed, exactly like any other verification failure in this
//! system), `quarantine` (a third fragment destination beyond
//! ACK-purge and timeout-purge — Section 8.6 of Project Lacre Prime
//! only ever specified two), and `pass_with_flag` (the fragment is
//! delivered, annotated with which rule failed, leaving the final call
//! to the consuming agent). All three are implemented here as the
//! `RuleOutcome` enum this module returns — not just `reject`, which
//! would have been the easy subset but would have left `quarantine`
//! (the one behavior with no precedent anywhere else in this catalog)
//! unimplemented, defeating the point of building this completely
//! rather than as a shortcut.
//!
//! # `statefulness`: declared and checked, even though nothing here is
//! stateful yet
//!
//! `RuleEngineProfile` always declares `statefulness = Stateless` — no
//! condition in the vocabulary above depends on any fragment other
//! than the one currently being evaluated. Annex 5.0 Section 3.3
//! describes a `statefulness` field precisely so a future stateful
//! rule vocabulary (Section 3.4, still a sketch, not built by this
//! module or any other) can be rejected at configuration-load time if
//! it's declared `Stateless` but actually needs memory across
//! fragments — this module has no stateful condition to reject yet,
//! but the field exists on `RuleEngineProfile` from the start so that
//! check has somewhere to live once a stateful condition is ever
//! added, rather than being retrofitted later.
//!
//! # What this module does NOT do
//!
//! It does not parse TOML or any other configuration file format —
//! `Rule`/`Condition`/`OnFail` are plain Rust types, constructed in
//! code (see `guardian.rs` for the construction this module is
//! validated against). Annex 5.0's own configuration examples are
//! TOML, but TOML deserialization is a distinct concern (which crate,
//! which error-reporting shape for a malformed file) from having a
//! correct interpreter to deserialize *into* — building the
//! interpreter first and validating it against a real Profile, then
//! adding a deserialization layer on top of an interpreter already
//! proven correct, is the same order this project already used for
//! `declarative_adapter.rs` (dispatch table proven against real
//! Adapters first, before any config-file format was discussed for
//! it).

use crate::profile::ViewOf;
#[cfg(test)]
use lacre_core::frame::LacreFrame;
use std::fmt;

/// Which JSON-like scalar type a field's value must have. Deliberately
/// narrow — the four closed types Annex 2.0's own example
/// (`type = "integer"`) and the rest of the catalog's field validation
/// needs (Guardian's own purpose statement: "valores del tipo y rango
/// esperados"), not a full JSON Schema type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Integer,
    String,
    Boolean,
    Array,
}

impl FieldType {
    fn matches(self, value: &JsonValue) -> bool {
        matches!(
            (self, value),
            (FieldType::Integer, JsonValue::Integer(_))
                | (FieldType::String, JsonValue::String(_))
                | (FieldType::Boolean, JsonValue::Boolean(_))
                | (FieldType::Array, JsonValue::Array(_))
        )
    }
}

/// A minimal structured-content value — deliberately not `serde_json`
/// (this crate has no `serde` dependency and this module doesn't
/// introduce one; see this module's header comment on scope). A
/// caller with an actual JSON fragment converts into this shape at the
/// boundary — the same kind of deliberately-narrow internal
/// representation `frame.rs` already uses for `LacreFrame` rather than
/// depending on a transport-level type.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Integer(i64),
    String(String),
    Boolean(bool),
    Array(Vec<JsonValue>),
}

/// A structured record a rule's `field` names look up by key —
/// intentionally flat (Annex 2.0's own rule examples — `order_id`,
/// nonce patterns — never nest), not a general recursive JSON object.
#[derive(Debug, Clone, Default)]
pub struct StructuredContent {
    fields: std::collections::HashMap<String, JsonValue>,
}

impl StructuredContent {
    pub fn new() -> Self {
        StructuredContent { fields: std::collections::HashMap::new() }
    }

    pub fn with_field(mut self, name: impl Into<String>, value: JsonValue) -> Self {
        self.fields.insert(name.into(), value);
        self
    }

    pub fn get(&self, name: &str) -> Option<&JsonValue> {
        self.fields.get(name)
    }
}

/// The closed condition vocabulary from Annex 2.0's own rule block
/// example. Each variant corresponds to exactly one of the seven
/// fields that example names (`exists`, `type`, `digits`, `pattern`,
/// `occurrences_min`, `pattern_list`, `match`) — grouped into the
/// combinations Annex 2.0's own three example rules actually use
/// together.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    /// `condition = { field = "order_id", exists = true, type = "integer", digits = 8 }`
    /// — Annex 2.0's own first example, verbatim.
    FieldCheck { field: String, expected_type: FieldType, digits: Option<u32> },
    /// `condition = { pattern = "LA-[0-9]{12}-[A-F0-9-]{36}", occurrences_min = 1 }`
    /// — Annex 2.0's own second example. Evaluated against the raw
    /// fragment payload (Certifier's own stated scope: "búsqueda de
    /// patrón ... sobre el contenido ya verificado").
    PatternMatch { pattern: String, occurrences_min: u32 },
    /// `condition = { pattern_list = "heuristicas_inyeccion_v3", match = false }`
    /// — Annex 2.0's own third example. Deliberately unimplemented at
    /// evaluation time — see this module's header comment.
    PatternListAbsence { pattern_list_name: String, expect_match: bool },
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::FieldCheck { field, .. } => write!(f, "field-check({field})"),
            Condition::PatternMatch { .. } => write!(f, "pattern-match"),
            Condition::PatternListAbsence { pattern_list_name, .. } => {
                write!(f, "pattern-list-absence({pattern_list_name})")
            }
        }
    }
}

/// What happens when a rule's condition evaluates to failure. Verbatim
/// the three values Annex 2.0 specifies for `on_fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFail {
    /// Axiom A4, fail-closed.
    Reject,
    /// A third fragment destination beyond ACK-purge and timeout-purge
    /// — held for later review, per Annex 2.0.
    Quarantine,
    /// The fragment is delivered, annotated with which rule failed.
    PassWithFlag,
}

/// A single declarative rule: a condition, and what to do if it fails.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub condition: Condition,
    pub on_fail: OnFail,
}

/// Whether a Profile's decision on a fragment can depend on fragments
/// processed earlier in the same session — Annex 5.0 Section 3.2's own
/// distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statefulness {
    Stateless,
    // `Stateful` deliberately not added yet — see this module's header
    // comment on Annex 5.0 Section 3.4 remaining a sketch.
}

/// Why loading a `RuleEngineProfile` configuration was rejected before
/// any fragment was ever evaluated against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Two or more rules share the same `id`.
    DuplicateRuleId(String),
    /// A configuration declared `Statefulness::Stateless` but contains
    /// a rule this module cannot prove is stateless. Currently
    /// unreachable — kept for when a stateful condition is ever added.
    StatefulRuleDeclaredStateless(String),
    /// A `Condition::PatternMatch`'s `pattern` failed to compile as a
    /// regular expression — caught here, at construction time, rather
    /// than the first time a fragment happens to hit that rule during
    /// evaluation. The `String` is the regex crate's own error message
    /// (e.g. an unbalanced character class), preserved so a caller
    /// debugging a bad configuration sees the real syntax problem
    /// instead of a generic "invalid pattern".
    InvalidPattern { rule_id: String, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::DuplicateRuleId(id) => write!(f, "duplicate rule id: {id}"),
            ConfigError::StatefulRuleDeclaredStateless(id) => {
                write!(f, "rule {id} requires state but profile declares stateless")
            }
            ConfigError::InvalidPattern { rule_id, reason } => {
                write!(f, "rule {rule_id} has an invalid pattern: {reason}")
            }
        }
    }
}

/// Why evaluating a fragment against an already-loaded configuration
/// could not produce a `RuleOutcome` at all — distinct from a rule
/// simply failing its condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// `Condition::PatternListAbsence` names a `pattern_list` this
    /// module has no registry for. Per Axiom A4, an unimplemented
    /// condition is a failure to evaluate, never a silent pass.
    UnregisteredPatternList(String),
    /// A `Condition::PatternMatch` was evaluated against a fragment
    /// payload that isn't valid UTF-8 text. Per Axiom A4, this fails
    /// closed rather than silently reporting zero matches — see
    /// `count_pattern_occurrences`'s own documentation for why those
    /// two facts ("valid text, pattern absent" vs. "not text at all")
    /// must not be conflated.
    PayloadNotUtf8,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::UnregisteredPatternList(name) => {
                write!(f, "pattern list '{name}' is not registered with this engine")
            }
            RuleError::PayloadNotUtf8 => {
                write!(f, "fragment payload is not valid UTF-8 text; cannot evaluate a text pattern against it")
            }
        }
    }
}

/// The result of evaluating one `RuleEngineProfile` configuration
/// against one already-Core-verified fragment.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleOutcome {
    /// Every rule's condition held. The fragment proceeds unmodified.
    Passed,
    /// The named rule's condition failed and its `on_fail` was
    /// `Reject`.
    Rejected { failing_rule_id: String },
    /// The named rule's condition failed and its `on_fail` was
    /// `Quarantine`.
    Quarantined { failing_rule_id: String },
    /// The named rule's condition failed and its `on_fail` was
    /// `PassWithFlag`.
    PassedWithFlag { failing_rule_id: String },
}

/// A `kind = "engine"` Profile (Annex 5.0 Section 3.3): a Profile whose
/// entire behavior is a list of declared rules, evaluated in
/// declaration order against one fragment at a time.
/// `GuardianProfile` (`guardian.rs`) is the first concrete instance.
#[derive(Debug)]
pub struct RuleEngineProfile {
    statefulness: Statefulness,
    rules: Vec<Rule>,
    /// Each `PatternMatch` rule's regex, compiled ONCE at construction
    /// (keyed by rule id). Before, `evaluate` recompiled the pattern on
    /// every call — measurable per-fragment cost on a live route.
    compiled: std::collections::HashMap<String, regex::Regex>,
}

/// Reads `frame.payload` (`PatternMatch`) and the structured fields of the
/// content (`FieldCheck`): it touches the payload (7.3.1).
impl crate::profile::Profile for RuleEngineProfile {
    type Access = lacre_core::access::FullContent;
}

impl RuleEngineProfile {
    /// Validates the configuration at construction time — the same
    /// fail-at-load-not-at-runtime discipline Annex 5.0 requires of
    /// both its declarative mechanisms.
    pub fn new(statefulness: Statefulness, rules: Vec<Rule>) -> Result<Self, ConfigError> {
        let mut seen_ids = std::collections::HashSet::new();
        let mut compiled = std::collections::HashMap::new();
        for rule in &rules {
            if !seen_ids.insert(rule.id.clone()) {
                return Err(ConfigError::DuplicateRuleId(rule.id.clone()));
            }
            if statefulness == Statefulness::Stateless
                && Self::condition_requires_state(&rule.condition)
            {
                return Err(ConfigError::StatefulRuleDeclaredStateless(rule.id.clone()));
            }
            if let Condition::PatternMatch { pattern, .. } = &rule.condition {
                match regex::Regex::new(pattern) {
                    Ok(re) => {
                        compiled.insert(rule.id.clone(), re);
                    }
                    Err(e) => {
                        return Err(ConfigError::InvalidPattern {
                            rule_id: rule.id.clone(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }
        Ok(RuleEngineProfile { statefulness, rules, compiled })
    }

    /// Every `Condition` variant that exists today evaluates a single
    /// fragment in isolation, so this always returns `false`.
    fn condition_requires_state(_condition: &Condition) -> bool {
        false
    }

    pub fn statefulness(&self) -> Statefulness {
        self.statefulness
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluates every declared rule, in declaration order, against
    /// `content` and the raw `frame` payload. Stops at the first rule
    /// whose condition fails and returns that outcome immediately.
    ///
    /// `frame` is required to have already passed
    /// `VerifierCore::verify_frame` successfully, same precondition
    /// every other Profile in this codebase already relies on.
    pub fn evaluate(
        &self,
        view: &ViewOf<'_, Self>,
        content: &StructuredContent,
    ) -> Result<RuleOutcome, RuleError> {
        for rule in &self.rules {
            let holds = Self::condition_holds(&rule.id, &rule.condition, view, content, &self.compiled)?;
            if !holds {
                return Ok(match rule.on_fail {
                    OnFail::Reject => RuleOutcome::Rejected { failing_rule_id: rule.id.clone() },
                    OnFail::Quarantine => {
                        RuleOutcome::Quarantined { failing_rule_id: rule.id.clone() }
                    }
                    OnFail::PassWithFlag => {
                        RuleOutcome::PassedWithFlag { failing_rule_id: rule.id.clone() }
                    }
                });
            }
        }
        Ok(RuleOutcome::Passed)
    }

    fn condition_holds(
        rule_id: &str,
        condition: &Condition,
        view: &ViewOf<'_, Self>,
        content: &StructuredContent,
        compiled: &std::collections::HashMap<String, regex::Regex>,
    ) -> Result<bool, RuleError> {
        match condition {
            Condition::FieldCheck { field, expected_type, digits } => {
                let Some(value) = content.get(field) else {
                    return Ok(false);
                };
                if !expected_type.matches(value) {
                    return Ok(false);
                }
                if let Some(expected_digits) = digits {
                    let JsonValue::Integer(n) = value else {
                        return Ok(false);
                    };
                    let actual_digits = n.unsigned_abs().to_string().len() as u32;
                    if actual_digits != *expected_digits {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::PatternMatch { occurrences_min, .. } => {
                let regex = compiled
                    .get(rule_id)
                    .expect("every PatternMatch rule was compiled at construction time");
                let occurrences = count_pattern_occurrences(view.content_bytes(), regex)?;
                Ok(occurrences >= *occurrences_min)
            }
            Condition::PatternListAbsence { pattern_list_name, .. } => {
                Err(RuleError::UnregisteredPatternList(pattern_list_name.clone()))
            }
        }
    }
}

/// Counts non-overlapping matches of a real regular expression
/// (Annex 2.0's own Certifier example, verbatim:
/// `"LA-[0-9]{12}-[A-F0-9-]{36}"`, has character classes and
/// quantifiers no literal-substring search could evaluate) within
/// `payload`, interpreted as UTF-8 text.
///
/// A payload that isn't valid UTF-8 fails closed
/// (`RuleError::PayloadNotUtf8`) rather than silently reporting zero
/// matches — the fragment's own HMAC integrity (verified upstream by
/// the Core) says nothing about whether its bytes happen to be valid
/// text, and a Certifier deployment configured to search for a text
/// pattern has no correct answer to give against bytes that aren't
/// text at all; reporting "zero occurrences" for that case would be
/// indistinguishable, to the caller, from "valid text, pattern
/// genuinely absent" — a different fact this module must not conflate,
/// per the same Axiom A4 discipline this module's own
/// `PatternListAbsence` already applies to an unimplemented condition.
///
/// A malformed regex pattern is caught at `RuleEngineProfile::new`
/// (configuration-load time — see `ConfigError::InvalidPattern`), not
/// here — by the time `evaluate` reaches this function, the pattern
/// has already compiled successfully once during construction, so this
/// function re-compiles it (regex has no built-in cross-call cache
/// this module manages itself; a future optimization could store the
/// compiled `Regex` on `Condition` instead of the source `String`, but
/// that changes `Condition`'s own shape and is out of scope for making
/// Certifier's example correct).
fn count_pattern_occurrences(payload: &[u8], regex: &regex::Regex) -> Result<u32, RuleError> {
    let text = std::str::from_utf8(payload).map_err(|_| RuleError::PayloadNotUtf8)?;
    Ok(regex.find_iter(text).count() as u32)
}

#[cfg(test)]
mod tests {
    fn full(f: &lacre_core::frame::LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;
    use lacre_core::session::SessionId;

    fn dummy_frame(payload: &[u8]) -> LacreFrame {
        LacreFrame {
            session_id: SessionId::generate(),
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn duplicate_rule_ids_are_rejected_at_construction() {
        let rules = vec![
            Rule {
                id: "same_id".into(),
                condition: Condition::FieldCheck {
                    field: "a".into(),
                    expected_type: FieldType::String,
                    digits: None,
                },
                on_fail: OnFail::Reject,
            },
            Rule {
                id: "same_id".into(),
                condition: Condition::FieldCheck {
                    field: "b".into(),
                    expected_type: FieldType::String,
                    digits: None,
                },
                on_fail: OnFail::Reject,
            },
        ];
        let result = RuleEngineProfile::new(Statefulness::Stateless, rules);
        assert_eq!(result.unwrap_err(), ConfigError::DuplicateRuleId("same_id".into()));
    }

    #[test]
    fn field_check_passes_when_field_exists_with_correct_type() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "order_id_required".into(),
                condition: Condition::FieldCheck {
                    field: "order_id".into(),
                    expected_type: FieldType::Integer,
                    digits: None,
                },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        let content = StructuredContent::new().with_field("order_id", JsonValue::Integer(12345678));
        let outcome = engine.evaluate(&full(&dummy_frame(b"irrelevant")), &content).unwrap();
        assert_eq!(outcome, RuleOutcome::Passed);
    }

    #[test]
    fn field_check_rejects_when_field_is_missing() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "order_id_required".into(),
                condition: Condition::FieldCheck {
                    field: "order_id".into(),
                    expected_type: FieldType::Integer,
                    digits: None,
                },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        let content = StructuredContent::new();
        let outcome = engine.evaluate(&full(&dummy_frame(b"irrelevant")), &content).unwrap();
        assert_eq!(
            outcome,
            RuleOutcome::Rejected { failing_rule_id: "order_id_required".into() }
        );
    }

    #[test]
    fn field_check_rejects_when_field_has_wrong_type() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "order_id_required".into(),
                condition: Condition::FieldCheck {
                    field: "order_id".into(),
                    expected_type: FieldType::Integer,
                    digits: None,
                },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        let content =
            StructuredContent::new().with_field("order_id", JsonValue::String("12345678".into()));
        let outcome = engine.evaluate(&full(&dummy_frame(b"irrelevant")), &content).unwrap();
        assert_eq!(
            outcome,
            RuleOutcome::Rejected { failing_rule_id: "order_id_required".into() }
        );
    }

    /// Annex 2.0's own first worked example, verbatim:
    /// `condition = { field = "order_id", exists = true, type = "integer", digits = 8 }`.
    #[test]
    fn digits_constraint_enforces_exact_digit_count() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "campo_obligatorio_order_id".into(),
                condition: Condition::FieldCheck {
                    field: "order_id".into(),
                    expected_type: FieldType::Integer,
                    digits: Some(8),
                },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        let seven_digits =
            StructuredContent::new().with_field("order_id", JsonValue::Integer(1234567));
        assert_eq!(
            engine.evaluate(&full(&dummy_frame(b"")), &seven_digits).unwrap(),
            RuleOutcome::Rejected { failing_rule_id: "campo_obligatorio_order_id".into() }
        );

        let eight_digits =
            StructuredContent::new().with_field("order_id", JsonValue::Integer(12345678));
        assert_eq!(
            engine.evaluate(&full(&dummy_frame(b"")), &eight_digits).unwrap(),
            RuleOutcome::Passed
        );
    }

    #[test]
    fn pattern_match_counts_non_overlapping_literal_occurrences() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "nonce_present".into(),
                condition: Condition::PatternMatch { pattern: "LA-".into(), occurrences_min: 1 },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        let with_nonce = dummy_frame(b"authorization token LA-000042 attached");
        assert_eq!(
            engine.evaluate(&full(&with_nonce), &StructuredContent::new()).unwrap(),
            RuleOutcome::Passed
        );

        let without_nonce = dummy_frame(b"no token here");
        assert_eq!(
            engine.evaluate(&full(&without_nonce), &StructuredContent::new()).unwrap(),
            RuleOutcome::Rejected { failing_rule_id: "nonce_present".into() }
        );
    }

    #[test]
    fn quarantine_on_fail_is_distinguished_from_reject() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "needs_review".into(),
                condition: Condition::FieldCheck {
                    field: "reviewed_by".into(),
                    expected_type: FieldType::String,
                    digits: None,
                },
                on_fail: OnFail::Quarantine,
            }],
        )
        .unwrap();

        let outcome = engine.evaluate(&full(&dummy_frame(b"")), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Quarantined { failing_rule_id: "needs_review".into() });
    }

    #[test]
    fn pass_with_flag_on_fail_is_distinguished_from_reject_and_quarantine() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "advisory_only".into(),
                condition: Condition::FieldCheck {
                    field: "note".into(),
                    expected_type: FieldType::String,
                    digits: None,
                },
                on_fail: OnFail::PassWithFlag,
            }],
        )
        .unwrap();

        let outcome = engine.evaluate(&full(&dummy_frame(b"")), &StructuredContent::new()).unwrap();
        assert_eq!(
            outcome,
            RuleOutcome::PassedWithFlag { failing_rule_id: "advisory_only".into() }
        );
    }

    /// Multiple rules: evaluation stops at the FIRST failing rule.
    #[test]
    fn evaluation_stops_at_the_first_failing_rule() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![
                Rule {
                    id: "first_check".into(),
                    condition: Condition::FieldCheck {
                        field: "missing_field".into(),
                        expected_type: FieldType::String,
                        digits: None,
                    },
                    on_fail: OnFail::Reject,
                },
                Rule {
                    id: "second_check_would_also_fail".into(),
                    condition: Condition::FieldCheck {
                        field: "also_missing".into(),
                        expected_type: FieldType::String,
                        digits: None,
                    },
                    on_fail: OnFail::Quarantine,
                },
            ],
        )
        .unwrap();

        let outcome = engine.evaluate(&full(&dummy_frame(b"")), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Rejected { failing_rule_id: "first_check".into() });
    }

    /// A configuration with several rules where all of them hold must
    /// report `Passed`.
    #[test]
    fn all_rules_holding_reports_passed() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![
                Rule {
                    id: "order_id_present".into(),
                    condition: Condition::FieldCheck {
                        field: "order_id".into(),
                        expected_type: FieldType::Integer,
                        digits: None,
                    },
                    on_fail: OnFail::Reject,
                },
                Rule {
                    id: "nonce_present".into(),
                    condition: Condition::PatternMatch { pattern: "LA-".into(), occurrences_min: 1 },
                    on_fail: OnFail::Reject,
                },
            ],
        )
        .unwrap();

        let content = StructuredContent::new().with_field("order_id", JsonValue::Integer(42));
        let frame = dummy_frame(b"contains LA-000042 in the body");
        assert_eq!(engine.evaluate(&full(&frame), &content).unwrap(), RuleOutcome::Passed);
    }

    /// `pattern_list` is deliberately unimplemented — evaluating a
    /// condition that names one must return `RuleError`, never
    /// silently pass, per Axiom A4.
    #[test]
    fn pattern_list_condition_fails_closed_as_an_error_not_a_silent_pass() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "no_injection_patterns".into(),
                condition: Condition::PatternListAbsence {
                    pattern_list_name: "heuristicas_inyeccion_v3".into(),
                    expect_match: false,
                },
                on_fail: OnFail::Quarantine,
            }],
        )
        .unwrap();

        let result = engine.evaluate(&full(&dummy_frame(b"anything")), &StructuredContent::new());
        assert_eq!(
            result.unwrap_err(),
            RuleError::UnregisteredPatternList("heuristicas_inyeccion_v3".into())
        );
    }

    #[test]
    fn rule_count_reports_the_number_of_declared_rules() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![
                Rule {
                    id: "a".into(),
                    condition: Condition::FieldCheck {
                        field: "x".into(),
                        expected_type: FieldType::String,
                        digits: None,
                    },
                    on_fail: OnFail::Reject,
                },
                Rule {
                    id: "b".into(),
                    condition: Condition::PatternMatch { pattern: "y".into(), occurrences_min: 1 },
                    on_fail: OnFail::Reject,
                },
            ],
        )
        .unwrap();
        assert_eq!(engine.rule_count(), 2);
        assert_eq!(engine.statefulness(), Statefulness::Stateless);
    }

    /// Annex 2.0's own Certifier example, verbatim:
    /// `condition = { pattern = "LA-[0-9]{12}-[A-F0-9-]{36}", occurrences_min = 1 }`
    /// — a real regular expression with a character class and a
    /// repetition quantifier, not the literal substring the earlier
    /// `pattern_match_counts_non_overlapping_literal_occurrences` test
    /// above already covers. This is the test that would have failed
    /// against this module's original substring-only implementation.
    #[test]
    fn certifier_example_pattern_from_annex_2_0_matches_a_real_uuid_shaped_token() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "patron_nonce_autorizacion".into(),
                condition: Condition::PatternMatch {
                    pattern: "LA-[0-9]{12}-[A-F0-9-]{36}".into(),
                    occurrences_min: 1,
                },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        let with_token = dummy_frame(
            b"authorization: LA-202609220001-3F2A9B1C-4D5E-11CE-BC0A-0080CFCE3854 attached",
        );
        assert_eq!(
            engine.evaluate(&full(&with_token), &StructuredContent::new()).unwrap(),
            RuleOutcome::Passed
        );

        // A literal "LA-" prefix with a shape that does NOT satisfy
        // the digit/hex-group structure (what a substring-literal
        // match on "LA-" alone would have wrongly accepted) must still
        // be rejected — this is exactly the distinction a real regex
        // engine makes that a literal-substring search cannot.
        let malformed = dummy_frame(b"authorization: LA-not-a-valid-token attached");
        assert_eq!(
            engine.evaluate(&full(&malformed), &StructuredContent::new()).unwrap(),
            RuleOutcome::Rejected { failing_rule_id: "patron_nonce_autorizacion".into() }
        );
    }

    /// A malformed regex must fail at `RuleEngineProfile::new`
    /// (configuration-load time), never surface as a runtime error the
    /// first time a fragment happens to reach that rule.
    #[test]
    fn a_malformed_regex_pattern_is_rejected_at_construction_not_at_evaluation() {
        let result = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "broken_pattern".into(),
                // Unbalanced character class — invalid regex syntax.
                condition: Condition::PatternMatch {
                    pattern: "[0-9".into(),
                    occurrences_min: 1,
                },
                on_fail: OnFail::Reject,
            }],
        );
        match result {
            Err(ConfigError::InvalidPattern { rule_id, .. }) => {
                assert_eq!(rule_id, "broken_pattern");
            }
            other => panic!("expected ConfigError::InvalidPattern, got {other:?}"),
        }
    }

    /// A fragment payload that isn't valid UTF-8 must fail closed
    /// (`RuleError::PayloadNotUtf8`) when evaluated against a
    /// `PatternMatch` condition, never silently report zero matches —
    /// see `count_pattern_occurrences`'s own documentation for why
    /// those two facts must not be conflated.
    #[test]
    fn pattern_match_against_non_utf8_payload_fails_closed() {
        let engine = RuleEngineProfile::new(
            Statefulness::Stateless,
            vec![Rule {
                id: "text_pattern".into(),
                condition: Condition::PatternMatch { pattern: "anything".into(), occurrences_min: 1 },
                on_fail: OnFail::Reject,
            }],
        )
        .unwrap();

        // 0xFF, 0xFE is not valid UTF-8 under any interpretation.
        let invalid_utf8_frame = dummy_frame(&[0xFF, 0xFE, 0x00, 0x01]);
        let result = engine.evaluate(&full(&invalid_utf8_frame), &StructuredContent::new());
        assert_eq!(result.unwrap_err(), RuleError::PayloadNotUtf8);
    }
}

//! Guardian — Profiles Annex 2.0, Family X ("Procesamiento Semántico y
//! Validación Estructural"). The first Family X Profile implemented in
//! this codebase, and the first Profile in this codebase expressed as
//! `RuleEngineProfile` configuration rather than as its own
//! hand-written struct.
//!
//! # What Guardian is, per Annex 2.0
//!
//! "Validar que el contenido de un fragmento (JSON, XML o un formato
//! binario estructurado equivalente) incluya los campos obligatorios
//! definidos por una regla de negocio, con valores del tipo y rango
//! esperados, sin interpretar el significado semántico de dichos
//! valores." Annex 2.0's own distinguishing feature for Guardian: "Es,
//! de los cuatro perfiles de la Familia X, el que más se aproxima en
//! espíritu al Motor de Reglas ... Guardian es, en esencia, la
//! implementación de un conjunto fijo de reglas de existencia y tipo."
//! That sentence is the reason Guardian, not Certifier or Sanitizer,
//! was chosen as the first real test of `rule_engine.rs` — Annex 2.0
//! itself already names Guardian as the closest thing to a rule-engine
//! configuration among the four Family X Profiles.
//!
//! # Why this module builds a `GuardianConfig` rather than exposing
//! `RuleEngineProfile` directly for Guardian's use
//!
//! `RuleEngineProfile::new` takes `Vec<Rule>` — correct and general,
//! but general enough that constructing a Guardian configuration by
//! hand at every call site would repeat the same
//! `Condition::FieldCheck { .. }` boilerplate for every required
//! field, with no guardrail against a caller accidentally reaching for
//! `Condition::PatternMatch` (Certifier's shape, not Guardian's) inside
//! what's meant to be a Guardian deployment. `GuardianConfig` is a
//! thin, Guardian-specific builder over the same underlying engine —
//! it does not duplicate any evaluation logic (every actual check
//! still happens inside `RuleEngineProfile::evaluate`), it only
//! narrows the construction surface to the one condition shape
//! Guardian's own purpose statement describes: required fields with an
//! expected type.
//!
//! # What this module does NOT do
//!
//! It does not touch payload transformation or re-sealing — Annex
//! 2.0's own text is explicit that Guardian, in its simplest form of
//! operation, "no modifica el contenido del fragmento ... por lo cual
//! no necesita ejecutar el mecanismo de re-sellado en cadena". A
//! variant of Guardian that normalizes JSON spacing (Annex 2.0's own
//! aside: "Si una variante del Profile normaliza el formato del
//! contenido ... entonces sí debe re-sellar, exactamente como Lingua")
//! is explicitly out of scope here — this module implements the base
//! Guardian, not that variant.

use crate::profile::ViewOf;
#[cfg(test)]
use lacre_core::frame::LacreFrame;
use crate::rule_engine::{
    ConfigError, FieldType, OnFail, Rule, RuleEngineProfile, RuleError, RuleOutcome, Statefulness,
    StructuredContent,
};

/// One required field in a Guardian deployment: its name, the type its
/// value must have, and — for the integer case Annex 2.0's own worked
/// example uses (`order_id`, 8 digits) — an optional exact digit
/// count. Every field a Guardian configuration declares defaults to
/// `on_fail = Reject` (Annex 2.0's own description: "si una variante
/// del Profile falla, el fragmento se descarta"); a deployment that
/// genuinely wants quarantine or pass-with-flag semantics for a
/// specific field can still reach `RuleEngineProfile` directly with a
/// hand-built `Rule` — `GuardianConfig` covers the common case Annex
/// 2.0 itself describes as Guardian's own default behavior, not every
/// possible variant.
#[derive(Debug, Clone)]
pub struct RequiredField {
    pub name: String,
    pub expected_type: FieldType,
    pub digits: Option<u32>,
}

impl RequiredField {
    pub fn new(name: impl Into<String>, expected_type: FieldType) -> Self {
        RequiredField { name: name.into(), expected_type, digits: None }
    }

    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = Some(digits);
        self
    }
}

/// A Guardian deployment: a named list of required fields. Builds a
/// `RuleEngineProfile` with one `Rule` per field, each with
/// `on_fail = Reject`, in the order the fields were declared — the
/// order matters only in that
/// `RuleEngineProfile::evaluate` reports the FIRST missing/wrong-typed
/// field it encounters, so declaring fields in a deployment's own
/// priority order (which one to report first if several are wrong)
/// is a real, if minor, configuration choice a caller retains control
/// over.
pub struct GuardianConfig {
    fields: Vec<RequiredField>,
}

impl GuardianConfig {
    pub fn new() -> Self {
        GuardianConfig { fields: Vec::new() }
    }

    pub fn require(mut self, field: RequiredField) -> Self {
        self.fields.push(field);
        self
    }

    /// Builds the underlying `RuleEngineProfile`. Each field's `Rule`
    /// id is `"required_field_{name}"` — deterministic and readable
    /// directly in a `RuleOutcome::Rejected { failing_rule_id }`
    /// without needing a separate lookup table to know which
    /// configured field it refers to.
    pub fn build(self) -> Result<GuardianProfile, ConfigError> {
        let rules = self
            .fields
            .into_iter()
            .map(|field| Rule {
                id: format!("required_field_{}", field.name),
                condition: crate::rule_engine::Condition::FieldCheck {
                    field: field.name,
                    expected_type: field.expected_type,
                    digits: field.digits,
                },
                on_fail: OnFail::Reject,
            })
            .collect();
        let engine = RuleEngineProfile::new(Statefulness::Stateless, rules)?;
        Ok(GuardianProfile { engine })
    }
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A built Guardian deployment, ready to evaluate fragments. Wraps
/// `RuleEngineProfile` — this struct exists so a caller working with
/// Guardian specifically can hold a `GuardianProfile` rather than a
/// bare `RuleEngineProfile` with no indication of which Family X
/// Profile it represents, while `RuleEngineProfile::evaluate` itself
/// remains the only place any actual condition logic executes.
#[derive(Debug)]
pub struct GuardianProfile {
    engine: RuleEngineProfile,
}

/// Evaluates fields parsed from the fragment's content: it touches the
/// payload (7.3.1), even though it never reads the raw `frame` bytes itself.
impl crate::profile::Profile for GuardianProfile {
    type Access = lacre_core::access::FullContent;
}

impl GuardianProfile {
    /// Evaluates `content` (the fragment's structured fields) against
    /// every required field this Guardian deployment declares.
    /// `frame` is accepted for the same reason
    /// `RuleEngineProfile::evaluate` requires it — Guardian's own
    /// condition shape (`FieldCheck`) never actually reads `frame`
    /// itself, but the underlying engine's signature is shared with
    /// Profiles that do (Certifier's `PatternMatch`, once it exists),
    /// so this method takes the same two arguments rather than
    /// exposing a Guardian-specific signature that would diverge from
    /// the engine it delegates to.
    pub fn evaluate(
        &self,
        view: &ViewOf<'_, Self>,
        content: &StructuredContent,
    ) -> Result<RuleOutcome, RuleError> {
        self.engine.evaluate(view, content)
    }

    pub fn required_field_count(&self) -> usize {
        self.engine.rule_count()
    }
}

#[cfg(test)]
mod tests {
    fn full(f: &lacre_core::frame::LacreFrame) -> lacre_core::access::FullView<'_> {
        lacre_core::access::ContentView::caller_supplied(f)
    }

    use super::*;
    use crate::rule_engine::JsonValue;
    use lacre_core::session::SessionId;

    fn dummy_frame() -> LacreFrame {
        LacreFrame {
            session_id: SessionId::generate(),
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: Vec::new(),
        }
    }

    /// Annex 2.0's own Guardian use case, built verbatim: "Validación
    /// de esquemas de API ... donde la ausencia de un campo
    /// obligatorio (por ejemplo, la fecha de una transacción) debe
    /// descartar el fragmento de inmediato, incluso si el resto del
    /// mensaje es sintácticamente correcto".
    #[test]
    fn a_transaction_missing_its_required_date_field_is_rejected() {
        let guardian = GuardianConfig::new()
            .require(RequiredField::new("transaction_date", FieldType::String))
            .require(RequiredField::new("amount", FieldType::Integer))
            .build()
            .unwrap();

        // Syntactically fine JSON otherwise — amount is present and
        // well-typed, only the date is missing, exactly Annex 2.0's
        // own scenario.
        let content = StructuredContent::new().with_field("amount", JsonValue::Integer(500));
        let outcome = guardian.evaluate(&full(&dummy_frame()), &content).unwrap();
        assert_eq!(
            outcome,
            RuleOutcome::Rejected { failing_rule_id: "required_field_transaction_date".into() }
        );
    }

    /// The mirror case: every required field present and well-typed
    /// must pass, even though the fragment's HMAC integrity (verified
    /// upstream by the Core, not by Guardian) is not this test's
    /// concern — Guardian's own scope, per Annex 2.0, is business-rule
    /// validation on content the Core has already certified intact.
    #[test]
    fn a_transaction_with_every_required_field_present_and_well_typed_passes() {
        let guardian = GuardianConfig::new()
            .require(RequiredField::new("transaction_date", FieldType::String))
            .require(RequiredField::new("amount", FieldType::Integer))
            .build()
            .unwrap();

        let content = StructuredContent::new()
            .with_field("transaction_date", JsonValue::String("2026-09-22".into()))
            .with_field("amount", JsonValue::Integer(500));
        let outcome = guardian.evaluate(&full(&dummy_frame()), &content).unwrap();
        assert_eq!(outcome, RuleOutcome::Passed);
    }

    /// Annex 2.0's own distinguishing description of Guardian, made
    /// concrete: "Core confirma que el sobre lleva un sello; Guardian
    /// confirma, además, que el sobre tiene el remitente escrito en la
    /// esquina correcta" — a field present with the WRONG type is
    /// still a Guardian rejection, not a pass, because syntactic
    /// well-formedness (which Core-level validation already covers)
    /// is not the same as the business-rule type Guardian requires.
    #[test]
    fn a_present_field_with_the_wrong_type_is_still_rejected() {
        let guardian = GuardianConfig::new()
            .require(RequiredField::new("amount", FieldType::Integer))
            .build()
            .unwrap();

        // "amount" is present, so a naive exists-only check would pass
        // it — but it's a string, not the integer Guardian requires.
        let content = StructuredContent::new().with_field("amount", JsonValue::String("500".into()));
        let outcome = guardian.evaluate(&full(&dummy_frame()), &content).unwrap();
        assert_eq!(outcome, RuleOutcome::Rejected { failing_rule_id: "required_field_amount".into() });
    }

    /// Annex 2.0's own `digits` example, through the Guardian-specific
    /// builder rather than a hand-built `Rule`.
    #[test]
    fn a_field_with_the_wrong_digit_count_is_rejected() {
        let guardian = GuardianConfig::new()
            .require(RequiredField::new("order_id", FieldType::Integer).with_digits(8))
            .build()
            .unwrap();

        let too_short = StructuredContent::new().with_field("order_id", JsonValue::Integer(1234));
        assert_eq!(
            guardian.evaluate(&full(&dummy_frame()), &too_short).unwrap(),
            RuleOutcome::Rejected { failing_rule_id: "required_field_order_id".into() }
        );

        let correct = StructuredContent::new().with_field("order_id", JsonValue::Integer(12345678));
        assert_eq!(guardian.evaluate(&full(&dummy_frame()), &correct).unwrap(), RuleOutcome::Passed);
    }

    /// A Guardian deployment with no required fields at all is a valid
    /// (if useless) configuration — it should build successfully and
    /// pass everything, never panic or error out on an empty field
    /// list.
    #[test]
    fn a_guardian_with_no_required_fields_passes_everything() {
        let guardian = GuardianConfig::new().build().unwrap();
        assert_eq!(guardian.required_field_count(), 0);
        let outcome = guardian.evaluate(&full(&dummy_frame()), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Passed);
    }

    /// Two fields with the same name would collide into the same
    /// `Rule` id (`required_field_{name}`) — confirms this actually
    /// surfaces as `ConfigError::DuplicateRuleId` at build time,
    /// rather than silently keeping only one of the two.
    #[test]
    fn declaring_the_same_field_name_twice_fails_at_build_time() {
        let result = GuardianConfig::new()
            .require(RequiredField::new("amount", FieldType::Integer))
            .require(RequiredField::new("amount", FieldType::String))
            .build();
        assert_eq!(
            result.unwrap_err(),
            ConfigError::DuplicateRuleId("required_field_amount".into())
        );
    }

    /// `required_field_count` must reflect exactly the fields declared
    /// — an inspection utility real deployments can use to confirm
    /// their own configuration loaded as expected.
    #[test]
    fn required_field_count_reflects_the_declared_configuration() {
        let guardian = GuardianConfig::new()
            .require(RequiredField::new("a", FieldType::String))
            .require(RequiredField::new("b", FieldType::Boolean))
            .require(RequiredField::new("c", FieldType::Array))
            .build()
            .unwrap();
        assert_eq!(guardian.required_field_count(), 3);
    }
}

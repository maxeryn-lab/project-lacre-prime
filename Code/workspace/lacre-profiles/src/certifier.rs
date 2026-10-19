//! Certifier — Profiles Annex 2.0, Family X. The second Family X
//! Profile implemented in this codebase, and the first Profile
//! expressed as `RuleEngineProfile` configuration that actually
//! exercises `Condition::PatternMatch` against a real regular
//! expression — Guardian only ever needed `Condition::FieldCheck`.
//!
//! # What Certifier is, per Annex 2.0
//!
//! "Verificar que el contenido de un fragmento, ya confirmado íntegro
//! por el Núcleo, contenga un patrón específico incrustado en el
//! propio texto o datos — por ejemplo, un identificador único
//! universal (UUID) de autorización, un sello fiscal, o un nonce de
//! negocio — sin que dicho patrón necesite viajar en la cabecera del
//! mensaje de transporte." Annex 2.0's own worked example, matched
//! verbatim by this module's own test suite:
//! `condition = { pattern = "LA-[0-9]{12}-[A-F0-9-]{36}", occurrences_min = 1 }`.
//!
//! # Why building this is what actually validated `regex` support in
//! `rule_engine.rs`, not Guardian
//!
//! `rule_engine.rs`'s own `Condition::PatternMatch` originally matched
//! only literal byte substrings — sufficient to compile and pass its
//! own unit tests, but not sufficient to evaluate Annex 2.0's own
//! Certifier example, which has a character class (`[0-9]`,
//! `[A-F0-9-]`) and a repetition quantifier (`{12}`, `{36}`) no
//! literal-substring search can express. Certifier is the Profile that
//! actually needed the fix, not a hypothetical future one — see
//! `rule_engine.rs`'s own header comment for the fix itself and why it
//! was added only once a real Profile needed it, not speculatively
//! ahead of time.
//!
//! # Why this module builds a `CertifierConfig` rather than exposing
//! `RuleEngineProfile` directly
//!
//! Same reasoning as `guardian.rs`'s own `GuardianConfig`: a thin,
//! Certifier-specific builder over the same underlying engine, so a
//! caller configuring a Certifier deployment reaches for
//! `require_pattern` rather than hand-building a `Condition::PatternMatch`
//! and risking a `Condition::FieldCheck` (Guardian's shape) inside what
//! is meant to be a Certifier deployment. No evaluation logic is
//! duplicated here — every actual regex match happens inside
//! `RuleEngineProfile::evaluate`.
//!
//! # What this module does NOT do
//!
//! It does not attach the matched pattern to the post-purge receipt —
//! Annex 2.0's own text describes this as an OPTIONAL feature of a
//! Certifier deployment ("El patrón buscado se extrae y se adjunta al
//! recibo post-purga ... cuando el perfil de despliegue lo requiere"),
//! not part of Certifier's core evaluation. Wiring a matched pattern
//! into `receipt.rs`'s existing post-purge mechanism is real, separate
//! work this module leaves undone rather than half-implementing it
//! without a concrete receipt consumer to validate the shape against —
//! the same "don't build ahead of a real second use" discipline
//! already applied elsewhere in this codebase. It also does not touch
//! payload transformation or re-sealing, for the same reason
//! `guardian.rs` doesn't: Certifier's own purpose statement describes
//! reading the payload to confirm a pattern's presence, never
//! modifying it.

use crate::profile::ViewOf;
#[cfg(test)]
use lacre_core::frame::LacreFrame;
use crate::rule_engine::{
    ConfigError, OnFail, Rule, RuleEngineProfile, RuleError, RuleOutcome, Statefulness,
    StructuredContent,
};

/// One required pattern in a Certifier deployment: the regular
/// expression itself, and the minimum number of times it must occur in
/// the fragment's payload. Every pattern a Certifier configuration
/// declares defaults to `on_fail = Reject` — Annex 2.0's own text is
/// explicit that Certifier "aplica el Axioma A4 ... de manera estricta
/// y explícita: si el patrón no se encuentra ... el fragmento se
/// descarta". A deployment that genuinely wants quarantine or
/// pass-with-flag semantics for a specific pattern can still reach
/// `RuleEngineProfile` directly with a hand-built `Rule` — this builder
/// covers Certifier's own default behavior, not every possible
/// variant, the same scope `RequiredField` in `guardian.rs` gives
/// itself.
#[derive(Debug, Clone)]
pub struct RequiredPattern {
    pub pattern: String,
    pub occurrences_min: u32,
}

impl RequiredPattern {
    /// `occurrences_min` defaults to 1 — Annex 2.0's own worked example
    /// never asks for more than a single occurrence; a deployment that
    /// genuinely needs more can override it with
    /// [`RequiredPattern::occurring_at_least`].
    pub fn new(pattern: impl Into<String>) -> Self {
        RequiredPattern { pattern: pattern.into(), occurrences_min: 1 }
    }

    pub fn occurring_at_least(mut self, occurrences_min: u32) -> Self {
        self.occurrences_min = occurrences_min;
        self
    }
}

/// A Certifier deployment: a named list of required patterns. Builds a
/// `RuleEngineProfile` with one `Rule` per pattern, each with
/// `on_fail = Reject`, in the order the patterns were declared —
/// evaluation stops at the first pattern not found, same
/// first-failure-wins behavior `RuleEngineProfile::evaluate` already
/// documents.
pub struct CertifierConfig {
    patterns: Vec<RequiredPattern>,
}

impl CertifierConfig {
    pub fn new() -> Self {
        CertifierConfig { patterns: Vec::new() }
    }

    pub fn require(mut self, pattern: RequiredPattern) -> Self {
        self.patterns.push(pattern);
        self
    }

    /// Builds the underlying `RuleEngineProfile`. Each pattern's `Rule`
    /// id is `"required_pattern_{n}"` (`n` its zero-based declaration
    /// index) rather than derived from the pattern text itself — a
    /// regex like `"LA-[0-9]{12}-[A-F0-9-]{36}"` is not a readable or
    /// stable identifier on its own the way a Guardian field name
    /// (`"order_id"`) already is, and two different patterns could
    /// otherwise collide into the same sanitized id where two Guardian
    /// field names never would.
    pub fn build(self) -> Result<CertifierProfile, ConfigError> {
        let rules = self
            .patterns
            .into_iter()
            .enumerate()
            .map(|(index, pattern)| Rule {
                id: format!("required_pattern_{index}"),
                condition: crate::rule_engine::Condition::PatternMatch {
                    pattern: pattern.pattern,
                    occurrences_min: pattern.occurrences_min,
                },
                on_fail: OnFail::Reject,
            })
            .collect();
        let engine = RuleEngineProfile::new(Statefulness::Stateless, rules)?;
        Ok(CertifierProfile { engine })
    }
}

impl Default for CertifierConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A built Certifier deployment, ready to evaluate fragments. Wraps
/// `RuleEngineProfile` — same reasoning as `guardian.rs`'s own
/// `GuardianProfile`: a caller working with Certifier specifically
/// holds a `CertifierProfile` rather than a bare `RuleEngineProfile`
/// with no indication of which Family X Profile it represents, while
/// `RuleEngineProfile::evaluate` remains the only place any actual
/// pattern matching executes.
#[derive(Debug)]
pub struct CertifierProfile {
    engine: RuleEngineProfile,
}

/// Matches regular expressions against `frame.payload`: it touches the
/// payload (7.3.1).
impl crate::profile::Profile for CertifierProfile {
    type Access = lacre_core::access::FullContent;
}

impl CertifierProfile {
    /// Evaluates `frame`'s payload against every required pattern this
    /// Certifier deployment declares. `content` is accepted for the
    /// same reason `GuardianProfile::evaluate` accepts `frame` — the
    /// underlying engine's signature is shared with `FieldCheck`-shaped
    /// Profiles (Guardian), even though Certifier's own condition shape
    /// (`PatternMatch`) never reads `content` itself, only
    /// `frame.payload`.
    pub fn evaluate(
        &self,
        view: &ViewOf<'_, Self>,
        content: &StructuredContent,
    ) -> Result<RuleOutcome, RuleError> {
        self.engine.evaluate(view, content)
    }

    pub fn required_pattern_count(&self) -> usize {
        self.engine.rule_count()
    }
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

    /// Annex 2.0's own Certifier use case, built verbatim: "Contratos
    /// inteligentes que exigen que la respuesta generada ... incluya
    /// un nonce específico ... antes de que el contrato acepte
    /// ejecutar una orden derivada de esa respuesta."
    #[test]
    fn a_fragment_with_the_required_nonce_pattern_passes() {
        let certifier = CertifierConfig::new()
            .require(RequiredPattern::new("LA-[0-9]{12}-[A-F0-9-]{36}"))
            .build()
            .unwrap();

        let frame = dummy_frame(
            b"order confirmed, nonce LA-202609220001-3F2A9B1C-4D5E-11CE-BC0A-0080CFCE3854 attached",
        );
        let outcome = certifier.evaluate(&full(&frame), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Passed);
    }

    /// The mirror case: a fragment with no matching nonce at all must
    /// be rejected, per Annex 2.0's own strict Axiom A4 language for
    /// Certifier — "independientemente de que su HMAC haya verificado
    /// correctamente en la etapa del Núcleo".
    #[test]
    fn a_fragment_missing_the_required_nonce_pattern_is_rejected() {
        let certifier = CertifierConfig::new()
            .require(RequiredPattern::new("LA-[0-9]{12}-[A-F0-9-]{36}"))
            .build()
            .unwrap();

        let frame = dummy_frame(b"order confirmed, no nonce in this message at all");
        let outcome = certifier.evaluate(&full(&frame), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Rejected { failing_rule_id: "required_pattern_0".into() });
    }

    /// A fragment containing something that merely LOOKS like it might
    /// be the pattern (same literal prefix, wrong overall shape) must
    /// still be rejected — the distinction a real regex engine makes
    /// that a literal-substring search cannot, per `rule_engine.rs`'s
    /// own equivalent test.
    #[test]
    fn a_fragment_with_a_similarly_prefixed_but_malformed_token_is_rejected() {
        let certifier = CertifierConfig::new()
            .require(RequiredPattern::new("LA-[0-9]{12}-[A-F0-9-]{36}"))
            .build()
            .unwrap();

        let frame = dummy_frame(b"nonce LA-not-actually-a-valid-shaped-token here");
        let outcome = certifier.evaluate(&full(&frame), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Rejected { failing_rule_id: "required_pattern_0".into() });
    }

    /// `occurring_at_least` — a Certifier deployment that requires the
    /// pattern to appear more than once.
    #[test]
    fn occurring_at_least_enforces_a_minimum_occurrence_count_above_one() {
        let certifier = CertifierConfig::new()
            .require(RequiredPattern::new("TOKEN").occurring_at_least(2))
            .build()
            .unwrap();

        let one_occurrence = dummy_frame(b"only one TOKEN here");
        assert_eq!(
            certifier.evaluate(&full(&one_occurrence), &StructuredContent::new()).unwrap(),
            RuleOutcome::Rejected { failing_rule_id: "required_pattern_0".into() }
        );

        let two_occurrences = dummy_frame(b"TOKEN appears twice: TOKEN");
        assert_eq!(
            certifier.evaluate(&full(&two_occurrences), &StructuredContent::new()).unwrap(),
            RuleOutcome::Passed
        );
    }

    /// Multiple required patterns: evaluation stops at the first one
    /// not found, same first-failure-wins behavior
    /// `RuleEngineProfile::evaluate` already documents and
    /// `guardian.rs`'s own equivalent test already confirms for
    /// `FieldCheck`.
    #[test]
    fn multiple_required_patterns_report_the_first_missing_one() {
        let certifier = CertifierConfig::new()
            .require(RequiredPattern::new("FIRST-PATTERN"))
            .require(RequiredPattern::new("SECOND-PATTERN"))
            .build()
            .unwrap();

        // Neither pattern present — must report the FIRST rule's id,
        // never the second.
        let frame = dummy_frame(b"contains neither pattern");
        let outcome = certifier.evaluate(&full(&frame), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Rejected { failing_rule_id: "required_pattern_0".into() });
    }

    /// A malformed regex declared through the Certifier-specific
    /// builder must still be caught at build time, via the same
    /// `RuleEngineProfile::new` validation `rule_engine.rs`'s own test
    /// already confirms — `CertifierConfig::build` does not swallow or
    /// bypass that check.
    #[test]
    fn a_malformed_pattern_fails_at_build_not_at_evaluation() {
        let result = CertifierConfig::new().require(RequiredPattern::new("[0-9")).build();
        assert!(matches!(result, Err(ConfigError::InvalidPattern { .. })));
    }

    /// A Certifier deployment with no required patterns at all is a
    /// valid (if useless) configuration, same as `guardian.rs`'s own
    /// equivalent empty-configuration test.
    #[test]
    fn a_certifier_with_no_required_patterns_passes_everything() {
        let certifier = CertifierConfig::new().build().unwrap();
        assert_eq!(certifier.required_pattern_count(), 0);
        let outcome = certifier.evaluate(&full(&dummy_frame(b"anything at all")), &StructuredContent::new()).unwrap();
        assert_eq!(outcome, RuleOutcome::Passed);
    }

    #[test]
    fn required_pattern_count_reflects_the_declared_configuration() {
        let certifier = CertifierConfig::new()
            .require(RequiredPattern::new("A"))
            .require(RequiredPattern::new("B"))
            .require(RequiredPattern::new("C"))
            .build()
            .unwrap();
        assert_eq!(certifier.required_pattern_count(), 3);
    }
}

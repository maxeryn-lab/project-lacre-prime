//! `touches_payload` declarations — Chapter 7.3.1 of Project Lacre Prime.
//!
//! > "Cada Profile debe declarar, en su configuración, si su ejecución
//! > implica el acceso al contenido del fragmento (...) un auditor externo
//! > puede inspeccionar la configuración de un nodo y determinar, sin
//! > necesidad de leer el código fuente de cada Profile, cuáles de ellos
//! > rompen la neutralidad del sistema."
//!
//! The declaration lives in the type (`Profile::TOUCHES_PAYLOAD`), so the
//! compiler refuses a Profile that does not declare it. This module turns
//! those constants into ONE list an auditor can read — `DECLARATIONS`, also
//! served by the node as `GET /v1/profiles` — and builds each entry *from the
//! trait constant itself* (`declare::<P>`), so the list cannot disagree with
//! the type. A `true` entry carries the justification Prime 7.3.1 requires.
//!
//! What this module does NOT claim: that a `false` declaration is honest.
//! That cannot be proven for arbitrary code; `tests/touches_payload.rs`
//! gives the mechanical check that is possible (`assert_content_blind`: a
//! Profile that declares `false` must give the same outcome for any content)
//! and today no Profile declares `false`.
//!
//! The deployment presets `lite`, `core` and `vault` (Prime 15.1) are not
//! Profiles in this sense: they are parameters of the Core, which never
//! touches content (A1). They do not appear here.

use crate::certifier::CertifierProfile;
use lacre_core::access::ContentAccess;
use crate::guardian::GuardianProfile;
use crate::profile::{Profile, ReassembleProfile};
use crate::rule_engine::RuleEngineProfile;
use crate::toolchain::ToolchainProfile;

/// One auditable entry: which Profile, whether it touches content, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileDeclaration {
    pub name: &'static str,
    /// The declared level of content access: `none`, `derived` or `full`.
    /// It comes from the type's associated `Access`, and the compiler limits
    /// what the Profile's entry points can reach to that level.
    pub access: ContentAccess,
    /// `true` for every level that can read bytes (`derived` and `full`).
    /// Kept so the earlier boolean declaration stays readable.
    pub touches_payload: bool,
    /// Required (non-empty) when the Profile can read bytes.
    pub justification: &'static str,
}

/// Builds an entry from the type's own constant — never from a literal.
pub const fn declare<P: Profile>(name: &'static str, justification: &'static str) -> ProfileDeclaration {
    ProfileDeclaration { name, access: P::ACCESS, touches_payload: P::TOUCHES_PAYLOAD, justification }
}

/// Every Profile this build contains. Adding a Profile type without adding it
/// here is caught by `tests/touches_payload.rs` (source scan).
pub const DECLARATIONS: &[ProfileDeclaration] = &[
    declare::<ReassembleProfile>(
        "reassemble",
        "concatenates the payload bytes of verified frames to rebuild the complete message",
    ),
    declare::<ToolchainProfile>(
        "toolchain",
        "reads each node's content to compute its chained seal and to check supplied contents against it",
    ),
    declare::<RuleEngineProfile>(
        "rule-engine",
        "evaluates conditions over the payload bytes (pattern match) and the fields parsed from the content",
    ),
    declare::<GuardianProfile>(
        "guardian",
        "checks that fields parsed from the fragment's content are present and of the declared type",
    ),
    declare::<CertifierProfile>(
        "certifier",
        "matches regular expressions against the payload bytes",
    ),
];

/// The names of the Profiles that break content neutrality, sorted.
pub fn content_touching() -> Vec<&'static str> {
    let mut v: Vec<_> = DECLARATIONS.iter().filter(|d| d.touches_payload).map(|d| d.name).collect();
    v.sort_unstable();
    v
}

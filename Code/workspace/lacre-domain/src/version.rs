//! Protocol version (Axiom A8, Prime 9.2 and Chapter 12).
//!
//! A request that declares a version this node does not accept is refused
//! with the same severity as a seal that does not verify: never "accepted
//! with caution", never downgraded to a version the client did not ask for.
//!
//! Today exactly one version exists, so there is nothing to negotiate and
//! nothing to downgrade to; what this module fixes now is the contract a
//! later version has to respect: the version is declared once, when a session
//! is opened (handshake, seal, Toolchain episode) or when frames are
//! verified, and an unknown value is refused before anything else happens.
//!
//! A request that omits `version` is read as the current version. That is a
//! deliberate compatibility rule while a single version exists, not a
//! fallback: it cannot select a weaker format because none exists. Once a
//! second version is accepted, omission must stop being accepted (or must be
//! tied to a stored session version); that is recorded as a pending decision.
//!
//! The version is NOT bound into the seal (Prime 9.2 sketches
//! `δᵢ = HMAC(fᵢ ∥ Sᵢ ∥ version_tag, k)`). Changing the seal construction is
//! a cryptographic change and was out of scope for this extension; with one
//! version there is no downgrade the binding could prevent. The HKDF context
//! string `lacre-core/v1/session-key` already separates key derivation by
//! major version.

use crate::domain::DomainError;

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Versions this node accepts, most preferred first.
pub const ACCEPTED_VERSIONS: &[u32] = &[PROTOCOL_VERSION];

/// Checks the version a request declares. `None` means "the current one".
/// Returns the version the session will use.
pub fn check(declared: Option<u32>) -> Result<u32, DomainError> {
    match declared {
        None => Ok(PROTOCOL_VERSION),
        Some(v) if ACCEPTED_VERSIONS.contains(&v) => Ok(v),
        Some(v) => Err(DomainError::BadRequest(format!(
            "unsupported protocol version {v}; this node accepts {ACCEPTED_VERSIONS:?}"
        ))),
    }
}

/// Which wire a request speaks, once the version rules have been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    V1,
    V2,
}

/// The version rules of wire v2 (spec/LACRE-WIRE-v2.md). They run
/// first, before the profile, the suite or the payload is read, and they
/// never reinterpret a request:
///
/// - `version: 2` needs a `suite`; a `suite` needs `version: 2`.
/// - An absent `version` means v1 for ever, and only if the policy still
///   accepts v1 and `allow_implicit_version` is true (or there is no policy:
///   the node speaks v1 only).
/// - A version outside the node's accepted set is refused. Without a policy
///   the accepted set is `[1]`.
pub fn resolve(
    runtime: Option<&crate::seal_policy::SealRuntime>,
    declared: Option<u32>,
    has_suite: bool,
) -> Result<Wire, DomainError> {
    let accepted: &[u32] = runtime.map_or(ACCEPTED_VERSIONS, |r| r.wire_versions());
    match declared {
        None => {
            if has_suite {
                return Err(DomainError::BadRequest(
                    "`suite` belongs to version 2: state `\"version\": 2` explicitly".to_string(),
                ));
            }
            if let Some(r) = runtime {
                if !r.allow_implicit_version() {
                    return Err(DomainError::BadRequest(
                        "this node requires an explicit `version` in every request".to_string(),
                    ));
                }
            }
            if !accepted.contains(&1) {
                return Err(DomainError::BadRequest(format!(
                    "an absent `version` means 1, and this node accepts {accepted:?}"
                )));
            }
            Ok(Wire::V1)
        }
        Some(v) if !accepted.contains(&v) => Err(DomainError::BadRequest(format!(
            "unsupported protocol version {v}; this node accepts {accepted:?}"
        ))),
        Some(1) => {
            if has_suite {
                return Err(DomainError::BadRequest(
                    "`suite` is not allowed under version 1: use `\"version\": 2`".to_string(),
                ));
            }
            Ok(Wire::V1)
        }
        Some(2) => {
            if !has_suite {
                return Err(DomainError::BadRequest(
                    "version 2 needs a `suite`: there is no default suite".to_string(),
                ));
            }
            Ok(Wire::V2)
        }
        Some(v) => Err(DomainError::BadRequest(format!("unsupported protocol version {v}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_and_omission_are_accepted() {
        assert_eq!(check(Some(PROTOCOL_VERSION)), Ok(PROTOCOL_VERSION));
        assert_eq!(check(None), Ok(PROTOCOL_VERSION));
    }

    #[test]
    fn every_other_version_is_refused() {
        for v in [0u32, 2, 3, 255, u32::MAX] {
            assert!(matches!(check(Some(v)), Err(DomainError::BadRequest(_))), "version {v}");
        }
    }

    #[test]
    fn the_accepted_set_always_contains_the_current_version() {
        assert!(ACCEPTED_VERSIONS.contains(&PROTOCOL_VERSION));
    }

    // ---- wire v2 rules ----

    use crate::seal_policy::{SealRegistry, SealRuntime};

    fn rt(json: &str) -> SealRuntime {
        SealRuntime::from_json(SealRegistry::new(vec![]).unwrap(), json).unwrap()
    }

    #[test]
    fn without_a_policy_only_v1_exists_and_a_suite_is_refused() {
        assert_eq!(resolve(None, None, false), Ok(Wire::V1));
        assert_eq!(resolve(None, Some(1), false), Ok(Wire::V1));
        assert!(resolve(None, Some(2), true).is_err(), "v2 is off without an explicit policy");
        assert!(resolve(None, None, true).is_err());
        assert!(resolve(None, Some(1), true).is_err());
    }

    #[test]
    fn version_two_needs_its_suite_and_a_suite_needs_version_two() {
        let r = rt(r#"{"wire_versions":[1],"max_session_memory_bytes":1,"algorithms":[]}"#);
        assert!(resolve(Some(&r), Some(2), true).is_err(), "v2 not in wire_versions");
        // wire_versions [2] needs an algorithm; use a registry-free v1+2 test through the file shape:
        let both = SealRuntime::new(
            SealRegistry::new(vec![]).unwrap(),
            serde_json::from_str(r#"{"wire_versions":[1],"max_session_memory_bytes":1,"algorithms":[]}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(resolve(Some(&both), None, false), Ok(Wire::V1));
    }

    #[test]
    fn an_explicit_version_can_be_demanded_and_v1_can_be_switched_off() {
        let strict = rt(r#"{"wire_versions":[1],"allow_implicit_version":false,"max_session_memory_bytes":1,"algorithms":[]}"#);
        assert!(resolve(Some(&strict), None, false).is_err(), "omission refused when the policy demands a version");
        assert_eq!(resolve(Some(&strict), Some(1), false), Ok(Wire::V1));
    }

    #[test]
    fn unknown_versions_are_refused_in_every_form() {
        for v in [0u32, 3, 255, u32::MAX] {
            assert!(matches!(resolve(None, Some(v), false), Err(DomainError::BadRequest(_))), "{v}");
            assert!(matches!(resolve(None, Some(v), true), Err(DomainError::BadRequest(_))), "{v} with suite");
        }
    }
}

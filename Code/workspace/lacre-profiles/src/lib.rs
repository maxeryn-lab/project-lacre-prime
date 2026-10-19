//! lacre-profiles — Profiles layer (Axiom A7): components that may
//! inspect or transform content ALREADY verified by the Core.
//! It depends on `lacre-core` in one direction only; the Core does not know this crate.
pub mod certifier;
pub mod declaration;
pub mod guardian;
pub mod profile;
pub mod profile_engine;
pub mod rule_engine;
pub mod toolchain;
pub mod transit_taxonomy;

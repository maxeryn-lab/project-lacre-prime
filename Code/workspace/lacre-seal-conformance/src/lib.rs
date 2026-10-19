//! Conformance suite for `lacre_core::suite::SealMac` implementations.
//!
//! An algorithm is admitted to a Lacre registry only if it passes this suite;
//! nothing in `lacre-core` changes to accept it. The suite judges
//! *behaviour*:
//!
//! * known-answer vectors supplied by the candidate (at least one is
//!   mandatory — an algorithm without vectors is not checked, it is trusted);
//! * exact output length and full write of the output buffer;
//! * sensitivity to every bit of key, fragment and chain state;
//! * the declared parameters (`OutputKind`) against the Core's validation;
//! * robustness (empty, huge, degenerate keys; panics are failures);
//! * statelessness (interleaving, threads);
//! * isolation between algorithms (`check_crossed`, `check_catalogue`);
//! * the Core's own guarantees with the candidate plugged in (tampering,
//!   truncation, reordering, replay, session and suite binding);
//! * slow implementations (the Core's buffers and purge keep working);
//! * the declared cost class against measured time.
//!
//! What it cannot judge, by construction: constant-time execution inside the
//! algorithm and the cryptographic strength of the primitive.
//! A passing report means "behaves as a `SealMac` and reproduces its
//! vectors", not "is secure".
#![forbid(unsafe_code)]

mod checks;
mod kat;
mod report;

pub use checks::{check_catalogue, check_crossed, check_seal_mac, Options, SlowMac};
pub use kat::Kat;
pub use report::{Check, Group, Report};

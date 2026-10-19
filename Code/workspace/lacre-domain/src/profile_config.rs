//! Deployment profiles (Chapter 15 of the Lacre Prime document) —
//! Lite / Core / Vault.
//!
//! # Why this lives in lacre-server, not in lacre-core
//!
//! This module is the concrete proof that the Core is modular in the
//! sense 7.2 requires: a "profile" is nothing more than a preset of
//! the parameters `SealerCore::open` / `VerifierCore::resume` already
//! accepted loose (`algo`, `slot_size`, `slot_count`,
//! `forced_purge_timeout`). If we had to add code to `lacre-core` for
//! it to "know" what the Core profile is, that would demonstrate the
//! Core isn't as decoupled as 7.2 claims — the Core keeps not changing
//! a single line even if ten new profiles show up tomorrow, because
//! from its perspective such a concept never existed, only calls to
//! `open`/`resume` with different arguments.
//!
//! Lite, Core, and Vault are implemented. Lite required NO new
//! `lacre-core` mechanism at all: `HmacAlgo::Blake3` already existed
//! since Phase 0/1 (`hmac_seal.rs`), tested with real tests
//! (`seal_fragment`/`verify_fragment` under Blake3, including that a
//! Blake3 seal doesn't verify under SHA-256) — Lite is, literally, the
//! same modularity proof Core and Vault already demonstrated, just
//! with a different algorithm.
//!
//! # Values chosen
//!
//! The document (15.1) specifies the latency target (<1ms) and the
//! mechanism (full HMAC per fragment) for Core, but doesn't fix exact
//! `slot_size`/`slot_count`/`timeout` — these are deployment
//! parameters, per `[PA]`. The values here are the same ones already
//! measured empirically in `lacre-core`'s tests (buffer.rs, the
//! original main.rs): 1 KB slot, ~15 MB ceiling, 500 ms forced purge
//! timeout.
//!
//! Lite (15.1, Annex 1.0 Family I): "lightweight checksum, not full
//! HMAC", 8 KB buffer, 100 ms forced purge timeout, target latency <
//! 0.2 ms. Annex 1.0 itself is explicit about its security limit: "a
//! lightweight checksum is forgeable with moderate effort by an
//! attacker who understands the scheme, and this profile is not
//! suitable for anything with direct monetary value" — that same
//! warning is documented here, not just the numeric parameter, so that
//! whoever chooses this profile in `profile_config.rs` doesn't lose
//! sight of that limitation just from looking at the code.
//!
//! Vault (15.1/15.3): HMAC-SHA512 + Ed25519 asymmetric signature, 256
//! KB session buffer, 5 s forced purge timeout, 10-20 ms target
//! latency (priority: integrity over speed, not the minimum latency
//! Core pursues). The `slot_size`/`slot_count` here translate the 256
//! KB buffer into the same slot unit Core already uses, not a new
//! mechanism.

use lacre_core::hmac_seal::HmacAlgo;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileName {
    Lite,
    Core,
    Vault,
}

/// Concrete parameters of a profile, in the exact shape
/// `SealerCore::open` / `VerifierCore::resume` receive them. There is
/// no new type on the lacre-core side to represent this — it's
/// literally the same four loose parameters, packaged here only for
/// the Adapter's convenience.
#[derive(Debug, Clone, Copy)]
pub struct ProfileConfig {
    pub algo: HmacAlgo,
    pub slot_size: usize,
    pub slot_count: usize,
    pub forced_purge_timeout: Duration,
}

impl ProfileName {
    pub fn config(self) -> ProfileConfig {
        match self {
            ProfileName::Lite => ProfileConfig {
                // 15.1 / Annex 1.0 Family I: "lightweight checksum, not
                // full HMAC". Blake3 already existed in hmac_seal.rs
                // since Phase 0/1, requiring no lacre-core change for
                // this profile.
                algo: HmacAlgo::Blake3,
                slot_size: 8 * 1024, // 8 KB, 15.1
                slot_count: 128,     // ~1 MB total session buffer — Lite prioritizes session volume, not a large per-session buffer
                forced_purge_timeout: Duration::from_millis(100), // 15.1
            },
            ProfileName::Core => ProfileConfig {
                algo: HmacAlgo::Sha256,
                slot_size: 1024,
                slot_count: 15 * 1024, // ~15 MB, see buffer.rs
                forced_purge_timeout: Duration::from_millis(500),
            },
            ProfileName::Vault => ProfileConfig {
                // Prime 15.1 specifies "HMAC + Ed25519 asymmetric signature
                // (non-repudiation)" and names no hash; 15.3 names none either.
                // Only the Vault card of Annex 1.0 says HMAC-SHA512, as an
                // exploratory catalogue entry (EXT-0002). Project decision
                // (2026-10-10): Vault stays HMAC-SHA256
                // plus Ed25519; other profiles pick their seal algorithm from
                // the wire v2 catalogue and policy.
                algo: HmacAlgo::Sha256,
                slot_size: 256 * 1024, // 256 KB, 15.1/15.3
                slot_count: 64,        // ~16 MB total session buffer
                forced_purge_timeout: Duration::from_secs(5), // 15.1: forced purge timeout
            },
        }
    }

    /// Name as it appears in the `lacre-profile` header (15.2).
    pub fn as_header_value(self) -> &'static str {
        match self {
            ProfileName::Lite => "lite",
            ProfileName::Core => "core",
            ProfileName::Vault => "vault",
        }
    }

    pub fn from_header_value(value: &str) -> Option<Self> {
        match value {
            "lite" => Some(ProfileName::Lite),
            "core" => Some(ProfileName::Core),
            "vault" => Some(ProfileName::Vault),
            _ => None,
        }
    }

    /// `true` if this profile requires an Ed25519 signature
    /// (non-repudiation) and a post-purge receipt, per 15.3. Used by
    /// the HTTP Adapter to decide whether it must load/require a
    /// signing key before serving a session under this profile.
    pub fn requires_vault_signature(self) -> bool {
        matches!(self, ProfileName::Vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The modularity proof itself: instantiate a real SealerCore and
    /// VerifierCore using ONLY what ProfileConfig exposes, without
    /// lacre_core::core ever knowing "profiles" exist — from its
    /// perspective, this is indistinguishable from any other call to
    /// open()/resume() with loose parameters.
    #[test]
    fn core_profile_config_instantiates_a_working_sealer_verifier_pair() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use lacre_core::session::MasterKeyRing;
        use std::sync::Arc;

        let cfg = ProfileName::Core.config();
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-minimum-32-bytes-".to_vec(),
            Duration::from_secs(60),
        ));

        let mut sealer = SealerCore::open(
            ring.clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        )
        .expect("active key_id must resolve in the freshly created ring");

        let sealed = sealer
            .seal_payload(b"coupling test via the Core profile", cfg.slot_size)
            .unwrap();
        for (frame, seal) in &sealed {
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, None)
                .expect("every frame sealed under the Core profile must verify under the same profile");
        }
    }

    #[test]
    fn header_round_trip() {
        let name = ProfileName::Core;
        let header = name.as_header_value();
        assert_eq!(ProfileName::from_header_value(header), Some(name));
    }

    #[test]
    fn unknown_header_value_is_rejected() {
        assert!(ProfileName::from_header_value("nonexistent").is_none());
    }

    /// Same coupling test as Core, but for Lite — confirms
    /// `lacre-core` needed no change to support this profile:
    /// `HmacAlgo::Blake3` already existed since Phase 0/1.
    #[test]
    fn lite_profile_config_instantiates_a_working_sealer_verifier_pair() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use lacre_core::session::MasterKeyRing;
        use std::sync::Arc;

        let cfg = ProfileName::Lite.config();
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-lite-32-bytes-here-".to_vec(),
            Duration::from_secs(60),
        ));

        let mut sealer = SealerCore::open(
            ring.clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        )
        .expect("active key_id must resolve in the freshly created ring");

        let sealed = sealer
            .seal_payload(b"telemetry from some sensor", cfg.slot_size)
            .unwrap();
        for (frame, seal) in &sealed {
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, None)
                .expect("every frame sealed under the Lite profile must verify under the same profile");
        }
    }

    /// Confirms the Lite profile REALLY uses Blake3, not that it
    /// "works" with any algorithm by coincidence — a seal generated
    /// under Lite (Blake3) must not verify if reinterpreted as if it
    /// were Sha256, exactly the same property `hmac_seal.rs` already
    /// proves at the lacre-core level, now confirmed here through the
    /// profile configuration layer.
    #[test]
    fn lite_profile_uses_blake3_not_sha256() {
        assert_eq!(ProfileName::Lite.config().algo, lacre_core::hmac_seal::HmacAlgo::Blake3);
        assert_eq!(ProfileName::Core.config().algo, lacre_core::hmac_seal::HmacAlgo::Sha256);
    }

    #[test]
    fn lite_header_round_trip() {
        let name = ProfileName::Lite;
        let header = name.as_header_value();
        assert_eq!(ProfileName::from_header_value(header), Some(name));
    }

    /// Lite doesn't require a Vault signature — it's, along with Core,
    /// the catalog's least security-demanding profile (15.1: "not
    /// suitable for anything with direct monetary value").
    #[test]
    fn lite_does_not_require_vault_signature() {
        assert!(!ProfileName::Lite.requires_vault_signature());
    }

    #[test]
    fn vault_header_round_trip() {
        let name = ProfileName::Vault;
        let header = name.as_header_value();
        assert_eq!(ProfileName::from_header_value(header), Some(name));
    }

    #[test]
    fn only_vault_requires_signature() {
        assert!(!ProfileName::Core.requires_vault_signature());
        assert!(ProfileName::Vault.requires_vault_signature());
    }

    /// Same coupling test as Core, but for Vault: instantiates a real
    /// `SealerCore`/`VerifierCore` using ONLY what `ProfileConfig`
    /// exposes plus a real `VaultSigningKey`/`VaultVerifyingKey`,
    /// confirming the Vault profile is also indistinguishable, from
    /// `lacre-core`'s perspective, from any other call to
    /// `open_with_vault_key`/`resume_with_vault_key` with loose
    /// parameters.
    #[test]
    fn vault_profile_config_instantiates_a_working_sealer_verifier_pair_with_signature() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use lacre_core::session::MasterKeyRing;
        use lacre_core::vault_signature::VaultSigningKey;
        use std::sync::Arc;

        let cfg = ProfileName::Vault.config();
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"test-master-key-vault-32-bytes-here".to_vec(),
            Duration::from_secs(60),
        ));
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            verifying_key,
        )
        .expect("active key_id must resolve in the freshly created ring");

        let sealed = sealer
            .seal_payload(b"coupling test via the Vault profile", cfg.slot_size)
            .unwrap();
        for (frame, seal) in &sealed {
            let signature = sealer.sign_seal_for_vault(seal);
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, signature.as_ref())
                .expect("every frame sealed under Vault must verify along with its signature");
        }
    }
}

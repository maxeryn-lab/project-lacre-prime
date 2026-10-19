//! AppState — shared state of the application layer (moved from http_server.rs
//! when the `lacre-domain` crate was split out; no logic changes in the body).
use lacre_core::session::MasterKeyRing;
use lacre_core::vault_signature::{VaultSigningKey, VaultVerifyingKey};
use std::sync::Arc;
use std::time::Duration;

/// Server state shared across all requests. `Clone` is cheap: every
/// field is an `Arc` or a `Copy` value — cloning `AppState` clones
/// reference-counted pointers, not the underlying data.
#[derive(Clone)]
pub struct AppState {
    pub key_ring: Arc<MasterKeyRing>,
    /// Where a `MasterKeyRing` resulting from a completed X25519
    /// handshake lives between `POST /v1/handshake` and a subsequent
    /// `POST /v1/seal`/`POST /v1/verify` that references that same
    /// `session_id` — see `session_store.rs`'s own header comment for
    /// why this needs a store at all.
    pub handshake_sessions: Arc<dyn crate::session_store::SessionStore>,
    pub vault_signing_key: Arc<VaultSigningKey>,
    pub vault_verifying_key: VaultVerifyingKey,
    pub sealer_sessions: Arc<crate::sealer_session_store::SealerSessionStore>,
    /// Where a `VerifierCore` lives between separate `/v1/verify` calls
    /// for the same session, so incremental verification (frames
    /// arriving one at a time) keeps its real `next_expected_index`
    /// instead of it resetting on every call — see
    /// `verifier_session_store.rs`'s own header for the full account of
    /// the gap this closes.
    pub verifier_sessions: Arc<crate::verifier_session_store::VerifierSessionStore>,
    /// Live `ToolchainProfile` episodes between the HTTP requests that
    /// build up a reasoning episode's graph one node at a time — see
    /// `toolchain_session_store.rs`'s own header comment for why this
    /// needs a store at all (unlike `VerifierCore`, a
    /// `ToolchainProfile`'s graph cannot be reconstructed from a
    /// session ID alone).
    pub toolchain_sessions: Arc<crate::toolchain_session_store::ToolchainSessionStore>,
    /// Root of the stateless capability tokens (`capability.rs`).
    pub capabilities: Arc<crate::capability::CapabilityRoot>,
    /// Named rule sets (Guardian / Certifier / Rule Engine) a request may
    /// pick by name; empty unless the deployment loaded some.
    pub rulesets: Arc<crate::rulesets::RuleSets>,
    /// Wire v2: registry, operator policy and quarantine. `None` means the
    /// node speaks wire v1 only (there is no default policy).
    pub seal_runtime: Option<Arc<crate::seal_policy::SealRuntime>>,
    /// Optional admission control the operator configured. `None` means no
    /// limit was configured.
    pub admission: Option<Arc<crate::admission::AdmissionGate>>,
    /// Optional deadline for Seal/Verify, configured by the operator. `None`
    /// means no deadline exists (no default).
    pub request_deadline: Option<Duration>,
    /// Largest request body the HTTP adapter accepts, in bytes. Always set:
    /// `DEFAULT_MAX_BODY_BYTES` unless the operator chose another value.
    pub max_body_bytes: usize,
    /// How often an idle WebSocket connection is sent a Ping, so that a proxy
    /// or balancer with an idle timeout does not cut it.
    pub ws_ping_interval: Duration,
}

/// Default request body limit of the HTTP adapter (2 MiB). It is the value the
/// adapter always had, now written down; changing it is a decision, and a test
/// fixes it.
/// Default WebSocket ping interval: under the 30 s idle timeout that common
/// proxies and balancers ship with.
pub const DEFAULT_WS_PING_INTERVAL: Duration = Duration::from_secs(25);

pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

impl AppState {
    pub fn key_ring(&self) -> &Arc<MasterKeyRing> {
        &self.key_ring
    }

    pub fn handshake_sessions(&self) -> &Arc<dyn crate::session_store::SessionStore> {
        &self.handshake_sessions
    }

    pub fn sealer_sessions(&self) -> &Arc<crate::sealer_session_store::SealerSessionStore> {
        &self.sealer_sessions
    }

    pub fn verifier_sessions(&self) -> &Arc<crate::verifier_session_store::VerifierSessionStore> {
        &self.verifier_sessions
    }

    pub fn toolchain_sessions(
        &self,
    ) -> &Arc<crate::toolchain_session_store::ToolchainSessionStore> {
        &self.toolchain_sessions
    }

    /// Turns wire v2 on with an already validated policy.
    pub fn with_seal_runtime(mut self, runtime: Arc<crate::seal_policy::SealRuntime>) -> Self {
        self.seal_runtime = Some(runtime);
        self
    }

    pub fn with_admission(mut self, gate: Arc<crate::admission::AdmissionGate>) -> Self {
        self.admission = Some(gate);
        self
    }

    pub fn with_request_deadline(mut self, d: Duration) -> Self {
        self.request_deadline = Some(d);
        self
    }

    pub fn request_deadline(&self) -> Option<Duration> {
        self.request_deadline
    }

    pub fn with_max_body_bytes(mut self, n: usize) -> Self {
        self.max_body_bytes = n;
        self
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn with_ws_ping_interval(mut self, d: Duration) -> Self {
        self.ws_ping_interval = d;
        self
    }

    pub fn ws_ping_interval(&self) -> Duration {
        self.ws_ping_interval
    }

    pub fn seal_runtime(&self) -> Option<&Arc<crate::seal_policy::SealRuntime>> {
        self.seal_runtime.as_ref()
    }

    pub fn admission(&self) -> Option<&Arc<crate::admission::AdmissionGate>> {
        self.admission.as_ref()
    }

    pub fn rulesets(&self) -> &Arc<crate::rulesets::RuleSets> {
        &self.rulesets
    }

    pub fn capabilities(&self) -> &Arc<crate::capability::CapabilityRoot> {
        &self.capabilities
    }

    pub fn vault_verifying_key(&self) -> VaultVerifyingKey {
        self.vault_verifying_key
    }

    /// Returns the server's raw signing key bytes — `VaultSigningKey`
    /// doesn't implement `Clone` (see vault_signature.rs), so every
    /// caller that needs its own instance (for example,
    /// `SealerCore::open_with_vault_key`, which consumes the key by
    /// value) reconstructs it from these bytes with
    /// `VaultSigningKey::from_bytes`.
    pub fn vault_signing_key_bytes(&self) -> [u8; 32] {
        self.vault_signing_key.to_bytes()
    }

    /// Purges every store's idle/expired entries —
    /// `handshake_sessions`, `sealer_sessions`, `verifier_sessions`, and
    /// `toolchain_sessions`. Exists so `main.rs` can run a single
    /// periodic sweep across all four without needing to know their
    /// individual types, closing the same "who calls
    /// `purge_expired`" gap that left `SealerSessionStore::purge_expired`,
    /// `SessionStore::purge_expired`, and
    /// `ToolchainSessionStore::purge_expired`/`remove` as
    /// implemented-but-never-invoked dead code — the same shape of gap
    /// found three times before, closed here for all four stores at
    /// once (`verifier_sessions` included from the same commit that
    /// introduces it, rather than repeating the gap a fourth time).
    pub fn purge_all_expired(&self) {
        self.handshake_sessions.purge_expired();
        self.sealer_sessions.purge_expired();
        self.verifier_sessions.purge_expired();
        self.toolchain_sessions.purge_expired();
    }

    /// Convenience constructor for tests in this and other crates.
    pub fn new_for_test(
        key_ring: Arc<MasterKeyRing>,
        handshake_sessions: Arc<dyn crate::session_store::SessionStore>,
        vault_signing_key: VaultSigningKey,
        sealer_sessions: Arc<crate::sealer_session_store::SealerSessionStore>,
    ) -> Self {
        let vault_verifying_key = vault_signing_key.verifying_key();
        AppState {
            key_ring,
            handshake_sessions,
            vault_signing_key: Arc::new(vault_signing_key),
            vault_verifying_key,
            sealer_sessions,
            verifier_sessions: Arc::new(crate::verifier_session_store::VerifierSessionStore::new(
                Duration::from_secs(600),
            )),
            toolchain_sessions: Arc::new(crate::toolchain_session_store::ToolchainSessionStore::new(
                Duration::from_secs(600),
            )),
            capabilities: Arc::new(crate::capability::CapabilityRoot::generate()),
            rulesets: Arc::new(crate::rulesets::RuleSets::empty()),
            seal_runtime: None,
            admission: None,
            request_deadline: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            ws_ping_interval: DEFAULT_WS_PING_INTERVAL,
        }
    }
}


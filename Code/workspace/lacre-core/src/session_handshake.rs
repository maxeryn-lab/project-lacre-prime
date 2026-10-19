//! Session key establishment — Section 8.4, step 1, of the Lacre Prime
//! document.
//!
//! # What the document requires, literally
//!
//! 8.4 specifies a three-layer complementary scheme:
//!   1. Establishment (once per session): ephemeral Diffie-Hellman
//!      exchange (X25519 curve) → produces a shared secret that never
//!      travels over the network.
//!   2. Derivation (once, from the shared secret):
//!      k_session = HKDF(shared_secret, salt=session_id, info="lacre-v1")
//!   3. Operation (per fragment): δᵢ = HMAC(fᵢ ∥ Sᵢ, k_session)
//!
//! This module implements EXCLUSIVELY step 1.
//!
//! # INTEGRATION CORRECTION (made with the real `session.rs` in view,
//! which earlier passes of this module did not have)
//!
//! Step 2 **already exists, complete, in `session.rs`**:
//! `MasterKeyRing::derive_for_sealing`/`derive_for_verifying` call
//! `derive_session_key(key_id, ikm, session_id)`, which executes
//! literally `Hkdf::<Sha256>::new(Some(&session_id.0),
//! ikm).expand(HKDF_INFO, ...)` — that is, `HKDF(ikm,
//! salt=session_id, info=...)`. This is step 2 of 8.4 to the letter
//! (the only difference is that `HKDF_INFO` in `session.rs` is
//! `"lacre-core/v1/session-key"` instead of the literal `"lacre-v1"`
//! from 8.4's prose — a more specific domain context name, not a
//! different mechanism; see RFC 5869 §3.2 on the purpose of the "info"
//! field).
//!
//! **Consequence:** this module must NOT apply HKDF over the DH secret
//! again. Earlier passes of this phase (delivered without `session.rs`
//! in view) implemented `derive_session_key_material` as an additional
//! full HKDF (`Hkdf::new(salt=session_id, secret).expand("lacre-v1")`)
//! — that is exactly risk 3 that both prior closing reports flagged
//! without being able to resolve: feeding that result into
//! `MasterKeyRing::new(key_id, ikm, ...)` would have produced
//! `HKDF(HKDF(secret, session_id, "lacre-v1"), session_id,
//! "lacre-core/v1/session-key")` — double derivation, no longer what
//! 8.4 describes. That method was removed from this file. Instead,
//! `EphemeralSharedSecret` exposes the raw 32 bytes of the DH secret
//! (`into_ikm_bytes`), meant to go directly as the `ikm` parameter of
//! `MasterKeyRing::new`/`MasterKeyRing::rotate` — the only HKDF with
//! `salt=session_id` happens there, exactly once, as 8.4 requires.
//!
//! # Epistemic classification of this piece
//!
//! The document itself classifies 8.4's scheme as a whole as `[CA]`
//! Accepted Knowledge (Appendix C: "TLS 1.3 pattern"), not `[DO]`.
//! This module, therefore, doesn't invent a new mechanism: it applies
//! ephemeral X25519 exactly the way TLS 1.3 does for forward secrecy,
//! with the sole particularity that the result feeds into the HKDF
//! already existing in `session.rs` instead of a TLS context.
//!
//! # Engineering decisions NOT specified by the document
//!
//! 8.4 fixes the algorithm (X25519) and the derivation formula, but
//! does NOT fix:
//!   1. The exact format of handshake messages (which bytes travel, in
//!      what order, over which channel). By definition of 7.4, that's
//!      the responsibility of a transport Adapter — this module limits
//!      itself to producing and consuming public key bytes (32 fixed
//!      bytes, X25519's native size) and producing the resulting
//!      secret. It imposes no HTTP, no framing, no transport at all.
//!   2. Whether there's an "initiator"/"responder" role distinction in
//!      the exchange. Decision made here: there is NONE — X25519 is
//!      symmetric by construction (both parties perform the same DH
//!      operation with their own ephemeral key and the other's public
//!      key), so it's modeled as a single `EphemeralHandshake` type
//!      used identically by both sides, instead of two separate
//!      "initiator"/"responder" types that would duplicate identical
//!      logic unnecessarily. This is a deliberate difference from how
//!      `SealerCore`/`VerifierCore` ARE split into two types (there
//!      the role asymmetry is real: one originates the session, the
//!      other resumes it). Here there's no role asymmetry to justify
//!      one.
//!   3. Who derives the final session key: it was decided, at this
//!      checkpoint, that it's NOT this module — it's `session.rs`,
//!      which already had step 2's complete implementation before
//!      Phase 2 started. This module ends its responsibility at the
//!      raw DH secret.
//!
//! # What this module deliberately does NOT do
//!
//! It doesn't replace `MasterKeyRing` nor duplicate its HKDF.
//! `MasterKeyRing` remains, unchanged, the only component that applies
//! HKDF with `salt = session_id` — this module only produces the 32
//! bytes of `ikm` that used to be passed by hand as a fixed
//! `master_key_bytes` to `MasterKeyRing::new`. The real integration
//! (where the handshake gets called, who builds the resulting
//! `MasterKeyRing`, and how `SealerCore` and `VerifierCore` are forced
//! to share the same already-agreed `session_id`) is resolved in
//! `core.rs`, not in this file — see
//! `open_with_session_key`/`resume_with_session_key` and the
//! corresponding header comment there.

use x25519_dalek::{EphemeralSecret, PublicKey};

/// Length in bytes of an X25519 public key — the curve's native size,
/// not our own choice.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// One party's ephemeral public key in the exchange. Distributed
/// freely (it is, by definition, the public half of the DH); what must
/// never travel is the corresponding private ephemeral key
/// (`EphemeralHandshake`, which deliberately doesn't implement
/// `Clone`/`Debug` — see below). `Debug` here is safe and deliberate:
/// unlike `EphemeralHandshake`/`EphemeralSharedSecret`, this type never
/// contains secret material — it's exactly what already travels in the
/// clear over the network. Also needed so `assert_eq!` compiles in
/// `from_slice`'s tests (a real error found only when compiling
/// against this checkpoint, not caught by the earlier manual review).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralPublicKey([u8; X25519_PUBLIC_KEY_LEN]);

/// Error reconstructing an `EphemeralPublicKey` from variable-length
/// bytes received over a real transport channel.
///
/// # Why this didn't exist in the first delivery and why it's needed
///
/// `from_bytes([u8; 32])` (below) is infallible because the compiler
/// already guarantees the length at compile time — it serves the
/// internal/test case where the caller already has a fixed array. But
/// a real Adapter (7.4) receives bytes from a socket, an HTTP header
/// field, or a gRPC message as a `&[u8]` of NOT guaranteed length: the
/// other end could be corrupted, truncated, or simply hostile. Without
/// this fallible variant, the caller's only option would be a blind
/// `.try_into().unwrap()` before reaching here — exactly the kind of
/// panic at the network trust boundary that 7.4 requires avoiding (the
/// Adapter must delimit bytes without exposing the Core, or its
/// associated capabilities, to a panic inducible by a malicious peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralPublicKeyError {
    /// The number of bytes received isn't exactly 32 — neither more
    /// nor less. The received length is recorded so whoever handles
    /// the error can decide whether the incident is worth logging (a
    /// length of 0 or absurdly large suggests a hostile peer or broken
    /// framing, not a simple bit-flip).
    InvalidLength { received: usize },
}

impl EphemeralPublicKey {
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.0
    }

    /// Infallible construction from an array already validated at
    /// compile time (internal use / tests). For variable-length bytes
    /// coming from a real transport, use `from_slice`.
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_LEN]) -> Self {
        EphemeralPublicKey(bytes)
    }

    /// Fallible construction from an arbitrary-length slice — meant
    /// for the point where an Adapter (7.4) hands over bytes just read
    /// from the network. Rejects any length other than 32 with an
    /// explicit error instead of panicking.
    ///
    /// Deliberate note: like the underlying `x25519_dalek` library
    /// (`PublicKey::from([u8;32])`), this does NOT validate that the
    /// bytes represent a valid curve point, nor does it discard
    /// low-order points — RFC 7748 allows operating on any 32-byte
    /// input by design (X25519 itself is built to be secure even
    /// against this within pure ephemeral Diffie-Hellman's standard
    /// threat model). If Lacre ever needs to explicitly discard
    /// low-order points as an additional safeguard (some higher-level
    /// protocols do — see `SharedSecret::was_contributory()` in
    /// `x25519-dalek`), that's an additional engineering decision to
    /// make explicitly, not something this method should assume
    /// silently.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EphemeralPublicKeyError> {
        let array: [u8; X25519_PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| EphemeralPublicKeyError::InvalidLength {
                received: bytes.len(),
            })?;
        Ok(EphemeralPublicKey(array))
    }
}

/// The shared secret resulting from DH — 8.4 is explicit that it
/// "never travels over the network". Doesn't implement Debug/Clone for
/// the same reason as `SessionState` in `core.rs` and
/// `VaultSigningKey` in `vault_signature.rs`: it's exactly what a
/// memory dump or a careless log would expose, and sharing it via an
/// accidental clone would defeat the forward secrecy property
/// ephemeral X25519 exists to provide.
///
/// # Why this type does NOT derive the session key itself
///
/// An earlier pass of this phase (delivered without the real
/// `session.rs` in view) implemented a `derive_session_key_material`
/// method here that applied its own
/// `Hkdf::new(salt=session_id, secret).expand("lacre-v1")`. With the
/// real `session.rs` confirmed, that method would have produced a
/// double derivation: `MasterKeyRing::derive_for_sealing` ALREADY
/// executes `Hkdf::new(salt=session_id, ikm).expand(HKDF_INFO)` over
/// whatever it receives as `ikm`. Passing it the result of an
/// already-applied HKDF would have produced `HKDF(HKDF(secret, ...),
/// ...)`, which is no longer literally "HKDF(shared_secret,
/// salt=session_id, info='lacre-v1')" as 8.4 requires — a silent
/// deviation from the document's text. This type therefore limits
/// itself to exposing the raw 32 bytes of the DH secret: the only
/// HKDF with `salt=session_id` happens exactly once, inside
/// `MasterKeyRing`.
pub struct EphemeralSharedSecret([u8; 32]);

impl EphemeralSharedSecret {
    /// Exposes the raw DH secret as `ikm` (input key material) ready
    /// to be passed directly to
    /// `MasterKeyRing::new`/`MasterKeyRing::rotate` instead of a
    /// static master key. Consumes `self`: once the bytes are
    /// extracted to build the ring, there's no legitimate reason to
    /// retain the `EphemeralSharedSecret` any longer than necessary —
    /// again, the same "ephemeral, single-use" discipline as the rest
    /// of this module.
    ///
    /// Deliberately named `into_ikm_bytes` (not
    /// `derive_session_key_material`, the earlier pass's name) so the
    /// method name makes clear, at the call site, that this is NOT yet
    /// a session key ready for HMAC — it's input material for the
    /// derivation `MasterKeyRing` does afterward.
    pub fn into_ikm_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Drop for EphemeralSharedSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// One side of an ephemeral X25519 exchange. There's no
/// "initiator"/"responder" distinction — see the justification in this
/// module's header comment, point 2.
///
/// Doesn't implement Debug/Clone: it holds the ephemeral private key
/// (`x25519_dalek::EphemeralSecret` already prevents this at the
/// library level, for the same key-hygiene reason).
pub struct EphemeralHandshake {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralHandshake {
    /// Generates a new ephemeral pair. "Ephemeral" isn't just a name:
    /// this value is designed to be used exactly once and then
    /// discarded — there is no method to serialize the private part,
    /// on purpose.
    ///
    /// Compatibility note NOT verified by a real compilation (see
    /// environment limitation in the closing report): uses
    /// `rand::rngs::OsRng`, same as `vault_signature.rs` already does
    /// for Ed25519, instead of `rand_core::OsRng` as shown in
    /// `x25519-dalek`'s official examples. Both crates (`rand` 0.8 and
    /// `x25519-dalek` 2.x) depend on the `rand_core = "0.6.x"` family
    /// — confirmed against `ed25519-dalek` 2.x's source `Cargo.toml`
    /// (which also pins `rand_core = "0.6.4"`) and against a public
    /// fork of `x25519-dalek` that pins `rand_core = "0.6"` — so
    /// `rand::rngs::OsRng`, which implements `rand_core` 0.6's traits,
    /// should be accepted by `EphemeralSecret::random_from_rng`
    /// without a version conflict. This is a verification by external
    /// documentation, NOT by a real compilation of the crate — it
    /// needs to be confirmed with `cargo build` as soon as this file
    /// gets integrated into the real workspace.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        EphemeralHandshake { secret, public }
    }

    /// The public key to send to the counterparty. How it travels
    /// (message format, channel) is an Adapter's (7.4) responsibility
    /// — this method only hands over the native 32 bytes.
    pub fn public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey(self.public.to_bytes())
    }

    /// Completes the exchange: combines this own ephemeral key with
    /// the counterparty's ephemeral public key received, producing the
    /// shared secret. Consumes `self` because the private ephemeral
    /// key must not be reused after completing an exchange — once
    /// spent, there is no legitimate operation to "recombine" with a
    /// different public key under the same ephemeral secret without
    /// violating the "ephemeral, single-use" property 8.4 explicitly
    /// requires ("shared secret that never travels over the network"
    /// presupposes it's also single-use: reusing the same ephemeral
    /// key across two different sessions would nullify forward secrecy
    /// between those two sessions).
    pub fn complete(self, their_public: EphemeralPublicKey) -> EphemeralSharedSecret {
        // `PublicKey::from([u8; 32])` reconstructs a FOREIGN public key
        // from its raw bytes received over the transport channel —
        // different from the `PublicKey::from(&EphemeralSecret)` used
        // in `public_key()` above to derive one's own public key from
        // one's own secret. These are two different `impl From` of the
        // same library; confusing them would be a type error the
        // compiler would reject, not something that could remain
        // ambiguous in practice.
        let their_public = PublicKey::from(their_public.0);
        let shared = self.secret.diffie_hellman(&their_public);
        EphemeralSharedSecret(*shared.as_bytes())
    }
}

// -----------------------------------------------------------------
// Scope note — written with the real session.rs in view
// -----------------------------------------------------------------
//
// This module resolves 8.4's step 1 in a self-contained, tested way
// (see tests below: two independent `EphemeralHandshake`s that
// exchange public keys produce the SAME raw DH secret on both sides).
//
// Integration with `MasterKeyRing` (step 2, already implemented in
// `session.rs`) and with `SealerCore`/`VerifierCore` (step 3, in
// `core.rs`) is resolved in `core.rs`, not in this file — see
// `SealerCore::open_with_session_key` and
// `VerifierCore::resume_with_session_key`. The three questions the two
// earlier passes of this phase left open for lack of the real
// `session.rs` are answered there:
//
//   1. `MasterKeyRing::derive_for_sealing`/`derive_for_verifying` DO
//      apply HKDF internally over `ikm` — confirmed by reading
//      `derive_session_key` in `session.rs`. That's why this module no
//      longer applies its own HKDF (see this module's and
//      `EphemeralSharedSecret`'s header comments above) — corrected
//      relative to the earlier pass, which did.
//   2. `SessionId::generate()` is a free function in `session.rs`, it
//      doesn't depend on living inside `SealerCore::open` — it can be
//      invoked before the handshake without touching `session.rs`.
//   3. `SealerCore::open` didn't accept an already-agreed
//      `session_id` from outside (it always generated its own
//      internally) — this was the one real gap. `open_with_session_key`
//      was added as a new method (same pattern as
//      `open_with_vault_key`: doesn't break `open`'s existing
//      signature), which does accept it.
//
// Phase 1 (`core.rs`, `vault_signature.rs`, `receipt.rs`,
// `profile_config.rs`) remains unchanged in behavior outside of the
// new methods explicitly added for this integration.

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal hex decoder, no external dependencies — deliberate:
    /// adding `hex-literal` just for one test would violate the
    /// "no unnecessary dependencies" instruction for a benefit an
    /// 8-line helper already covers. Panics on invalid hex, which is
    /// acceptable HERE because it's only used with literal constants
    /// from this same file, never with external data.
    fn hex_to_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "test vector must represent exactly 32 bytes");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .expect("hardcoded test vector must be valid hex");
        }
        out
    }

    /// OFFICIAL test vector from RFC 7748 §6.1 (Langley, Hamburg,
    /// Turner, January 2016) — transcribed and verified character by
    /// character against the primary source
    /// (https://www.rfc-editor.org/rfc/rfc7748.html, section 6.1, "Test
    /// vector"), not quoted from memory nor taken from a search
    /// snippet without cross-checking. Each hex constant below has
    /// exactly 64 characters (32 bytes) — confirmed programmatically
    /// before writing this test, after a first manual transcription
    /// introduced a one-character-missing error per string.
    ///
    /// # Why this uses `x25519_dalek::StaticSecret` and not
    /// `EphemeralHandshake`
    ///
    /// `EphemeralHandshake`/`EphemeralSecret` are DELIBERATELY not
    /// deserializable from fixed bytes — it's the property that
    /// prevents reusing an ephemeral key, and it's correct for
    /// production code. But an RFC test vector requires loading an
    /// exact, known PRIVATE key, which `EphemeralSecret` doesn't allow
    /// by design. `StaticSecret::from([u8;32])` applies the SAME
    /// `clamp_scalar` that `EphemeralSecret` uses internally (confirmed
    /// against `x25519-dalek`'s source code: both types share RFC
    /// 7748 §5's clamping operation), so the mathematical result is
    /// identical — this test verifies the CORRECTNESS OF THE
    /// UNDERLYING LIBRARY that `EphemeralHandshake` wraps, without
    /// needing (or being able) to instantiate `EphemeralHandshake`
    /// with a fixed key. This is an external verification harness, not
    /// a test of `EphemeralHandshake` itself — that distinction is
    /// left explicit so whoever audits this test doesn't assume it
    /// covers more than it does.
    #[test]
    fn rfc7748_section_6_1_test_vector() {
        use x25519_dalek::StaticSecret;

        let alice_private = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public_expected = hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_private = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public_expected = hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_expected = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice_secret = StaticSecret::from(alice_private);
        let alice_public = PublicKey::from(&alice_secret);
        assert_eq!(
            alice_public.to_bytes(),
            alice_public_expected,
            "Alice's public key doesn't match RFC 7748 §6.1"
        );

        let bob_secret = StaticSecret::from(bob_private);
        let bob_public = PublicKey::from(&bob_secret);
        assert_eq!(
            bob_public.to_bytes(),
            bob_public_expected,
            "Bob's public key doesn't match RFC 7748 §6.1"
        );

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(
            alice_shared.as_bytes(),
            &shared_expected,
            "shared secret (Alice's side) doesn't match RFC 7748 §6.1"
        );
        assert_eq!(
            bob_shared.as_bytes(),
            &shared_expected,
            "shared secret (Bob's side) doesn't match RFC 7748 §6.1"
        );
        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "both sides must agree with each other, not just with the vector"
        );
    }

    /// Core X25519 test: two parties that generate their own ephemeral
    /// pair, exchange ONLY the public key, and run `complete` with the
    /// other's public key, must arrive at the SAME shared secret — this
    /// is the basic mathematical property of Diffie-Hellman (g^ab ==
    /// g^ba), not an assumption of ours.
    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let alice = EphemeralHandshake::generate();
        let bob = EphemeralHandshake::generate();

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_secret = alice.complete(bob_public);
        let bob_secret = bob.complete(alice_public);

        // As of this checkpoint, `EphemeralSharedSecret` no longer
        // applies its own HKDF (see this module's header comment) — it
        // exposes the raw DH secret with `into_ikm_bytes`, which is
        // what DH's mathematical property guarantees is identical on
        // both sides.
        let ikm_a = alice_secret.into_ikm_bytes();
        let ikm_b = bob_secret.into_ikm_bytes();

        assert_eq!(ikm_a, ikm_b);
    }

    /// Two different handshake runs (two new ephemeral pairs) must
    /// produce different shared secrets, even if in theory "the same
    /// two parties" talk again — this is exactly forward secrecy: each
    /// session is cryptographically independent of the previous one
    /// because the ephemeral key is never reused.
    #[test]
    fn independent_handshakes_produce_independent_secrets() {
        let alice1 = EphemeralHandshake::generate();
        let bob1 = EphemeralHandshake::generate();
        let alice1_public = alice1.public_key();
        let secret1 = bob1.complete(alice1_public);

        let alice2 = EphemeralHandshake::generate();
        let bob2 = EphemeralHandshake::generate();
        let alice2_public = alice2.public_key();
        let secret2 = bob2.complete(alice2_public);

        assert_ne!(
            secret1.into_ikm_bytes(),
            secret2.into_ikm_bytes(),
            "sessions with independent ephemeral handshakes must never share a secret"
        );
    }

    /// A third party who only observes the two ephemeral public keys
    /// (the only thing that "travels over the network" per 8.4) must
    /// not be able to reconstruct the secret without knowing at least
    /// one of the two private keys. This test can't prove computational
    /// security (that's X25519's own guarantee, already externally
    /// audited as a primitive), but it does confirm that the public key
    /// alone isn't equal to, nor contains in the clear, the secret.
    #[test]
    fn public_key_bytes_differ_from_resulting_shared_secret() {
        let alice = EphemeralHandshake::generate();
        let bob = EphemeralHandshake::generate();
        let alice_public = alice.public_key();
        let bob_public_bytes = bob.public_key().to_bytes();

        let shared = alice
            .complete(EphemeralPublicKey::from_bytes(bob_public_bytes))
            .into_ikm_bytes();

        assert_ne!(shared, alice_public.to_bytes());
        assert_ne!(shared, bob_public_bytes);
    }

    /// Round-trip serialization of the public key — needed because an
    /// Adapter (7.4) will need to transport these bytes over
    /// HTTP/gRPC/etc.
    #[test]
    fn public_key_round_trips_through_bytes() {
        let handshake = EphemeralHandshake::generate();
        let public = handshake.public_key();
        let bytes = public.to_bytes();
        let restored = EphemeralPublicKey::from_bytes(bytes);

        assert_eq!(public.to_bytes(), restored.to_bytes());
    }

    // -------------------------------------------------------------
    // Robustness tests explicitly requested: a real Adapter (7.4)
    // hands over a &[u8] of NOT guaranteed length, not an already
    // compiler-validated [u8;32]. These tests cover exactly the edge
    // where `from_bytes` (infallible, internal use) isn't enough.
    // -------------------------------------------------------------

    /// `from_slice` must reject, with an explicit error and no panic,
    /// bytes shorter than 32 — the case of a message truncated
    /// mid-transport (dropped connection, partial socket read).
    #[test]
    fn from_slice_rejects_truncated_input() {
        let too_short = [0u8; 16];
        let result = EphemeralPublicKey::from_slice(&too_short);

        assert_eq!(
            result,
            Err(EphemeralPublicKeyError::InvalidLength { received: 16 })
        );
    }

    /// `from_slice` must reject, just as explicitly, bytes longer than
    /// 32 — the case of a broken Adapter framing that delivers the next
    /// field stuck to the public key's own.
    #[test]
    fn from_slice_rejects_oversized_input() {
        let too_long = [0u8; 40];
        let result = EphemeralPublicKey::from_slice(&too_long);

        assert_eq!(
            result,
            Err(EphemeralPublicKeyError::InvalidLength { received: 40 })
        );
    }

    /// Explicit edge case: empty input. It shouldn't be treated any
    /// differently from any other incorrect length, but it's tested
    /// separately because it's the most likely case for a connection
    /// that closes before sending anything.
    #[test]
    fn from_slice_rejects_empty_input() {
        let result = EphemeralPublicKey::from_slice(&[]);

        assert_eq!(
            result,
            Err(EphemeralPublicKeyError::InvalidLength { received: 0 })
        );
    }

    /// `from_slice` with exactly 32 bytes must accept and produce the
    /// same value as `from_bytes` with the equivalent array — confirms
    /// the fallible variant doesn't introduce any additional
    /// transformation over the happy path, it only validates the
    /// length.
    #[test]
    fn from_slice_accepts_exact_length_and_matches_from_bytes() {
        let handshake = EphemeralHandshake::generate();
        let bytes = handshake.public_key().to_bytes();

        let via_from_bytes = EphemeralPublicKey::from_bytes(bytes);
        let via_from_slice = EphemeralPublicKey::from_slice(&bytes)
            .expect("exactly 32 bytes must be accepted");

        assert_eq!(via_from_bytes.to_bytes(), via_from_slice.to_bytes());
    }

    // Note: the HKDF boundary tests (255*32 = 8160 bytes, RFC 5869
    // §2.3) that existed in the earlier pass were removed along with
    // `derive_session_key_material` — that HKDF no longer lives in
    // this module. `session.rs::derive_session_key` still uses
    // `.expect()` on that boundary, justified there because
    // `SESSION_KEY_LEN` is a fixed 32-byte constant, well below the
    // limit, with no variable `out_len` that could trigger it — see
    // `session.rs` for that comment.
}

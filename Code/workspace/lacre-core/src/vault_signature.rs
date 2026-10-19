//! Ed25519 signature for non-repudiation — Sections 9.5 and 15.3 of
//! the Lacre Prime document.
//!
//! # What this solves that HMAC doesn't
//!
//! 15.3 is explicit: a shared-key HMAC certifies integrity and
//! authenticity to a third party who doesn't possess the key, but it
//! does *not* certify origin against the counterparty who does possess
//! it — either of the two parties could have generated the seal.
//! Asymmetric signature solves that case: only whoever holds the
//! private key can produce a valid signature, so not even the
//! verifier (who only has the public key) could have forged it.
//!
//! # Engineering decision not specified by the document
//!
//! The document (9.5) fixes the algorithm (Ed25519) and the reason,
//! but doesn't specify WHAT exactly gets signed. This implementation
//! signs the fragment's `Seal` (HMAC), not the fragment itself — our
//! own decision, not the document's, for two reasons:
//!   1. The HMAC already cryptographically depends on the complete
//!      fragment (Block 8.2: δᵢ = HMAC(fᵢ ∥ Sᵢ, k)), so signing the
//!      HMAC transitively certifies the fragment without processing it
//!      in full a second time.
//!   2. The resulting signature's size is fixed (64 bytes) regardless
//!      of the fragment's size — consistent with A2 (the seal lives in
//!      the header, of bounded size, not proportional to the body).
//!
//! If this decision proves incorrect in practice (for example, if a
//! real use case needs the signature to cover the fragment
//! independently of the HMAC), the document gets updated to reflect
//! what was learned — not the other way around.

use crate::hmac_seal::Seal;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const VAULT_SIGNATURE_LEN: usize = 64;

/// The sealer's Ed25519 private key. Doesn't implement Debug/Clone: it
/// must never end up in a log, and implicitly sharing it via a
/// careless clone would be exactly the kind of mistake non-repudiation
/// is meant to make impossible in the first place.
pub struct VaultSigningKey(SigningKey);

impl VaultSigningKey {
    /// Generates a new key. Ed25519 key generation doesn't require
    /// randomness of any special quality beyond what any standard
    /// CSPRNG already provides (9.5: unlike ECDSA, Ed25519 doesn't
    /// depend on high-quality randomness during SIGNING — key
    /// generation itself still needs a good CSPRNG, which is what
    /// rand::thread_rng() provides).
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        VaultSigningKey(SigningKey::generate(&mut csprng))
    }

    /// Reconstructs a signing key from its raw 32 bytes — added during
    /// the HTTP Adapter phase (7.4/15.3): an Adapter needs to persist
    /// the server's signing key across process restarts, not generate
    /// a new one every time it starts up. Generating a new one on
    /// every startup would break the long-term non-repudiation purpose
    /// 15.3 describes: an external verifier who already knows a
    /// session's public key from before would no longer be able to
    /// verify signatures made after a server restart. Symmetric to
    /// `VaultVerifyingKey::from_bytes`, which already existed.
    ///
    /// Doesn't implement `Debug` over the input bytes anywhere in the
    /// signature — the caller is responsible for not logging the value
    /// it passes to this function, the same way it's already
    /// responsible for that with any other secret
    /// (`LACRE_MASTER_KEY`, for example).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        VaultSigningKey(SigningKey::from_bytes(bytes))
    }

    /// Exposes the key's raw 32 bytes — needed so an Adapter can
    /// persist it (for example, in an environment variable or a
    /// configuration file) across restarts. The caller takes on the
    /// same secret-handling responsibility it already has over any
    /// other key material in the project: this method doesn't decide
    /// where the result ends up.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verifying_key(&self) -> VaultVerifyingKey {
        VaultVerifyingKey(self.0.verifying_key())
    }

    /// Signs a fragment's `Seal` (HMAC) — not the fragment itself, see
    /// the reasoning in this module's own header comment.
    pub fn sign_seal(&self, seal: &Seal) -> VaultSignature {
        VaultSignature(self.0.sign(&seal.0))
    }
}

/// The verifier's Ed25519 public key — distributed freely, unlike
/// `VaultSigningKey`.
#[derive(Clone, Copy)]
pub struct VaultVerifyingKey(VerifyingKey);

impl VaultVerifyingKey {
    pub fn verify_seal(&self, seal: &Seal, signature: &VaultSignature) -> bool {
        self.0.verify(&seal.0, &signature.0).is_ok()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, VaultKeyError> {
        VerifyingKey::from_bytes(bytes)
            .map(VaultVerifyingKey)
            .map_err(|_| VaultKeyError::InvalidPublicKeyBytes)
    }
}

#[derive(Debug)]
pub enum VaultKeyError {
    InvalidPublicKeyBytes,
}

/// A signature over a `Seal`, not over the fragment. Fixed size (64
/// bytes) independent of the signed fragment's size.
#[derive(Clone, Copy)]
pub struct VaultSignature(Signature);

impl VaultSignature {
    pub fn to_bytes(&self) -> [u8; VAULT_SIGNATURE_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; VAULT_SIGNATURE_LEN]) -> Self {
        VaultSignature(Signature::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal() -> Seal {
        Seal([0x42u8; SEAL_LEN])
    }

    #[test]
    fn valid_signature_verifies() {
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let seal = dummy_seal();

        let signature = signing_key.sign_seal(&seal);
        assert!(verifying_key.verify_seal(&seal, &signature));
    }

    /// Non-repudiation in practice: a signature made with one key
    /// doesn't verify under another key's public key — unlike a
    /// shared-key HMAC, there's no way the verifier (who only has the
    /// public key) could have produced this signature itself.
    #[test]
    fn signature_from_different_key_fails_verification() {
        let signer_a = VaultSigningKey::generate();
        let signer_b = VaultSigningKey::generate();
        let seal = dummy_seal();

        let signature = signer_a.sign_seal(&seal);
        let verifying_key_b = signer_b.verifying_key();

        assert!(!verifying_key_b.verify_seal(&seal, &signature));
    }

    /// Block IV test 1, extended to the signature: a seal tampered
    /// with after signing must also fail signature verification, not
    /// just HMAC verification.
    #[test]
    fn tampered_seal_fails_signature_verification() {
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let original_seal = dummy_seal();
        let signature = signing_key.sign_seal(&original_seal);

        let mut tampered_seal = original_seal;
        tampered_seal.0[0] ^= 0x01;

        assert!(!verifying_key.verify_seal(&tampered_seal, &signature));
    }

    #[test]
    fn verifying_key_round_trips_through_bytes() {
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_bytes();
        let restored = VaultVerifyingKey::from_bytes(&bytes).unwrap();

        let seal = dummy_seal();
        let signature = signing_key.sign_seal(&seal);
        assert!(restored.verify_seal(&seal, &signature));
    }

    /// `VaultSigningKey::from_bytes`/`to_bytes` must produce exactly
    /// the same private key — not just "some valid key" — because the
    /// real use case (persisting the server's signing key across
    /// restarts, see header comment) requires a verifier who already
    /// knows the public key from before a restart to keep being able
    /// to verify signatures made after that restart.
    #[test]
    fn signing_key_round_trips_through_bytes_producing_the_same_key() {
        let original = VaultSigningKey::generate();
        let original_verifying_key_bytes = original.verifying_key().to_bytes();
        let seal = dummy_seal();
        let signature_before_round_trip = original.sign_seal(&seal);

        let bytes = original.to_bytes();
        let restored = VaultSigningKey::from_bytes(&bytes);

        // The public key derived from the restored key must be
        // IDENTICAL to the original — not a different key that also
        // happens to be valid.
        assert_eq!(restored.verifying_key().to_bytes(), original_verifying_key_bytes);

        // A signature made with the restored key must verify under the
        // original public key, and vice versa.
        let signature_after_round_trip = restored.sign_seal(&seal);
        let verifying_key = original.verifying_key();
        assert!(verifying_key.verify_seal(&seal, &signature_before_round_trip));
        assert!(verifying_key.verify_seal(&seal, &signature_after_round_trip));
    }
}

//! Signature schemes for the vault profile (wire v2, E5). Same rule as the
//! seal catalogue: an adapter over a maintained crate, never a primitive
//! written here, and outside the Core.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lacre_core::suite::{SignInput, SignatureScheme, Status};

/// Ed25519 (RFC 8032), pure, over the canonical `SignInput`. Verification is
/// strict: malleable encodings and small-order keys are refused.
pub struct Ed25519;

impl SignatureScheme for Ed25519 {
    fn id(&self) -> &'static str {
        "ed25519"
    }
    fn status(&self) -> Status {
        Status::Standard
    }
    fn security_bits(&self) -> u16 {
        128
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn secret_key_len(&self) -> usize {
        32
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn public_from_secret(&self, secret: &[u8]) -> Option<Vec<u8>> {
        let s: [u8; 32] = secret.try_into().ok()?;
        Some(SigningKey::from_bytes(&s).verifying_key().to_bytes().to_vec())
    }
    fn sign(&self, secret: &[u8], input: &SignInput<'_>) -> Vec<u8> {
        let Ok(s) = <[u8; 32]>::try_from(secret) else {
            return vec![0u8; 64];
        };
        SigningKey::from_bytes(&s).sign(&input.to_vec()).to_bytes().to_vec()
    }
    fn verify(&self, public: &[u8], input: &SignInput<'_>, signature: &[u8]) -> bool {
        let Ok(p) = <[u8; 32]>::try_from(public) else { return false };
        let Ok(sg) = <[u8; 64]>::try_from(signature) else { return false };
        let Ok(vk) = VerifyingKey::from_bytes(&p) else { return false };
        vk.verify_strict(&input.to_vec(), &Signature::from_bytes(&sg)).is_ok()
    }
}

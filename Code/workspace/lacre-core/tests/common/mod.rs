//! Reference `SealMac` implementations used only by tests. They live outside
//! `src/` on purpose: the Core does not know any primitive of the catalogue.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::suite::{
    xof_params, CostClass, OutputKind, SealInput, SealMac, SignInput, SignatureScheme, Status, SuiteDescriptor,
    ValidatedSuite,
};
use sha2::{Sha256, Sha512};

pub struct HmacSha256Ref;
impl SealMac for HmacSha256Ref {
    fn id(&self) -> &'static str { "hmac-sha256" }
    fn status(&self) -> Status { Status::Standard }
    fn cost(&self) -> CostClass { CostClass::Light }
    fn security_bits(&self) -> u16 { 128 }
    fn key_len(&self) -> usize { 32 }
    fn output(&self) -> OutputKind { OutputKind::Fixed(32) }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
        for p in input.parts() { m.update(p); }
        out.copy_from_slice(&m.finalize().into_bytes());
    }
}

pub struct HmacSha512Ref;
impl SealMac for HmacSha512Ref {
    fn id(&self) -> &'static str { "hmac-sha512" }
    fn status(&self) -> Status { Status::Standard }
    fn cost(&self) -> CostClass { CostClass::Standard }
    fn security_bits(&self) -> u16 { 256 }
    fn key_len(&self) -> usize { 64 }
    fn output(&self) -> OutputKind { OutputKind::Fixed(64) }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        let mut m = Hmac::<Sha512>::new_from_slice(key).unwrap();
        for p in input.parts() { m.update(p); }
        out.copy_from_slice(&m.finalize().into_bytes());
    }
}

/// Keyed BLAKE3 with extendable output: a variable-length seal.
pub struct Blake3XofRef;
impl SealMac for Blake3XofRef {
    fn id(&self) -> &'static str { "blake3-keyed-xof" }
    fn status(&self) -> Status { Status::Standard }
    fn cost(&self) -> CostClass { CostClass::Light }
    fn security_bits(&self) -> u16 { 128 }
    fn key_len(&self) -> usize { 32 }
    fn output(&self) -> OutputKind { OutputKind::Xof { min: 16, max: 1024 } }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        let key: [u8; 32] = key.try_into().unwrap();
        let mut h = blake3::Hasher::new_keyed(&key);
        for p in input.parts() { h.update(p); }
        h.finalize_xof().fill(out);
    }
}

/// Ed25519 over `ed25519-dalek`, used only by tests. Lives outside `src/`: the
/// Core does not name a scheme (the catalogue's is `lacre_seals::signatures`).
pub struct Ed25519Ref;
impl SignatureScheme for Ed25519Ref {
    fn id(&self) -> &'static str { "ed25519" }
    fn status(&self) -> Status { Status::Standard }
    fn security_bits(&self) -> u16 { 128 }
    fn public_key_len(&self) -> usize { 32 }
    fn secret_key_len(&self) -> usize { 32 }
    fn signature_len(&self) -> usize { 64 }
    fn public_from_secret(&self, secret: &[u8]) -> Option<Vec<u8>> {
        let s: [u8; 32] = secret.try_into().ok()?;
        Some(ed25519_dalek::SigningKey::from_bytes(&s).verifying_key().to_bytes().to_vec())
    }
    fn sign(&self, secret: &[u8], input: &SignInput<'_>) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let s: [u8; 32] = secret.try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&s).sign(&input.to_vec()).to_bytes().to_vec()
    }
    fn verify(&self, public: &[u8], input: &SignInput<'_>, signature: &[u8]) -> bool {
        let Ok(p) = <[u8; 32]>::try_from(public) else { return false };
        let Ok(sg) = <[u8; 64]>::try_from(signature) else { return false };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&p) else { return false };
        vk.verify_strict(&input.to_vec(), &ed25519_dalek::Signature::from_bytes(&sg)).is_ok()
    }
}

pub fn suite_for(mac: Arc<dyn SealMac>, params: Vec<u8>, signature: Option<&str>) -> ValidatedSuite {
    let d = SuiteDescriptor::new(mac.id(), params, signature).unwrap();
    let scheme: Option<Arc<dyn SignatureScheme>> = signature.map(|_| Arc::new(Ed25519Ref) as Arc<dyn SignatureScheme>);
    ValidatedSuite::with_signature(d, mac, scheme).unwrap()
}

pub fn sha256_suite() -> ValidatedSuite { suite_for(Arc::new(HmacSha256Ref), vec![], None) }
pub fn sha512_suite() -> ValidatedSuite { suite_for(Arc::new(HmacSha512Ref), vec![], None) }
pub fn xof_suite(tag_len: u16) -> ValidatedSuite { suite_for(Arc::new(Blake3XofRef), xof_params(tag_len), None) }

pub fn ring() -> Arc<MasterKeyRing> {
    Arc::new(MasterKeyRing::new(0, b"test-master-key-minimum-32-bytes-".to_vec(), Duration::from_secs(60)))
}

pub fn sid(b: u8) -> SessionId { SessionId([b; 16]) }

/// A fixed test secret key and its public key.
pub fn vault_secret() -> [u8; 32] { [5u8; 32] }
pub fn vault_public() -> Vec<u8> { Ed25519Ref.public_from_secret(&vault_secret()).unwrap() }
pub fn signed_suite() -> ValidatedSuite { suite_for(Arc::new(HmacSha256Ref), vec![], Some("ed25519")) }

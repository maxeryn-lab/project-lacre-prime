//! Thin adapters. Each `fn x(key, parts, out)` feeds `parts` to the
//! underlying MAC in order and writes exactly `out.len()` bytes (the Core
//! sized `out` from the suite).

use blake2::Blake2bMac512;
use hmac::{Hmac, Mac};
use lacre_core::suite::{CostClass, OutputKind, SealInput, SealMac, Status};
use sha2::{Sha256, Sha512};
use sha3::Sha3_512;

pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    out.copy_from_slice(&m.finalize().into_bytes());
}

pub(crate) fn hmac_sha512(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut m = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    out.copy_from_slice(&m.finalize().into_bytes());
}

pub(crate) fn hmac_sha3_512(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut m = Hmac::<Sha3_512>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    out.copy_from_slice(&m.finalize().into_bytes());
}

pub(crate) fn blake2b_keyed(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut m = <Blake2bMac512 as Mac>::new_from_slice(key).expect("BLAKE2b key is 1..=64 bytes");
    for p in parts {
        m.update(p);
    }
    out.copy_from_slice(&m.finalize().into_bytes());
}

/// Keyed BLAKE3; fills `out` from the extendable output (at 32 bytes it is the
/// ordinary keyed hash).
pub(crate) fn blake3_keyed(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let key: [u8; 32] = key.try_into().expect("BLAKE3 key is 32 bytes");
    let mut h = blake3::Hasher::new_keyed(&key);
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().fill(out);
}

pub(crate) fn aes_cmac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut m = <cmac::Cmac<aes::Aes256> as Mac>::new_from_slice(key).expect("AES-256 key is 32 bytes");
    for p in parts {
        m.update(p);
    }
    out.copy_from_slice(&m.finalize().into_bytes());
}

#[cfg(feature = "legacy-seals")]
pub(crate) fn hmac_sha1(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut m = Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    out.copy_from_slice(&m.finalize().into_bytes());
}

macro_rules! algorithm {
    ($(#[$doc:meta])* $name:ident, $id:literal, $status:expr, $cost:expr, $bits:expr, $key_len:expr, $output:expr, $f:path) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $name;

        impl SealMac for $name {
            fn id(&self) -> &'static str { $id }
            fn status(&self) -> Status { $status }
            fn cost(&self) -> CostClass { $cost }
            fn security_bits(&self) -> u16 { $bits }
            fn key_len(&self) -> usize { $key_len }
            fn output(&self) -> OutputKind { $output }
            fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
                $f(key, &input.parts(), out)
            }
        }
    };
}

algorithm!(
    /// HMAC-SHA-256 (RFC 2104, FIPS 198-1). The wire v1 seal.
    HmacSha256, "hmac-sha256", Status::Standard, CostClass::Light, 128, 32, OutputKind::Fixed(32), hmac_sha256
);
algorithm!(
    /// HMAC-SHA-512.
    HmacSha512, "hmac-sha512", Status::Standard, CostClass::Standard, 256, 64, OutputKind::Fixed(64), hmac_sha512
);
algorithm!(
    /// HMAC-SHA3-512 (not the native SHA-3 keyed mode: HMAC over SHA3-512).
    HmacSha3_512, "hmac-sha3-512", Status::Standard, CostClass::Standard, 256, 64, OutputKind::Fixed(64), hmac_sha3_512
);
algorithm!(
    /// BLAKE2b keyed mode with a 64-byte key and 64-byte output (RFC 7693).
    Blake2bKeyed, "blake2b-keyed", Status::Standard, CostClass::Light, 256, 64, OutputKind::Fixed(64), blake2b_keyed
);
algorithm!(
    /// BLAKE3 keyed hash with extendable output: a seal of 16..=1024 bytes
    /// chosen by the session's parameters. Not a truncation of another id.
    Blake3KeyedXof, "blake3-keyed-xof", Status::Standard, CostClass::Light, 128, 32, OutputKind::Xof { min: 16, max: 1024 }, blake3_keyed
);
algorithm!(
    /// AES-256-CMAC (NIST SP 800-38B, RFC 4493). 128-bit tag.
    Aes256Cmac, "aes-cmac", Status::Standard, CostClass::Light, 128, 32, OutputKind::Fixed(16), aes_cmac
);
#[cfg(feature = "legacy-seals")]
algorithm!(
    /// HMAC-SHA-1. Historical interoperability only; blocked by default policy.
    HmacSha1, "hmac-sha1", Status::Legacy, CostClass::Light, 80, 20, OutputKind::Fixed(20), hmac_sha1
);

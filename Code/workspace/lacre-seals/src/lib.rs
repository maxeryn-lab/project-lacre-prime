//! Catalogue of `SealMac` algorithms (wire v2). Outside the Core: the Core
//! never names a primitive, and a registry is composed from this crate at
//! compile time by whoever builds the binary.
//!
//! Every algorithm is an adapter over a maintained crate; none implements a
//! primitive. The one construction assembled here, KMAC256, is built on the
//! cSHAKE of the `sha3` crate, is marked `Experimental`, and is included only
//! because it reproduces the official NIST SP 800-185 sample.
//!
//! BLAKE3 appears once, as `blake3-keyed-xof`: with `tag_len = 32` it is exactly
//! the ordinary 32-byte keyed hash, and a second id for the same function is
//! rejected by the conformance suite as an alias.
//!
//! Which algorithms an operator *allows* is policy (lacre-domain, E4), not
//! catalogue: `Legacy` entries exist only behind the `legacy-seals` feature
//! and are blocked by the default policy even then.
#![forbid(unsafe_code)]

mod algorithms;
mod kmac;
pub mod signatures;

use std::sync::Arc;

use lacre_core::suite::{SealMac, SignatureScheme};

pub use algorithms::{
    Aes256Cmac, Blake2bKeyed, Blake3KeyedXof, HmacSha256, HmacSha3_512, HmacSha512,
};
#[cfg(feature = "legacy-seals")]
pub use algorithms::HmacSha1;
pub use kmac::Kmac256;

/// Every algorithm compiled into this build, standard first.
pub fn all() -> Vec<Arc<dyn SealMac>> {
    #[allow(unused_mut)]
    let mut v: Vec<Arc<dyn SealMac>> = vec![
        Arc::new(HmacSha256),
        Arc::new(HmacSha512),
        Arc::new(HmacSha3_512),
        Arc::new(Blake2bKeyed),
        Arc::new(Blake3KeyedXof),
        Arc::new(Aes256Cmac),
        Arc::new(Kmac256),
    ];
    #[cfg(feature = "legacy-seals")]
    v.push(Arc::new(HmacSha1));
    v
}

/// The algorithm with this id, if it is compiled into this build.
pub fn find(id: &str) -> Option<Arc<dyn SealMac>> {
    all().into_iter().find(|m| m.id() == id)
}

/// The primitive over an arbitrary message, with no Lacre framing. Exists so
/// that official known-answer vectors (RFCs, NIST, upstream suites) can be
/// checked against the very code the adapters call. `s` is KMAC's
/// customization string and is ignored by the other algorithms.
pub fn raw(id: &str, key: &[u8], message: &[u8], s: &[u8], out: &mut [u8]) -> Result<(), String> {
    match id {
        "hmac-sha256" => algorithms::hmac_sha256(key, &[message], out),
        "hmac-sha512" => algorithms::hmac_sha512(key, &[message], out),
        "hmac-sha3-512" => algorithms::hmac_sha3_512(key, &[message], out),
        "blake2b-keyed" => algorithms::blake2b_keyed(key, &[message], out),
        "blake3-keyed-xof" => algorithms::blake3_keyed(key, &[message], out),
        "aes-cmac" => algorithms::aes_cmac(key, &[message], out),
        "kmac256" => kmac::kmac256(key, s, &[message], out),
        #[cfg(feature = "legacy-seals")]
        "hmac-sha1" => algorithms::hmac_sha1(key, &[message], out),
        other => return Err(format!("unknown algorithm {other}")),
    }
    Ok(())
}

/// Every signature scheme compiled into this build.
pub fn signatures() -> Vec<Arc<dyn SignatureScheme>> {
    vec![Arc::new(signatures::Ed25519)]
}

/// The signature scheme with this id, if it is compiled into this build.
pub fn find_signature(id: &str) -> Option<Arc<dyn SignatureScheme>> {
    signatures().into_iter().find(|s| s.id() == id)
}

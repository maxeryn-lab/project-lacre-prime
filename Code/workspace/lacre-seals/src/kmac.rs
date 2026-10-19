//! KMAC256 (NIST SP 800-185) assembled on the `sha3` crate's cSHAKE256.
//! Experimental: kept only while it reproduces the official sample; see
//! `tests/official_vectors.rs`.

use lacre_core::suite::{CostClass, OutputKind, SealInput, SealMac, Status};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

/// Customization string of the Lacre algorithm (`S` in SP 800-185).
pub const LACRE_S: &[u8] = b"lacre/v2/seal";
const RATE: usize = 136; // cSHAKE256 rate in bytes

fn left_encode(x: usize) -> Vec<u8> {
    let be = (x as u64).to_be_bytes();
    let skip = be.iter().take_while(|&&b| b == 0).count().min(7);
    let n = &be[skip..];
    let mut v = vec![n.len() as u8];
    v.extend_from_slice(n);
    v
}

fn right_encode(x: usize) -> Vec<u8> {
    let be = (x as u64).to_be_bytes();
    let skip = be.iter().take_while(|&&b| b == 0).count().min(7);
    let n = &be[skip..];
    let mut v = n.to_vec();
    v.push(n.len() as u8);
    v
}

fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut v = left_encode(s.len() * 8);
    v.extend_from_slice(s);
    v
}

fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut z = left_encode(w);
    z.extend_from_slice(x);
    while !z.len().is_multiple_of(w) {
        z.push(0);
    }
    z
}

/// KMAC256(K, X, L, S) with `X` given as consecutive parts and `L = 8·out.len()`.
pub(crate) fn kmac256(key: &[u8], s: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut h = CShake256::from_core(CShake256Core::new_with_function_name(b"KMAC", s));
    h.update(&bytepad(&encode_string(key), RATE));
    for p in parts {
        h.update(p);
    }
    h.update(&right_encode(out.len() * 8));
    h.finalize_xof().read(out);
}

/// KMAC256 as a variable-length seal (16..=1024 bytes), key 32 bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kmac256;

impl SealMac for Kmac256 {
    fn id(&self) -> &'static str {
        "kmac256"
    }
    fn status(&self) -> Status {
        Status::Experimental
    }
    fn cost(&self) -> CostClass {
        CostClass::Light
    }
    fn security_bits(&self) -> u16 {
        256
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output(&self) -> OutputKind {
        OutputKind::Xof { min: 16, max: 1024 }
    }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        kmac256(key, LACRE_S, &input.parts(), out)
    }
}

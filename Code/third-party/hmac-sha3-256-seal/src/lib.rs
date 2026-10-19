//! HMAC-SHA3-256 as a Lacre seal algorithm, outside the production workspace.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use lacre_core::suite::{CostClass, OutputKind, SealInput, SealMac, Status};
use sha3::Sha3_256;

pub struct HmacSha3_256;

impl SealMac for HmacSha3_256 {
    fn id(&self) -> &'static str {
        "hmac-sha3-256"
    }
    // A third party does not declare `standard`: that word is given by Lacre's catalogue.
    fn status(&self) -> Status {
        Status::Experimental
    }
    fn cost(&self) -> CostClass {
        CostClass::Light
    }
    fn security_bits(&self) -> u16 {
        128
    }
    fn key_len(&self) -> usize {
        32
    }
    fn output(&self) -> OutputKind {
        OutputKind::Fixed(32)
    }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        let mut m = Hmac::<Sha3_256>::new_from_slice(key).expect("HMAC accepts any key length");
        for part in input.parts() {
            m.update(part);
        }
        out.copy_from_slice(&m.finalize().into_bytes());
    }
}

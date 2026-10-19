//! Capability tokens — the authentication layer.
//!
//! Before this module the `session_id` was the only capability: whoever
//! knew it could verify, add Toolchain nodes, and `ack` Vault fragments.
//! Now the `session_id` only *names* a session; every operation that acts
//! on one must present a token of the right **scope**, and tokens are
//! unrelated to the id (an HMAC under a server secret), so seeing an id in
//! a log or a URL grants nothing.
//!
//! * `Write`  — the sender: continue a handshake session, add Toolchain
//!   nodes, read Vault receipts (the sender's proof that the receiver purged).
//! * `Verify` — whoever checks integrity: `verify`, Toolchain `verify`.
//! * `Ack`    — the receiver: confirm (purge) Vault fragments.
//!
//! Tokens are **stateless**: `HMAC-SHA256(root, domain ‖ scope ‖ session_id)`.
//! No per-session storage (nothing for an attacker to exhaust), identical
//! across the verifier and the sealer if they share the root
//! (`LACRE_CAPABILITY_KEY`), and a token for one session or scope is
//! useless for another. Checking is constant-time. A failed check never
//! says *why* (unknown session, wrong scope and wrong token look alike),
//! so there is no existence oracle.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const DOMAIN: &[u8] = b"lacre-domain/v1/capability";

/// What a token allows. The scope is part of the HMAC input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Write,
    Verify,
    Ack,
}

impl Scope {
    fn label(self) -> &'static [u8] {
        match self {
            Scope::Write => b"write",
            Scope::Verify => b"verify",
            Scope::Ack => b"ack",
        }
    }
}

/// The server secret every token derives from. Wiped on drop.
pub struct CapabilityRoot {
    key: [u8; 32],
}

impl Drop for CapabilityRoot {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl CapabilityRoot {
    pub fn from_bytes(key: [u8; 32]) -> Self {
        CapabilityRoot { key }
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        CapabilityRoot { key }
    }

    fn mac(&self, scope: Scope, session_id: &[u8; 16]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(DOMAIN);
        mac.update(&[0]);
        mac.update(scope.label());
        mac.update(&[0]);
        mac.update(session_id);
        let out = mac.finalize().into_bytes();
        let mut t = [0u8; 32];
        t.copy_from_slice(&out);
        t
    }

    /// The token for `(scope, session_id)`, hex-encoded.
    pub fn token_hex(&self, scope: Scope, session_id: &[u8; 16]) -> String {
        hex::encode(self.mac(scope, session_id))
    }

    /// Constant-time check of a presented token. `None`, bad hex, wrong
    /// length, wrong scope and wrong session all return `false`.
    pub fn check(&self, scope: Scope, session_id: &[u8; 16], presented_hex: Option<&str>) -> bool {
        let Some(p) = presented_hex else { return false };
        let Ok(bytes) = hex::decode(p.trim()) else { return false };
        let expected = self.mac(scope, session_id);
        bytes.len() == 32 && bool::from(expected.ct_eq(&bytes[..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: [u8; 16] = [7u8; 16];

    #[test]
    fn a_token_verifies_only_for_its_own_scope_and_session() {
        let root = CapabilityRoot::from_bytes([1u8; 32]);
        for scope in [Scope::Write, Scope::Verify, Scope::Ack] {
            let t = root.token_hex(scope, &SID);
            assert!(root.check(scope, &SID, Some(&t)));
            for other in [Scope::Write, Scope::Verify, Scope::Ack] {
                if other != scope {
                    assert!(!root.check(other, &SID, Some(&t)), "{scope:?} token accepted as {other:?}");
                }
            }
            assert!(!root.check(scope, &[8u8; 16], Some(&t)), "token accepted for another session");
        }
    }

    #[test]
    fn the_three_scopes_give_three_different_tokens() {
        let root = CapabilityRoot::from_bytes([1u8; 32]);
        let a = root.token_hex(Scope::Write, &SID);
        let b = root.token_hex(Scope::Verify, &SID);
        let c = root.token_hex(Scope::Ack, &SID);
        assert!(a != b && b != c && a != c);
    }

    #[test]
    fn a_different_root_gives_different_tokens() {
        let r1 = CapabilityRoot::from_bytes([1u8; 32]);
        let r2 = CapabilityRoot::from_bytes([2u8; 32]);
        let t = r1.token_hex(Scope::Verify, &SID);
        assert!(!r2.check(Scope::Verify, &SID, Some(&t)));
    }

    #[test]
    fn malformed_or_missing_tokens_are_refused() {
        let root = CapabilityRoot::from_bytes([1u8; 32]);
        let t = root.token_hex(Scope::Write, &SID);
        assert!(!root.check(Scope::Write, &SID, None));
        assert!(!root.check(Scope::Write, &SID, Some("")));
        assert!(!root.check(Scope::Write, &SID, Some("zz")));
        assert!(!root.check(Scope::Write, &SID, Some(&t[..62])), "truncated token accepted");
        assert!(!root.check(Scope::Write, &SID, Some(&format!("{t}00"))), "extended token accepted");
        let mut flipped = t.clone().into_bytes();
        flipped[0] = if flipped[0] == b'0' { b'1' } else { b'0' };
        assert!(!root.check(Scope::Write, &SID, Some(std::str::from_utf8(&flipped).unwrap())));
    }

    /// Known-answer vector, computed independently in Python
    /// (hmac/sha256), so the derivation is a fixed contract, not
    /// whatever this file happens to do.
    #[test]
    fn known_answer_vector_matches_independent_python() {
        let root = CapabilityRoot::from_bytes([1u8; 32]);
        assert_eq!(root.token_hex(Scope::Write, &SID), KAT_WRITE);
        assert_eq!(root.token_hex(Scope::Verify, &SID), KAT_VERIFY);
        assert_eq!(root.token_hex(Scope::Ack, &SID), KAT_ACK);
    }

    const KAT_WRITE: &str = "8b13f896809daab9df8909ab81b5ea285a5d342b4936bc363304e9fd0938c73c";
    const KAT_VERIFY: &str = "199a52ed394cec978db065f0a561b18c5be79c6a9fdeb7a5ebfdd86c46005a44";
    const KAT_ACK: &str = "9b2854cf08117b72e37655f35f57756d697282981c483b05bcc74507a882964d";
}

//! Suite contracts for wire v2 (see spec/LACRE-WIRE-v2.md).
//!
//! The Core fixes small contracts and does not know any primitive of the
//! catalogue. This module defines:
//!
//! * `SealMac` — keyed authentication of a fragment (the seal). The only
//!   interchangeable function in v2. The Core decides the output length and
//!   does the comparison; the algorithm only computes.
//! * `KdfSuite` and `ChainSuite` — normative identifiers with one registered
//!   value each (`hkdf-sha256`, `hmac-sha256`). They are not traits: there is
//!   one real use of each today (DECISIONS point 17).
//! * `SuiteDescriptor` — the canonical description of everything a session
//!   uses. Its hash enters key derivation, the chain's initial state and
//!   (later) the signature input, so two ends with different suites cannot
//!   agree on a single frame.
//! * `ValidatedSuite` — a descriptor checked against a concrete `SealMac`.
//!
//! What the compiler enforces here: the Core, not the algorithm, builds the
//! output buffer and compares tags (the trait has no `verify`). What it does
//! not: that a primitive is correct or constant-time inside — that is the
//! conformance suite and audit.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Protocol version of this suite format.
pub const VERSION_V2: u8 = 2;
/// Longest tag the v2 wire accepts. Raising it later is backward compatible;
/// lowering it is not.
pub const MAX_TAG_LEN: usize = 1024;
pub const MIN_KEY_LEN: usize = 16;
pub const MAX_KEY_LEN: usize = 128;
pub const MAX_ID_LEN: usize = 48;
pub const MAX_PARAMS_LEN: usize = 16;
pub const MAX_DESCRIPTOR_LEN: usize = 256;
/// Es(i) is always 32 bytes under `hmac-sha256`.
pub const CHAIN_STATE_LEN: usize = 32;
/// Longest signature or key of a `SignatureScheme` the Core will accept. A
/// reserved open envelope (spec/LACRE-WIRE-v2.md); which schemes exist
/// is the catalogue's and the operator's policy, not the Core's.
pub const MAX_SIGNATURE_LEN: usize = 8192;
pub const MAX_SIGNATURE_KEY_LEN: usize = 8192;
/// Domain of the signature input and of the v2 receipt.
pub const SIGN_DOMAIN: &[u8] = b"lacre/v2/vault-sig";
pub const RECEIPT_DOMAIN_V2: &[u8] = b"lacre/v2/receipt";

pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";
pub const CHAIN_HMAC_SHA256: &str = "hmac-sha256";

const SUITE_HASH_DOMAIN: &[u8] = b"lacre/v2/suite";

// Field tags of the canonical descriptor, in the fixed order they appear.
const TAG_KDF: u8 = 1;
const TAG_CHAIN: u8 = 2;
const TAG_SEAL: u8 = 3;
const TAG_PARAMS: u8 = 4;
const TAG_SIGNATURE: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteError {
    InvalidId,
    DescriptorMalformed,
    DescriptorTooLarge,
    UnsupportedVersion(u8),
    UnsupportedKdf,
    UnsupportedChain,
    IdMismatch,
    KeyLenOutOfRange(usize),
    TagLenOutOfRange(usize),
    ParamsInvalid,
    MemoryBudgetExceeded { required: usize, cap: usize },
    UnknownKeyId,
    KeyDerivationFailed,
    /// The descriptor names a signature scheme and none was given, a scheme
    /// was given that the descriptor does not name, or the ids differ.
    SignatureSchemeMismatch,
    SignatureLenOutOfRange(usize),
    SignatureKeyLenOutOfRange(usize),
    /// The secret or public key handed to a signing session is not what the scheme declares.
    SignatureKeyInvalid,
}

/// Lifecycle status of an algorithm. The policy decides which are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Standard,
    Experimental,
    /// Kept only for historical compatibility; blocked by default policy and
    /// absent from production builds.
    Legacy,
}

impl Status {
    pub const fn name(self) -> &'static str {
        match self {
            Status::Standard => "standard",
            Status::Experimental => "experimental",
            Status::Legacy => "legacy",
        }
    }
}

/// Declared cost class. A declaration, not a promise: the Core is synchronous
/// and cannot cancel a running computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostClass {
    Light,
    Standard,
    Heavy,
}

/// The output a `SealMac` produces. Truncation does not exist: a truncated
/// variant is a different algorithm with its own id and vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// Always exactly `n` bytes.
    Fixed(usize),
    /// Any length in `min..=max`, chosen by the session's parameters.
    Xof { min: usize, max: usize },
}

/// The canonical message a seal authenticates:
/// `u64be(len(fragment)) ∥ fragment ∥ Es(i)`. The length prefix makes the
/// encoding unambiguous without relying on Es(i) having a fixed size.
/// The algorithm must feed `parts()` to its MAC in order.
pub struct SealInput<'a> {
    len_prefix: [u8; 8],
    fragment: &'a [u8],
    state: &'a [u8; CHAIN_STATE_LEN],
}

impl<'a> SealInput<'a> {
    pub fn new(fragment: &'a [u8], state: &'a [u8; CHAIN_STATE_LEN]) -> Self {
        SealInput { len_prefix: (fragment.len() as u64).to_be_bytes(), fragment, state }
    }

    /// The three pieces of the canonical message, in order. Their
    /// concatenation is the message; a streaming MAC feeds them one by one,
    /// so a 1 MiB fragment is never copied.
    pub fn parts(&self) -> [&[u8]; 3] {
        [&self.len_prefix, self.fragment, self.state]
    }

    /// The whole message as one buffer (tests and vectors).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + self.fragment.len() + CHAIN_STATE_LEN);
        for p in self.parts() {
            v.extend_from_slice(p);
        }
        v
    }
}

/// Keyed authentication of a fragment. Implemented by catalogue crates, never
/// by the Core. No `verify`: the Core recomputes and compares in constant time.
pub trait SealMac: Send + Sync + 'static {
    /// `[a-z0-9-]`, 1..=48, unique in a registry.
    fn id(&self) -> &'static str;
    fn status(&self) -> Status;
    fn cost(&self) -> CostClass;
    /// Declared security level in bits. Informational.
    fn security_bits(&self) -> u16;
    /// Bytes of key the algorithm needs (16..=128). The Core derives exactly
    /// this many.
    fn key_len(&self) -> usize;
    fn output(&self) -> OutputKind;
    /// Fills `out` (its length was fixed by the Core) with the MAC of the
    /// canonical message under `key`. Must be deterministic and stateless.
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]);
}

/// Canonical message a Vault signature covers:
/// `"lacre/v2/vault-sig" ∥ suite_hash ∥ session_id ∥ u64be(index) ∥ u64be(len(tag)) ∥ tag`.
/// It covers the suite, the session, the position and the tag length, so a
/// signature is not reusable across sessions, algorithms, indices or lengths.
pub struct SignInput<'a> {
    suite_hash: &'a [u8; 32],
    session_id: &'a [u8; 16],
    index: [u8; 8],
    tag_len: [u8; 8],
    tag: &'a [u8],
}

impl<'a> SignInput<'a> {
    pub fn new(suite_hash: &'a [u8; 32], session_id: &'a [u8; 16], index: u64, tag: &'a [u8]) -> Self {
        SignInput { suite_hash, session_id, index: index.to_be_bytes(), tag_len: (tag.len() as u64).to_be_bytes(), tag }
    }

    /// The pieces of the message, in order; their concatenation is the message.
    pub fn parts(&self) -> [&[u8]; 6] {
        [SIGN_DOMAIN, self.suite_hash, self.session_id, &self.index, &self.tag_len, self.tag]
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.parts().concat()
    }
}

/// An asymmetric signature scheme (non-repudiation, Vault). A family apart
/// from `SealMac`: lengths are the scheme's declaration, bounded by the Core.
/// The Core checks every length before calling the scheme and refuses a
/// `sign` output of any other length.
pub trait SignatureScheme: Send + Sync + 'static {
    /// `[a-z0-9-]`, 1..=48, the same text the descriptor carries.
    fn id(&self) -> &'static str;
    fn status(&self) -> Status;
    fn security_bits(&self) -> u16;
    fn public_key_len(&self) -> usize;
    fn secret_key_len(&self) -> usize;
    fn signature_len(&self) -> usize;
    /// The public key of `secret`, or `None` if `secret` is not a valid secret key.
    fn public_from_secret(&self, secret: &[u8]) -> Option<Vec<u8>>;
    /// Exactly `signature_len` bytes.
    fn sign(&self, secret: &[u8], input: &SignInput<'_>) -> Vec<u8>;
    /// `true` only for a valid signature. Never panics on malformed input.
    fn verify(&self, public: &[u8], input: &SignInput<'_>, signature: &[u8]) -> bool;
}

/// Receipt of wire v2: `SHA-256("lacre/v2/receipt" ∥ suite_hash ∥ u64be(index) ∥ tag)`.
pub fn derive_receipt_v2(suite_hash: &[u8; 32], index: u64, tag: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECEIPT_DOMAIN_V2);
    h.update(suite_hash);
    h.update(index.to_be_bytes());
    h.update(tag);
    h.finalize().into()
}

/// Key derivation suite. One registered value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfSuite {
    HkdfSha256,
}

impl KdfSuite {
    pub const fn id(self) -> &'static str {
        match self {
            KdfSuite::HkdfSha256 => KDF_HKDF_SHA256,
        }
    }
    pub fn from_id(id: &str) -> Result<Self, SuiteError> {
        match id {
            KDF_HKDF_SHA256 => Ok(KdfSuite::HkdfSha256),
            _ => Err(SuiteError::UnsupportedKdf),
        }
    }
}

/// State chain suite (Es(i)). One registered value; independent of the seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSuite {
    HmacSha256,
}

impl ChainSuite {
    pub const fn id(self) -> &'static str {
        match self {
            ChainSuite::HmacSha256 => CHAIN_HMAC_SHA256,
        }
    }
    pub fn from_id(id: &str) -> Result<Self, SuiteError> {
        match id {
            CHAIN_HMAC_SHA256 => Ok(ChainSuite::HmacSha256),
            _ => Err(SuiteError::UnsupportedChain),
        }
    }
}

/// `[a-z0-9-]`, 1..=48 bytes. Anything else is rejected, never normalised.
pub fn validate_id(id: &str) -> Result<(), SuiteError> {
    validate_id_bytes(id.as_bytes())
}

/// Same rule on raw bytes. The descriptor parser uses it so that identifier
/// bytes are checked as ASCII before they become a `String`, with no UTF-8
/// decoding anywhere in the Core.
pub fn validate_id_bytes(b: &[u8]) -> Result<(), SuiteError> {
    if b.is_empty() || b.len() > MAX_ID_LEN {
        return Err(SuiteError::InvalidId);
    }
    if b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') {
        Ok(())
    } else {
        Err(SuiteError::InvalidId)
    }
}

/// Parameters for an XOF seal: `tag_len` as 2 bytes big endian. Fixed-output
/// algorithms take no parameters.
pub fn xof_params(tag_len: u16) -> Vec<u8> {
    tag_len.to_be_bytes().to_vec()
}

/// Everything a v2 session uses, in a fixed canonical form.
///
/// Canonical bytes: `version(1) ∥ [tag(1) ∥ len(1) ∥ bytes]×5` with tags
/// 1..=5 always present and always in that order (kdf, chain, seal id, seal
/// parameters, signature scheme; an absent signature has length 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteDescriptor {
    kdf: KdfSuite,
    chain: ChainSuite,
    seal_id: String,
    params: Vec<u8>,
    signature: Option<String>,
}

impl SuiteDescriptor {
    pub fn new(
        seal_id: &str,
        params: Vec<u8>,
        signature: Option<&str>,
    ) -> Result<Self, SuiteError> {
        validate_id(seal_id)?;
        if params.len() > MAX_PARAMS_LEN {
            return Err(SuiteError::ParamsInvalid);
        }
        if let Some(s) = signature {
            validate_id(s)?;
        }
        Ok(SuiteDescriptor {
            kdf: KdfSuite::HkdfSha256,
            chain: ChainSuite::HmacSha256,
            seal_id: seal_id.to_string(),
            params,
            signature: signature.map(str::to_string),
        })
    }

    pub fn kdf(&self) -> KdfSuite {
        self.kdf
    }
    pub fn chain(&self) -> ChainSuite {
        self.chain
    }
    pub fn seal_id(&self) -> &str {
        &self.seal_id
    }
    pub fn params(&self) -> &[u8] {
        &self.params
    }
    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    pub fn canonical(&self) -> Vec<u8> {
        let mut out = vec![VERSION_V2];
        let sig = self.signature.as_deref().unwrap_or("").as_bytes();
        let fields: [(u8, &[u8]); 5] = [
            (TAG_KDF, self.kdf.id().as_bytes()),
            (TAG_CHAIN, self.chain.id().as_bytes()),
            (TAG_SEAL, self.seal_id.as_bytes()),
            (TAG_PARAMS, &self.params),
            (TAG_SIGNATURE, sig),
        ];
        for (tag, bytes) in fields {
            out.push(tag);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Strict inverse of `canonical`: exact structure, no trailing bytes, no
    /// unknown version, kdf or chain.
    pub fn parse(bytes: &[u8]) -> Result<Self, SuiteError> {
        if bytes.len() > MAX_DESCRIPTOR_LEN {
            return Err(SuiteError::DescriptorTooLarge);
        }
        let (&version, mut rest) = bytes.split_first().ok_or(SuiteError::DescriptorMalformed)?;
        if version != VERSION_V2 {
            return Err(SuiteError::UnsupportedVersion(version));
        }
        let mut fields: Vec<&[u8]> = Vec::with_capacity(5);
        for expected_tag in [TAG_KDF, TAG_CHAIN, TAG_SEAL, TAG_PARAMS, TAG_SIGNATURE] {
            let (&tag, r) = rest.split_first().ok_or(SuiteError::DescriptorMalformed)?;
            let (&len, r) = r.split_first().ok_or(SuiteError::DescriptorMalformed)?;
            if tag != expected_tag || r.len() < len as usize {
                return Err(SuiteError::DescriptorMalformed);
            }
            let (value, r) = r.split_at(len as usize);
            fields.push(value);
            rest = r;
        }
        if !rest.is_empty() {
            return Err(SuiteError::DescriptorMalformed);
        }
        // Identifiers are `[a-z0-9-]`: checked as bytes, then widened one by
        // one, so a non-ASCII byte is an error and never decoded.
        fn text(b: &[u8]) -> Result<String, SuiteError> {
            validate_id_bytes(b)?;
            Ok(b.iter().map(|&c| c as char).collect())
        }
        let kdf = KdfSuite::from_id(&text(fields[0])?)?;
        let chain = ChainSuite::from_id(&text(fields[1])?)?;
        let signature = if fields[4].is_empty() { None } else { Some(text(fields[4])?) };
        let mut d = SuiteDescriptor::new(&text(fields[2])?, fields[3].to_vec(), signature.as_deref())?;
        d.kdf = kdf;
        d.chain = chain;
        Ok(d)
    }

    /// `SHA-256("lacre/v2/suite" ∥ canonical)`.
    pub fn suite_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SUITE_HASH_DOMAIN);
        h.update(self.canonical());
        h.finalize().into()
    }
}

/// A descriptor checked against the algorithm it names.
#[derive(Clone)]
pub struct ValidatedSuite {
    descriptor: SuiteDescriptor,
    mac: Arc<dyn SealMac>,
    tag_len: usize,
    suite_hash: [u8; 32],
    signature: Option<Arc<dyn SignatureScheme>>,
}

impl ValidatedSuite {
    /// A suite without signature: a descriptor that names a scheme needs
    /// `with_signature` and the scheme itself.
    pub fn new(descriptor: SuiteDescriptor, mac: Arc<dyn SealMac>) -> Result<Self, SuiteError> {
        Self::with_signature(descriptor, mac, None)
    }

    pub fn with_signature(
        descriptor: SuiteDescriptor,
        mac: Arc<dyn SealMac>,
        scheme: Option<Arc<dyn SignatureScheme>>,
    ) -> Result<Self, SuiteError> {
        match (&scheme, descriptor.signature()) {
            (None, None) => {}
            (Some(sc), Some(named)) => {
                validate_id(sc.id())?;
                if named != sc.id() {
                    return Err(SuiteError::SignatureSchemeMismatch);
                }
                let sl = sc.signature_len();
                if sl == 0 || sl > MAX_SIGNATURE_LEN {
                    return Err(SuiteError::SignatureLenOutOfRange(sl));
                }
                for k in [sc.public_key_len(), sc.secret_key_len()] {
                    if k == 0 || k > MAX_SIGNATURE_KEY_LEN {
                        return Err(SuiteError::SignatureKeyLenOutOfRange(k));
                    }
                }
            }
            _ => return Err(SuiteError::SignatureSchemeMismatch),
        }
        validate_id(mac.id())?;
        if descriptor.seal_id() != mac.id() {
            return Err(SuiteError::IdMismatch);
        }
        let key_len = mac.key_len();
        if !(MIN_KEY_LEN..=MAX_KEY_LEN).contains(&key_len) {
            return Err(SuiteError::KeyLenOutOfRange(key_len));
        }
        let tag_len = match mac.output() {
            OutputKind::Fixed(n) => {
                if n == 0 || n > MAX_TAG_LEN {
                    return Err(SuiteError::TagLenOutOfRange(n));
                }
                if !descriptor.params().is_empty() {
                    return Err(SuiteError::ParamsInvalid);
                }
                n
            }
            OutputKind::Xof { min, max } => {
                if min == 0 || min > max || max > MAX_TAG_LEN {
                    return Err(SuiteError::TagLenOutOfRange(max));
                }
                let p: [u8; 2] =
                    descriptor.params().try_into().map_err(|_| SuiteError::ParamsInvalid)?;
                let n = u16::from_be_bytes(p) as usize;
                if n < min || n > max {
                    return Err(SuiteError::TagLenOutOfRange(n));
                }
                n
            }
        };
        let suite_hash = descriptor.suite_hash();
        Ok(ValidatedSuite { descriptor, mac, tag_len, suite_hash, signature: scheme })
    }

    pub fn descriptor(&self) -> &SuiteDescriptor {
        &self.descriptor
    }
    pub fn mac(&self) -> &dyn SealMac {
        self.mac.as_ref()
    }
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
    pub fn key_len(&self) -> usize {
        self.mac.key_len()
    }
    pub fn suite_hash(&self) -> &[u8; 32] {
        &self.suite_hash
    }
    pub fn signature_scheme(&self) -> Option<&dyn SignatureScheme> {
        self.signature.as_deref()
    }
}

/// Memory the buffers of a session need: `slot_count * (slot_size + tag_len)`.
/// Overflow is an error, as is exceeding `cap`; nothing is allocated before
/// this passes.
pub fn check_memory_budget(
    slot_size: usize,
    slot_count: usize,
    tag_len: usize,
    cap: usize,
) -> Result<usize, SuiteError> {
    let required = slot_size
        .checked_add(tag_len)
        .and_then(|per_slot| per_slot.checked_mul(slot_count))
        .ok_or(SuiteError::MemoryBudgetExceeded { required: usize::MAX, cap })?;
    if required > cap {
        return Err(SuiteError::MemoryBudgetExceeded { required, cap });
    }
    Ok(required)
}

/// A seal of wire v2: 1..=`MAX_TAG_LEN` bytes. Built only through `new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealTag(Vec<u8>);

impl SealTag {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SuiteError> {
        if bytes.is_empty() || bytes.len() > MAX_TAG_LEN {
            return Err(SuiteError::TagLenOutOfRange(bytes.len()));
        }
        Ok(SealTag(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time comparison. A different length is a mismatch.
    pub fn matches(&self, expected: &[u8]) -> bool {
        self.0.len() == expected.len() && bool::from(self.0.ct_eq(expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed32;
    impl SealMac for Fixed32 {
        fn id(&self) -> &'static str { "test-fixed32" }
        fn status(&self) -> Status { Status::Experimental }
        fn cost(&self) -> CostClass { CostClass::Light }
        fn security_bits(&self) -> u16 { 128 }
        fn key_len(&self) -> usize { 32 }
        fn output(&self) -> OutputKind { OutputKind::Fixed(32) }
        fn mac(&self, _key: &[u8], _input: &SealInput<'_>, out: &mut [u8]) { out.fill(7) }
    }

    struct Xof;
    impl SealMac for Xof {
        fn id(&self) -> &'static str { "test-xof" }
        fn status(&self) -> Status { Status::Experimental }
        fn cost(&self) -> CostClass { CostClass::Light }
        fn security_bits(&self) -> u16 { 128 }
        fn key_len(&self) -> usize { 32 }
        fn output(&self) -> OutputKind { OutputKind::Xof { min: 16, max: 1024 } }
        fn mac(&self, _key: &[u8], _input: &SealInput<'_>, out: &mut [u8]) { out.fill(9) }
    }

    struct KeyLen(usize);
    impl SealMac for KeyLen {
        fn id(&self) -> &'static str { "test-keylen" }
        fn status(&self) -> Status { Status::Experimental }
        fn cost(&self) -> CostClass { CostClass::Light }
        fn security_bits(&self) -> u16 { 128 }
        fn key_len(&self) -> usize { self.0 }
        fn output(&self) -> OutputKind { OutputKind::Fixed(32) }
        fn mac(&self, _key: &[u8], _input: &SealInput<'_>, out: &mut [u8]) { out.fill(1) }
    }

    #[test]
    fn key_length_must_be_within_bounds() {
        for bad in [0, 1, MIN_KEY_LEN - 1, MAX_KEY_LEN + 1, 1000] {
            let r = ValidatedSuite::new(desc("test-keylen", vec![]), Arc::new(KeyLen(bad)));
            assert_eq!(r.err(), Some(SuiteError::KeyLenOutOfRange(bad)));
        }
        for ok in [MIN_KEY_LEN, 32, MAX_KEY_LEN] {
            assert!(ValidatedSuite::new(desc("test-keylen", vec![]), Arc::new(KeyLen(ok))).is_ok());
        }
    }

    fn desc(id: &str, params: Vec<u8>) -> SuiteDescriptor {
        SuiteDescriptor::new(id, params, None).unwrap()
    }

    #[test]
    fn canonical_round_trips_and_is_deterministic() {
        let d = SuiteDescriptor::new("hmac-sha512", vec![], Some("ed25519")).unwrap();
        let bytes = d.canonical();
        assert_eq!(bytes, d.canonical());
        assert_eq!(SuiteDescriptor::parse(&bytes).unwrap(), d);
        assert!(bytes.len() <= MAX_DESCRIPTOR_LEN);
    }

    #[test]
    fn parse_rejects_every_malformed_shape() {
        let good = desc("hmac-sha512", vec![]).canonical();
        assert_eq!(SuiteDescriptor::parse(&[]), Err(SuiteError::DescriptorMalformed));
        let mut v1 = good.clone();
        v1[0] = 1;
        assert_eq!(SuiteDescriptor::parse(&v1), Err(SuiteError::UnsupportedVersion(1)));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(SuiteDescriptor::parse(&trailing), Err(SuiteError::DescriptorMalformed));
        let truncated = &good[..good.len() - 1];
        assert!(SuiteDescriptor::parse(truncated).is_err());
        let mut swapped = good.clone();
        swapped[1] = TAG_CHAIN; // first field tag out of order
        assert_eq!(SuiteDescriptor::parse(&swapped), Err(SuiteError::DescriptorMalformed));
        assert_eq!(
            SuiteDescriptor::parse(&vec![VERSION_V2; MAX_DESCRIPTOR_LEN + 1]),
            Err(SuiteError::DescriptorTooLarge)
        );
        // Unknown kdf / chain identifiers.
        let mut bad_kdf = good.clone();
        bad_kdf[3] = b'x';
        assert_eq!(SuiteDescriptor::parse(&bad_kdf), Err(SuiteError::UnsupportedKdf));
        // Unknown chain identifier (the chain field starts at offset 14, its value at 16).
        let mut bad_chain = good.clone();
        bad_chain[16] = b'x';
        assert_eq!(SuiteDescriptor::parse(&bad_chain), Err(SuiteError::UnsupportedChain));
        // A byte outside [a-z0-9-] is an invalid id, whatever its value (never decoded).
        for bad in [b'X', 0xC3, 0x00, b' '] {
            let mut d = good.clone();
            d[3] = bad;
            assert_eq!(SuiteDescriptor::parse(&d), Err(SuiteError::InvalidId), "byte {bad:#x}");
        }
    }

    #[test]
    fn ids_are_validated_strictly() {
        for bad in ["", "UPPER", "with space", "under_score", "é", &"a".repeat(MAX_ID_LEN + 1)] {
            assert_eq!(validate_id(bad), Err(SuiteError::InvalidId), "{bad:?}");
        }
        assert!(validate_id("hmac-sha3-512").is_ok());
        assert!(validate_id(&"a".repeat(MAX_ID_LEN)).is_ok());
        assert!(SuiteDescriptor::new("Bad_Id", vec![], None).is_err());
        assert!(SuiteDescriptor::new("ok", vec![0; MAX_PARAMS_LEN + 1], None).is_err());
    }

    #[test]
    fn suite_hash_depends_on_every_field() {
        let base = desc("test-fixed32", vec![]).suite_hash();
        assert_ne!(base, desc("test-xof", vec![]).suite_hash());
        assert_ne!(base, desc("test-fixed32", vec![0, 1]).suite_hash());
        assert_ne!(
            base,
            SuiteDescriptor::new("test-fixed32", vec![], Some("ed25519")).unwrap().suite_hash()
        );
    }

    #[test]
    fn validated_suite_enforces_output_and_params() {
        let fixed: Arc<dyn SealMac> = Arc::new(Fixed32);
        let ok = ValidatedSuite::new(desc("test-fixed32", vec![]), fixed.clone()).unwrap();
        assert_eq!(ok.tag_len(), 32);
        // Parameters on a fixed-output algorithm are an error, not ignored.
        assert_eq!(
            ValidatedSuite::new(desc("test-fixed32", vec![0, 32]), fixed.clone()).err(),
            Some(SuiteError::ParamsInvalid)
        );
        // Id mismatch.
        assert_eq!(
            ValidatedSuite::new(desc("other", vec![]), fixed).err(),
            Some(SuiteError::IdMismatch)
        );
        let xof: Arc<dyn SealMac> = Arc::new(Xof);
        let s = ValidatedSuite::new(desc("test-xof", xof_params(128)), xof.clone()).unwrap();
        assert_eq!(s.tag_len(), 128);
        for bad in [vec![], vec![0], vec![0, 0, 0], xof_params(15), xof_params(1025)] {
            assert!(ValidatedSuite::new(desc("test-xof", bad.clone()), xof.clone()).is_err(), "{bad:?}");
        }
        assert!(ValidatedSuite::new(desc("test-xof", xof_params(1024)), xof).is_ok());
    }

    #[test]
    fn memory_budget_is_checked_before_anything_is_allocated() {
        assert_eq!(check_memory_budget(1024, 15 * 1024, 32, usize::MAX).unwrap(), (1024 + 32) * 15 * 1024);
        // 1024-byte tags over 15 360 slots break a 15 MB budget on their own.
        let tags_only = 15 * 1024 * 1024;
        assert!(check_memory_budget(1024, 15 * 1024, 1024, tags_only + 15 * 1024 * 1024 - 1).is_err());
        assert!(check_memory_budget(usize::MAX, 2, 32, usize::MAX).is_err(), "overflow is an error");
        assert!(check_memory_budget(10, 10, 10, 200).is_ok());
        assert!(check_memory_budget(10, 10, 10, 199).is_err());
    }

    #[test]
    fn tag_bounds_and_constant_time_match() {
        assert!(SealTag::new(vec![]).is_err());
        assert!(SealTag::new(vec![0; MAX_TAG_LEN + 1]).is_err());
        let t = SealTag::new(vec![1, 2, 3]).unwrap();
        assert!(t.matches(&[1, 2, 3]));
        assert!(!t.matches(&[1, 2, 4]));
        assert!(!t.matches(&[1, 2]), "a prefix is not a match");
        assert!(!t.matches(&[1, 2, 3, 0]));
    }

    #[test]
    fn seal_input_is_length_prefixed_and_unambiguous() {
        let s1 = [1u8; CHAIN_STATE_LEN];
        let s2 = [2u8; CHAIN_STATE_LEN];
        let a = SealInput::new(b"ab", &s1).to_vec();
        let b = SealInput::new(b"a", &s1).to_vec();
        assert_ne!(a, b);
        assert_eq!(&a[..8], &2u64.to_be_bytes());
        assert_eq!(a.len(), 8 + 2 + CHAIN_STATE_LEN);
        assert_ne!(SealInput::new(b"ab", &s1).to_vec(), SealInput::new(b"ab", &s2).to_vec());
    }
}

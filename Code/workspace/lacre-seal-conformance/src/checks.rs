//! The checks themselves. Each group is one function so that the suite's own
//! mutation harness can disable one group at a time and see a control fail.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lacre_core::core::CoreError;
use lacre_core::core_v2::{BufferSpec, SealerCoreV2, VerifierCoreV2};
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::suite::{
    validate_id, xof_params, CostClass, OutputKind, SealInput, SealMac, SealTag, SignInput,
    SignatureScheme, Status, SuiteDescriptor, ValidatedSuite, CHAIN_STATE_LEN, MAX_KEY_LEN, MAX_TAG_LEN, MIN_KEY_LEN,
};

use crate::kat::Kat;
use crate::report::{Check, Group, Report};

/// Knobs of a run. Defaults are generous so that a debug build on a slow
/// machine does not produce false failures.
#[derive(Debug, Clone)]
pub struct Options {
    /// Delay injected by the slowness group.
    pub slow_delay: Duration,
    /// Maximum average time for one 1 KiB seal, per declared cost class.
    pub light_budget: Duration,
    pub standard_budget: Duration,
    pub heavy_budget: Duration,
    /// Threads of the statelessness group.
    pub threads: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            slow_delay: Duration::from_millis(20),
            light_budget: Duration::from_millis(50),
            standard_budget: Duration::from_millis(500),
            heavy_budget: Duration::from_secs(5),
            threads: 4,
        }
    }
}

/// Wraps an algorithm and sleeps before every computation. Used by the
/// slowness group; public so a registry's tests can use it too. It reports
/// the inner algorithm's id, so descriptors are interchangeable.
pub struct SlowMac {
    pub inner: Arc<dyn SealMac>,
    pub delay: Duration,
}

impl SealMac for SlowMac {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn status(&self) -> Status {
        self.inner.status()
    }
    fn cost(&self) -> CostClass {
        self.inner.cost()
    }
    fn security_bits(&self) -> u16 {
        self.inner.security_bits()
    }
    fn key_len(&self) -> usize {
        self.inner.key_len()
    }
    fn output(&self) -> OutputKind {
        self.inner.output()
    }
    fn mac(&self, key: &[u8], input: &SealInput<'_>, out: &mut [u8]) {
        std::thread::sleep(self.delay);
        self.inner.mac(key, input, out);
    }
}

// ---------------------------------------------------------------- runner

struct Runner {
    report: Report,
}

impl Runner {
    fn new() -> Self {
        Runner { report: Report::default() }
    }

    /// Runs one check. A panic inside it is a failure of the check, not of
    /// the suite: a defective implementation must be reported, not abort.
    fn check(&mut self, group: Group, name: &str, f: impl FnOnce() -> Result<(), String>) {
        let failure = match catch_unwind(AssertUnwindSafe(f)) {
            Ok(Ok(())) => None,
            Ok(Err(why)) => Some(why),
            Err(p) => {
                let msg = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic".to_string());
                Some(format!("panicked: {msg}"))
            }
        };
        self.report.push(Check { group, name: name.to_string(), failure });
    }
}

fn ensure(cond: bool, why: impl FnOnce() -> String) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(why())
    }
}

// --------------------------------------------------------------- helpers

fn pat(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn pat_state(seed: u8) -> [u8; CHAIN_STATE_LEN] {
    let mut s = [0u8; CHAIN_STATE_LEN];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(seed);
    }
    s
}

fn run_mac(
    mac: &dyn SealMac,
    key: &[u8],
    fragment: &[u8],
    state: &[u8; CHAIN_STATE_LEN],
    n: usize,
    fill: u8,
) -> Vec<u8> {
    let mut out = vec![fill; n];
    mac.mac(key, &SealInput::new(fragment, state), &mut out);
    out
}

fn tag(mac: &dyn SealMac, key: &[u8], fragment: &[u8], state: &[u8; 32], n: usize) -> Vec<u8> {
    run_mac(mac, key, fragment, state, n, 0)
}

/// Tag lengths the algorithm must handle, or `None` if its declaration is
/// not usable (then only the metadata group is meaningful).
fn tag_lens(mac: &dyn SealMac) -> Option<Vec<usize>> {
    match mac.output() {
        OutputKind::Fixed(n) if (1..=MAX_TAG_LEN).contains(&n) => Some(vec![n]),
        OutputKind::Xof { min, max } if min >= 1 && min <= max && max <= MAX_TAG_LEN => {
            let mut v = vec![min, min + 1, (min + max) / 2, max];
            v.retain(|n| (min..=max).contains(n));
            v.sort_unstable();
            v.dedup();
            Some(v)
        }
        _ => None,
    }
}

/// Lengths at which two algorithms are compared for aliasing: each one's own
/// sampled lengths plus the common sizes real tags have, so that an
/// extendable-output algorithm is compared with a fixed-length one wherever
/// their ranges overlap (a plain sample of `[min, min+1, mid, max]` misses
/// e.g. a 32-byte overlap).
fn crossed_lens(mac: &dyn SealMac) -> Option<Vec<usize>> {
    let mut v = tag_lens(mac)?;
    for n in [16usize, 20, 24, 32, 48, 64, 128] {
        let ok = match mac.output() {
            OutputKind::Fixed(f) => n == f,
            OutputKind::Xof { min, max } => (min..=max).contains(&n),
        };
        if ok {
            v.push(n);
        }
    }
    v.sort_unstable();
    v.dedup();
    Some(v)
}

fn key_len_ok(mac: &dyn SealMac) -> bool {
    (MIN_KEY_LEN..=MAX_KEY_LEN).contains(&mac.key_len())
}

fn params_for(mac: &dyn SealMac, n: usize) -> Vec<u8> {
    match mac.output() {
        OutputKind::Fixed(_) => Vec::new(),
        OutputKind::Xof { .. } => xof_params(n as u16),
    }
}

fn suite_of(mac: &Arc<dyn SealMac>, n: usize, signature: Option<&str>) -> Result<ValidatedSuite, String> {
    if signature.is_some() {
        return signed_suite_of(mac, n);
    }
    let d = SuiteDescriptor::new(mac.id(), params_for(mac.as_ref(), n), None)
        .map_err(|e| format!("descriptor rejected: {e:?}"))?;
    ValidatedSuite::new(d, mac.clone()).map_err(|e| format!("suite rejected: {e:?}"))
}

/// Test-only signature scheme: not secure, only shaped like one. It lets the
/// conformance checks exercise the binding of a declared scheme to the suite
/// without the Core or this crate depending on a real signature primitive.
struct ToySignature;

impl SignatureScheme for ToySignature {
    fn id(&self) -> &'static str {
        "toy-signature"
    }
    fn status(&self) -> Status {
        Status::Experimental
    }
    fn security_bits(&self) -> u16 {
        0
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn secret_key_len(&self) -> usize {
        32
    }
    fn signature_len(&self) -> usize {
        32
    }
    fn public_from_secret(&self, secret: &[u8]) -> Option<Vec<u8>> {
        (secret.len() == 32).then(|| secret.to_vec())
    }
    fn sign(&self, secret: &[u8], input: &SignInput<'_>) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        for (i, b) in input.to_vec().iter().enumerate() {
            out[i % 32] ^= b ^ secret[i % secret.len()];
        }
        out
    }
    fn verify(&self, public: &[u8], input: &SignInput<'_>, signature: &[u8]) -> bool {
        public.len() == 32 && signature == self.sign(public, input).as_slice()
    }
}

fn signed_suite_of(mac: &Arc<dyn SealMac>, n: usize) -> Result<ValidatedSuite, String> {
    let d = SuiteDescriptor::new(mac.id(), params_for(mac.as_ref(), n), Some("toy-signature"))
        .map_err(|e| format!("descriptor rejected: {e:?}"))?;
    ValidatedSuite::with_signature(d, mac.clone(), Some(Arc::new(ToySignature)))
        .map_err(|e| format!("suite rejected: {e:?}"))
}

fn ring() -> Arc<MasterKeyRing> {
    Arc::new(MasterKeyRing::new(0, b"conformance-master-key-32-bytes!".to_vec(), Duration::from_secs(60)))
}

fn sid(b: u8) -> SessionId {
    SessionId([b; 16])
}

fn spec() -> BufferSpec {
    BufferSpec::new(1024, 64, Duration::from_secs(60), 1 << 22)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ------------------------------------------------------------- entry point

/// Runs every per-algorithm group against `mac` with the candidate's `kats`.
pub fn check_seal_mac(mac: Arc<dyn SealMac>, kats: &[Kat], opts: &Options) -> Report {
    let mut r = Runner::new();
    group_metadata(&mut r, &mac);
    let usable = tag_lens(mac.as_ref()).is_some() && key_len_ok(mac.as_ref());
    if usable {
        group_vectors(&mut r, &mac, kats);
        group_lengths(&mut r, &mac);
        group_sensitivity(&mut r, &mac);
        group_parameters(&mut r, &mac);
        group_robustness(&mut r, &mac);
        group_statelessness(&mut r, &mac, opts);
        group_journey(&mut r, &mac);
        group_slowness(&mut r, &mac, opts);
        group_cost(&mut r, &mac, opts);
    } else {
        r.check(Group::Metadata, "declaration is usable (other groups skipped)", || {
            Err("output/key_len declaration is invalid; remaining groups cannot run".into())
        });
    }
    r.report
}

// ---------------------------------------------------------------- metadata

fn group_metadata(r: &mut Runner, mac: &Arc<dyn SealMac>) {
    let m = mac.clone();
    r.check(Group::Metadata, "id is valid ([a-z0-9-], 1..=48)", move || {
        validate_id(m.id()).map_err(|e| format!("{e:?}"))
    });
    let m = mac.clone();
    r.check(Group::Metadata, "key_len within Core limits", move || {
        ensure(key_len_ok(m.as_ref()), || {
            format!("key_len {} outside {MIN_KEY_LEN}..={MAX_KEY_LEN}", m.key_len())
        })
    });
    let m = mac.clone();
    r.check(Group::Metadata, "output declaration is coherent", move || {
        ensure(tag_lens(m.as_ref()).is_some(), || format!("unusable output {:?}", m.output()))
    });
    let m = mac.clone();
    r.check(Group::Metadata, "security_bits is declared (> 0)", move || {
        ensure(m.security_bits() > 0, || "security_bits is 0".into())
    });
    let m = mac.clone();
    r.check(Group::Metadata, "declarations are stable across calls", move || {
        let a = (m.id(), m.key_len(), format!("{:?}", m.output()), m.security_bits());
        let b = (m.id(), m.key_len(), format!("{:?}", m.output()), m.security_bits());
        ensure(a == b, || "metadata changed between calls".into())
    });
    let m = mac.clone();
    r.check(Group::Metadata, "Core accepts a descriptor built from the declaration", move || {
        let n = match tag_lens(m.as_ref()) {
            Some(v) => v[0],
            None => return Err("no valid tag length".into()),
        };
        suite_of(&m, n, None).map(|_| ())
    });
}

// ----------------------------------------------------------------- vectors

fn group_vectors(r: &mut Runner, mac: &Arc<dyn SealMac>, kats: &[Kat]) {
    let k = kats.len();
    r.check(Group::Vectors, "at least one known-answer vector is supplied", move || {
        ensure(k >= 1, || "no vectors: an algorithm without vectors is not verified".into())
    });
    for kat in kats {
        let m = mac.clone();
        let kat = kat.clone();
        let name = format!("vector '{}'", kat.name);
        r.check(Group::Vectors, &name, move || {
            ensure(kat.key.len() == m.key_len(), || {
                format!("vector key is {} bytes, algorithm wants {}", kat.key.len(), m.key_len())
            })?;
            let n = kat.expected.len();
            let ok_len = match m.output() {
                OutputKind::Fixed(f) => n == f,
                OutputKind::Xof { min, max } => (min..=max).contains(&n),
            };
            ensure(ok_len, || format!("vector tag length {n} is not valid for the declared output"))?;
            let got = tag(m.as_ref(), &kat.key, &kat.fragment, &kat.state, n);
            ensure(got == kat.expected, || {
                format!("expected {} got {}", hex(&kat.expected), hex(&got))
            })
        });
    }
}

// ----------------------------------------------------------------- lengths

fn group_lengths(r: &mut Runner, mac: &Arc<dyn SealMac>) {
    let m = mac.clone();
    r.check(Group::Lengths, "output buffer is fully written (0xAA vs 0x55 prefill)", move || {
        let key = pat(m.key_len(), 1);
        let st = pat_state(2);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            for frag in [Vec::new(), pat(1, 3), pat(100, 4)] {
                let a = run_mac(m.as_ref(), &key, &frag, &st, n, 0xAA);
                let b = run_mac(m.as_ref(), &key, &frag, &st, n, 0x55);
                ensure(a == b, || {
                    format!("tag depends on the buffer's previous contents (len {n}, fragment {} B)", frag.len())
                })?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Lengths, "block-boundary and large fragments are deterministic and distinct", move || {
        let key = pat(m.key_len(), 5);
        let st = pat_state(6);
        let sizes = [
            0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 71, 72, 73, 103, 104, 105, 127, 128, 129,
            135, 136, 137, 167, 168, 169, 255, 256, 257, 1024, 1 << 20,
        ];
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let mut seen: Vec<Vec<u8>> = Vec::new();
            for &sz in &sizes {
                let frag = vec![0u8; sz];
                let t1 = tag(m.as_ref(), &key, &frag, &st, n);
                let t2 = tag(m.as_ref(), &key, &frag, &st, n);
                ensure(t1 == t2, || format!("non-deterministic at fragment size {sz}, tag length {n}"))?;
                ensure(!seen.contains(&t1), || {
                    format!("fragments of zeros with different lengths collide at size {sz} (length not authenticated?)")
                })?;
                seen.push(t1);
            }
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Lengths, "tag is not degenerate (constant, periodic or zero-padded)", move || {
        let key = pat(m.key_len(), 7);
        let st = pat_state(8);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            if n < 16 {
                continue;
            }
            for frag in [Vec::new(), pat(33, 9)] {
                let t = tag(m.as_ref(), &key, &frag, &st, n);
                for p in 1..=n / 2 {
                    if n % p == 0 && t.chunks(p).all(|c| c == &t[..p]) {
                        return Err(format!("tag of length {n} repeats with period {p} (p = 1 is a constant tag; otherwise silent truncation/fill?)"));
                    }
                }
                ensure(t[n - 8..].iter().any(|&b| b != 0), || {
                    format!("last 8 bytes of a {n}-byte tag are zero (padding?)")
                })?;
            }
        }
        Ok(())
    });
}

// ------------------------------------------------------------- sensitivity

fn group_sensitivity(r: &mut Runner, mac: &Arc<dyn SealMac>) {
    let m = mac.clone();
    r.check(Group::Sensitivity, "every bit of the key changes the tag", move || {
        let key = pat(m.key_len(), 11);
        let frag = pat(16, 12);
        let st = pat_state(13);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let base = tag(m.as_ref(), &key, &frag, &st, n);
            for bit in 0..key.len() * 8 {
                let mut k = key.clone();
                k[bit / 8] ^= 1 << (bit % 8);
                ensure(tag(m.as_ref(), &k, &frag, &st, n) != base, || {
                    format!("flipping key bit {bit} does not change the tag (length {n})")
                })?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Sensitivity, "every bit of a 16-byte fragment changes the tag", move || {
        let key = pat(m.key_len(), 14);
        let frag = pat(16, 15);
        let st = pat_state(16);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let base = tag(m.as_ref(), &key, &frag, &st, n);
            for bit in 0..frag.len() * 8 {
                let mut f = frag.clone();
                f[bit / 8] ^= 1 << (bit % 8);
                ensure(tag(m.as_ref(), &key, &f, &st, n) != base, || {
                    format!("flipping fragment bit {bit} does not change the tag (length {n})")
                })?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Sensitivity, "every bit of the chain state Es(i) changes the tag", move || {
        let key = pat(m.key_len(), 17);
        let frag = pat(16, 18);
        let st = pat_state(19);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let base = tag(m.as_ref(), &key, &frag, &st, n);
            for bit in 0..CHAIN_STATE_LEN * 8 {
                let mut s = st;
                s[bit / 8] ^= 1 << (bit % 8);
                ensure(tag(m.as_ref(), &key, &frag, &s, n) != base, || {
                    format!("flipping state bit {bit} does not change the tag (length {n})")
                })?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Sensitivity, "first, middle and last byte of a 1 KiB fragment matter", move || {
        let key = pat(m.key_len(), 20);
        let frag = pat(1024, 21);
        let st = pat_state(22);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let base = tag(m.as_ref(), &key, &frag, &st, n);
            for pos in [0usize, 511, 1023] {
                let mut f = frag.clone();
                f[pos] ^= 0x80;
                ensure(tag(m.as_ref(), &key, &f, &st, n) != base, || {
                    format!("byte {pos} of a 1 KiB fragment is ignored (length {n})")
                })?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Sensitivity, "first, middle and last byte of a 64 KiB fragment matter (no input truncation)", move || {
        let key = pat(m.key_len(), 29);
        let frag = pat(64 * 1024, 30);
        let st = pat_state(31);
        let n = tag_lens(m.as_ref()).and_then(|v| v.last().copied()).unwrap_or(32);
        let base = tag(m.as_ref(), &key, &frag, &st, n);
        for pos in [0usize, 32 * 1024, 64 * 1024 - 1] {
            let mut f = frag.clone();
            f[pos] ^= 0x01;
            ensure(tag(m.as_ref(), &key, &f, &st, n) != base, || {
                format!("byte {pos} of a 64 KiB fragment is ignored (input truncated?)")
            })?;
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Sensitivity, "the whole tag depends on the input (last 8 bytes too)", move || {
        let key = pat(m.key_len(), 23);
        let st = pat_state(24);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            if n < 16 {
                continue;
            }
            let a = tag(m.as_ref(), &key, &pat(40, 25), &st, n);
            let b = tag(m.as_ref(), &key, &pat(40, 26), &st, n);
            ensure(a[n - 8..] != b[n - 8..], || {
                format!("tail of a {n}-byte tag does not depend on the fragment")
            })?;
        }
        Ok(())
    });
}

// -------------------------------------------------------------- parameters

fn group_parameters(r: &mut Runner, mac: &Arc<dyn SealMac>) {
    let m = mac.clone();
    r.check(Group::Parameters, "Core rejects parameters the declaration does not allow", move || {
        let try_params = |p: Vec<u8>| -> Result<(), String> {
            let d = SuiteDescriptor::new(m.id(), p.clone(), None).map_err(|e| format!("{e:?}"))?;
            match ValidatedSuite::new(d, m.clone()) {
                Err(_) => Ok(()),
                Ok(_) => Err(format!("params {} were accepted", hex(&p))),
            }
        };
        match m.output() {
            OutputKind::Fixed(_) => {
                try_params(vec![0])?;
                try_params(vec![0, 32])?;
                try_params(xof_params(32))
            }
            OutputKind::Xof { min, max } => {
                try_params(vec![])?;
                try_params(vec![0])?;
                try_params(vec![0, 0, 0])?;
                try_params(xof_params(0))?;
                if min > 1 {
                    try_params(xof_params((min - 1) as u16))?;
                }
                try_params(xof_params((max + 1) as u16))?;
                try_params(xof_params(u16::MAX))
            }
        }
    });

    let m = mac.clone();
    r.check(Group::Parameters, "Core accepts the declared extremes", move || {
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let s = suite_of(&m, n, None)?;
            ensure(s.tag_len() == n, || format!("suite tag_len {} != requested {n}", s.tag_len()))?;
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Parameters, "tag length is bound to the session (no cross-verification)", move || {
        let OutputKind::Xof { min, max } = m.output() else { return Ok(()) };
        let sa = suite_of(&m, min, None)?;
        let sb = suite_of(&m, max, None)?;
        let mut sealer = SealerCoreV2::open_with_session_id(ring(), sid(3), sa, spec())
            .map_err(|e| format!("{e:?}"))?;
        let key_id = sealer.key_id();
        let (f, t) = sealer.seal_chunk(pat(10, 1), true).map_err(|e| format!("{e:?}"))?;
        let mut v = VerifierCoreV2::resume(ring(), sid(3), key_id, sb, spec()).map_err(|e| format!("{e:?}"))?;
        ensure(matches!(v.verify_frame(&f, key_id, &t), Err(CoreError::SealMismatch)), || {
            "a verifier with another tag length accepted the frame".into()
        })
    });
}

// -------------------------------------------------------------- robustness

fn group_robustness(r: &mut Runner, mac: &Arc<dyn SealMac>) {
    let m = mac.clone();
    r.check(Group::Robustness, "degenerate keys (all 0x00, all 0xFF) work and differ", move || {
        let st = pat_state(30);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let z = tag(m.as_ref(), &vec![0u8; m.key_len()], &[], &st, n);
            let f = tag(m.as_ref(), &vec![0xFFu8; m.key_len()], &[], &st, n);
            ensure(z != f, || "all-zero and all-FF keys give the same tag".into())?;
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Robustness, "empty fragment differs from one zero byte", move || {
        let key = pat(m.key_len(), 31);
        let st = pat_state(32);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            ensure(tag(m.as_ref(), &key, &[], &st, n) != tag(m.as_ref(), &key, &[0], &st, n), || {
                "empty fragment and [0] give the same tag".into()
            })?;
        }
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Robustness, "1 MiB fragment is handled without panic", move || {
        let key = pat(m.key_len(), 33);
        let st = pat_state(34);
        let n = tag_lens(m.as_ref()).and_then(|v| v.last().copied()).unwrap_or(32);
        let big = pat(1 << 20, 35);
        // The output length is fixed by the caller; what can go wrong here is a
        // panic or an abort, which the runner reports as a failure.
        let _ = tag(m.as_ref(), &key, &big, &st, n);
        Ok(())
    });

    let m = mac.clone();
    r.check(Group::Robustness, "a key longer or shorter than key_len is not required to work", move || {
        // Documented contract: the Core always passes exactly key_len bytes.
        // The suite only checks that the exact length works for every
        // supported tag length; behaviour on other lengths is unspecified.
        let key = pat(m.key_len(), 36);
        let st = pat_state(37);
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let _ = tag(m.as_ref(), &key, &[1, 2, 3], &st, n);
        }
        Ok(())
    });
}

// ----------------------------------------------------------- statelessness

fn group_statelessness(r: &mut Runner, mac: &Arc<dyn SealMac>, opts: &Options) {
    let m = mac.clone();
    r.check(Group::Statelessness, "interleaved calls do not influence each other", move || {
        let ka = pat(m.key_len(), 40);
        let kb = pat(m.key_len(), 41);
        let (sa, sb) = (pat_state(42), pat_state(43));
        for n in tag_lens(m.as_ref()).unwrap_or_default() {
            let a1 = tag(m.as_ref(), &ka, &pat(50, 1), &sa, n);
            let b1 = tag(m.as_ref(), &kb, &pat(70, 2), &sb, n);
            let _ = tag(m.as_ref(), &ka, &pat(10, 3), &sb, n);
            let a2 = tag(m.as_ref(), &ka, &pat(50, 1), &sa, n);
            let b2 = tag(m.as_ref(), &kb, &pat(70, 2), &sb, n);
            ensure(a1 == a2 && b1 == b2, || format!("result depends on earlier calls (length {n})"))?;
        }
        Ok(())
    });

    let m = mac.clone();
    let threads = opts.threads.max(2);
    r.check(Group::Statelessness, "concurrent calls from several threads agree", move || {
        let ns = tag_lens(m.as_ref()).unwrap_or_default();
        let key = pat(m.key_len(), 44);
        let inputs: Vec<(Vec<u8>, [u8; 32])> =
            (0..8u8).map(|i| (pat(20 + i as usize * 37, i), pat_state(i))).collect();
        let expect: Vec<Vec<Vec<u8>>> = ns
            .iter()
            .map(|&n| inputs.iter().map(|(f, s)| tag(m.as_ref(), &key, f, s, n)).collect())
            .collect();
        let bad = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    let (m, key, inputs, expect, ns) = (&m, &key, &inputs, &expect, &ns);
                    sc.spawn(move || {
                        for round in 0..40 {
                            for (ni, &n) in ns.iter().enumerate() {
                                let k = (round + t) % inputs.len();
                                let (f, s) = &inputs[k];
                                if tag(m.as_ref(), key, f, s, n) != expect[ni][k] {
                                    return false;
                                }
                            }
                        }
                        true
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap_or(false)).any(|ok| !ok)
        });
        ensure(!bad, || "a concurrent call gave a different tag or panicked".into())
    });
}

// ----------------------------------------------------------------- journey

type Pair = (SealerCoreV2, VerifierCoreV2);

fn session(m: &Arc<dyn SealMac>, n: usize, session_byte: u8) -> Result<Pair, String> {
    let suite = suite_of(m, n, None)?;
    let sealer = SealerCoreV2::open_with_session_id(ring(), sid(session_byte), suite.clone(), spec())
        .map_err(|e| format!("{e:?}"))?;
    let v = VerifierCoreV2::resume(ring(), sid(session_byte), sealer.key_id(), suite, spec())
        .map_err(|e| format!("{e:?}"))?;
    Ok((sealer, v))
}

fn mismatch<T>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::SealMismatch))
}

fn group_journey(r: &mut Runner, mac: &Arc<dyn SealMac>) {
    let lens = tag_lens(mac.as_ref()).unwrap_or_default();
    // Exercise the extremes only: they are the cases a variable-length
    // algorithm gets wrong.
    let lens: Vec<usize> = match (lens.first(), lens.last()) {
        (Some(&a), Some(&b)) if a != b => vec![a, b],
        (Some(&a), _) => vec![a],
        _ => vec![],
    };

    let m = mac.clone();
    let ls = lens.clone();
    r.check(Group::Journey, "multi-fragment payload round-trips through sealer and verifier", move || {
        for &n in &ls {
            let (mut s, mut v) = session(&m, n, 1)?;
            let key_id = s.key_id();
            let frames = s.seal_payload(&pat(5000, 50)).map_err(|e| format!("{e:?}"))?;
            ensure(frames.len() == 5, || format!("expected 5 frames, got {}", frames.len()))?;
            for (f, t) in &frames {
                ensure(t.len() == n, || format!("tag is {} bytes, suite says {n}", t.len()))?;
                v.verify_frame(f, key_id, t).map_err(|e| format!("valid frame rejected: {e:?}"))?;
            }
            ensure(v.next_expected_index() == 5, || "verifier did not advance".into())?;
            let (mut s, mut v) = session(&m, n, 2)?;
            let frames = s.seal_payload(&[]).map_err(|e| format!("{e:?}"))?;
            for (f, t) in &frames {
                v.verify_frame(f, s.key_id(), t).map_err(|e| format!("empty payload rejected: {e:?}"))?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    let ls = lens.clone();
    r.check(Group::Journey, "every tampering of frame or tag is rejected and leaves the session usable", move || {
        for &n in &ls {
            let (mut s, _) = session(&m, n, 3)?;
            let key_id = s.key_id();
            let frames = s.seal_payload(&pat(3000, 51)).map_err(|e| format!("{e:?}"))?;
            let (f0, t0) = frames[0].clone();
            let t1 = frames[1].1.clone();
            type Tamper = (&'static str, Box<dyn Fn() -> Option<(lacre_core::frame::LacreFrame, SealTag)>>);
            let (a, b) = (f0.clone(), t0.clone());
            let cases: Vec<Tamper> = vec![
                ("payload bit flipped", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || { let mut f = a.clone(); f.payload[0] ^= 1; Some((f, b.clone())) }
                })),
                ("payload extended", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || { let mut f = a.clone(); f.payload.push(0); Some((f, b.clone())) }
                })),
                ("payload truncated", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || { let mut f = a.clone(); f.payload.pop(); Some((f, b.clone())) }
                })),
                ("tag first byte flipped", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || {
                        let mut t = b.as_bytes().to_vec(); t[0] ^= 1;
                        SealTag::new(t).ok().map(|t| (a.clone(), t))
                    }
                })),
                ("tag last byte flipped", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || {
                        let mut t = b.as_bytes().to_vec(); let l = t.len() - 1; t[l] ^= 1;
                        SealTag::new(t).ok().map(|t| (a.clone(), t))
                    }
                })),
                ("tag truncated by one byte", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || {
                        let mut t = b.as_bytes().to_vec(); t.pop();
                        SealTag::new(t).ok().map(|t| (a.clone(), t))
                    }
                })),
                ("tag extended by one byte", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || {
                        let mut t = b.as_bytes().to_vec(); t.push(0);
                        SealTag::new(t).ok().map(|t| (a.clone(), t))
                    }
                })),
                ("tag all zeros", Box::new({
                    let (a, b) = (a.clone(), b.clone());
                    move || SealTag::new(vec![0; b.len()]).ok().map(|t| (a.clone(), t))
                })),
                ("tag of another frame", Box::new({
                    let (a, t1) = (a.clone(), t1.clone());
                    move || Some((a.clone(), t1.clone()))
                })),
            ];
            for (name, make) in &cases {
                let Some((f, t)) = make() else { continue };
                let (_, mut v) = session(&m, n, 3)?;
                ensure(mismatch(v.verify_frame(&f, key_id, &t)), || {
                    format!("tampering not rejected: {name} (tag length {n})")
                })?;
                ensure(v.next_expected_index() == 0, || format!("state advanced after rejecting: {name}"))?;
                v.verify_frame(&f0, key_id, &t0)
                    .map_err(|e| format!("session unusable after rejecting '{name}': {e:?}"))?;
            }
        }
        Ok(())
    });

    let m = mac.clone();
    let ls = lens.clone();
    r.check(Group::Journey, "reordering and replay are rejected by position", move || {
        for &n in &ls {
            let (mut s, mut v) = session(&m, n, 4)?;
            let key_id = s.key_id();
            let frames = s.seal_payload(&pat(2500, 52)).map_err(|e| format!("{e:?}"))?;
            ensure(
                matches!(v.verify_frame(&frames[1].0, key_id, &frames[1].1), Err(CoreError::OutOfSequence { .. })),
                || "frame 1 accepted before frame 0".into(),
            )?;
            v.verify_frame(&frames[0].0, key_id, &frames[0].1).map_err(|e| format!("{e:?}"))?;
            ensure(
                matches!(v.verify_frame(&frames[0].0, key_id, &frames[0].1), Err(CoreError::OutOfSequence { .. })),
                || "replay of frame 0 accepted".into(),
            )?;
        }
        Ok(())
    });

    let m = mac.clone();
    let ls = lens.clone();
    r.check(Group::Journey, "tags are deterministic per session and differ across sessions", move || {
        for &n in &ls {
            let payload = pat(16 * 1024, 53);
            let t = |sb: u8| -> Result<Vec<Vec<u8>>, String> {
                let (mut s, _) = session(&m, n, sb)?;
                Ok(s.seal_payload(&payload).map_err(|e| format!("{e:?}"))?.iter().map(|(_, t)| t.as_bytes().to_vec()).collect())
            };
            let (a1, a2, b) = (t(5)?, t(5)?, t(6)?);
            ensure(a1 == a2, || "same session and payload gave different tags".into())?;
            ensure(a1.iter().zip(&b).all(|(x, y)| x != y), || "two sessions share a tag".into())?;
        }
        Ok(())
    });

    let m = mac.clone();
    let ls = lens;
    r.check(Group::Journey, "the declared signature scheme is part of the suite binding", move || {
        for &n in &ls {
            let plain = suite_of(&m, n, None)?;
            let signed = signed_suite_of(&m, n)?;
            let mut s = SealerCoreV2::open_with_session_id(ring(), sid(7), plain, spec()).map_err(|e| format!("{e:?}"))?;
            let key_id = s.key_id();
            let (f, t) = s.seal_chunk(pat(30, 1), true).map_err(|e| format!("{e:?}"))?;
            let mut v = VerifierCoreV2::resume_signed(ring(), sid(7), key_id, signed, spec(), &[7u8; 32])
                .map_err(|e| format!("{e:?}"))?;
            // Neither a missing signature nor a frame sealed under another suite may pass.
            ensure(v.verify_frame_signed(&f, key_id, &t, None).is_err(), || {
                "a verifier whose descriptor names a signature scheme accepted a frame without a signature".into()
            })?;
            ensure(v.verify_frame_signed(&f, key_id, &t, Some(&[0u8; 32])).is_err(), || {
                "a verifier whose descriptor names a signature scheme accepted a frame sealed without one".into()
            })?;
        }
        Ok(())
    });
}

// ---------------------------------------------------------------- slowness

fn group_slowness(r: &mut Runner, mac: &Arc<dyn SealMac>, opts: &Options) {
    let m = mac.clone();
    let delay = opts.slow_delay;
    r.check(Group::Slowness, "a slow implementation yields the same tags", move || {
        let n = tag_lens(m.as_ref()).and_then(|v| v.first().copied()).unwrap_or(32);
        let slow: Arc<dyn SealMac> = Arc::new(SlowMac { inner: m.clone(), delay });
        let (mut fast, _) = session(&m, n, 8)?;
        let (mut slo, _) = session(&slow, n, 8)?;
        let a = fast.seal_payload(&pat(3000, 60)).map_err(|e| format!("{e:?}"))?;
        let b = slo.seal_payload(&pat(3000, 60)).map_err(|e| format!("{e:?}"))?;
        ensure(a.iter().zip(&b).all(|(x, y)| x.1 == y.1), || "delay changed the tags".into())
    });

    let m = mac.clone();
    let delay = opts.slow_delay;
    r.check(Group::Slowness, "with a slow algorithm the buffer cap holds and ack frees a slot", move || {
        let n = tag_lens(m.as_ref()).and_then(|v| v.first().copied()).unwrap_or(32);
        let slow: Arc<dyn SealMac> = Arc::new(SlowMac { inner: m.clone(), delay });
        let suite = suite_of(&slow, n, None)?;
        let tiny = BufferSpec::new(16, 2, Duration::from_secs(60), 1 << 16);
        let mut s = SealerCoreV2::open_with_session_id(ring(), sid(9), suite, tiny).map_err(|e| format!("{e:?}"))?;
        s.seal_chunk(pat(16, 1), false).map_err(|e| format!("{e:?}"))?;
        s.seal_chunk(pat(16, 2), false).map_err(|e| format!("{e:?}"))?;
        ensure(s.pending_count() == 2, || format!("pending {} != 2", s.pending_count()))?;
        ensure(s.seal_chunk(pat(16, 3), true).is_err(), || "third chunk accepted beyond the slot cap".into())?;
        ensure(s.ack(0), || "ack(0) did not free the slot".into())?;
        s.seal_chunk(pat(16, 3), true).map(|_| ()).map_err(|e| format!("after ack: {e:?}"))
    });

    let m = mac.clone();
    let delay = opts.slow_delay;
    r.check(Group::Slowness, "forced purge works while the algorithm is slow", move || {
        let n = tag_lens(m.as_ref()).and_then(|v| v.first().copied()).unwrap_or(32);
        let slow: Arc<dyn SealMac> = Arc::new(SlowMac { inner: m.clone(), delay });
        let suite = suite_of(&slow, n, None)?;
        let quick = BufferSpec::new(16, 4, delay / 2, 1 << 16);
        let mut s = SealerCoreV2::open_with_session_id(ring(), sid(10), suite, quick).map_err(|e| format!("{e:?}"))?;
        s.seal_chunk(pat(16, 1), false).map_err(|e| format!("{e:?}"))?;
        std::thread::sleep(delay * 2);
        let purged = s.purge_expired();
        ensure(purged >= 1 && s.pending_count() == 0, || {
            format!("purged {purged}, pending {}", s.pending_count())
        })
    });
}

// -------------------------------------------------------------------- cost

fn group_cost(r: &mut Runner, mac: &Arc<dyn SealMac>, opts: &Options) {
    let m = mac.clone();
    let opts = opts.clone();
    r.check(Group::Cost, "measured time fits the declared cost class", move || {
        let key = pat(m.key_len(), 70);
        let st = pat_state(71);
        let frag = pat(1024, 72);
        let n = tag_lens(m.as_ref()).and_then(|v| v.last().copied()).unwrap_or(32);
        let _ = tag(m.as_ref(), &key, &frag, &st, n); // warm-up
        let rounds = 20u32;
        let t0 = Instant::now();
        for _ in 0..rounds {
            let _ = tag(m.as_ref(), &key, &frag, &st, n);
        }
        let avg = t0.elapsed() / rounds;
        let budget = match m.cost() {
            CostClass::Light => opts.light_budget,
            CostClass::Standard => opts.standard_budget,
            CostClass::Heavy => opts.heavy_budget,
        };
        ensure(avg <= budget, || {
            format!("average {avg:?} for 1 KiB exceeds the budget {budget:?} of its declared class")
        })
    });
}

// ----------------------------------------------------- several algorithms

/// Two algorithms of the same registry must be distinguishable: different
/// ids, never the same function under another name, and a frame sealed under
/// one must never verify under the other.
pub fn check_crossed(a: Arc<dyn SealMac>, b: Arc<dyn SealMac>) -> Report {
    let mut r = Runner::new();
    let (ida, idb) = (a.id(), b.id());
    let name = format!("{ida} vs {idb}");

    let (a1, b1) = (a.clone(), b.clone());
    r.check(Group::Crossed, &format!("{name}: ids differ"), move || {
        ensure(a1.id() != b1.id(), || "two algorithms share an id".into())
    });

    let (a1, b1) = (a.clone(), b.clone());
    r.check(Group::Crossed, &format!("{name}: not the same function under two ids"), move || {
        let (Some(la), Some(lb)) = (crossed_lens(a1.as_ref()), crossed_lens(b1.as_ref())) else {
            return Err("unusable declaration".into());
        };
        let kl = a1.key_len().max(b1.key_len());
        let key = pat(kl, 80);
        let st = pat_state(81);
        for &na in &la {
            for &nb in &lb {
                if na != nb {
                    continue;
                }
                for frag in [Vec::new(), pat(64, 82)] {
                    let ta = tag(a1.as_ref(), &key[..a1.key_len()], &frag, &st, na);
                    let tb = tag(b1.as_ref(), &key[..b1.key_len()], &frag, &st, nb);
                    ensure(ta != tb, || format!("same tag for the same input at length {na}: aliases"))?;
                }
            }
        }
        Ok(())
    });

    let (a1, b1) = (a, b);
    r.check(Group::Crossed, &format!("{name}: a session sealed under one is rejected under the other"), move || {
        let (Some(la), Some(lb)) = (tag_lens(a1.as_ref()), tag_lens(b1.as_ref())) else {
            return Err("unusable declaration".into());
        };
        let sa = suite_of(&a1, la[0], None)?;
        let sb = suite_of(&b1, lb[0], None)?;
        let mut s = SealerCoreV2::open_with_session_id(ring(), sid(11), sa, spec()).map_err(|e| format!("{e:?}"))?;
        let key_id = s.key_id();
        let (f, t) = s.seal_chunk(pat(40, 1), true).map_err(|e| format!("{e:?}"))?;
        let mut v = VerifierCoreV2::resume(ring(), sid(11), key_id, sb, spec()).map_err(|e| format!("{e:?}"))?;
        ensure(mismatch(v.verify_frame(&f, key_id, &t)), || "frame sealed under A verified under B".into())
    });
    r.report
}

/// Runs the full suite on each entry and every pair for isolation, and
/// checks that ids are unique. `entries` carry each algorithm's vectors.
pub fn check_catalogue(entries: &[(Arc<dyn SealMac>, Vec<Kat>)], opts: &Options) -> Report {
    let mut rep = Report::default();
    let mut ids: Vec<&str> = entries.iter().map(|(m, _)| m.id()).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    let unique = ids.len() == total;
    let mut r = Runner::new();
    r.check(Group::Crossed, "catalogue: ids are unique", move || {
        ensure(unique, || "duplicate ids in the catalogue".into())
    });
    rep.extend(r.report);
    for (m, kats) in entries {
        rep.extend(check_seal_mac(m.clone(), kats, opts));
    }
    for i in 0..entries.len() {
        for j in i + 1..entries.len() {
            rep.extend(check_crossed(entries[i].0.clone(), entries[j].0.clone()));
        }
    }
    rep
}

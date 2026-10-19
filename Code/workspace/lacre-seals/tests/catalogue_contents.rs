//! The catalogue is exactly what was decided: ids, status, cost, key and
//! output. Changing any of them is a deliberate act that must touch this table.

use lacre_core::suite::{CostClass as C, OutputKind as O, Status as S};

#[test]
fn the_catalogue_is_exactly_the_decided_one() {
    #[allow(unused_mut)]
    let mut want: Vec<(&str, S, C, u16, usize, O)> = vec![
        ("hmac-sha256", S::Standard, C::Light, 128, 32, O::Fixed(32)),
        ("hmac-sha512", S::Standard, C::Standard, 256, 64, O::Fixed(64)),
        ("hmac-sha3-512", S::Standard, C::Standard, 256, 64, O::Fixed(64)),
        ("blake2b-keyed", S::Standard, C::Light, 256, 64, O::Fixed(64)),
        ("blake3-keyed-xof", S::Standard, C::Light, 128, 32, O::Xof { min: 16, max: 1024 }),
        ("aes-cmac", S::Standard, C::Light, 128, 32, O::Fixed(16)),
        ("kmac256", S::Experimental, C::Light, 256, 32, O::Xof { min: 16, max: 1024 }),
    ];
    #[cfg(feature = "legacy-seals")]
    want.push(("hmac-sha1", S::Legacy, C::Light, 80, 20, O::Fixed(20)));

    let all = lacre_seals::all();
    let got: Vec<_> = all.iter().map(|m| (m.id(), m.status(), m.cost(), m.security_bits(), m.key_len(), m.output())).collect();
    assert_eq!(got, want);
}

#[test]
fn no_catalogue_algorithm_exceeds_the_core_limits() {
    for m in lacre_seals::all() {
        assert!((16..=128).contains(&m.key_len()), "{}", m.id());
        match m.output() {
            O::Fixed(n) => assert!((1..=1024).contains(&n)),
            O::Xof { min, max } => assert!(1 <= min && min <= max && max <= 1024),
        }
    }
}

#[test]
fn the_core_does_not_know_the_catalogue() {
    let ws = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let toml = std::fs::read_to_string(format!("{ws}/lacre-core/Cargo.toml")).unwrap();
    for banned in ["lacre-seals", "sha3", "blake2", "cmac", "kmac", "sha1", "aes"] {
        assert!(!toml.contains(banned), "lacre-core/Cargo.toml mentions {banned}");
    }
    for entry in std::fs::read_dir(format!("{ws}/lacre-core/src")).unwrap() {
        let p = entry.unwrap().path();
        let src = std::fs::read_to_string(&p).unwrap();
        assert!(!src.contains("lacre_seals"), "{} references lacre_seals", p.display());
    }
}

#[test]
fn sha1_is_opt_in_and_never_default() {
    let toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    assert!(toml.contains("default = []"));
    assert!(toml.contains("sha1 = { version = \"0.10\", optional = true }"));
    assert!(toml.contains("legacy-seals = [\"dep:sha1\"]"));
}

#[test]
fn the_catalogue_contains_no_unsafe_and_implements_no_primitive() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    for f in ["lib.rs", "algorithms.rs", "kmac.rs"] {
        let src = std::fs::read_to_string(format!("{dir}/{f}")).unwrap();
        assert!(!src.lines().any(|l| l.trim_start().starts_with("unsafe") || l.contains(" unsafe {")), "{f}");
    }
    let lib = std::fs::read_to_string(format!("{dir}/lib.rs")).unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    // Only KMAC is assembled here (on cSHAKE); no round function or permutation.
    for f in ["lib.rs", "algorithms.rs", "kmac.rs"] {
        let src = std::fs::read_to_string(format!("{dir}/{f}")).unwrap();
        for banned in ["rotate_left", "rotate_right", "keccak", "wrapping_add", "0x6a09e667", "0x428a2f98"] {
            assert!(!src.contains(banned), "{f} looks like it implements a primitive: {banned}");
        }
    }
}

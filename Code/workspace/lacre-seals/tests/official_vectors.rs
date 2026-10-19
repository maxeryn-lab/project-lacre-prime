//! Official known-answer vectors against the primitive code the adapters
//! call (`lacre_seals::raw`), with no Lacre framing. Sources, in order of
//! authority: upstream test-vector files of the algorithms (BLAKE3, BLAKE2),
//! NIST (SP 800-38B, SP 800-185), IETF RFCs 2202/4231.

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

fn raw(id: &str, key: &[u8], msg: &[u8], s: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    lacre_seals::raw(id, key, msg, s, &mut out).unwrap();
    out
}

#[test]
fn rfc4231_hmac_sha256_and_sha512() {
    // Test cases 1 and 2.
    let k1 = [0x0bu8; 20];
    assert_eq!(raw("hmac-sha256", &k1, b"Hi There", b"", 32), unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    assert_eq!(raw("hmac-sha512", &k1, b"Hi There", b"", 64), unhex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"));
    let m2 = b"what do ya want for nothing?";
    assert_eq!(raw("hmac-sha256", b"Jefe", m2, b"", 32), unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    assert_eq!(raw("hmac-sha512", b"Jefe", m2, b"", 64), unhex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
}

#[test]
fn nist_sp800_38b_aes256_cmac() {
    // Appendix D.3, AES-256, Examples 1-4 (the same messages as RFC 4493).
    let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let m = unhex("6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710");
    for (len, tag) in [
        (0, "028962f61b7bf89efc6b551f4667d983"),
        (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
        (40, "aaf3d8f1de5640c232f5b169b9c911e6"),
        (64, "e1992190549f6ed5696a2c056c315410"),
    ] {
        assert_eq!(raw("aes-cmac", &key, &m[..len], b"", 16), unhex(tag), "message length {len}");
    }
}

#[test]
fn rfc2202_hmac_sha1() {
    #[cfg(feature = "legacy-seals")]
    {
        let k1 = [0x0bu8; 20];
        assert_eq!(raw("hmac-sha1", &k1, b"Hi There", b"", 20), unhex("b617318655057264e28bc0b6fb378c8ef146be00"));
        assert_eq!(raw("hmac-sha1", b"Jefe", b"what do ya want for nothing?", b"", 20), unhex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
    }
    #[cfg(not(feature = "legacy-seals"))]
    assert!(lacre_seals::raw("hmac-sha1", &[0; 20], b"", b"", &mut [0; 20]).is_err(), "hmac-sha1 must not exist without the feature");
}

#[test]
fn nist_sp800_185_kmac256_sample_4() {
    // KMAC_samples.pdf, Sample #4: K = 40..5F, X = 00 01 02 03,
    // S = "My Tagged Application", L = 512 bits.
    let key: Vec<u8> = (0x40u8..=0x5F).collect();
    let got = raw("kmac256", &key, &[0, 1, 2, 3], b"My Tagged Application", 64);
    assert_eq!(
        got,
        unhex("20C570C31346F703C9AC36C61C03CB64 C3970D0CFC787E9B79599D273A68D2F7 F69D4CC3DE9D104A351689F27CF6F595 1F0103F33F4F24871024D9C27773A8DD")
    );
}

#[test]
fn blake3_official_keyed_hash_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/official/blake3-test_vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let key = v["key"].as_str().unwrap().as_bytes().to_vec();
    assert_eq!(key.len(), 32);
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for c in cases {
        let n = c["input_len"].as_u64().unwrap() as usize;
        let input: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let want = unhex(c["keyed_hash"].as_str().unwrap());
        assert_eq!(want.len(), 131);
        assert_eq!(raw("blake3-keyed-xof", &key, &input, b"", 131), want, "xof input_len {n}");
        // tag_len = 32 is the ordinary keyed hash.
        assert_eq!(raw("blake3-keyed-xof", &key, &input, b"", 32), want[..32], "32-byte input_len {n}");
    }
}

#[test]
fn blake2b_official_keyed_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors/official/blake2-kat.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut n = 0;
    for c in v.as_array().unwrap() {
        if c["hash"] != "blake2b" || c["key"].as_str().unwrap().is_empty() {
            continue;
        }
        let key = unhex(c["key"].as_str().unwrap());
        if key.len() != 64 {
            continue;
        }
        let want = unhex(c["out"].as_str().unwrap());
        if want.len() != 64 {
            continue;
        }
        assert_eq!(raw("blake2b-keyed", &key, &unhex(c["in"].as_str().unwrap()), b"", 64), want);
        n += 1;
    }
    assert!(n >= 200, "only {n} official keyed BLAKE2b vectors matched the 64/64 shape");
}

#!/usr/bin/env python3
"""E3: mutaciones sobre el catálogo lacre-seals. Cada mutante rompe un adaptador, la tabla de
metadatos, el despacho o la composición KMAC; los tests del catálogo (vectores oficiales, vectores
independientes de Python, suite de conformidad, tabla decidida) deben detectarlo. Se ejecuta con la
feature legacy-seals para cubrir SHA-1. Restaura siempre los archivos; no correr junto a otra
herramienta que compile el workspace."""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
A = 'lacre-seals/src/algorithms.rs'; K = 'lacre-seals/src/kmac.rs'; L = 'lacre-seals/src/lib.rs'
def rev(fn_sig):  # invierte el orden de las partes dentro de un adaptador
    return (A, fn_sig, fn_sig, None)
MUTS = [
 (A, 'Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts {', 'Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts.iter().rev() {', 'hmac-sha256: partes en orden inverso'),
 (A, 'Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts {', 'Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts.iter().rev() {', 'hmac-sha512: partes en orden inverso'),
 (A, 'Hmac::<Sha3_512>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts {', 'Hmac::<Sha3_512>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts.iter().rev() {', 'hmac-sha3-512: partes en orden inverso'),
 (A, 'expect("BLAKE2b key is 1..=64 bytes");\n    for p in parts {', 'expect("BLAKE2b key is 1..=64 bytes");\n    for p in parts.iter().rev() {', 'blake2b-keyed: partes en orden inverso'),
 (A, 'let mut h = blake3::Hasher::new_keyed(&key);\n    for p in parts {', 'let mut h = blake3::Hasher::new_keyed(&key);\n    for p in parts.iter().rev() {', 'blake3-keyed-xof: partes en orden inverso'),
 (A, 'expect("AES-256 key is 32 bytes");\n    for p in parts {', 'expect("AES-256 key is 32 bytes");\n    for p in parts.iter().rev() {', 'aes-cmac: partes en orden inverso'),
 (A, 'Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts {', 'Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC accepts any key length");\n    for p in parts.iter().rev() {', 'hmac-sha1: partes en orden inverso'),
 (A, 'Hmac::<Sha256>::new_from_slice(key)', 'Hmac::<Sha256>::new_from_slice(&[0u8; 32])', 'hmac-sha256: ignora la clave'),
 (A, 'Hmac::<Sha3_512>::new_from_slice(key)', 'Hmac::<Sha3_512>::new_from_slice(&key[..key.len() - 1])', 'hmac-sha3-512: ignora el último byte de la clave'),
 (A, '<cmac::Cmac<aes::Aes256> as Mac>', '<cmac::Cmac<aes::Aes128> as Mac>', 'aes-cmac: AES-128 en vez de AES-256'),
 (A, 'HmacSha512, "hmac-sha512", Status::Standard, CostClass::Standard, 256, 64, OutputKind::Fixed(64), hmac_sha512', 'HmacSha512, "hmac-sha512", Status::Standard, CostClass::Standard, 256, 64, OutputKind::Fixed(64), hmac_sha3_512', 'hmac-sha512 usa el adaptador de sha3'),
 (A, 'Blake2bKeyed, "blake2b-keyed", Status::Standard, CostClass::Light, 256, 64,', 'Blake2bKeyed, "blake2b-keyed", Status::Standard, CostClass::Light, 256, 32,', 'blake2b-keyed declara clave de 32'),
 (A, 'HmacSha3_512, "hmac-sha3-512", Status::Standard, CostClass::Standard,', 'HmacSha3_512, "hmac-sha3-512", Status::Standard, CostClass::Heavy,', 'hmac-sha3-512 declara coste Heavy'),
 (A, 'Aes256Cmac, "aes-cmac", Status::Standard, CostClass::Light, 128, 32, OutputKind::Fixed(16)', 'Aes256Cmac, "aes-cmac", Status::Standard, CostClass::Light, 128, 32, OutputKind::Fixed(32)', 'aes-cmac declara salida de 32'),
 (A, 'HmacSha1, "hmac-sha1", Status::Legacy,', 'HmacSha1, "hmac-sha1", Status::Standard,', 'hmac-sha1 deja de ser Legacy'),
 (A, 'Blake3KeyedXof, "blake3-keyed-xof", Status::Standard, CostClass::Light, 128, 32, OutputKind::Xof { min: 16, max: 1024 }', 'Blake3KeyedXof, "blake3-keyed-xof", Status::Standard, CostClass::Light, 128, 32, OutputKind::Xof { min: 16, max: 4096 }', 'blake3-keyed-xof declara tope de 4096'),
 (K, 'h.update(&right_encode(out.len() * 8));', '', 'kmac256: sin right_encode(L)'),
 (K, 'const RATE: usize = 136;', 'const RATE: usize = 168;', 'kmac256: tasa de cSHAKE128 en vez de cSHAKE256'),
 (K, 'pub const LACRE_S: &[u8] = b"lacre/v2/seal";', 'pub const LACRE_S: &[u8] = b"lacre/v2/seaL";', 'kmac256: cambia la cadena de personalización'),
 (K, 'h.update(&bytepad(&encode_string(key), RATE));', 'h.update(&bytepad(&encode_string(&key[..key.len() - 1]), RATE));', 'kmac256: clave truncada'),
 (K, 'for p in parts {\n        h.update(p);\n    }', 'for p in parts.iter().rev() {\n        h.update(p);\n    }', 'kmac256: partes en orden inverso'),
 (K, 'fn status(&self) -> Status {\n        Status::Experimental', 'fn status(&self) -> Status {\n        Status::Standard', 'kmac256 deja de ser Experimental'),
 (K, 'let mut v = left_encode(s.len() * 8);', 'let mut v = left_encode(s.len());', 'kmac256: encode_string con longitud en bytes'),
 (L, '        Arc::new(Kmac256),\n', '', 'all() olvida kmac256'),
 (L, '        Arc::new(Blake2bKeyed),\n', '', 'all() olvida blake2b-keyed'),
 (L, '    all().into_iter().find(|m| m.id() == id)', '    all().into_iter().find(|m| m.id() == "hmac-sha256")', 'find devuelve siempre hmac-sha256'),
 (L, '"aes-cmac" => algorithms::aes_cmac(key, &[message], out),', '"aes-cmac" => algorithms::hmac_sha256(key, &[message], out),', 'raw: aes-cmac despacha a hmac-sha256'),
 (L, '    #[cfg(feature = "legacy-seals")]\n    v.push(Arc::new(HmacSha1));', '    v.push(Arc::new(Blake2bKeyed));', 'all() duplica blake2b y omite sha1'),
]
def main():
    only = set(sys.argv[1:]); killed = total = 0
    for i, (f, a, b, name) in enumerate(MUTS, 1):
        tag = f'S{i:02d}'
        if only and tag not in only: continue
        s = open(f).read()
        if a not in s:
            print(f'{tag}: NO APLICA — {name}', flush=True); continue
        total += 1
        open(f, 'w').write(s.replace(a, b, 1))
        try:
            r = subprocess.run(['cargo', 'test', '-p', 'lacre-seals', '--features', 'legacy-seals'], capture_output=True, text=True, timeout=290)
            dead = r.returncode != 0
        finally:
            open(f, 'w').write(s)
        killed += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} — {name}', flush=True)
    print(f'Mutantes muertos: {killed}/{total}')
main()

#!/usr/bin/env python3
"""Genera spec/vectors/seals-v2.json: tags del catálogo lacre-seals sobre el mensaje canónico
u64be(len f) || f || Es(i), calculados con implementaciones que no son las de Rust:
hashlib/hmac (HMAC-SHA256/512/SHA3-512/SHA1, BLAKE2b con clave), blake3 (paquete oficial),
cryptography (AES-256-CMAC) y pycryptodome (KMAC256, que reproduce la muestra #4 de NIST SP 800-185).
Uso: python3 Tools/gen_seal_vectors.py [--check]"""
import hashlib, hmac, json, os, sys
import blake3
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Hash import KMAC256

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'Code/workspace/spec/vectors/seals-v2.json')
KMAC_S = b'lacre/v2/seal'

def aes_cmac(key, msg):
    c = cmac.CMAC(algorithms.AES(key)); c.update(msg); return c.finalize()

ALGS = {  # id: (key_len, tag_lens, función)
    'hmac-sha256': (32, [32], lambda k, m, n: hmac.new(k, m, hashlib.sha256).digest()),
    'hmac-sha512': (64, [64], lambda k, m, n: hmac.new(k, m, hashlib.sha512).digest()),
    'hmac-sha3-512': (64, [64], lambda k, m, n: hmac.new(k, m, hashlib.sha3_512).digest()),
    'blake2b-keyed': (64, [64], lambda k, m, n: hashlib.blake2b(m, key=k, digest_size=64).digest()),
    'blake3-keyed-xof': (32, [16, 17, 32, 100, 1024], lambda k, m, n: blake3.blake3(m, key=k).digest(length=n)),
    'aes-cmac': (32, [16], lambda k, m, n: aes_cmac(k, m)),
    'kmac256': (32, [16, 32, 64, 200, 1024], lambda k, m, n: KMAC256.new(key=k, data=m, mac_len=n, custom=KMAC_S).digest()),
    'hmac-sha1': (20, [20], lambda k, m, n: hmac.new(k, m, hashlib.sha1).digest()),
}
FRAGMENT_LENS = [0, 1, 100, 135, 136, 137, 300, 1024]

def build():
    cases = []
    for aid, (klen, tlens, f) in ALGS.items():
        key = bytes((i * 7 + 3) & 0xFF for i in range(klen))
        for n in tlens:
            for flen in FRAGMENT_LENS:
                frag = bytes((i * 31 + 5) & 0xFF for i in range(flen))
                state = bytes((i * 13 + flen) & 0xFF for i in range(32))
                msg = flen.to_bytes(8, 'big') + frag + state
                cases.append({'seal_id': aid, 'tag_len': n, 'key_hex': key.hex(), 'fragment_hex': frag.hex(),
                              'state_hex': state.hex(), 'tag_hex': f(key, msg, n).hex()})
    return {'format': 'lacre-seal-vectors', 'protocol_version': 2,
            'generator': 'Tools/gen_seal_vectors.py (Python: hashlib, hmac, blake3, cryptography, pycryptodome; independiente de Rust)',
            'kmac_customization': KMAC_S.decode(), 'cases': cases}

def main():
    text = json.dumps(build(), indent=1) + '\n'
    if '--check' in sys.argv:
        ok = os.path.exists(OUT) and open(OUT).read() == text
        print('OK: vectores al día' if ok else 'FALLA: vectores desactualizados'); sys.exit(0 if ok else 1)
    open(OUT, 'w').write(text); print(f'escrito {OUT}: {len(build()["cases"])} casos')
main()

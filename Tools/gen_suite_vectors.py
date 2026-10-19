#!/usr/bin/env python3
"""Genera spec/vectors/suite-v2.json con Python (hashlib, hmac, blake3), sin usar Rust.
Cubre el descriptor canónico, el hash de suite, la derivación de claves por contexto, la cadena Es(i),
la entrada canónica del sello y los tags. Uso: python3 Tools/gen_suite_vectors.py [--check]"""
import hashlib, hmac, json, os, sys
import blake3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'Code/workspace/spec/vectors/suite-v2.json')

def descriptor(seal_id, params=b'', sig=None):
    out = bytes([2])
    for tag, val in ((1, b'hkdf-sha256'), (2, b'hmac-sha256'), (3, seal_id.encode()), (4, params), (5, (sig or '').encode())):
        out += bytes([tag, len(val)]) + val
    return out

def suite_hash(canon): return hashlib.sha256(b'lacre/v2/suite' + canon).digest()

def hkdf(ikm, salt, info, n):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b'', b'', 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); okm += t; i += 1
    return okm[:n]

def mac(alg, key, msg, out_len):
    if alg == 'hmac-sha256': return hmac.new(key, msg, hashlib.sha256).digest()
    if alg == 'hmac-sha512': return hmac.new(key, msg, hashlib.sha512).digest()
    if alg == 'blake3-keyed-xof': return blake3.blake3(msg, key=key).digest(length=out_len)
    raise SystemExit('unknown ' + alg)

ALGS = {  # id: (key_len, tag_len, params)
    'hmac-sha256': (32, 32, b''),
    'hmac-sha512': (64, 64, b''),
    'blake3-keyed-xof': (32, 128, (128).to_bytes(2, 'big')),
}
IKM = bytes(range(32)); SID = bytes(range(0x10, 0x20))
FRAGS = [b'', b'a', bytes(range(100)), b'\xff' * 33]

def case(name, alg, sig=None):
    key_len, tag_len, params = ALGS[alg]
    canon = descriptor(alg, params, sig); sh = suite_hash(canon)
    k_seal = hkdf(IKM, SID, b'lacre/v2/seal-key' + sh, key_len)
    k_chain = hkdf(IKM, SID, b'lacre/v2/chain-key' + sh, 32)
    es = hmac.new(k_chain, SID + b'lacre/v2/initial-state' + sh, hashlib.sha256).digest()
    frames = []
    for i, f in enumerate(FRAGS):
        msg = len(f).to_bytes(8, 'big') + f + es
        frames.append({'index': i, 'fragment_hex': f.hex(), 'state_hex': es.hex(), 'seal_input_hex': msg.hex(),
                       'tag_hex': mac(alg, k_seal, msg, tag_len).hex()})
        es = hmac.new(k_chain, es + f, hashlib.sha256).digest()
    return {'name': name, 'seal_id': alg, 'params_hex': params.hex(), 'signature': sig, 'tag_len': tag_len, 'key_len': key_len,
            'descriptor_hex': canon.hex(), 'suite_hash_hex': sh.hex(), 'seal_key_hex': k_seal.hex(),
            'chain_key_hex': k_chain.hex(), 'frames': frames}

doc = {
    'format': 'lacre-suite-vectors', 'protocol_version': 2,
    'generator': 'Tools/gen_suite_vectors.py (Python: hashlib, hmac, blake3; independiente de Rust)',
    'constants': {'suite_hash_domain': 'lacre/v2/suite', 'seal_key_label': 'lacre/v2/seal-key',
                  'chain_key_label': 'lacre/v2/chain-key', 'initial_state_context': 'lacre/v2/initial-state',
                  'chain_state_len': 32, 'max_tag_len': 1024},
    'ikm_hex': IKM.hex(), 'session_id_hex': SID.hex(),
    'cases': [case('hmac-sha256, 32 bytes', 'hmac-sha256'), case('hmac-sha512, 64 bytes', 'hmac-sha512'),
              case('hmac-sha512 con firma ed25519 en el descriptor', 'hmac-sha512', 'ed25519'),
              case('blake3 con clave y salida extensible, 128 bytes (1024 bits)', 'blake3-keyed-xof')],
}
text = json.dumps(doc, indent=1) + '\n'
if '--check' in sys.argv:
    sys.exit(0 if open(OUT).read() == text else 'suite-v2.json no coincide con el generador')
open(OUT, 'w').write(text); print('escrito', OUT, len(text), 'bytes')

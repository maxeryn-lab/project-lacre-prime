#!/usr/bin/env python3
"""Genera Code/third-party/hmac-sha3-256-seal/tests/vectors.json con Python (hmac + hashlib.sha3_256), sin Rust.
Entrada del sello: u64be(len(fragmento)) ∥ fragmento ∥ estado(32). Uso: python3 Tools/gen_third_party_vectors.py [--check]"""
import hashlib, hmac, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'Code/third-party/hmac-sha3-256-seal/tests/vectors.json')
cases = []
for i, frag in enumerate([b'', b'a', bytes(range(100)), b'\xff' * 1024, bytes(range(256)) * 8]):
    key = bytes((i * 7 + j) % 256 for j in range(32)); state = bytes((i * 13 + j * 3) % 256 for j in range(32))
    msg = len(frag).to_bytes(8, 'big') + frag + state
    cases.append({'key_hex': key.hex(), 'fragment_hex': frag.hex(), 'state_hex': state.hex(),
                  'tag_hex': hmac.new(key, msg, hashlib.sha3_256).hexdigest()})
doc = {'format': 'lacre-third-party-vectors', 'algorithm': 'hmac-sha3-256', 'generator': 'Tools/gen_third_party_vectors.py (Python: hmac, hashlib; independiente de Rust)', 'cases': cases}
text = json.dumps(doc, indent=2) + '\n'
if '--check' in sys.argv: sys.exit(0 if os.path.exists(OUT) and open(OUT).read() == text else 'desfasado')
open(OUT, 'w').write(text); print('escrito', OUT, len(cases), 'casos')

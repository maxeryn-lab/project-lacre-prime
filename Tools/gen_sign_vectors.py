#!/usr/bin/env python3
"""Genera spec/vectors/signatures-v2.json con Python (librería `cryptography`, OpenSSL), sin usar Rust.
Cubre la entrada de firma canónica (SignInput), firmas Ed25519 (deterministas, RFC 8032) y recibos v2.
Uso: python3 Tools/gen_sign_vectors.py [--check]"""
import hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'Code/workspace/spec/vectors/signatures-v2.json')
SIGN_DOMAIN = b'lacre/v2/vault-sig'; RECEIPT_DOMAIN = b'lacre/v2/receipt'

def u64(n): return n.to_bytes(8, 'big')
def pub(sk): return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

SECRET = bytes(range(0x40, 0x60))
SUITE_HASH = hashlib.sha256(b'vector-suite').digest()
SID = bytes(range(0x10, 0x20))
CASES = [(0, b'\x01' * 32), (1, b'\x02' * 64), (7, bytes(range(16))), (2**40, b'\xff' * 128), (3, b'\x00')]

sk = Ed25519PrivateKey.from_private_bytes(SECRET)
cases = []
for index, tag in CASES:
    msg = SIGN_DOMAIN + SUITE_HASH + SID + u64(index) + u64(len(tag)) + tag
    cases.append({'index': index, 'tag_hex': tag.hex(), 'sign_input_hex': msg.hex(), 'signature_hex': sk.sign(msg).hex(),
                  'receipt_hex': hashlib.sha256(RECEIPT_DOMAIN + SUITE_HASH + u64(index) + tag).hexdigest()})
doc = {'format': 'lacre-signature-vectors', 'protocol_version': 2,
       'generator': 'Tools/gen_sign_vectors.py (Python: cryptography/OpenSSL; independiente de Rust)',
       'constants': {'sign_domain': SIGN_DOMAIN.decode(), 'receipt_domain': RECEIPT_DOMAIN.decode()},
       'scheme': 'ed25519', 'secret_hex': SECRET.hex(), 'public_hex': pub(sk).hex(),
       'suite_hash_hex': SUITE_HASH.hex(), 'session_id_hex': SID.hex(), 'cases': cases}
text = json.dumps(doc, indent=2) + '\n'
if '--check' in sys.argv:
    sys.exit(0 if os.path.exists(OUT) and open(OUT).read() == text else 'desfasado')
open(OUT, 'w').write(text); print('escrito', OUT, len(cases), 'casos')

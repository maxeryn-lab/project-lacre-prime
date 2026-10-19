#!/usr/bin/env python3
"""Genera los vectores de respuesta conocida del formato de cable v1 con una
implementación INDEPENDIENTE de la de Rust (hashlib, hmac, cryptography, blake3).

Salida: Code/workspace/spec/vectors/wire-v1.json. Es determinista: volver a correrlo
debe producir el mismo archivo byte a byte (la prueba `python3 Tools/gen_vectors.py --check`
lo comprueba). Los vectores fijan el contrato de `Code/workspace/spec/LACRE-WIRE-v1.md`;
si el código Rust deja de reproducirlos, o cambia el contrato, o hay un error.
"""
import argparse, hashlib, hmac, json, sys
from pathlib import Path
import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

OUT = Path(__file__).resolve().parent.parent / 'Code' / 'workspace' / 'spec' / 'vectors' / 'wire-v1.json'
HKDF_INFO = b'lacre-core/v1/session-key'
STATE_CTX = b'lacre-core/v1/initial-state'
CAP_DOMAIN = b'lacre-domain/v1/capability'


def hkdf_key(ikm, sid):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=sid, info=HKDF_INFO).derive(ikm)


def hm(key, *parts):
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p)
    return m.digest()


def seal(algo, key, frag, state):
    if algo == 'sha256':
        return hm(key, frag, state)
    return blake3.blake3(frag + state, key=key).digest()


def split(payload, slot):
    return [payload[i:i + slot] for i in range(0, len(payload), slot)]


def chain(name, algo, ikm, sid, payload, slot):
    key = hkdf_key(ikm, sid)
    st = hm(key, sid, STATE_CTX)
    es0 = st
    frames = split(payload, slot)
    out = []
    for i, f in enumerate(frames):
        s = seal(algo, key, f, st)
        st = hm(key, st, f)
        out.append({
            'index': i, 'total_fragments': len(frames), 'is_last': i == len(frames) - 1,
            'payload_hex': f.hex(), 'seal_hex': s.hex(), 'state_after_hex': st.hex(),
            'receipt_hex': hashlib.sha256(s).hexdigest(),
        })
    return {'name': name, 'algo': algo, 'key_id': 0, 'ikm_hex': ikm.hex(), 'session_id_hex': sid.hex(),
            'session_key_hex': key.hex(), 'initial_state_hex': es0.hex(), 'slot_size': slot,
            'payload_hex': payload.hex(), 'frames': out}


def build():
    ikm = bytes(range(32))
    sid_a = bytes(range(0x10, 0x20))
    sid_b = bytes([0xA5] * 16)
    payload = bytes((i * 7 + 3) % 256 for i in range(2500))
    ch_sha = chain('core-sha256', 'sha256', ikm, sid_a, payload, 1024)
    ch_b3 = chain('lite-blake3', 'blake3', bytes([0x42] * 32), sid_b, payload[:700], 256)
    # X25519 -> HKDF (RFC 7748 §6.1 claves de Alice y Bob)
    a = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    b = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
    ka, kb = X25519PrivateKey.from_private_bytes(a), X25519PrivateKey.from_private_bytes(b)
    raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = ka.exchange(kb.public_key())
    assert shared == kb.exchange(ka.public_key())
    sid_h = bytes([0x33] * 16)
    # Ed25519 (RFC 8032, determinista): firma el sello de 32 bytes del primer frame de core-sha256
    seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    seal0 = bytes.fromhex(ch_sha['frames'][0]['seal_hex'])
    # Capacidades
    root, csid = bytes([1] * 32), bytes([7] * 16)
    caps = {s: hm(root, CAP_DOMAIN, b'\0', s.encode(), b'\0', csid).hex() for s in ('write', 'verify', 'ack')}
    scenarios = [
        {'name': 'secuencia correcta', 'chain': 'core-sha256', 'steps': [
            {'frame': 0, 'expect': 'ok'}, {'frame': 1, 'expect': 'ok'}, {'frame': 2, 'expect': 'ok'}]},
        {'name': 'un byte del payload alterado', 'chain': 'core-sha256', 'steps': [
            {'frame': 0, 'tamper': 'flip_payload_byte_0', 'expect': 'SealMismatch'},
            {'frame': 0, 'expect': 'ok'}]},
        {'name': 'el sello de otro fragmento', 'chain': 'core-sha256', 'steps': [
            {'frame': 0, 'tamper': 'seal_of_frame_1', 'expect': 'SealMismatch'}]},
        {'name': 'fuera de orden', 'chain': 'core-sha256', 'steps': [
            {'frame': 1, 'expect': 'OutOfSequence:0:1'}]},
        {'name': 'repetición de un fragmento ya verificado', 'chain': 'core-sha256', 'steps': [
            {'frame': 0, 'expect': 'ok'}, {'frame': 0, 'expect': 'OutOfSequence:1:0'}]},
        {'name': 'key_id desconocido', 'chain': 'core-sha256', 'steps': [
            {'frame': 0, 'key_id': 9, 'expect': 'UnknownKeyId'}]},
        {'name': 'cadena blake3 correcta', 'chain': 'lite-blake3', 'steps': [
            {'frame': 0, 'expect': 'ok'}, {'frame': 1, 'expect': 'ok'}, {'frame': 2, 'expect': 'ok'}]},
        {'name': 'blake3: el sello de la cadena sha256 no sirve', 'chain': 'lite-blake3', 'steps': [
            {'frame': 0, 'tamper': 'seal_from_chain:core-sha256:0', 'expect': 'SealMismatch'}]},
    ]
    return {
        'format': 'lacre-wire-vectors', 'protocol_version': 1,
        'generator': 'Tools/gen_vectors.py (Python: hashlib, hmac, cryptography, blake3; independiente de Rust)',
        'constants': {'hkdf_info': HKDF_INFO.decode(), 'initial_state_context': STATE_CTX.decode(),
                      'capability_domain': CAP_DOMAIN.decode(), 'seal_len': 32, 'session_id_len': 16,
                      'session_key_len': 32, 'vault_signature_len': 64},
        'key_derivation': [
            {'name': 'ikm de prueba, sesión A', 'ikm_hex': ikm.hex(), 'session_id_hex': sid_a.hex(),
             'session_key_hex': hkdf_key(ikm, sid_a).hex()},
            {'name': 'otra sesión, mismo ikm: clave distinta', 'ikm_hex': ikm.hex(), 'session_id_hex': sid_b.hex(),
             'session_key_hex': hkdf_key(ikm, sid_b).hex()},
        ],
        'handshake': {
            'name': 'RFC 7748 §6.1: claves de Alice y Bob', 'client_private_hex': a.hex(),
            'client_public_hex': raw(ka).hex(), 'server_private_hex': b.hex(), 'server_public_hex': raw(kb).hex(),
            'shared_secret_hex': shared.hex(), 'session_id_hex': sid_h.hex(),
            'session_key_hex': hkdf_key(shared, sid_h).hex(),
        },
        'chains': [ch_sha, ch_b3],
        'scenarios': scenarios,
        'vault': {
            'name': 'RFC 8032 §7.1 test 1: semilla', 'seed_hex': seed.hex(),
            'public_key_hex': raw_ed(sk).hex(), 'signed_seal_hex': seal0.hex(),
            'signature_hex': sk.sign(seal0).hex(),
        },
        'capability': {'root_hex': root.hex(), 'session_id_hex': csid.hex(), **caps},
    }


def raw_ed(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true', help='falla si el archivo existente difiere')
    a = ap.parse_args()
    text = json.dumps(build(), indent=1, ensure_ascii=False, sort_keys=False) + '\n'
    if a.check:
        ok = OUT.exists() and OUT.read_text() == text
        print('vectores', 'IGUALES' if ok else 'DIFERENTES o ausentes')
        sys.exit(0 if ok else 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print('escrito', OUT, len(text), 'bytes')


if __name__ == '__main__':
    main()

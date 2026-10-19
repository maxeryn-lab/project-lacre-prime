#!/usr/bin/env python3
"""E6: un algoritmo de un tercero (HMAC-SHA3-256, Code/third-party) recorre seal -> wire v2 -> verify contra el
nodo REAL (mismo servidor, registro compuesto en compilación). Los sellos se re-derivan fuera de Rust.
Uso: python3 Tools/e6_third_party_e2e.py --node RUTA_AL_BINARIO_DEL_TERCERO --stock RUTA_A_lacre-server"""
import argparse, hashlib, hmac, json, os, subprocess, sys, tempfile, time
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import external_suite as X

ID = 'hmac-sha3-256'
POLICY = {'wire_versions': [1, 2], 'max_session_memory_bytes': 67108864,
          'algorithms': [
              {'id': 'hmac-sha256', 'expect_status': 'standard', 'profiles': ['lite', 'core'], 'max_cost': 'standard'},
              {'id': ID, 'expect_status': 'experimental', 'profiles': ['lite', 'core'], 'max_cost': 'light'}]}
results = []
def rec(name, ok, detail=''):
    results.append(bool(ok)); print(('PASS ' if ok else 'FAIL ') + name + (f' | {detail}' if detail else ''))

def launch(binary, policy):
    port = X.free_port()
    pf = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False); json.dump(policy, pf); pf.close()
    env = dict(os.environ, LACRE_HTTP_ADDR=f'127.0.0.1:{port}', LACRE_SEAL_POLICY=pf.name)
    p = subprocess.Popen([binary] + (['--serve'] if 'lacre-server' in os.path.basename(binary) else []), env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f'http://127.0.0.1:{port}'
    for _ in range(100):
        if p.poll() is not None: return p, None
        try: requests.get(base + '/v1/health', timeout=0.5); return p, base
        except Exception: time.sleep(0.1)
    return p, None

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--node', required=True); ap.add_argument('--stock', required=True)
    a = ap.parse_args()

    # 1. El servidor de serie NO conoce el algoritmo: con esa política ni arranca.
    p, base = launch(a.stock, POLICY)
    try: p.wait(timeout=5)
    except subprocess.TimeoutExpired: pass
    err = p.stderr.read().decode() if p.poll() is not None else ''
    rec('servidor de serie + política que nombra al tercero: no arranca (no está compilado)', p.poll() == 1 and ID in err, f'código {p.poll()}')
    if p.poll() is None: p.terminate()

    # 2. El nodo compuesto con el tercero arranca y lo sirve.
    p, base = launch(a.node, POLICY)
    rec('nodo compuesto con el tercero arranca con la política', base is not None)
    if base is None: sys.exit(1)
    try:
        X.BASE = base
        post = X.post   # adjunta el token de capacidad como un cliente legítimo
        suite = {'seal': ID}
        k = X25519PrivateKey.generate()
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        c, hs = post('/v1/handshake', {'client_public_key_hex': pub.hex()})
        shared = k.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(hs['server_public_key_hex'])))
        payload = os.urandom(2500)
        c, s = post('/v1/seal', {'version': 2, 'profile': 'core', 'payload_hex': payload.hex(), 'session_id': hs['session_id'], 'suite': suite})
        rec('seal v2 con el algoritmo del tercero -> 200, version 2, suite y hash', c == 200 and s.get('version') == 2 and s['suite']['seal'] == ID, f'{c}')
        sh = hashlib.sha256(b'lacre/v2/suite' + X._v2_descriptor(ID, b'')).digest()
        rec('suite_hash del servidor = el calculado fuera', s.get('suite_hash_hex') == sh.hex())
        sid = bytes.fromhex(hs['session_id'])
        k_seal = X._v2_hkdf(shared, sid, b'lacre/v2/seal-key' + sh, 32)
        k_chain = X._v2_hkdf(shared, sid, b'lacre/v2/chain-key' + sh, 32)
        es = hmac.new(k_chain, sid + b'lacre/v2/initial-state' + sh, hashlib.sha256).digest()
        ok = len(s['frames']) == 3
        for f in s['frames']:
            frag = bytes.fromhex(f['payload_hex'])
            msg = len(frag).to_bytes(8, 'big') + frag + es
            ok &= hmac.new(k_seal, msg, hashlib.sha3_256).hexdigest() == f['seal_hex']
            es = hmac.new(k_chain, es + frag, hashlib.sha256).digest()
        rec('RE-DERIVACIÓN INDEPENDIENTE (HKDF + HMAC-SHA3-256 de Python) coincide con los sellos', ok)
        vb = {'version': 2, 'profile': 'core', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames'], 'suite': suite, 'reassemble': True}
        c, v = post('/v1/verify', vb)
        rec('verify v2 -> íntegro y payload completo', c == 200 and v.get('all_verified') is True and v.get('payload_hex') == payload.hex(), f'{c}')
        c, s2 = post('/v1/seal', {'version': 2, 'profile': 'core', 'payload_hex': os.urandom(40).hex(), 'suite': suite})
        fr = dict(s2['frames'][0], seal_hex=X.flip(s2['frames'][0]['seal_hex']))
        c, v = post('/v1/verify', {'version': 2, 'profile': 'core', 'session_id': s2['session_id'], 'key_id': 0, 'frames': [fr], 'suite': suite})
        rec('sello alterado -> rechazado', c == 200 and v.get('all_verified') is False)
        c, v = post('/v1/verify', {'version': 2, 'profile': 'core', 'session_id': s2['session_id'], 'key_id': 0, 'frames': s2['frames'], 'suite': suite})
        rec('tras el rechazo, la sesión intacta verifica', c == 200 and v.get('all_verified') is True)
        c, _ = post('/v1/seal', {'version': 2, 'profile': 'vault', 'payload_hex': '6162', 'suite': suite})
        rec('compilado no es autorizado: vault no está en su política -> 400/403', c in (400, 403), f'{c}')
        c, _ = post('/v1/seal', {'profile': 'core', 'payload_hex': '6162'})
        rec('v1 sigue idéntico en el nodo compuesto', c == 200)
    finally:
        p.terminate()

    # 3. Compilado no es autorizado: con el preset estándar el tercero no se admite.
    port = X.free_port()
    env = dict(os.environ, LACRE_HTTP_ADDR=f'127.0.0.1:{port}', LACRE_SEAL_POLICY='preset:standard')
    p = subprocess.Popen([a.node], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f'http://127.0.0.1:{port}'
    for _ in range(100):
        try: requests.get(base + '/v1/health', timeout=0.5); break
        except Exception: time.sleep(0.1)
    try:
        r = requests.post(base + '/v1/seal', json={'version': 2, 'profile': 'core', 'payload_hex': '6162', 'suite': {'seal': ID}}, timeout=30)
        rec('compilado pero fuera de la política (preset estándar) -> 403', r.status_code == 403, f'{r.status_code}')
    finally:
        p.terminate()
    print(f'TOTAL {len(results)}  PASS {sum(results)}  FAIL {len(results) - sum(results)}')
    sys.exit(0 if all(results) else 1)
main()

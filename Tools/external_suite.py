#!/usr/bin/env python3
"""Lacre — suite externa de caja negra (conformidad + regresión + benchmark).

Habla con un `lacre-server` por HTTP/WebSocket y NO importa nada del código
Rust: lo que comprueba es el contrato observable, y re-deriva los sellos de
forma independiente (HKDF + HMAC en Python) para no confiar en el propio
servidor. Pensada para correr también en la máquina del usuario.

Uso:
    python3 external_suite.py --url http://127.0.0.1:3917
    python3 external_suite.py --spawn path/al/lacre-server [--slow] [--bench]
    python3 external_suite.py --spawn ... --json resultado.json

Dependencias: stdlib + requests + websockets + cryptography.
Códigos de salida: 0 = todo conforme; 1 = algún check falló.

Tipos de resultado:
    PASS  conforme            FAIL  incumple el contrato (cuenta como fallo)
    GAP   brecha CONOCIDA y documentada: se espera que el
          servidor sea vulnerable hoy. No cuenta como fallo; si el servidor
          deja de ser vulnerable pasa a «GAP-CERRADO» (señal de que hay que
          actualizar el registro).
"""
import argparse, asyncio, copy, hashlib, hmac, json, os, re, signal, socket
import subprocess, sys, threading, time

import requests

V2_ON = False
TOKEN_IN_BODY = True    # forma de referencia (P1): el token de capacidad va en el cuerpo; con --token-in-header va en Authorization
WS_SSL = None     # contexto TLS para wss:// (solo con --cafile)
R = []          # (kind, name, detail)
BASE = None


def _wsopt():
    return {'ssl': WS_SSL} if WS_SSL is not None else {}


class _H2Requests:
    """Sustituto mínimo de `requests` que habla HTTP/2 (httpx), para probar un
    intermediario que expone h2. Solo cubre lo que usa esta suite."""
    def __init__(self, cafile):
        import httpx
        self._c = httpx.Client(http2=True, verify=cafile or True, timeout=60)

    def _call(self, method, url, **kw):
        if 'data' in kw:
            kw['content'] = kw.pop('data')
        t = kw.pop('timeout', None)
        if t is not None:
            kw['timeout'] = t
        return self._c.request(method, url, **kw)

    def post(self, url, **kw): return self._call('POST', url, **kw)
    def get(self, url, **kw): return self._call('GET', url, **kw)
    def request(self, method, url, **kw): return self._call(method, url, **kw)
    def Session(self): return self


def rec(name, ok, detail=''):
    R.append(('PASS' if ok else 'FAIL', name, detail))
    print(('PASS ' if ok else 'FAIL ') + name + (' | ' + detail if detail else ''))
    sys.stdout.flush()


def gap(name, still_vulnerable, detail=''):
    kind = 'GAP' if still_vulnerable else 'GAP-CERRADO'
    R.append((kind, name, detail))
    print(f'{kind} {name}' + (' | ' + detail if detail else ''))


RULESETS = {
    'orders': {'kind': 'guardian', 'fields': [{'name': 'order_id', 'type': 'integer', 'digits': 8}, {'name': 'customer', 'type': 'string'}]},
    'ids': {'kind': 'certifier', 'patterns': [{'pattern': 'LA-[0-9]{12}', 'occurrences_min': 1}]},
    'mixed': {'kind': 'engine', 'rules': [
        {'id': 'amount', 'on_fail': 'quarantine', 'field': 'amount', 'type': 'integer'},
        {'id': 'tag', 'on_fail': 'pass_with_flag', 'pattern': 'urgent', 'occurrences_min': 1}]},
}


CAPS = {}      # session_id -> {'write':..,'verify':..,'ack':..}  (tokens que el servidor entregó al abrir)
NOAUTH = object()   # token=NOAUTH: no enviar token aunque se conozca


def _scope_for(path, body):
    if path in ('/v1/verify', '/v1/toolchain/verify'):
        return 'verify'
    if path == '/v1/ack':
        return 'ack'
    if path in ('/v1/receipts', '/v1/toolchain/nodes', '/v1/seal/part') or (path == '/v1/seal' and body.get('session_id')):
        return 'write'
    return None


def _remember(j):
    if isinstance(j, dict) and 'capabilities' in j and 'session_id' in j:
        CAPS[j['session_id']] = j['capabilities']


def post(path, body, timeout=60, token=None):
    """POST JSON. Por defecto adjunta (Authorization: Bearer) el token del alcance
    correcto de la sesión nombrada en `body`, tal como lo haría un cliente legítimo.
    token=NOAUTH no envía nada; token='...' envía exactamente ese."""
    headers = {}
    if token is None:
        sc = _scope_for(path, body)
        caps = CAPS.get(body.get('session_id')) if sc else None
        if caps and caps.get(sc):
            headers['Authorization'] = 'Bearer ' + caps[sc]
    elif token is not NOAUTH:
        headers['Authorization'] = 'Bearer ' + token
    if TOKEN_IN_BODY and 'Authorization' in headers:
        body = dict(body, token=headers.pop('Authorization')[len('Bearer '):])
    r = requests.post(BASE + path, json=body, timeout=timeout, headers=headers)
    try:
        j = r.json()
    except Exception:
        return r.status_code, {'_raw': r.text[:200]}
    _remember(j)
    return r.status_code, j


def get(path):
    r = requests.get(BASE + path, timeout=30)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {'_raw': r.text[:200]}


def flip(hexstr):
    return ('00' if hexstr[:2] != '00' else '01') + hexstr[2:]


def accepted(c, v, key='all_verified'):
    return c == 200 and bool(v.get(key))


# ───────────────────────── grupos de checks ─────────────────────────

def group_frames():
    payload = os.urandom(200000).hex()
    for prof in ('lite', 'core', 'vault'):
        c, s = post('/v1/seal', {'profile': prof, 'payload_hex': payload})
        ok = c == 200
        rec(f'{prof}: seal 200000 B', ok, f'status {c}')
        if not ok:
            continue
        frames, sid = s['frames'], s['session_id']
        c, v = post('/v1/verify', {'profile': prof, 'session_id': sid, 'key_id': 0, 'frames': frames})
        rec(f'{prof}: verificación honesta', accepted(c, v))
        v_first = v
        rec(f'{prof}: payload reensamblado == original',
            ''.join(f['payload_hex'] for f in frames) == payload)

        c, s2 = post('/v1/seal', {'profile': prof, 'payload_hex': payload})
        f2 = copy.deepcopy(s2['frames']); f2[0]['payload_hex'] = flip(f2[0]['payload_hex'])
        c, v = post('/v1/verify', {'profile': prof, 'session_id': s2['session_id'], 'key_id': 0, 'frames': f2})
        rec(f'{prof}: payload alterado rechazado', not accepted(c, v))

        if len(frames) > 1:
            c, s3 = post('/v1/seal', {'profile': prof, 'payload_hex': payload})
            f3 = s3['frames']; f3[0], f3[1] = f3[1], f3[0]
            c, v = post('/v1/verify', {'profile': prof, 'session_id': s3['session_id'], 'key_id': 0, 'frames': f3})
            rec(f'{prof}: frames reordenados rechazados', not accepted(c, v))
            err = ((v.get('results') or [{}])[0].get('error') or '')
            rec(f'{prof}: el rechazo de un reorden se diagnostica como error de ORDEN (no solo como sello inválido)',
                'order' in err.lower(), err[:90])

            c, s3b = post('/v1/seal', {'profile': prof, 'payload_hex': payload})
            f3b = s3b['frames'][:-1]
            c, v = post('/v1/verify', {'profile': prof, 'session_id': s3b['session_id'], 'key_id': 0, 'frames': f3b})
            rec(f'{prof}: flujo truncado (falta el último frame) no se da por completo',
                not (accepted(c, v) and v.get('complete', False)),
                f'status {c}')

        c, s4 = post('/v1/seal', {'profile': prof, 'payload_hex': payload})
        f4 = s4['frames']; f4[0]['seal_hex'] = '00' * 32
        c, v = post('/v1/verify', {'profile': prof, 'session_id': s4['session_id'], 'key_id': 0, 'frames': f4})
        rec(f'{prof}: sello forjado rechazado', not accepted(c, v))

        c, s5 = post('/v1/seal', {'profile': prof, 'payload_hex': payload})
        c, v = post('/v1/verify', {'profile': prof, 'session_id': s5['session_id'], 'key_id': 7, 'frames': s5['frames']})
        rec(f'{prof}: key_id desconocido rechazado', not accepted(c, v), f'status {c}')

        # P3: repetir IDÉNTICA la petición ya aceptada (reintento de un intermediario) devuelve el mismo
        # veredicto, o se rechaza si su respuesta no cabe en el tope de repetición; nunca es una aceptación nueva.
        c, v = post('/v1/verify', {'profile': prof, 'session_id': sid, 'key_id': 0, 'frames': frames})
        rec(f'{prof}: repetición idéntica de lo ya verificado: mismo veredicto o rechazo, nunca una aceptación distinta',
            (c == 200 and v == v_first) or not accepted(c, v), f'status {c}')
        c, v = post('/v1/verify', {'profile': prof, 'session_id': sid, 'key_id': 0, 'frames': frames, 'reassemble': True})
        rec(f'{prof}: replay DISTINTO sobre la sesión terminada rechazado', not accepted(c, v), f'status {c}')

        # frames de una sesión presentados bajo el session_id de otra
        c, sa = post('/v1/seal', {'profile': prof, 'payload_hex': os.urandom(300).hex()})
        c, sb = post('/v1/seal', {'profile': prof, 'payload_hex': os.urandom(300).hex()})
        c, v = post('/v1/verify', {'profile': prof, 'session_id': sb['session_id'], 'key_id': 0, 'frames': sa['frames']})
        rec(f'{prof}: frames de la sesión A bajo la sesión B rechazados', not accepted(c, v))

    c, s = post('/v1/seal', {'profile': 'vault', 'payload_hex': payload}); f = s['frames']
    for x in f:
        x.pop('vault_signature_hex', None)
    c, v = post('/v1/verify', {'profile': 'vault', 'session_id': s['session_id'], 'key_id': 0, 'frames': f})
    rec('vault: frames sin firma rechazados', not accepted(c, v))

    c, s = post('/v1/seal', {'profile': 'vault', 'payload_hex': payload}); f = s['frames']
    for x in f:
        if x.get('vault_signature_hex'):
            x['vault_signature_hex'] = flip(x['vault_signature_hex'])
    c, v = post('/v1/verify', {'profile': 'vault', 'session_id': s['session_id'], 'key_id': 0, 'frames': f})
    rec('vault: firma alterada rechazada', not accepted(c, v))

    c, s = post('/v1/seal', {'profile': 'lite', 'payload_hex': payload})
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames']})
    rec('cross-profile (sellado lite, verificado core) rechazado', not accepted(c, v), f'status {c}')


def group_inputs():
    c, _ = post('/v1/seal', {'profile': 'nope', 'payload_hex': 'aa'}); rec('perfil desconocido -> 4xx', 400 <= c < 500, str(c))
    c, _ = post('/v1/seal', {'profile': 'core', 'payload_hex': 'zz'}); rec('hex inválido -> 4xx', 400 <= c < 500, str(c))
    c, _ = post('/v1/seal', {'profile': 'core', 'payload_hex': 'abc'}); rec('hex de longitud impar -> 4xx', 400 <= c < 500, str(c))
    c, _ = post('/v1/seal', {'profile': 'core'}); rec('campo payload_hex ausente -> 4xx', 400 <= c < 500, str(c))
    r = requests.post(BASE + '/v1/seal', data='no es json', headers={'content-type': 'application/json'})
    rec('cuerpo no-JSON -> 4xx', 400 <= r.status_code < 500, str(r.status_code))
    c, _ = post('/v1/seal', {'profile': 'core', 'payload_hex': ''}); rec('payload vacío manejado sin 5xx', c < 500, str(c))
    c, _ = post('/v1/verify', {'profile': 'core', 'session_id': '00' * 16, 'key_id': 0, 'frames': []})
    rec('verificar con session_id inexistente -> 4xx', 400 <= c < 500, str(c))
    c, real = post('/v1/seal', {'profile': 'core', 'payload_hex': os.urandom(100).hex()})
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': real['session_id'], 'key_id': 0, 'frames': []})
    rec('verify con 0 frames (sesión real, token válido) -> 400, nunca «all_verified» (A4, verdad vacía)',
        c == 400 and not v.get('all_verified'), f'status {c}')
    c, _ = post('/v1/receipts', {'session_id': '00' * 16}); rec('recibos de sesión inexistente -> 4xx', 400 <= c < 500, str(c))
    c, h = get('/v1/health'); rec('health responde', c == 200, json.dumps(h)[:80])


def group_big():
    big = os.urandom(20 * 1024 * 1024).hex()
    try:
        c, _ = post('/v1/seal', {'profile': 'lite', 'payload_hex': big})
        rec('payload de 20 MB: sin caída ni 5xx inesperado', c in (200, 400, 413, 422, 503), f'status {c}')
    except Exception as e:
        rec('payload de 20 MB: sin caída', False, str(e)[:100])
    c, h = get('/v1/health'); rec('health tras payload grande', c == 200)


def group_vault_ack():
    pl = os.urandom(3000).hex()
    c, s = post('/v1/seal', {'profile': 'vault', 'payload_hex': pl})
    c, v = post('/v1/verify', {'profile': 'vault', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames']})
    c, a = post('/v1/ack', {'session_id': s['session_id'], 'indices': [f['index'] for f in s['frames']]})
    rec('vault: ack de todos los fragmentos', c == 200, f'{c} {json.dumps(a)[:100]}')
    c, rc = post('/v1/receipts', {'session_id': s['session_id']})
    rec('vault: recibos == fragmentos', c == 200 and len(rc.get('entries', [])) == len(s['frames']),
        f"{len(rc.get('entries', []))}/{len(s['frames'])}")
    c, a2 = post('/v1/ack', {'session_id': s['session_id'], 'indices': [0]})
    c3, rc2 = post('/v1/receipts', {'session_id': s['session_id']})
    rec('vault: ack repetido es idempotente (no duplica recibos)',
        c3 == 200 and len(rc2.get('entries', [])) == len(s['frames']), f"ack2={c} recibos={len(rc2.get('entries', []))}")


def group_handshake_kat():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    k = X25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    c, hs = post('/v1/handshake', {'client_public_key_hex': pub.hex()})
    rec('handshake X25519 aceptado', c == 200, f'status {c}')
    if c != 200:
        return
    shared = k.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(hs['server_public_key_hex'])))
    pl = os.urandom(5000).hex()
    hb = {'profile': 'core', 'payload_hex': pl, 'session_id': hs['session_id']}
    c, _ = post('/v1/seal', hb, token=NOAUTH)
    rec('sesión de handshake: sellar sin token -> 401', c == 401, f'status {c}')
    c, _ = post('/v1/seal', hb, token=hs['capabilities']['verify'])
    rec('sesión de handshake: sellar con token verify -> 401', c == 401, f'status {c}')
    c, s = post('/v1/seal', {'profile': 'core', 'payload_hex': pl, 'session_id': hs['session_id']})
    rec('seal bajo sesión de handshake', c == 200, f'status {c}')
    if c != 200:
        return
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': hs['session_id'], 'key_id': 0, 'frames': s['frames']})
    rec('verify bajo sesión de handshake', accepted(c, v))
    # Constantes de dominio (parte del contrato de Core v1; vectores fijados).
    INFO, CTX = b'lacre-core/v1/session-key', b'lacre-core/v1/initial-state'
    sidb = bytes.fromhex(hs['session_id'])
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=sidb, info=INFO).derive(shared)
    st = hmac.new(key, sidb + CTX, hashlib.sha256).digest()
    allok = True
    for f in s['frames']:
        frag = bytes.fromhex(f['payload_hex'])
        allok &= hmac.new(key, frag + st, hashlib.sha256).hexdigest() == f['seal_hex']
        st = hmac.new(key, st + frag, hashlib.sha256).digest()
    rec('RE-DERIVACIÓN INDEPENDIENTE de los sellos (X25519+HKDF+cadena HMAC) coincide con el servidor', allok)
    # un sello válido bajo el protocolo pero con un byte cambiado en el payload
    # debe fallar, y uno re-derivado a mano sobre el payload alterado debe fallar
    # igualmente si no usa la clave (clave equivocada):
    bad = hmac.new(b'\x00' * 32, bytes.fromhex(s['frames'][0]['payload_hex']), hashlib.sha256).hexdigest()
    rec('un sello calculado con otra clave no coincide', bad != s['frames'][0]['seal_hex'])


def group_toolchain_http():
    H = lambda b: b.hex()
    for algo in ('sha256', 'blake3'):
        c, e = post('/v1/toolchain/episodes', {'episode_id_hex': os.urandom(8).hex(), 'algo': algo, 'max_node_age_ms': 3600000})
        rec(f'toolchain[{algo}]: crear episodio', c == 200, str(c))
        sid = e['session_id']
        nodes = [('prompt', b'sell BTC if the price goes up', []), ('market_price', b'BTC=65000', ['prompt']),
                 ('news', b'no relevant events', ['prompt']),
                 ('recommendation', b'sell: favorable price, no news risk', ['market_price', 'news'])]
        seals = {}
        for n, cont, par in nodes:
            c, r = post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': n, 'content_hex': H(cont), 'parent_ids': par})
            seals[n] = r.get('chain_seal_hex')
        rec(f'toolchain[{algo}]: DAG con fan-in aceptado, sellos distintos', len(set(seals.values())) == 4)
        good = {n: H(c) for n, c, _ in nodes}
        V = lambda contents, out='recommendation': post('/v1/toolchain/verify', {'session_id': sid, 'output_node_id': out, 'contents_hex': contents})
        c, v = V(good)
        rec(f'toolchain[{algo}]: salida honesta verifica', c == 200 and v.get('valid'), json.dumps(v)[:80])
        for victim in ('prompt', 'market_price', 'news', 'recommendation'):
            bad = dict(good); bad[victim] = H(b'tampered')
            c, v = V(bad)
            rec(f'toolchain[{algo}]: alteración de {victim} detectada', c == 200 and not v.get('valid'), f"failed_node={v.get('failed_node')}")
        # REGRESIÓN: verificar mal NO contamina el episodio.
        c, v = V(good)
        rec(f'toolchain[{algo}]: tras verificaciones fallidas, la honesta SIGUE verificando (sin envenenamiento)',
            c == 200 and v.get('valid'), json.dumps(v)[:80])
        c, r = post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': 'extra', 'content_hex': H(b'x'), 'parent_ids': ['news']})
        rec(f'toolchain[{algo}]: tras verificaciones fallidas se pueden añadir nodos', c == 200, str(c))
        miss = dict(good); miss.pop('news')
        c, v = V(miss); rec(f'toolchain[{algo}]: contenido faltante no se acepta', not (c == 200 and v.get('valid')))
        c, r = post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': 'orphan', 'content_hex': H(b'x'), 'parent_ids': ['ghost']})
        rec(f'toolchain[{algo}]: padre desconocido rechazado', c >= 400, str(c))
        c, r = post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': 'prompt', 'content_hex': H(b'again'), 'parent_ids': []})
        rec(f'toolchain[{algo}]: id de nodo duplicado rechazado', c >= 400, str(c))
        c, v = V(good, 'nope'); rec(f'toolchain[{algo}]: nodo de salida desconocido rechazado', not (c == 200 and v.get('valid')))
        # alterar la ascendencia sin tocar el contenido: mismo contenido, otro padre
        c, e2 = post('/v1/toolchain/episodes', {'episode_id_hex': os.urandom(8).hex(), 'algo': algo, 'max_node_age_ms': 3600000})
        s2 = e2['session_id']
        for n, cont, par in [('a', b'A', []), ('b', b'B', []), ('c', b'C', ['a'])]:
            post('/v1/toolchain/nodes', {'session_id': s2, 'node_id': n, 'content_hex': H(cont), 'parent_ids': par})
        c, v = post('/v1/toolchain/verify', {'session_id': s2, 'output_node_id': 'c', 'contents_hex': {'a': H(b'A'), 'c': H(b'C')}})
        rec(f'toolchain[{algo}]: cadena lineal honesta verifica', c == 200 and v.get('valid'))
        c, v = post('/v1/toolchain/verify', {'session_id': s2, 'output_node_id': 'c', 'contents_hex': {'a': H(b'B'), 'c': H(b'C')}})
        rec(f'toolchain[{algo}]: contenido del padre intercambiado por el de otro nodo detectado', c == 200 and not v.get('valid'))
    c, e = post('/v1/toolchain/episodes', {'episode_id_hex': os.urandom(8).hex(), 'algo': 'sha256', 'max_node_age_ms': 3600000})
    c, v = post('/v1/toolchain/verify', {'session_id': e['session_id'], 'output_node_id': 'x', 'contents_hex': {}})
    rec('toolchain: verificar episodio vacío no da válido', not (c == 200 and v.get('valid')))


def group_auth():
    """Autenticación por capacidades. Antes eran GAP conocidos."""
    H = lambda b: b.hex()
    # --- el session_id solo no concede nada
    c, s = post('/v1/seal', {'profile': 'vault', 'payload_hex': os.urandom(500).hex()})
    sid, caps = s['session_id'], s['capabilities']
    rec('el sellado devuelve tres tokens distintos (write, verify, ack), no derivables del session_id',
        len({caps['write'], caps['verify'], caps['ack']}) == 3 and sid not in caps.values())
    N = NOAUTH
    for name, path, body in [
        ('verify', '/v1/verify', {'profile': 'vault', 'session_id': sid, 'key_id': 0, 'frames': s['frames']}),
        ('ack', '/v1/ack', {'session_id': sid, 'indices': [0]}),
        ('receipts', '/v1/receipts', {'session_id': sid}),
    ]:
        c, r = post(path, body, token=N)
        rec(f'sin token: {name} -> 401 (conocer el session_id no basta)', c == 401, f'{c}')
    # --- ataque 3: ack con otro alcance, no purga ni emite recibos
    for label, tk in (('write', caps['write']), ('verify', caps['verify'])):
        c, r = post('/v1/ack', {'session_id': sid, 'indices': [f['index'] for f in s['frames']]}, token=tk)
        rec(f'ataque 3 cerrado: ack con token {label} -> 401', c == 401, f'{c}')
    c, rc = post('/v1/receipts', {'session_id': sid})
    rec('ataque 3 cerrado: los ack rechazados no dejaron recibos ni purgaron', c == 200 and len(rc.get('entries', [])) == 0)
    for label, tk in (('verify', caps['verify']), ('ack', caps['ack'])):
        c, r = post('/v1/receipts', {'session_id': sid}, token=tk)
        rec(f'recibos con token {label} -> 401 (solo write)', c == 401, f'{c}')
    for label, tk in (('write', caps['write']), ('ack', caps['ack'])):
        c, r = post('/v1/verify', {'profile': 'vault', 'session_id': sid, 'key_id': 0, 'frames': s['frames']}, token=tk)
        rec(f'verify con token {label} -> 401 (solo verify)', c == 401, f'{c}')
    c, a = post('/v1/ack', {'session_id': sid, 'indices': [f['index'] for f in s['frames']]})
    rec('el titular del token ack sí puede confirmar', c == 200 and a.get('all_acknowledged'), f'{c}')
    # --- token de otra sesión
    c, other = post('/v1/seal', {'profile': 'vault', 'payload_hex': os.urandom(200).hex()})
    c, r = post('/v1/ack', {'session_id': other['session_id'], 'indices': [0]}, token=caps['ack'])
    rec('token de la sesión A no sirve en la sesión B -> 401', c == 401, f'{c}')
    # --- no hay oráculo de existencia
    bad = 'ab' * 32
    c1, r1 = post('/v1/ack', {'session_id': other['session_id'], 'indices': [0]}, token=bad)
    c2, r2 = post('/v1/ack', {'session_id': os.urandom(16).hex(), 'indices': [0]}, token=bad)
    rec('un token malo recibe la misma respuesta con sesión existente o inexistente (sin oráculo)', (c1, r1) == (c2, r2) and c1 == 401, f'{c1} / {c2}')
    for tk in ('', 'zz', '00', 'ab' * 33):
        c, r = post('/v1/ack', {'session_id': other['session_id'], 'indices': [0]}, token=tk)
        if c != 401:
            rec('token malformado -> 401', False, f'{tk!r}: {c}'); break
    else:
        rec('tokens vacíos, no hex, cortos o largos -> 401', True)
    # token casi correcto (mismo primer byte / mismo prefijo / último byte alterado) -> 401
    good = other['capabilities']['ack']
    near = [good[:2], good[:32], good[:-2] + ('00' if good[-2:] != '00' else '01'), good[:2] + '00' * 31]
    codes = [post('/v1/ack', {'session_id': other['session_id'], 'indices': [0]}, token=t)[0] for t in near]
    rec('tokens casi correctos (prefijo, mismo primer byte, último byte alterado) -> 401', all(c == 401 for c in codes), str(codes))
    # sin token sobre sesiones inexistentes de cualquier forma: siempre 401, nunca 404 (sin oráculo)
    ghosts = ['00' + os.urandom(15).hex(), '00' * 16, 'ff' + os.urandom(15).hex(), os.urandom(16).hex()]
    codes = [post('/v1/ack', {'session_id': g, 'indices': [0]}, token=NOAUTH)[0] for g in ghosts]
    rec('sin token sobre sesiones inexistentes -> siempre 401 (nunca 404)', all(c == 401 for c in codes), str(codes))
    codes = [post('/v1/toolchain/nodes', {'session_id': g, 'node_id': 'x', 'content_hex': 'aa', 'parent_ids': []}, token=NOAUTH)[0] for g in ghosts]
    rec('Toolchain sin token sobre sesiones inexistentes -> siempre 401', all(c == 401 for c in codes), str(codes))
    # el token también viaja en el cuerpo
    c, r = post('/v1/ack', {'session_id': other['session_id'], 'indices': [0], 'token': other['capabilities']['ack']}, token=N)
    rec('el token puede ir en el cuerpo (no solo en la cabecera)', c == 200, f'{c}')
    # --- el session_id ya no va en la URL
    for method, path in (('POST', f'/v1/toolchain/episodes/{sid}/nodes'), ('POST', f'/v1/toolchain/episodes/{sid}/verify'), ('GET', f'/v1/receipts/{sid}')):
        r = requests.request(method, BASE + path, json={})
        rec(f'rutas con session_id en la URL eliminadas ({method} …/{path.split("/")[2]}/…)', r.status_code in (404, 405), str(r.status_code))
    # --- ataque 2: inyección de nodo en Toolchain
    c, e = post('/v1/toolchain/episodes', {'episode_id_hex': os.urandom(8).hex(), 'algo': 'sha256', 'max_node_age_ms': 3600000})
    esid, ec = e['session_id'], e['capabilities']
    rec('episodio Toolchain: write y verify, sin ack', 'ack' not in ec and ec['write'] != ec['verify'])
    post('/v1/toolchain/nodes', {'session_id': esid, 'node_id': 'prompt', 'content_hex': H(b'p'), 'parent_ids': []})
    forged = {'session_id': esid, 'node_id': 'forged', 'content_hex': H(b'lie'), 'parent_ids': ['prompt']}
    c, r = post('/v1/toolchain/nodes', forged, token=ec['verify'])
    rec('ataque 2 cerrado: inyectar nodo con token verify -> 401', c == 401, f'{c}')
    c, r = post('/v1/toolchain/nodes', forged, token=N)
    rec('ataque 2 cerrado: inyectar nodo sin token -> 401', c == 401, f'{c}')
    c, v = post('/v1/toolchain/verify', {'session_id': esid, 'output_node_id': 'forged', 'contents_hex': {'prompt': H(b'p'), 'forged': H(b'lie')}})
    rec('ataque 2 cerrado: el nodo falso nunca llegó al grafo (no verifica)', c == 200 and not v.get('valid'))
    c, v = post('/v1/toolchain/verify', {'session_id': esid, 'output_node_id': 'prompt', 'contents_hex': {'prompt': H(b'p')}}, token=ec['write'])
    rec('verificar Toolchain con token write -> 401', c == 401, f'{c}')
    # --- límite de verificaciones fallidas (frena el sondeo del titular de verify)
    c, e2 = post('/v1/toolchain/episodes', {'episode_id_hex': os.urandom(8).hex(), 'algo': 'sha256', 'max_node_age_ms': 3600000})
    s2 = e2['session_id']
    post('/v1/toolchain/nodes', {'session_id': s2, 'node_id': 'n', 'content_hex': H(b'real'), 'parent_ids': []})
    codes = []
    for i in range(40):
        c, v = post('/v1/toolchain/verify', {'session_id': s2, 'output_node_id': 'n', 'contents_hex': {'n': H(b'guess%d' % i)}})
        codes.append(c)
    rec('tras 32 verificaciones fallidas el episodio devuelve 429 (el sondeo se corta)',
        codes[:32] == [200] * 32 and all(x == 429 for x in codes[32:]), f'{codes[30:36]}')
    c, v = post('/v1/toolchain/verify', {'session_id': s2, 'output_node_id': 'n', 'contents_hex': {'n': H(b'real')}})
    rec('episodio bloqueado: ni el contenido honesto verifica (fallo cerrado; hay que abrir otro)', c == 429, f'{c}')


def group_tolerance():
    """Tolerancia a intermediarios. Sellado por partes (P2), verify idempotente (P3), errores negociados (P5)."""
    def parts(profile, extra=None, n_bytes=7000, step=2500):
        o = post('/v1/seal/open', dict({'profile': profile}, **(extra or {})))
        c, o = o
        if c != 200:
            return c, o, None, None
        orig = os.urandom(n_bytes)
        frames, outs = [], []
        pieces = [orig[i:i + step] for i in range(0, len(orig), step)]
        for i, piece in enumerate(pieces):
            body = {'session_id': o['session_id'], 'part_index': i, 'payload_hex': piece.hex(), 'is_last': i + 1 == len(pieces)}
            cc, r = post('/v1/seal/part', body)
            outs.append((cc, r, body))
            if cc == 200:
                frames += r['frames']
        return 200, o, (orig, frames), outs
    cases = [('core', None), ('vault', None)]
    if V2_ON:
        cases += [('core', {'version': 2, 'suite': {'seal': 'hmac-sha256'}}), ('vault', {'version': 2, 'suite': {'seal': 'hmac-sha256', 'signature': 'ed25519'}})]
    for profile, extra in cases:
        tag = f'{profile}{" v2" if extra else ""}'
        c, o, data, outs = parts(profile, extra)
        rec(f'partes {tag}: /v1/seal/open abre la sesión y publica límites', c == 200 and o.get('max_part_bytes', 0) >= 2500 and o.get('slot_size', 0) > 0, f'{c}')
        if c != 200:
            continue
        orig, frames = data
        rec(f'partes {tag}: todas las partes se sellan', all(x[0] == 200 for x in outs), str([x[0] for x in outs]))
        rec(f'partes {tag}: solo el último frame de la última parte cierra el flujo', [f['is_last'] for f in frames] == [False] * (len(frames) - 1) + [True], f'{len(frames)} frames')
        again = post('/v1/seal/part', outs[-1][2])
        rec(f'partes {tag}: repetir la última parte devuelve los mismos frames', again[0] == 200 and again[1]['frames'] == outs[-1][1]['frames'], f'{again[0]}')
        diff = post('/v1/seal/part', dict(outs[-1][2], payload_hex=os.urandom(10).hex()))
        rec(f'partes {tag}: mismo índice con otro contenido -> 409', diff[0] == 409, f'{diff[0]}')
        skip = post('/v1/seal/part', dict(outs[-1][2], part_index=99))
        rec(f'partes {tag}: índice saltado -> 409', skip[0] == 409, f'{skip[0]}')
        vbody = {'profile': profile, 'session_id': o['session_id'], 'key_id': 0, 'frames': frames, 'reassemble': True}
        if extra:
            vbody.update(extra)
        c1, v = post('/v1/verify', vbody)
        rec(f'partes {tag}: el flujo verifica y reensambla el original', c1 == 200 and v.get('all_verified') is True and v.get('payload_hex') == orig.hex(), f'{c1}')
        c2, v2 = post('/v1/verify', vbody)
        rec(f'verify idéntico repetido {tag} (P3): mismo veredicto, no error', c2 == 200 and v2 == v, f'{c2}')
        c3, _ = post('/v1/verify', dict(vbody, reassemble=False))
        rec(f'verify distinto sobre la sesión terminada {tag}: sigue rechazado', c3 == 400, f'{c3}')
    # sin token de escritura: no se sellan partes
    c, o = post('/v1/seal/open', {'profile': 'core'})
    c1, _ = post('/v1/seal/part', {'session_id': o['session_id'], 'part_index': 0, 'payload_hex': '00', 'is_last': True}, token='basura')
    rec('partes: sin token de escritura válido -> 401', c1 == 401, f'{c1}')
    # un /v1/seal entero no admite partes
    c, w = post('/v1/seal', {'profile': 'vault', 'payload_hex': '00'})
    c1, _ = post('/v1/seal/part', {'session_id': w['session_id'], 'part_index': 0, 'payload_hex': '00', 'is_last': True}, token=w['capabilities']['write'])
    rec('partes: una sesión sellada de una vez (vault) no admite partes -> 400', c1 == 400, f'{c1}')
    # P5: errores negociados
    r = requests.post(BASE + '/v1/seal', json={'profile': 'no-existe', 'payload_hex': '00'}, headers={'Accept': 'application/problem+json'}, timeout=30)
    try:
        d = r.json()
    except Exception:
        d = {}
    rec('errores (P5): con Accept problem+json, documento con type, status, detail y code',
        r.status_code == 400 and r.headers.get('content-type', '').startswith('application/problem+json') and d.get('code') == 'unknown-profile'
        and d.get('type') == 'urn:lacre:error:unknown-profile' and d.get('status') == 400 and 'detail' in d, f'{r.status_code} {r.headers.get("content-type")} {d.get("code")}')
    r = requests.post(BASE + '/v1/seal', json={'profile': 'no-existe', 'payload_hex': '00'}, timeout=30)
    rec('errores (P5): sin Accept, el texto plano de siempre', r.status_code == 400 and r.headers.get('content-type', '').startswith('text/plain') and r.text.startswith('unknown profile'), f'{r.status_code} {r.headers.get("content-type")}')
    r = requests.post(BASE + '/v1/seal', data=b'{no es json', headers={'Content-Type': 'application/json', 'Accept': 'application/problem+json'}, timeout=30)
    try:
        d = r.json()
    except Exception:
        d = {}
    rec('errores (P5): cuerpo malformado -> código malformed-body', r.status_code in (400, 422) and d.get('code') == 'malformed-body', f'{r.status_code} {d.get("code")}')


def group_version():
    """A8 (extensión E1): versión de protocolo. Desconocida = rechazo; ausente = la actual; se devuelve en la respuesta."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as S
    def pub():
        return X25519PrivateKey.generate().public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex()
    def bodies(v):
        b = [('/v1/handshake', {'client_public_key_hex': pub()}),
             ('/v1/seal', {'profile': 'core', 'payload_hex': os.urandom(40).hex()}),
             ('/v1/toolchain/episodes', {'episode_id_hex': 'aabb', 'algo': 'sha256', 'max_node_age_ms': 60000})]
        for path, body in b:
            body = dict(body)
            if v is not NOAUTH:
                body['version'] = v
            yield path, body
    for bad in (0, 2, 255, 4294967295, 4294967296, -1, '1', 1.5, True, [1]):
        for path, body in bodies(bad):
            c, r = post(path, body)
            rec(f'versión {bad!r} en {path} -> rechazo 4xx', 400 <= c < 500, f'{c}')
    for path, body in bodies(0):
        c, r = post(path, body)
        rec(f'versión desconocida en {path} -> exactamente 400', c == 400, f'{c}')
    for declared in (1, NOAUTH):
        for path, body in bodies(declared):
            c, r = post(path, body)
            rec(f'versión {"omitida" if declared is NOAUTH else declared} en {path} -> 200 y devuelve version 1',
                c == 200 and r.get('version') == 1, f'{c} {r.get("version")}')
    c, s = post('/v1/seal', {'profile': 'core', 'payload_hex': os.urandom(900).hex(), 'version': 1})
    c1, v = post('/v1/verify', {'profile': 'core', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames'], 'version': 1})
    rec('verify con version 1 -> verificado y devuelve version 1', accepted(c1, v) and v.get('version') == 1)
    c, s2 = post('/v1/seal', {'profile': 'core', 'payload_hex': os.urandom(900).hex()})
    c2, v2 = post('/v1/verify', {'profile': 'core', 'session_id': s2['session_id'], 'key_id': 0, 'frames': s2['frames'], 'version': 2})
    rec('verify con version 2 -> 400 aunque los frames y el token sean válidos', c2 == 400, f'{c2}')
    c3, v3 = post('/v1/verify', {'profile': 'core', 'session_id': s2['session_id'], 'key_id': 0, 'frames': s2['frames']})
    rec('...y el rechazo por versión no consumió la sesión: sin version, el mismo verify sí verifica', accepted(c3, v3), f'{c3}')


def group_rules_reassembly():
    """Guardian / Certifier / Rule Engine, reensamblado y taxonomía, por rutas vivas."""
    import json as _j
    GOOD = _j.dumps({'order_id': 12345678, 'customer': 'ana'}).encode()
    V = lambda name, payload: post('/v1/validate', {'ruleset': name, 'payload_hex': payload.hex()}, token=NOAUTH)
    c, b = V('orders', GOOD)
    rec('validate: Guardian acepta un registro completo', c == 200 and b.get('outcome') == 'passed' and b.get('kind') == 'guardian', str(b))
    c, b = V('orders', b'{"order_id":12345678}')
    rec('validate: Guardian rechaza nombrando la regla (campo obligatorio ausente)', c == 200 and b.get('outcome') == 'rejected' and b.get('failing_rule_id') == 'required_field_customer', str(b))
    c, b = V('orders', b'{"order_id":1234,"customer":"ana"}')
    rec('validate: Guardian rechaza un entero con dígitos distintos de 8', b.get('outcome') == 'rejected' and b.get('failing_rule_id') == 'required_field_order_id', str(b))
    ok = True
    for bad in (b'not json', b'[1,2]', b'42', b'', b'{"order_id":null,"customer":null}', b'{"order_id":"12345678","customer":"a"}'):
        c, b = V('orders', bad); ok &= (c == 200 and b.get('outcome') == 'rejected')
    rec('validate: Guardian falla cerrado con JSON inválido, no-objeto, nulo o de tipo erróneo', ok)
    c, b = V('ids', b'ref LA-123456789012 ok')
    rec('validate: Certifier cuenta una expresión regular real', c == 200 and b.get('outcome') == 'passed' and b.get('kind') == 'certifier', str(b))
    c, b = V('ids', b'ref LA-12 short'); rec('validate: Certifier rechaza si el patrón no aparece', b.get('outcome') == 'rejected', str(b))
    c, b = V('ids', bytes([0xff, 0xfe]))
    rec('validate: Certifier con bytes no UTF-8 -> 422 (no «cero coincidencias»)', c == 422, f'{c}')
    c, b = V('mixed', b'{"amount":"x"}'); rec('validate: Rule Engine, on_fail=quarantine', b.get('outcome') == 'quarantined', str(b))
    c, b = V('mixed', b'{"amount":1}')
    rec('validate: Rule Engine, on_fail=pass_with_flag nombra la regla', b.get('outcome') == 'passed_with_flag' and b.get('failing_rule_id') == 'tag', str(b))
    c, b = V('nope', b'x'); rec('validate: conjunto desconocido -> 400', c == 400, f'{c}')
    c, b = post('/v1/validate', {'ruleset': 'orders', 'payload_hex': 'zz'}, token=NOAUTH); rec('validate: hex inválido -> 400', c == 400, f'{c}')
    # el cliente no puede aportar reglas propias
    c, b = post('/v1/validate', {'ruleset': 'orders', 'payload_hex': GOOD.hex(), 'rules': [{'pattern': '(a+)+$'}]}, token=NOAUTH)
    rec('validate: campos de reglas aportados por el cliente se ignoran (las reglas son del despliegue)', c == 200 and b.get('kind') == 'guardian', str(c))

    # --- sellar con ruleset
    S = lambda name, payload: post('/v1/seal', {'profile': 'core', 'payload_hex': payload.hex(), 'ruleset': name})
    c, b = S('orders', b'{"order_id":1}')
    rec('seal+ruleset: un payload rechazado NO se sella (422, sin frames)', c == 422 and 'frames' not in b, f'{c}')
    c, b = S('mixed', b'{"amount":"x"}'); rec('seal+ruleset: cuarentena tampoco se sella', c == 422, f'{c}')
    c, b = S('orders', GOOD); rec('seal+ruleset: un payload válido se sella e informa el veredicto', c == 200 and b.get('ruleset_outcome', {}).get('outcome') == 'passed', f'{c}')
    c, b = S('mixed', b'{"amount":1}'); rec('seal+ruleset: pass_with_flag se sella y muestra la regla marcada', c == 200 and b.get('ruleset_outcome', {}).get('failing_rule_id') == 'tag', f'{c}')
    c, b = S('nope', GOOD); rec('seal+ruleset: conjunto desconocido -> 400', c == 400, f'{c}')

    # --- reensamblado
    original = bytes((i % 251) for i in range(3500))
    def sealed():
        c, b = post('/v1/seal', {'profile': 'core', 'payload_hex': original.hex()})
        assert c == 200 and len(b['frames']) >= 3
        return b
    sb = sealed()
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': sb['session_id'], 'key_id': 0, 'frames': sb['frames'], 'reassemble': True})
    rec('reensamblado: la verificación devuelve el payload original idéntico', c == 200 and v.get('payload_hex') == original.hex(), f'{c} frames={len(sb["frames"])}')
    sb = sealed(); got = None; early = False
    for i, f in enumerate(sb['frames']):
        c, v = post('/v1/verify', {'profile': 'core', 'session_id': sb['session_id'], 'key_id': 0, 'frames': [f], 'reassemble': True})
        if i + 1 < len(sb['frames']):
            early |= 'payload_hex' in v
        else:
            got = v.get('payload_hex')
    rec('reensamblado incremental: el payload sale solo con el último frame', got == original.hex() and not early)
    sb = sealed()
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': sb['session_id'], 'key_id': 0, 'frames': sb['frames']})
    rec('sin `reassemble` no se devuelve payload (comportamiento anterior intacto)', c == 200 and v.get('all_verified') and 'payload_hex' not in v)
    sb = sealed(); fr = copy.deepcopy(sb['frames']); fr[1]['payload_hex'] = flip(fr[1]['payload_hex'])
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': sb['session_id'], 'key_id': 0, 'frames': fr, 'reassemble': True})
    rec('reensamblado: un frame alterado nunca produce payload', not v.get('all_verified') and 'payload_hex' not in v)

    # --- taxonomía: diagnóstico de reenvíos, sin perdonar nada
    sb = sealed(); F = sb['frames']
    call = lambda frames, **kw: post('/v1/verify', dict({'profile': 'core', 'session_id': sb['session_id'], 'key_id': 0, 'frames': frames, 'reassemble': True}, **kw))
    call([F[0], F[1]])
    c, v = call([F[0]])
    r0 = (v.get('results') or [{}])[0]
    rec('taxonomía: reenvío idéntico -> rechazado y diagnosticado «same_content_unclear_origin»', not r0.get('ok') and r0.get('diagnosis') == 'same_content_unclear_origin', str(r0))
    other = copy.deepcopy(F[1]); other['payload_hex'] = b"someone else's content".hex()
    c, v = call([other]); r0 = (v.get('results') or [{}])[0]
    rec('taxonomía: otro contenido en un índice ya aceptado -> rechazado y diagnosticado «new_message»', not r0.get('ok') and r0.get('diagnosis') == 'new_message', str(r0))
    c, v = call(F[2:])
    rec('taxonomía: tras los rechazos la sesión sigue y los frames legítimos la completan', v.get('all_verified') and v.get('payload_hex') == original.hex(), str(c))
    sb2 = sealed()
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': sb2['session_id'], 'key_id': 0, 'frames': [sb2['frames'][2]], 'reassemble': True})
    rec('taxonomía: un frame adelantado se rechaza SIN diagnóstico engañoso', not v.get('all_verified') and 'diagnosis' not in (v.get('results') or [{}])[0])

    # --- reglas sobre el mensaje completo
    pad = 'X' * 3000
    good_big = _j.dumps({'order_id': 12345678, 'customer': 'ana', 'pad': pad}).encode()
    bad_big = _j.dumps({'order_id': 12345678, 'Xustomer': 'ana', 'pad': pad}).encode()
    for payload, outcome, released in ((good_big, 'passed', True), (bad_big, 'rejected', False)):
        c, sbx = post('/v1/seal', {'profile': 'core', 'payload_hex': payload.hex()})
        c, v = post('/v1/verify', {'profile': 'core', 'session_id': sbx['session_id'], 'key_id': 0, 'frames': sbx['frames'], 'reassemble': True, 'ruleset': 'orders'})
        rec(f'reensamblado+ruleset: veredicto «{outcome}»; payload {"liberado" if released else "retenido"}; integridad independiente de las reglas',
            v.get('all_verified') is True and v.get('ruleset_outcome', {}).get('outcome') == outcome and (('payload_hex' in v) == released), str(v.get('ruleset_outcome')))
    c, sbx = post('/v1/seal', {'profile': 'core', 'payload_hex': (b'\xff' * 3500).hex()})
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': sbx['session_id'], 'key_id': 0, 'frames': sbx['frames'], 'reassemble': True, 'ruleset': 'ids'})
    rec('reensamblado+ruleset: si las reglas no pueden juzgar el payload (outcome «error»), se retiene', v.get('ruleset_outcome', {}).get('outcome') == 'error' and 'payload_hex' not in v)
    sb = sealed()
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': sb['session_id'], 'key_id': 0, 'frames': sb['frames'], 'ruleset': 'orders'})
    rec('verify: `ruleset` sin `reassemble` -> 400', c == 400, f'{c}')


async def ws_group(ws_url):
    import websockets
    H = lambda b: b.hex()
    async with websockets.connect(ws_url, max_size=64 * 1024 * 1024, **_wsopt()) as w:
        async def call(kind, payload):
            await w.send(json.dumps({'kind': kind, 'payload': payload})); return json.loads(await w.recv())
        pl = os.urandom(5000).hex()
        for prof in ('lite', 'core', 'vault'):
            s = await call('seal', {'profile': prof, 'payload_hex': pl})
            sp = s['payload']; fr = sp['frames']
            v = await call('verify', {'profile': prof, 'session_id': sp['session_id'], 'key_id': 0, 'frames': fr, 'token': sp['capabilities']['verify']})
            rec(f'ws[{prof}]: seal+verify', s['kind'] in ('seal', 'seal_response') and v['payload']['all_verified'])
            s2 = await call('seal', {'profile': prof, 'payload_hex': pl}); f3 = s2['payload']['frames']
            f3[0]['payload_hex'] = flip(f3[0]['payload_hex'])
            v2 = await call('verify', {'profile': prof, 'session_id': s2['payload']['session_id'], 'key_id': 0, 'frames': f3, 'token': s2['payload']['capabilities']['verify']})
            rec(f'ws[{prof}]: alteración rechazada', not v2['payload'].get('all_verified', False))
        await w.send('no es json'); m = json.loads(await w.recv())
        rec('ws: JSON malformado -> sobre de error', m['kind'] == 'error')
        m = await call('nonsense', {}); rec('ws: kind desconocido -> sobre de error', m['kind'] == 'error')
        e = await call('toolchain_create_episode', {'episode_id_hex': os.urandom(8).hex(), 'algo': 'sha256', 'max_node_age_ms': 3600000})
        sid = e['payload']['session_id']; wt = e['payload']['capabilities']['write']; vt = e['payload']['capabilities']['verify']
        for n, c_, par in [('a', b'one', []), ('b', b'two', ['a'])]:
            await call('toolchain_add_node', {'session_id': sid, 'node_id': n, 'content_hex': H(c_), 'parent_ids': par, 'token': wt})
        bad = await call('toolchain_verify_output', {'session_id': sid, 'output_node_id': 'b', 'token': vt, 'contents_hex': {'a': H(b'ONE'), 'b': H(b'two')}})
        rec('ws: toolchain detecta alteración', bad['payload']['valid'] is False)
        ok = await call('toolchain_verify_output', {'session_id': sid, 'output_node_id': 'b', 'token': vt, 'contents_hex': {'a': H(b'one'), 'b': H(b'two')}})
        rec('ws: toolchain, tras una verificación fallida la honesta sigue válida (sin envenenamiento)', ok['payload']['valid'] is True)
        inj = await call('toolchain_add_node', {'session_id': sid, 'node_id': 'forged', 'content_hex': H(b'x'), 'parent_ids': ['a'], 'token': vt})
        rec('ws: inyectar nodo con token verify -> error de capacidad', inj['kind'] == 'error' and 'capability' in inj['payload']['message'])
        wv = await call('validate', {'ruleset': 'orders', 'payload_hex': b'{"order_id":12345678,"customer":"a"}'.hex()})
        rec('ws: validate (Guardian) acepta', wv['kind'] == 'validate_response' and wv['payload']['outcome'] == 'passed')
        wv = await call('validate', {'ruleset': 'orders', 'payload_hex': b'{"order_id":1}'.hex()})
        rec('ws: validate (Guardian) rechaza', wv['payload']['outcome'] == 'rejected')
        orig = bytes((i % 251) for i in range(3500))
        ws_ = await call('seal', {'profile': 'core', 'payload_hex': orig.hex()})
        wr = await call('verify', {'profile': 'core', 'session_id': ws_['payload']['session_id'], 'key_id': 0, 'frames': ws_['payload']['frames'], 'reassemble': True, 'token': ws_['payload']['capabilities']['verify']})
        rec('ws: reensamblado devuelve el payload original', wr['payload'].get('payload_hex') == orig.hex())
        if V2_ON:
            for alg, tl, n in (('hmac-sha512', None, 64), ('blake3-keyed-xof', 48, 48)):
                st = {'seal': alg, **({'tag_len_bytes': tl} if tl else {})}
                o2 = os.urandom(2600)
                s2 = await call('seal', {'version': 2, 'profile': 'core', 'payload_hex': o2.hex(), 'suite': st})
                p2 = s2['payload']
                rec(f'ws v2 [{alg}]: seal devuelve version 2, suite y sellos de {n} bytes',
                    s2['kind'] != 'error' and p2.get('version') == 2 and all(len(f['seal_hex']) == 2 * n for f in p2['frames']), str(p2)[:80])
                v2 = await call('verify', {'version': 2, 'profile': 'core', 'session_id': p2['session_id'], 'key_id': 0, 'frames': p2['frames'],
                                           'suite': st, 'reassemble': True, 'token': p2['capabilities']['verify']})
                rec(f'ws v2 [{alg}]: verify íntegro con payload reensamblado',
                    v2['payload'].get('all_verified') is True and v2['payload'].get('payload_hex') == o2.hex())
            e = await call('seal', {'version': 2, 'profile': 'core', 'payload_hex': '6162'})
            rec('ws v2: version 2 sin suite -> sobre de error', e['kind'] == 'error')
            e = await call('seal', {'version': 2, 'profile': 'vault', 'payload_hex': '6162', 'suite': {'seal': 'hmac-sha256'}})
            rec('ws v2: vault bajo v2 sin esquema de firma -> sobre de error (sin degradar a v1)', e['kind'] == 'error')
            vs = {'seal': 'hmac-sha256', 'signature': 'ed25519'}
            vo = os.urandom(300)
            vp = await call('seal', {'version': 2, 'profile': 'vault', 'payload_hex': vo.hex(), 'suite': vs})
            vf = vp['payload'].get('frames', [])
            rec('ws v2 vault: seal con firma {scheme, sig_hex} por fragmento',
                vp['kind'] != 'error' and bool(vf) and all((f.get('signature') or {}).get('scheme') == 'ed25519' for f in vf))
            vv = await call('verify', {'version': 2, 'profile': 'vault', 'session_id': vp['payload']['session_id'], 'key_id': 0,
                                       'frames': vf, 'suite': vs, 'reassemble': True, 'token': vp['payload']['capabilities']['verify']})
            rec('ws v2 vault: verify íntegro con payload reensamblado',
                vv['payload'].get('all_verified') is True and vv['payload'].get('payload_hex') == vo.hex())
            e = await call('seal', {'version': 2, 'profile': 'core', 'payload_hex': '6162', 'suite': {'seal': 'kmac256', 'tag_len_bytes': 32}})
            rec('ws v2: algoritmo fuera de la política -> sobre de error', e['kind'] == 'error' and 'not allowed' in e['payload']['message'])
        sv = await call('seal', {'profile': 'vault', 'payload_hex': os.urandom(50).hex()})
        for tk in (None, sv['payload']['capabilities']['write'], sv['payload']['capabilities']['verify']):
            p = {'session_id': sv['payload']['session_id'], 'indices': [0]}
            if tk: p['token'] = tk
            ak = await call('ack', p)
            rec('ws: ack sin el token ack -> error de capacidad', ak['kind'] == 'error' and 'capability' in ak['payload']['message'])
        ak = await call('ack', {'session_id': sv['payload']['session_id'], 'indices': [0], 'token': sv['payload']['capabilities']['ack']})
        rec('ws: ack con el token ack funciona', ak['kind'] == 'ack_response' and ak['payload']['all_acknowledged'] is True)
    async with websockets.connect(ws_url, **_wsopt()) as w2:
        await w2.send(json.dumps({'kind': 'seal', 'payload': {'profile': 'core', 'payload_hex': os.urandom(4000).hex()}}))
        s = json.loads(await w2.recv())['payload']
        CAPS[s['session_id']] = s['capabilities']
    c, v = post('/v1/verify', {'profile': 'core', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames']})
    rec('cross-adapter: sellado por WebSocket, verificado por HTTP', accepted(c, v))


def group_expiry_slow():
    c, e = post('/v1/toolchain/episodes', {'episode_id_hex': os.urandom(8).hex(), 'algo': 'sha256', 'max_node_age_ms': 2000})
    sid = e['session_id']
    post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': 'root', 'content_hex': 'aa', 'parent_ids': []})
    c2, _ = post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': 'early', 'content_hex': 'bb', 'parent_ids': ['root']})
    rec('expiración: hijo añadido con la raíz fresca', c2 == 200)
    print('   esperando 70 s a un barrido del servidor…'); sys.stdout.flush(); time.sleep(70)
    c3, _ = post('/v1/toolchain/nodes', {'session_id': sid, 'node_id': 'late', 'content_hex': 'cc', 'parent_ids': ['root']})
    rec('expiración: tras max_node_age + barrido, nuevo hijo de raíz sin resolver rechazado (fallo cerrado)', c3 >= 400, str(c3))
    c4, v = post('/v1/toolchain/verify', {'session_id': sid, 'output_node_id': 'early', 'contents_hex': {'root': 'aa', 'early': 'bb'}})
    rec('expiración: ascendencia caducada ya no verifica', not (c4 == 200 and v.get('valid')))


def group_bench():
    pl = os.urandom(4096).hex()
    N, PER = 4, 300
    lat, errs = [], [0]
    lock = threading.Lock()

    def worker():
        s = requests.Session(); mine = []
        for _ in range(PER):
            t = time.perf_counter()
            d = s.post(BASE + '/v1/seal', json={'profile': 'core', 'payload_hex': pl}).json()
            v = s.post(BASE + '/v1/verify', json={'profile': 'core', 'session_id': d['session_id'], 'key_id': 0, 'frames': d['frames']}, headers={'Authorization': 'Bearer ' + d['capabilities']['verify']}).json()
            mine.append(time.perf_counter() - t)
            if not v.get('all_verified'):
                errs[0] += 1
        with lock:
            lat.extend(mine)
    ts = [threading.Thread(target=worker) for _ in range(N)]; t0 = time.time()
    [t.start() for t in ts]; [t.join() for t in ts]; el = time.time() - t0
    lat.sort(); n = len(lat)
    out = {'roundtrips': n, 'clients': N, 'rt_per_s': round(n / el), 'p50_ms': round(lat[n // 2] * 1000, 2),
           'p99_ms': round(lat[int(n * .99)] * 1000, 2), 'errors': errs[0]}
    print('BENCH', json.dumps(out))
    rec('bench: carga concurrente sin errores de verificación', errs[0] == 0, json.dumps(out))
    return out


# ───────────────────────── ejecución ─────────────────────────

def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


def group_spec():
    """E2: la especificación LACRE-WIRE-v1 y el servidor en marcha dicen lo mismo."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = open(os.path.join(root, 'Code/workspace/spec/LACRE-WIRE-v1.md'), encoding='utf-8').read()
    gen = subprocess.run([sys.executable, os.path.join(root, 'Tools/gen_vectors.py'), '--check'],
                         capture_output=True, text=True)
    rec('vectores del archivo = generador independiente', gen.returncode == 0, (gen.stdout + gen.stderr).strip()[:80])
    table = re.findall(r'^\| `(/v1/[a-z/]+?)\*?` \| (GET|POST) \|', spec, re.M)
    rec('la especificación lista las rutas principales', len(table) >= 7, f'{len(table)} rutas')
    for path, method in table:
        if path.endswith('/'):
            continue
        c, _ = (get(path) if method == 'GET' else post(path, {}))
        rec(f'ruta de la especificación existe: {method} {path}', c != 404 and c != 405, f'{c}')
    # E4 (spec §13): touches_payload publicado, estático, de solo lectura
    c, j = get('/v1/profiles')
    j = j if isinstance(j, dict) else {}
    rec('GET /v1/profiles -> 200 con version 1 (spec §13)', c == 200 and j.get('version') == 1, f'{c}')
    rec('el Núcleo declara touches_payload=false (spec §13.4)', j.get('core_touches_payload') is False, str(j.get('core_touches_payload')))
    touching = sorted(p['name'] for p in j.get('profiles', []) if p.get('touches_payload') is True)
    rec('Profiles que tocan contenido = los cinco fijados (spec §13.7)',
        touching == ['certifier', 'guardian', 'reassemble', 'rule-engine', 'toolchain'], str(touching))
    rec('todo Profile que toca contenido tiene justificación (spec §13.3)',
        all(p.get('justification') for p in j.get('profiles', []) if p.get('touches_payload')) and bool(j.get('profiles')), '')
    prof = j.get('profiles', [])
    rec('cada Profile publica content_access in {none, derived, full} (spec §13.4)',
        bool(prof) and all(p.get('content_access') in ('none', 'derived', 'full') for p in prof), str([p.get('content_access') for p in prof]))
    rec('touches_payload coincide con content_access (spec §13.2)',
        bool(prof) and all((p.get('content_access') != 'none') == (p.get('touches_payload') is True) for p in prof), '')
    c, _ = post('/v1/profiles', {})
    rec('POST /v1/profiles -> 405 (spec §13.4)', c == 405, f'{c}')
    c, _ = post('/v1/ruta-que-no-existe', {})
    rec('una ruta fuera de la especificación no existe', c in (404, 405), f'{c}')
    # Longitudes de la especificación: session_id 16 B, sello 32 B, firma 64 B -> otra cosa es 400
    bad = {'session_id': 'aa' * 15, 'index': 0, 'total_fragments': 1, 'is_last': True,
           'payload_hex': '00', 'seal_hex': '00' * 32, 'vault_signature_hex': None}
    c, _ = post('/v1/verify', {'profile': 'core', 'session_id': 'aa' * 15, 'key_id': 0, 'frames': [bad]})
    rec('session_id de 15 bytes -> 400 (spec §2)', c == 400, f'{c}')
    c, r = post('/v1/seal', {'profile': 'core', 'payload_hex': os.urandom(40).hex()})
    if c == 200:
        j = r if isinstance(r, dict) else json.loads(r)
        fr = dict(j['frames'][0], seal_hex=j['frames'][0]['seal_hex'][:-2])
        body = {'profile': 'core', 'session_id': j['session_id'], 'key_id': 0, 'frames': [fr]}
        c2, r2 = post('/v1/verify', body, token=j['capabilities']['verify'])
        res = (r2.get('results') or [{}])[0]
        rec('sello de 31 bytes -> 200 con el frame ok:false y error (spec §9)',
            c2 == 200 and res.get('ok') is False and bool(res.get('error')) and r2.get('all_verified') is False, f'{c2} {res}')
        body['frames'] = [j['frames'][0]]
        c3, r3 = post('/v1/verify', body, token=j['capabilities']['verify'])
        rec('...y la sesión no avanzó: el frame correcto verifica después (spec §9)',
            c3 == 200 and r3.get('all_verified') is True, f'{c3}')
    else:
        rec('sello de 31 bytes -> 200 con el frame ok:false y error (spec §9)', False, f'seal {c}')
    c, _ = post('/v1/verify', {'profile': 'perfil-inexistente', 'session_id': 'aa' * 16, 'key_id': 0, 'frames': []})
    rec('perfil desconocido -> 400 (spec §9)', c == 400, f'{c}')


V2_POLICY = {
    'wire_versions': [1, 2], 'max_session_memory_bytes': 67108864, 'expose_discovery': True,
    'algorithms': [
        {'id': 'hmac-sha256', 'expect_status': 'standard', 'profiles': ['lite', 'core', 'vault'], 'max_cost': 'standard'},
        {'id': 'hmac-sha512', 'expect_status': 'standard', 'profiles': ['lite', 'core'], 'max_cost': 'standard'},
        {'id': 'hmac-sha3-512', 'expect_status': 'standard', 'profiles': ['lite', 'core'], 'max_cost': 'standard'},
        {'id': 'blake2b-keyed', 'expect_status': 'standard', 'profiles': ['lite', 'core'], 'max_cost': 'standard'},
        {'id': 'aes-cmac', 'expect_status': 'standard', 'profiles': ['lite', 'core'], 'max_cost': 'standard'},
        {'id': 'blake3-keyed-xof', 'expect_status': 'standard', 'profiles': ['core'],
         'tag_len_bytes': {'min': 16, 'max': 1024}, 'max_cost': 'standard'},
    ],
    'signatures': [{'id': 'ed25519', 'expect_status': 'standard'}],
}   # `kmac256` (compilado, experimental) queda FUERA a propósito: debe dar 403


VAULT_SEED = bytes(range(0xA0, 0xC0))   # clave de firma del servidor lanzado con --spawn (se conoce, así se verifica fuera)


def _v2_descriptor(seal_id, params=b'', sig=''):
    out = bytes([2])
    for tag, val in ((1, b'hkdf-sha256'), (2, b'hmac-sha256'), (3, seal_id.encode()), (4, params), (5, sig.encode())):
        out += bytes([tag, len(val)]) + val
    return out


def _v2_hkdf(ikm, salt, info, n):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b'', b'', 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); okm += t; i += 1
    return okm[:n]


def _v2_mac(alg, key, msg, n):
    """Cada algoritmo con una implementación DISTINTA de la del servidor (hashlib / blake3 / cryptography)."""
    if alg == 'hmac-sha256': return hmac.new(key, msg, hashlib.sha256).digest()
    if alg == 'hmac-sha512': return hmac.new(key, msg, hashlib.sha512).digest()
    if alg == 'hmac-sha3-512': return hmac.new(key, msg, hashlib.sha3_512).digest()
    if alg == 'blake2b-keyed': return hashlib.blake2b(msg, key=key, digest_size=64).digest()
    if alg == 'blake3-keyed-xof':
        import blake3
        return blake3.blake3(msg, key=key).digest(length=n)
    if alg == 'aes-cmac':
        from cryptography.hazmat.primitives.cmac import CMAC
        from cryptography.hazmat.primitives.ciphers import algorithms
        c = CMAC(algorithms.AES(key)); c.update(msg); return c.finalize()
    raise ValueError(alg)


V2_KEYLEN = {'hmac-sha256': 32, 'hmac-sha512': 64, 'hmac-sha3-512': 64, 'blake2b-keyed': 64, 'aes-cmac': 32, 'blake3-keyed-xof': 32}


def group_vault_v2():
    """E5: vault bajo v2. La firma Ed25519 y el recibo se verifican con OTRA implementación (OpenSSL)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
    pub = Ed25519PrivateKey.from_private_bytes(VAULT_SEED).public_key()
    suite = {'seal': 'hmac-sha256', 'signature': 'ed25519'}
    sh = hashlib.sha256(b'lacre/v2/suite' + _v2_descriptor('hmac-sha256', b'', 'ed25519')).digest()
    payload = os.urandom(600_000)
    c, s = post('/v1/seal', {'version': 2, 'profile': 'vault', 'payload_hex': payload.hex(), 'suite': suite})
    rec('v2 vault: seal 200 con suite_hash que incluye el esquema', c == 200 and s.get('suite_hash_hex') == sh.hex(), f'{c}')
    if c != 200:
        return
    sid = bytes.fromhex(s['session_id'])
    allok = len(s['frames']) > 1
    for f in s['frames']:
        sg = f.get('signature') or {}
        tag = bytes.fromhex(f['seal_hex'])
        msg = b'lacre/v2/vault-sig' + sh + sid + f['index'].to_bytes(8, 'big') + len(tag).to_bytes(8, 'big') + tag
        try:
            pub.verify(bytes.fromhex(sg.get('sig_hex', '')), msg)
            allok &= sg.get('scheme') == 'ed25519' and 'vault_signature_hex' not in f or f.get('vault_signature_hex') is None
        except (InvalidSignature, ValueError):
            allok = False
    rec('v2 vault: cada firma Ed25519 verifica fuera del servidor sobre la entrada canónica', allok)
    vb = {'version': 2, 'profile': 'vault', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames'],
          'suite': suite, 'reassemble': True}
    swapped = copy.deepcopy(s['frames']); swapped[0]['signature'] = swapped[1]['signature']
    c, v = post('/v1/verify', dict(vb, frames=swapped))
    rec('v2 vault: firma de otro fragmento -> rechazada', c == 200 and v.get('all_verified') is False, f'{c}')
    unsigned = copy.deepcopy(s['frames']); unsigned[0]['signature'] = None
    c, v = post('/v1/verify', dict(vb, frames=unsigned))
    rec('v2 vault: sin firma -> rechazada', c == 200 and v.get('all_verified') is False, f'{c}')
    altered = copy.deepcopy(s['frames']); altered[0]['signature']['sig_hex'] = flip(altered[0]['signature']['sig_hex'])
    c, v = post('/v1/verify', dict(vb, frames=altered))
    rec('v2 vault: firma alterada -> rechazada', c == 200 and v.get('all_verified') is False, f'{c}')
    c, v = post('/v1/verify', vb)
    rec('v2 vault: tras los rechazos, la sesión intacta verifica y entrega el payload',
        accepted(c, v) and v.get('payload_hex') == payload.hex(), f'{c}')
    c, a = post('/v1/ack', {'session_id': s['session_id'], 'indices': [f['index'] for f in s['frames']]})
    c2, rc = post('/v1/receipts', {'session_id': s['session_id']})
    exp = [hashlib.sha256(b'lacre/v2/receipt' + sh + f['index'].to_bytes(8, 'big') + bytes.fromhex(f['seal_hex'])).hexdigest()
           for f in s['frames']]
    got = [e['receipt_hex'] for e in rc.get('entries', [])]
    rec('v2 vault: recibos v2 = SHA-256 recalculado fuera', c == 200 and c2 == 200 and sorted(got) == sorted(exp), f'{c} {c2} {len(got)}/{len(exp)}')
    # v1 y v2 no se mezclan en la trama
    c, s1 = post('/v1/seal', {'profile': 'vault', 'payload_hex': '6162'})
    f1 = copy.deepcopy(s1['frames']); f1[0]['signature'] = {'scheme': 'ed25519', 'sig_hex': '00' * 64}
    c, v = post('/v1/verify', {'profile': 'vault', 'session_id': s1['session_id'], 'key_id': 0, 'frames': f1})
    rec('v1 vault: un campo `signature` de v2 se rechaza', not accepted(c, v), f'{c}')


def group_wire_v2():
    """E4: wire v2. Cada sello se re-deriva fuera del servidor (HKDF + MAC de otra implementación)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization
    cases = [('hmac-sha256', None), ('hmac-sha512', None), ('hmac-sha3-512', None), ('blake2b-keyed', None),
             ('aes-cmac', None), ('blake3-keyed-xof', 16), ('blake3-keyed-xof', 32), ('blake3-keyed-xof', 64),
             ('blake3-keyed-xof', 1024)]
    for alg, tl in cases:
        suite = {'seal': alg}
        if tl: suite['tag_len_bytes'] = tl
        name = f'{alg}' + (f' tag {tl} B' if tl else '')
        k = X25519PrivateKey.generate()
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        c, hs = post('/v1/handshake', {'client_public_key_hex': pub.hex()})
        if c != 200:
            rec(f'v2 {name}: handshake', False, f'{c}'); continue
        shared = k.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(hs['server_public_key_hex'])))
        payload = os.urandom(2500)          # core: 1 KiB por fragmento -> 3 frames
        c, s = post('/v1/seal', {'version': 2, 'profile': 'core', 'payload_hex': payload.hex(),
                                 'session_id': hs['session_id'], 'suite': suite})
        rec(f'v2 {name}: seal 200 con version 2, suite y suite_hash', c == 200 and s.get('version') == 2
            and s.get('suite', {}).get('seal') == alg and len(s.get('suite_hash_hex', '')) == 64, f'{c}')
        if c != 200:
            continue
        params = tl.to_bytes(2, 'big') if tl else b''
        sh = hashlib.sha256(b'lacre/v2/suite' + _v2_descriptor(alg, params)).digest()
        rec(f'v2 {name}: suite_hash del servidor = el calculado fuera', s['suite_hash_hex'] == sh.hex())
        sid = bytes.fromhex(hs['session_id'])
        k_seal = _v2_hkdf(shared, sid, b'lacre/v2/seal-key' + sh, V2_KEYLEN[alg])
        k_chain = _v2_hkdf(shared, sid, b'lacre/v2/chain-key' + sh, 32)
        es = hmac.new(k_chain, sid + b'lacre/v2/initial-state' + sh, hashlib.sha256).digest()
        n_out = tl or 0
        allok = len(s['frames']) == 3
        for f in s['frames']:
            frag = bytes.fromhex(f['payload_hex'])
            msg = len(frag).to_bytes(8, 'big') + frag + es
            allok &= _v2_mac(alg, k_seal, msg, n_out).hex() == f['seal_hex']
            es = hmac.new(k_chain, es + frag, hashlib.sha256).digest()
        rec(f'v2 {name}: RE-DERIVACIÓN INDEPENDIENTE de los sellos coincide', allok)
        vb = {'version': 2, 'profile': 'core', 'session_id': s['session_id'], 'key_id': 0,
              'frames': s['frames'], 'suite': suite, 'reassemble': True}
        c, v = post('/v1/verify', vb)
        rec(f'v2 {name}: verify -> verificado, version 2, payload íntegro',
            accepted(c, v) and v.get('version') == 2 and v.get('payload_hex') == payload.hex(), f'{c}')
        # Manipulaciones: etiqueta alterada / truncada / ampliada -> ok:false y la sesión no avanza
        c, s2 = post('/v1/seal', {'version': 2, 'profile': 'core', 'payload_hex': os.urandom(40).hex(), 'suite': suite})
        for label, mut in (('alterada', lambda h: flip(h)), ('truncada', lambda h: h[:-2]), ('ampliada', lambda h: h + '00')):
            fr = dict(s2['frames'][0], seal_hex=mut(s2['frames'][0]['seal_hex']))
            c, v = post('/v1/verify', {'version': 2, 'profile': 'core', 'session_id': s2['session_id'], 'key_id': 0,
                                       'frames': [fr], 'suite': suite})
            res = (v.get('results') or [{}])[0]
            rec(f'v2 {name}: etiqueta {label} -> rechazada', c == 200 and res.get('ok') is False and v.get('all_verified') is False, f'{c}')
        c, v = post('/v1/verify', {'version': 2, 'profile': 'core', 'session_id': s2['session_id'], 'key_id': 0,
                                   'frames': s2['frames'], 'suite': suite})
        rec(f'v2 {name}: tras los rechazos, la sesión intacta verifica el original', accepted(c, v), f'{c}')

    # Reglas de versión y de suite: nada se reinterpreta
    S = {'seal': 'hmac-sha256'}
    base = {'profile': 'core', 'payload_hex': '6162'}
    neg = [
        ('v2 sin suite', dict(base, version=2), 400),
        ('suite con version 1', dict(base, version=1, suite=S), 400),
        ('suite sin version', dict(base, suite=S), 400),
        ('versión 3', dict(base, version=3, suite=S), 400),
        ('algoritmo desconocido', dict(base, version=2, suite={'seal': 'no-existe'}), 400),
        ('tag_len en algoritmo de longitud fija', dict(base, version=2, suite={'seal': 'hmac-sha256', 'tag_len_bytes': 32}), 400),
        ('XOF sin tag_len_bytes', dict(base, version=2, suite={'seal': 'blake3-keyed-xof'}), 400),
        ('XOF con 15 bytes (el Núcleo lo rechaza antes que la política)', dict(base, version=2, suite={'seal': 'blake3-keyed-xof', 'tag_len_bytes': 15}), 400),
        ('XOF con 1025 bytes', dict(base, version=2, suite={'seal': 'blake3-keyed-xof', 'tag_len_bytes': 1025}), 400),
        ('campo desconocido dentro de suite', dict(base, version=2, suite={'seal': 'hmac-sha256', 'extra': 1}), 400),
        ('firma fuera del perfil vault (core con ed25519)', dict(base, version=2, suite={'seal': 'hmac-sha256', 'signature': 'ed25519'}), 400),
        ('perfil vault sin esquema de firma', {'version': 2, 'profile': 'vault', 'payload_hex': '6162', 'suite': S}, 400),
        ('esquema de firma desconocido', {'version': 2, 'profile': 'vault', 'payload_hex': '6162', 'suite': {'seal': 'hmac-sha256', 'signature': 'no-existe'}}, 400),
        ('vault: algoritmo no permitido para vault (hmac-sha512)', {'version': 2, 'profile': 'vault', 'payload_hex': '6162', 'suite': {'seal': 'hmac-sha512', 'signature': 'ed25519'}}, 403),
        ('algoritmo compilado pero fuera de la política (kmac256)', dict(base, version=2, suite={'seal': 'kmac256', 'tag_len_bytes': 32}), 403),
        ('algoritmo fuera de la política para este perfil (XOF en lite)', {'version': 2, 'profile': 'lite', 'payload_hex': '6162', 'suite': {'seal': 'blake3-keyed-xof', 'tag_len_bytes': 32}}, 403),
        ('SHA-1: nunca permitido por esta política', dict(base, version=2, suite={'seal': 'hmac-sha1'}), None),
    ]
    for name, body, want in neg:
        c, _ = post('/v1/seal', body)
        if want is None:
            rec(f'v2 {name}: rechazado (400 si no está compilado, 403 si lo está)', c in (400, 403), f'{c}')
        else:
            rec(f'v2 {name} -> {want}', c == want, f'{c}')

    group_vault_v2()

    # La sesión queda ligada a su primera suite
    c, s = post('/v1/seal', {'version': 2, 'profile': 'lite', 'payload_hex': os.urandom(20000).hex(), 'suite': S})
    first = {'version': 2, 'profile': 'lite', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames'][:1], 'suite': S}
    c1, v1 = post('/v1/verify', first)
    rest = dict(first, frames=s['frames'][1:], suite={'seal': 'hmac-sha512'})
    c2, _ = post('/v1/verify', rest)
    rec('v2: segundo lote bajo OTRA suite permitida -> 400 (sesión ligada)', accepted(c1, v1) and c2 == 400, f'{c1} {c2}')
    rest1 = {k: v for k, v in dict(first, frames=s['frames'][1:]).items() if k not in ('version', 'suite')}
    c3, _ = post('/v1/verify', rest1)
    rec('v2: la sesión v2 no se reinterpreta como v1 -> 400', c3 == 400, f'{c3}')
    c4, v4 = post('/v1/verify', dict(first, frames=s['frames'][1:]))
    rec('v2: la sesión intacta termina con su suite', accepted(c4, v4), f'{c4}')

    # Descubrimiento opt-in
    c, d = get('/v1/seal-algorithms')
    ids = sorted(a['id'] for a in d.get('algorithms', [])) if c == 200 else []
    rec('GET /v1/seal-algorithms (política lo expone) lista lo permitido', c == 200 and ids == sorted(a['id'] for a in V2_POLICY['algorithms']), f'{c} {ids}')
    rec('descubrimiento no expone estado de carga ni de cuarentena', 'quarantine' not in json.dumps(d))
    # v1 intacto bajo política v2
    c, s = post('/v1/seal', {'profile': 'core', 'payload_hex': os.urandom(100).hex()})
    c2, v = post('/v1/verify', {'profile': 'core', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames']})
    rec('v1 sigue idéntico con la política v2 activa', c == 200 and accepted(c2, v) and s.get('version') == 1 and 'suite' not in s)


def main():
    global BASE
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--url', help='URL base de un servidor ya en marcha')
    ap.add_argument('--spawn', help='ruta al binario lacre-server; se lanza en un puerto libre')
    ap.add_argument('--slow', action='store_true', help='incluye la prueba de expiración (≈70 s) y el payload de 20 MB')
    ap.add_argument('--bench', action='store_true', help='incluye benchmark de carga concurrente')
    ap.add_argument('--v2', action='store_true', help='con --url: el servidor ya corre con política v2 (--spawn la activa solo)')
    ap.add_argument('--json', help='guarda el resultado en este fichero')
    ap.add_argument('--port', type=int, help='con --spawn: puerto fijo del servidor (para que un intermediario apunte a él)')
    ap.add_argument('--via', help='con --spawn: las peticiones van a esta URL (un intermediario delante del servidor)')
    ap.add_argument('--h2', action='store_true', help='habla HTTP/2 (httpx); necesita --via https y --cafile')
    ap.add_argument('--token-in-body', action='store_true', help='(obsoleto: ya es el modo por defecto)')
    ap.add_argument('--token-in-header', action='store_true', help='modo de compatibilidad: el token de capacidad va en Authorization: Bearer, que un intermediario puede borrar')
    ap.add_argument('--cafile', help='certificado (PEM) en el que confiar para https y wss')
    a = ap.parse_args()
    global requests, WS_SSL, TOKEN_IN_BODY
    TOKEN_IN_BODY = not a.token_in_header
    if a.cafile:
        os.environ['REQUESTS_CA_BUNDLE'] = a.cafile
        import ssl
        WS_SSL = ssl.create_default_context(cafile=a.cafile)
    if a.h2:
        requests = _H2Requests(a.cafile)
    proc = None
    if a.spawn:
        port = a.port or free_port()
        import tempfile
        rf = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False); json.dump(RULESETS, rf); rf.close()
        pf = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False); json.dump(V2_POLICY, pf); pf.close()
        env = dict(os.environ, LACRE_HTTP_ADDR=f'127.0.0.1:{port}', LACRE_RULESETS_FILE=rf.name, LACRE_SEAL_POLICY=pf.name,
                   LACRE_VAULT_SIGNING_KEY=VAULT_SEED.hex())
        a.v2 = True
        proc = subprocess.Popen([a.spawn, '--serve'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        BASE = (a.via or f'http://127.0.0.1:{port}').rstrip('/')
        for _ in range(100):
            try:
                requests.get(BASE + '/v1/health', timeout=0.5); break
            except Exception:
                time.sleep(0.1)
    elif a.url:
        BASE = a.url.rstrip('/')
    else:
        ap.error('indica --url o --spawn')
    global V2_ON
    V2_ON = bool(a.v2)
    ws_url = BASE.replace('http', 'ws', 1) + '/v1/ws'
    bench = None
    try:
        group_frames(); group_inputs(); group_vault_ack(); group_handshake_kat()
        group_toolchain_http(); group_auth(); group_rules_reassembly(); group_version(); group_tolerance(); group_spec()
        if a.v2:
            group_wire_v2()
        asyncio.run(ws_group(ws_url))
        if a.slow:
            group_big(); group_expiry_slow()
        if a.bench:
            bench = group_bench()
    finally:
        if proc:
            proc.send_signal(signal.SIGTERM); proc.wait(timeout=10)
    npass = sum(1 for r in R if r[0] == 'PASS'); nfail = sum(1 for r in R if r[0] == 'FAIL')
    ngap = sum(1 for r in R if r[0] == 'GAP'); nclosed = sum(1 for r in R if r[0] == 'GAP-CERRADO')
    print(f'\nTOTAL {len(R)}  PASS {npass}  FAIL {nfail}  GAP-conocida {ngap}  GAP-cerrada {nclosed}')
    if a.json:
        json.dump({'results': R, 'bench': bench, 'pass': npass, 'fail': nfail, 'gap': ngap, 'gap_closed': nclosed},
                  open(a.json, 'w'), indent=1)
    sys.exit(1 if nfail else 0)


if __name__ == '__main__':
    main()

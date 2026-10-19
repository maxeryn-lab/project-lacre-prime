#!/usr/bin/env python3
"""Lacre detrás de intermediarios reales (véase spec/LACRE-WIRE-v2.md, secciones 11 y 12).

Por cada escenario levanta un intermediario (nginx, haproxy, mitmproxy o una cadena)
delante de lacre-server y corre la suite externa a través de él. Compara con la
línea base (suite directa). Además corre dos controles propios:

  * control positivo de alteración: un intermediario que cambia un byte del payload
    (en la respuesta de seal o en la petición de verify) debe ser detectado siempre;
  * respuestas ajenas: un 502 y un 413 del intermediario deben distinguirse de un
    error de Lacre.

Uso (desde Code/workspace):
    python3 ../../Tools/intermediaries.py --server target/debug/lacre-server [--only NOMBRE ...] [--json salida.json]

Dependencias: nginx, haproxy, mitmproxy (mitmdump), openssl, httpx[http2], requests.
Las configuraciones son típicas, no productos de terceros en producción.
"""
import argparse, json, os, re, shutil, signal, socket, subprocess, sys, tempfile, textwrap, time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import external_suite as X  # noqa: E402  (constantes: V2_POLICY, RULESETS, VAULT_SEED)

TMP = tempfile.mkdtemp(prefix='lacre-interm-')
PROCS = []


def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


def start(cmd, name, env=None):
    log = open(os.path.join(TMP, name + '.log'), 'w')
    p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
    PROCS.append(p)
    return p


def stop(p):
    if p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
    if p in PROCS:
        PROCS.remove(p)


def wait_port(port, secs=20):
    t = time.time()
    while time.time() - t < secs:
        try:
            socket.create_connection(('127.0.0.1', port), 0.3).close(); return True
        except OSError:
            time.sleep(0.1)
    return False


def make_cert():
    key, crt, pem = (os.path.join(TMP, n) for n in ('k.pem', 'c.pem', 'kc.pem'))
    cnf = os.path.join(TMP, 'o.cnf')
    open(cnf, 'w').write('[req]\ndistinguished_name=d\nx509_extensions=v\nprompt=no\n[d]\nCN=localhost\n[v]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', key, '-out', crt, '-config', cnf],
                   check=True, capture_output=True)
    open(pem, 'w').write(open(crt).read() + open(key).read())
    return key, crt, pem


# ───────────────────────── configuraciones de intermediarios ─────────────────────────

def nginx_conf(listen, upstream, tls=None, buffering=True, req_buffering=True, gzip=False, max_body='64m', ws=True, read_timeout='120s'):
    ssl = ''
    if tls:
        ssl = f' ssl http2;\n            ssl_certificate {tls[1]};\n            ssl_certificate_key {tls[0]}'
    gz = 'gzip on; gzip_min_length 1; gzip_types application/json text/plain;' if gzip else ''
    conf = f"""
        daemon off;
        user root;
        pid {TMP}/nginx-{listen}.pid;
        error_log {TMP}/nginx-{listen}.err warn;
        events {{ worker_connections 256; }}
        http {{
          access_log off;
          client_body_temp_path {TMP}/nb-{listen}; proxy_temp_path {TMP}/np-{listen};
          fastcgi_temp_path {TMP}/nf-{listen}; uwsgi_temp_path {TMP}/nu-{listen}; scgi_temp_path {TMP}/ns-{listen};
          map $http_upgrade $conn_up {{ default upgrade; '' close; }}
          server {{
            listen 127.0.0.1:{listen}{ssl};
            client_max_body_size {max_body};
            {gz}
            location / {{
              proxy_pass http://127.0.0.1:{upstream};
              proxy_http_version 1.1;
              proxy_set_header Host $host;
              proxy_set_header X-Forwarded-For $remote_addr;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_set_header Upgrade $http_upgrade;
              proxy_set_header Connection $conn_up;
              proxy_buffering {'on' if buffering else 'off'};
              proxy_request_buffering {'on' if req_buffering else 'off'};
              proxy_read_timeout {read_timeout};
            }}
          }}
        }}
    """
    path = os.path.join(TMP, f'nginx-{listen}.conf')
    open(path, 'w').write(textwrap.dedent(conf))
    return path


def haproxy_conf(listen, upstream, tls_pem=None, strip_authz=False, extra=''):
    bind = f'bind 127.0.0.1:{listen}' + (f' ssl crt {tls_pem} alpn h2,http/1.1' if tls_pem else '')
    strip = '  http-request del-header Authorization\n' if strip_authz else ''
    conf = f"""
        global
          maxconn 512
        defaults
          mode http
          timeout connect 5s
          timeout client 120s
          timeout server 120s
          timeout tunnel 120s
        frontend f
          {bind}
          option forwardfor
          http-request set-header X-Forwarded-Proto {'https' if tls_pem else 'http'}
          http-response set-header X-Intermediary haproxy
        {strip}{extra}
          default_backend b
        backend b
          server s 127.0.0.1:{upstream}
    """
    path = os.path.join(TMP, f'haproxy-{listen}.cfg')
    open(path, 'w').write(textwrap.dedent(conf))
    return path


ADDON = r'''
import json, os
from mitmproxy import http

MODE = os.environ.get("LACRE_MITM_MODE", "rewrite")

def _count(kind):
    with open(os.environ["LACRE_MITM_STATS"], "a") as f:
        f.write(kind + "\n")

def _flip(h):
    return ("00" if h[:2] != "00" else "01") + h[2:]

def _reser(raw, flip_frames=False, flip_top=False):
    try:
        j = json.loads(raw)
    except Exception:
        return raw
    if flip_frames and isinstance(j, dict) and j.get("frames"):
        j["frames"][0]["payload_hex"] = _flip(j["frames"][0]["payload_hex"])
    return j

def _dump(j, ensure_ascii):
    return json.dumps(j, sort_keys=True, separators=(",", ":"), ensure_ascii=ensure_ascii).encode()

def request(flow: http.HTTPFlow):
    if MODE == "chunked":
        flow.request.stream = True
        return
    if not flow.request.content:
        return
    if MODE == "rewrite":
        j = _reser(flow.request.content)
        if not isinstance(j, bytes):
            flow.request.content = _dump(j, False)
            _count("request-rewritten")
        # mayúsculas de cabeceras y orden: mitmproxy ya las reescribe a su forma
    elif MODE == "tamper-request" and flow.request.path.startswith("/v1/verify"):
        j = _reser(flow.request.content, flip_frames=True)
        if not isinstance(j, bytes):
            flow.request.content = _dump(j, True)

def response(flow: http.HTTPFlow):
    if MODE in ("chunked",) or not flow.response or not flow.response.content:
        return
    if MODE == "rewrite" and "json" in flow.response.headers.get("content-type", ""):
        j = _reser(flow.response.content)
        if not isinstance(j, bytes):
            flow.response.content = _dump(j, False)
            _count("response-rewritten")
    elif MODE == "tamper-response" and flow.request.path.startswith("/v1/seal"):
        j = _reser(flow.response.content, flip_frames=True)
        if not isinstance(j, bytes):
            flow.response.content = _dump(j, True)
'''


def mitm_cmd(listen, upstream, mode):
    addon = os.path.join(TMP, 'addon.py')
    open(addon, 'w').write(ADDON)
    env = dict(os.environ, LACRE_MITM_MODE=mode, LACRE_MITM_STATS=os.path.join(TMP, f'mitm-stats-{listen}.txt'))
    cmd = ['mitmdump', '--mode', f'reverse:http://127.0.0.1:{upstream}', '--listen-host', '127.0.0.1', '--listen-port', str(listen),
           '-s', addon, '-q', '--set', 'connection_strategy=lazy', '--set', 'confdir=' + os.path.join(TMP, 'mitmconf')]
    return cmd, env


# ───────────────────────── escenarios ─────────────────────────
# Cada uno: (nombre, descripción, función que arranca los intermediarios y devuelve
# (via_url, opciones_extra_de_la_suite)); el servidor lo lanza la suite en `sp`.

def sc_direct(sp, tls):
    return None, []


def sc_nginx_http(sp, tls):
    port = free_port(); start(['nginx', '-c', nginx_conf(port, sp), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'http://127.0.0.1:{port}', []


def sc_nginx_limit(sp, tls):
    """Configuración recomendada: el tope del intermediario no supera el de Lacre (2 MiB)."""
    port = free_port(); start(['nginx', '-c', nginx_conf(port, sp, max_body='2m'), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'http://127.0.0.1:{port}', []


def sc_nginx_nobuf(sp, tls):
    port = free_port()
    start(['nginx', '-c', nginx_conf(port, sp, buffering=False, req_buffering=False), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'http://127.0.0.1:{port}', []


def sc_nginx_gzip(sp, tls):
    port = free_port(); start(['nginx', '-c', nginx_conf(port, sp, gzip=True), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'http://127.0.0.1:{port}', []


def sc_nginx_tls_h2(sp, tls):
    port = free_port()
    start(['nginx', '-c', nginx_conf(port, sp, tls=(tls[0], tls[1])), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'https://localhost:{port}', ['--h2', '--cafile', tls[1]]


def sc_nginx_tls_ws(sp, tls):
    """Mismo nginx TLS, pero el cliente habla HTTP/1.1 (así el WebSocket pasa por wss)."""
    port = free_port()
    start(['nginx', '-c', nginx_conf(port, sp, tls=(tls[0], tls[1])), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'https://localhost:{port}', ['--cafile', tls[1]]


def sc_haproxy_h2(sp, tls):
    port = free_port()
    start(['haproxy', '-f', haproxy_conf(port, sp, tls_pem=tls[2]), '-db'], f'haproxy{port}'); wait_port(port)
    return f'https://localhost:{port}', ['--h2', '--cafile', tls[1]]


def sc_haproxy_h1(sp, tls):
    port = free_port()
    start(['haproxy', '-f', haproxy_conf(port, sp), '-db'], f'haproxy{port}'); wait_port(port)
    return f'http://127.0.0.1:{port}', []


def sc_haproxy_strip(sp, tls):
    port = free_port()
    start(['haproxy', '-f', haproxy_conf(port, sp, strip_authz=True), '-db'], f'haproxy{port}'); wait_port(port)
    return f'http://127.0.0.1:{port}', ['--token-in-header']


def sc_haproxy_strip_body(sp, tls):
    via, _ = sc_haproxy_strip(sp, tls)
    return via, []


def sc_mitm_rewrite(sp, tls):
    port = free_port(); cmd, env = mitm_cmd(port, sp, 'rewrite'); start(cmd, f'mitm{port}', env); wait_port(port, 40)
    return f'http://127.0.0.1:{port}', []


def sc_mitm_chunked(sp, tls):
    port = free_port(); cmd, env = mitm_cmd(port, sp, 'chunked'); start(cmd, f'mitm{port}', env); wait_port(port, 40)
    return f'http://127.0.0.1:{port}', []


def sc_chain(sp, tls):
    """cliente (h2, TLS) → nginx → haproxy → lacre-server"""
    hp = free_port()
    start(['haproxy', '-f', haproxy_conf(hp, sp), '-db'], f'haproxy{hp}'); wait_port(hp)
    port = free_port()
    start(['nginx', '-c', nginx_conf(port, hp, tls=(tls[0], tls[1]), gzip=True), '-p', TMP], f'nginx{port}'); wait_port(port)
    return f'https://localhost:{port}', ['--h2', '--cafile', tls[1]]


def sc_chain3(sp, tls):
    """cliente → mitmproxy (reescribe JSON) → nginx (gzip) → haproxy → lacre-server"""
    hp = free_port()
    start(['haproxy', '-f', haproxy_conf(hp, sp), '-db'], f'haproxy{hp}'); wait_port(hp)
    ng = free_port()
    start(['nginx', '-c', nginx_conf(ng, hp, gzip=True), '-p', TMP], f'nginx{ng}'); wait_port(ng)
    port = free_port(); cmd, env = mitm_cmd(port, ng, 'rewrite'); start(cmd, f'mitm{port}', env); wait_port(port, 40)
    return f'http://127.0.0.1:{port}', []


SCENARIOS = [
    ('direct', 'línea base: sin intermediario', sc_direct),
    ('nginx-http', 'nginx proxy inverso HTTP/1.1, con búfer', sc_nginx_http),
    ('nginx-limit-2m', 'nginx con client_max_body_size 2m (tope no mayor que el de Lacre)', sc_nginx_limit),
    ('nginx-nobuf', 'nginx sin búfer (petición a Lacre en chunked)', sc_nginx_nobuf),
    ('nginx-gzip', 'nginx comprime las respuestas con gzip', sc_nginx_gzip),
    ('nginx-tls-h2', 'nginx TLS, cliente HTTP/2, Lacre HTTP/1.1', sc_nginx_tls_h2),
    ('nginx-tls-wss', 'nginx TLS, cliente HTTP/1.1 y WebSocket wss', sc_nginx_tls_ws),
    ('haproxy-h1', 'haproxy HTTP/1.1 con X-Forwarded-*', sc_haproxy_h1),
    ('haproxy-h2', 'haproxy TLS, cliente HTTP/2, Lacre HTTP/1.1', sc_haproxy_h2),
    ('haproxy-strip-authz', 'haproxy borra Authorization; token en cabecera (modo de compatibilidad: falla)', sc_haproxy_strip),
    ('haproxy-strip-authz+body', 'haproxy borra Authorization; token en el cuerpo (forma de referencia)', sc_haproxy_strip_body),
    ('mitm-rewrite', 'mitmproxy reserializa el JSON (claves ordenadas, sin espacios)', sc_mitm_rewrite),
    ('mitm-chunked', 'mitmproxy reenvía en streaming (chunked)', sc_mitm_chunked),
    ('chain-nginx-haproxy', 'cadena: nginx TLS+h2 con gzip → haproxy → Lacre', sc_chain),
    ('chain-mitm-nginx-haproxy', 'cadena: mitmproxy reescribe → nginx gzip → haproxy → Lacre', sc_chain3),
]


def probe(via, extra, direct):
    """Evidencia de que el intermediario está en el camino y qué le hace al mensaje."""
    cafile = extra[extra.index('--cafile') + 1] if '--cafile' in extra else None
    h2 = '--h2' in extra
    try:
        if h2:
            import httpx
            c = httpx.Client(http2=True, verify=cafile or True, timeout=20)
            r = c.get(via + '/v1/profiles', headers={'accept-encoding': 'gzip'})
            ver = r.http_version
        else:
            r = requests.get(via + '/v1/profiles', timeout=20, verify=cafile or True, headers={'accept-encoding': 'gzip'}, stream=True)
            ver = 'HTTP/1.1'
            r.raw.decode_content = False
        raw = r.content if h2 else r.raw.read()
        d = requests.get(direct + '/v1/profiles', timeout=20, headers={'accept-encoding': 'identity'}).content
        h = {k.lower(): v for k, v in r.headers.items()}
        body = raw
        if h.get('content-encoding') == 'gzip':
            import gzip
            try:
                body = gzip.decompress(raw)
            except gzip.BadGzipFile:       # httpx ya lo descomprimió
                body = raw
        return dict(http=ver, server=h.get('server') or h.get('x-intermediary') or h.get('via') or '-', content_encoding=h.get('content-encoding', '-'),
                    transfer_encoding=h.get('transfer-encoding', '-'), body_identical_to_direct=(body == d),
                    json_equal=(json.loads(body) == json.loads(d)))
    except Exception as e:
        return dict(error=repr(e)[:200])


def _mitm_counts():
    import glob, collections
    c = collections.Counter()
    for f in glob.glob(os.path.join(TMP, 'mitm-stats-*.txt')):
        c.update(open(f).read().split())
        os.remove(f)
    return {k: v for k, v in c.items()}


def run_scenario(server, name, fn, tls, slow=False):
    sp = free_port()
    started = len(PROCS)
    try:
        via, extra = fn(sp, tls)
        srv = spawn_server(server, sp)
        direct = f'http://127.0.0.1:{sp}'
        pr = probe(via, extra, direct) if via else {}
        out = os.path.join(TMP, name + '.json')
        cmd = [sys.executable, os.path.join(HERE, 'external_suite.py'), '--url', via or direct, '--v2', '--json', out] + extra + (['--slow'] if slow else [])
        t = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        dt = time.time() - t
        res = json.load(open(out)) if os.path.exists(out) else None
        fails = [x[1] for x in res['results'] if x[0] == 'FAIL'] if res else []
        tail = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()[-300:]
        return dict(name=name, pass_=res['pass'] if res else 0, fail=res['fail'] if res else None, total=len(res['results']) if res else 0,
                    failures=fails, seconds=round(dt, 1), tail=tail, probe=dict(pr, **_mitm_counts()), error=None if res else r.stderr[-400:])
    finally:
        for p in PROCS[started:]:
            stop(p)
        for p in list(PROCS):
            if p.poll() is not None:
                PROCS.remove(p)


# ───────────────────────── controles propios ─────────────────────────

def spawn_server(server, port, extra_env=None):
    import tempfile as tf
    rf = tf.NamedTemporaryFile('w', suffix='.json', delete=False, dir=TMP); json.dump(X.RULESETS, rf); rf.close()
    pf = tf.NamedTemporaryFile('w', suffix='.json', delete=False, dir=TMP); json.dump(X.V2_POLICY, pf); pf.close()
    env = dict(os.environ, LACRE_HTTP_ADDR=f'127.0.0.1:{port}', LACRE_RULESETS_FILE=rf.name, LACRE_SEAL_POLICY=pf.name,
               LACRE_VAULT_SIGNING_KEY=X.VAULT_SEED.hex(), **(extra_env or {}))
    p = start([server, '--serve'], f'server{port}', env)
    for _ in range(100):
        try:
            requests.get(f'http://127.0.0.1:{port}/v1/health', timeout=0.5); break
        except Exception:
            time.sleep(0.1)
    return p


def seal_then_verify(seal_base, verify_base, profile, size):
    payload = os.urandom(size).hex()
    s = requests.post(seal_base + '/v1/seal', json={'profile': profile, 'payload_hex': payload}, timeout=60)
    j = s.json()
    h = {'Authorization': 'Bearer ' + j['capabilities']['verify']}
    v = requests.post(verify_base + '/v1/verify', json={'profile': profile, 'session_id': j['session_id'], 'key_id': 0, 'frames': j['frames']},
                      headers=h, timeout=60)
    return v.status_code, v.json().get('all_verified') is True


def control_tamper(server):
    """Un intermediario que cambia un byte del payload debe ser detectado siempre."""
    results = []
    sp = free_port(); srv = spawn_server(server, sp)
    direct = f'http://127.0.0.1:{sp}'
    try:
        # sano: pasar por un mitmproxy sin alterar no rompe nada (el control no es vacuo)
        port = free_port(); cmd, env = mitm_cmd(port, sp, 'chunked'); p = start(cmd, 'mitm-ok', env); wait_port(port, 40)
        ok = [seal_then_verify(f'http://127.0.0.1:{port}', direct, pr, 3000) for pr in ('lite', 'core') for _ in range(5)]
        results.append(('sano: sellar por el intermediario sin alterar y verificar directo', all(a for _, a in ok), f'{sum(a for _, a in ok)}/{len(ok)} aceptados'))
        stop(p)
        for mode, where in (('tamper-response', 'respuesta de seal'), ('tamper-request', 'petición de verify')):
            port = free_port(); cmd, env = mitm_cmd(port, sp, mode); p = start(cmd, 'mitm-' + mode, env); wait_port(port, 40)
            via = f'http://127.0.0.1:{port}'
            runs = []
            for pr in ('lite', 'core'):
                for _ in range(10):
                    if mode == 'tamper-response':
                        runs.append(seal_then_verify(via, direct, pr, 3000))
                    else:
                        runs.append(seal_then_verify(direct, via, pr, 3000))
            rejected = sum(1 for _, a in runs if not a)
            results.append((f'alteración en la {where}: detectada', rejected == len(runs), f'{rejected}/{len(runs)} rechazadas'))
            stop(p)
    finally:
        stop(srv)
    return results


def control_foreign(server, tls):
    """Un 502 y un 413 del intermediario no se confunden con un error de Lacre."""
    results = []
    sp = free_port()
    # 502: el intermediario apunta a un puerto sin servidor
    port = free_port(); start(['nginx', '-c', nginx_conf(port, sp), '-p', TMP], f'nginx{port}'); wait_port(port)
    r = requests.post(f'http://127.0.0.1:{port}/v1/seal', json={'profile': 'core', 'payload_hex': '00'}, timeout=30)
    try:
        j = r.json()
        lacre_like = isinstance(j, dict) and ('error' in j or 'code' in j)
    except Exception:
        lacre_like = False
    results.append(('502 del intermediario con Lacre caído: status 502 y sin sobre de error de Lacre', r.status_code == 502 and not lacre_like,
                    f'status {r.status_code}, cuerpo no-Lacre={not lacre_like}'))
    # 413: tope de cuerpo del intermediario (1 MB por defecto en nginx)
    srv = spawn_server(server, sp)
    try:
        for mb, expect in (('1m', 413), ('64m', 200)):
            port2 = free_port()
            p = start(['nginx', '-c', nginx_conf(port2, sp, max_body=mb), '-p', TMP], f'nginx{port2}'); wait_port(port2)
            r = requests.post(f'http://127.0.0.1:{port2}/v1/seal', json={'profile': 'core', 'payload_hex': os.urandom(900_000).hex()}, timeout=120)
            try:
                j = r.json(); lacre_like = isinstance(j, dict) and ('error' in j or 'code' in j or 'frames' in j)
            except Exception:
                lacre_like = False
            if expect == 413:
                results.append((f'tope {mb} del intermediario: 413 propio, sin sobre de Lacre', r.status_code == 413 and not lacre_like, f'status {r.status_code}'))
            else:
                results.append((f'tope {mb}: un payload de 1,8 MB (hex) pasa y Lacre responde', r.status_code == 200 and lacre_like, f'status {r.status_code}'))
            stop(p)
        big = requests.post(f'http://127.0.0.1:{sp}/v1/seal', json={'profile': 'core', 'payload_hex': os.urandom(1_200_000).hex()}, timeout=120)
        results.append(('tope propio de Lacre: un cuerpo de 2,4 MB recibe 413 de texto plano, distinto de la página HTML del intermediario',
                        big.status_code == 413 and big.headers.get('content-type', '').startswith('text/plain'),
                        f"status {big.status_code}, {big.headers.get('content-type')}, «{big.text[:60]}»"))
    finally:
        stop(srv)
    return results


def move_by_parts(session, base, size, part_bytes=200 * 1024):
    """Mueve `size` bytes con /v1/seal/open + /v1/seal/part, verificando y confirmando cada parte (P2).
    Devuelve (ok, detalle). Registra el mayor cuerpo de petición enviado."""
    biggest = 0

    def post(path, body):
        nonlocal biggest
        biggest = max(biggest, len(json.dumps(body)))
        return session.post(base + path, json=body, timeout=120)

    o = post('/v1/seal/open', {'profile': 'core'})
    if o.status_code != 200:
        return False, f'open {o.status_code} {o.text[:80]}'
    o = o.json()
    wt, vt, at = (o['capabilities'][k] for k in ('write', 'verify', 'ack'))
    sid, sent, i, frames_total = o['session_id'], 0, 0, 0
    t = time.time()
    while sent < size:
        n = min(part_bytes, size - sent)
        last = sent + n >= size
        r = post('/v1/seal/part', {'session_id': sid, 'token': wt, 'part_index': i, 'payload_hex': os.urandom(n).hex(), 'is_last': last})
        if r.status_code != 200:
            return False, f'parte {i}: {r.status_code} {r.text[:80]}'
        frames = r.json()['frames']
        v = post('/v1/verify', {'profile': 'core', 'session_id': sid, 'key_id': 0, 'frames': frames, 'token': vt})
        if v.status_code != 200 or v.json().get('all_verified') is not True:
            return False, f'verify de la parte {i}: {v.status_code} {v.text[:80]}'
        a = post('/v1/ack', {'session_id': sid, 'token': at, 'indices': [f['index'] for f in frames]})
        if a.status_code != 200:
            return False, f'ack de la parte {i}: {a.status_code} {a.text[:80]}'
        frames_total += len(frames)
        sent += n
        i += 1
    return True, f'{size // (1024 * 1024)} MiB en {i} partes ({frames_total} frames), mayor petición {biggest // 1024} KiB, {time.time() - t:.1f} s'


def control_parts(server, tls):
    """P2: 20 MiB por partes detrás de nginx con su tope por defecto (1 MB) y detrás de haproxy con h2."""
    import httpx
    results = []
    size = 20 * 1024 * 1024
    sp = free_port(); srv = spawn_server(server, sp)
    try:
        port = free_port(); p = start(['nginx', '-c', nginx_conf(port, sp, max_body='1m'), '-p', TMP], f'nginx{port}'); wait_port(port)
        base = f'http://127.0.0.1:{port}'
        whole = requests.post(base + '/v1/seal', json={'profile': 'core', 'payload_hex': os.urandom(600_000).hex()}, timeout=60)
        results.append(('control: /v1/seal entero de 1,2 MB por nginx con tope 1 MB sigue rechazado por el intermediario', whole.status_code == 413, f'status {whole.status_code}'))
        ok, d = move_by_parts(requests.Session(), base, size)
        results.append(('20 MiB por partes detrás de nginx con client_max_body_size 1m (su valor por defecto)', ok, d))
        stop(p)
        hp = free_port(); hproc = start(['haproxy', '-f', haproxy_conf(hp, sp, tls_pem=tls[2]), '-db'], f'haproxy{hp}'); wait_port(hp)
        with httpx.Client(http2=True, verify=tls[1], timeout=120) as c:
            ok, d = move_by_parts(c, f'https://localhost:{hp}', size)
            proto = c.get(f'https://localhost:{hp}/v1/health').http_version
        results.append(('20 MiB por partes detrás de haproxy con TLS y cliente HTTP/2', ok and proto == 'HTTP/2', f'{d}; protocolo {proto}'))
        stop(hproc)
    finally:
        stop(srv)
    return results


def control_replay(server):
    """Un intermediario que reintenta reenvía la misma petición dos veces."""
    results = []
    sp = free_port(); srv = spawn_server(server, sp); base = f'http://127.0.0.1:{sp}'
    try:
        payload = os.urandom(3000).hex()
        j = requests.post(base + '/v1/seal', json={'profile': 'core', 'payload_hex': payload}, timeout=30).json()
        hv = {'Authorization': 'Bearer ' + j['capabilities']['verify']}
        body = {'profile': 'core', 'session_id': j['session_id'], 'key_id': 0, 'frames': j['frames']}
        r1 = requests.post(base + '/v1/verify', json=body, headers=hv, timeout=30)
        r2 = requests.post(base + '/v1/verify', json=body, headers=hv, timeout=30)
        a1 = r1.status_code == 200 and r1.json().get('all_verified') is True
        a2 = r2.status_code == 200 and r2.json() == r1.json()
        results.append(('verify repetido idéntico (P3): el reintento recibe el MISMO veredicto, no un error', a1 and a2,
                        f'1ª {r1.status_code} aceptada={a1}; 2ª {r2.status_code} idéntica={a2}'))
        # una petición DISTINTA sobre la sesión terminada sigue rechazada
        r3 = requests.post(base + '/v1/verify', json=dict(body, frames=body['frames'][:1]), headers=hv, timeout=30)
        results.append(('verify distinto sobre la sesión terminada: sigue rechazado (la repetición no abre nada nuevo)', r3.status_code == 400,
                        f'status {r3.status_code}'))
        # seal repetido: dos sesiones distintas, ninguna rompe a la otra
        s1 = requests.post(base + '/v1/seal', json={'profile': 'core', 'payload_hex': payload}, timeout=30).json()
        s2 = requests.post(base + '/v1/seal', json={'profile': 'core', 'payload_hex': payload}, timeout=30).json()
        results.append(('seal repetido: dos sesiones distintas y ambas verificables', s1['session_id'] != s2['session_id'], f"{s1['session_id'][:8]} / {s2['session_id'][:8]}"))
        for s in (s1, s2):
            hh = {'Authorization': 'Bearer ' + s['capabilities']['verify']}
            v = requests.post(base + '/v1/verify', json={'profile': 'core', 'session_id': s['session_id'], 'key_id': 0, 'frames': s['frames']}, headers=hh, timeout=30)
            results.append(('sesión del seal repetido verifica', v.status_code == 200 and v.json().get('all_verified') is True, f'status {v.status_code}'))
        # ack repetido (vault v1, que sí tiene ack/recibos)
        sv = requests.post(base + '/v1/seal', json={'profile': 'vault', 'payload_hex': payload}, timeout=30)
        if sv.status_code == 200:
            sj = sv.json()
            ha = {'Authorization': 'Bearer ' + sj['capabilities']['ack']}
            a = [requests.post(base + '/v1/ack', json={'session_id': sj['session_id'], 'indices': [f['index'] for f in sj['frames']]}, headers=ha, timeout=30) for _ in range(2)]
            results.append(('ack repetido: el primero se acepta y el segundo no rompe nada (se informa su status)', a[0].status_code == 200, f'1º {a[0].status_code}, 2º {a[1].status_code}'))
        else:
            results.append(('ack repetido: vault v1 sin política v1 de firma, no aplica', True, f'seal vault {sv.status_code}'))
    finally:
        stop(srv)
    return results


def control_extra(server):
    """Casos que quedaron fuera de la primera ronda: petición comprimida, h2 sin TLS, WebSocket inactivo."""
    import gzip, asyncio
    results = []
    sp = free_port(); srv = spawn_server(server, sp); base = f'http://127.0.0.1:{sp}'
    try:
        body = json.dumps({'profile': 'core', 'payload_hex': os.urandom(2000).hex()}).encode()
        r = requests.post(base + '/v1/seal', data=gzip.compress(body), headers={'content-type': 'application/json', 'content-encoding': 'gzip'}, timeout=30)
        results.append(('petición con Content-Encoding: gzip hacia Lacre: no se acepta como si fuera JSON (fallo cerrado, informado con su status)',
                        r.status_code in (400, 415) and 'frames' not in r.text, f'status {r.status_code}, «{r.text[:70]}»'))
        # el mismo cuerpo comprimido, pasando por nginx, que no descomprime peticiones
        port = free_port(); p = start(['nginx', '-c', nginx_conf(port, sp), '-p', TMP], f'nginx{port}'); wait_port(port)
        r2 = requests.post(f'http://127.0.0.1:{port}/v1/seal', data=gzip.compress(body), headers={'content-type': 'application/json', 'content-encoding': 'gzip'}, timeout=30)
        results.append(('petición gzip a través de nginx: mismo resultado que directo', r2.status_code == r.status_code, f'status {r2.status_code}'))
        stop(p)
        # HTTP/2 sin TLS (h2c con conocimiento previo) hacia Lacre
        if shutil.which('curl'):
            c = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code} %{http_version}', '--http2-prior-knowledge', base + '/v1/health'],
                               capture_output=True, text=True, timeout=30)
            results.append(('HTTP/2 sin TLS hacia Lacre: se informa lo que ocurre (no es un requisito de Lacre que lo hable)', True, f'curl: {c.stdout.strip() or c.stderr.strip()[:80]} (exit {c.returncode})'))
        # WebSocket inactivo detrás de un intermediario con tiempo de lectura corto
        import websockets
        port = free_port(); p = start(['nginx', '-c', nginx_conf(port, sp, read_timeout='3s'), '-p', TMP], f'nginx{port}'); wait_port(port)

        async def idle():
            async with websockets.connect(f'ws://127.0.0.1:{port}/v1/ws', ping_interval=None) as w:
                t = time.time()
                try:
                    await asyncio.wait_for(w.recv(), timeout=10)
                    return 'recibió algo', time.time() - t
                except websockets.ConnectionClosed:
                    return 'cerrada por el intermediario', time.time() - t
                except asyncio.TimeoutError:
                    return 'sigue abierta', time.time() - t

        what, dt = asyncio.run(idle())
        results.append(('WebSocket inactivo con proxy_read_timeout 3 s: el intermediario la corta y el cliente lo nota al instante', what == 'cerrada por el intermediario', f'{what} a los {dt:.1f} s'))

        async def reconnect():
            async with websockets.connect(f'ws://127.0.0.1:{port}/v1/ws') as w:
                await w.send(json.dumps({'kind': 'seal', 'payload': {'profile': 'core', 'payload_hex': '00'}}))
                try:
                    m = await asyncio.wait_for(w.recv(), timeout=10)
                    return json.loads(m).get('kind') == 'seal_response', str(m)[:60]
                except Exception as e:
                    return False, repr(e)[:80]
        ok, m = asyncio.run(reconnect())
        results.append(('tras el corte, una conexión nueva por el mismo intermediario responde', ok, m))
        stop(p)

        # P4: con LACRE_WS_PING_SECS=1 el mismo caso (inactiva 10 s, corte a los 3 s) ya no se corta
        sp2 = free_port(); srv2 = spawn_server(server, sp2, {'LACRE_WS_PING_SECS': '1'})
        port2 = free_port(); p2 = start(['nginx', '-c', nginx_conf(port2, sp2, read_timeout='3s'), '-p', TMP], f'nginx{port2}'); wait_port(port2)

        async def idle_ping():
            async with websockets.connect(f'ws://127.0.0.1:{port2}/v1/ws', ping_interval=None) as w:
                t = time.time()
                try:
                    await asyncio.wait_for(w.recv(), timeout=10)
                    return 'recibió algo', time.time() - t
                except websockets.ConnectionClosed:
                    return 'cerrada por el intermediario', time.time() - t
                except asyncio.TimeoutError:
                    # sigue abierta: comprueba que además responde
                    await w.send(json.dumps({'kind': 'seal', 'payload': {'profile': 'core', 'payload_hex': '00'}}))
                    m = await asyncio.wait_for(w.recv(), timeout=10)
                    return ('sigue abierta y responde' if json.loads(m).get('kind') == 'seal_response' else 'abierta pero respuesta rara'), time.time() - t

        what2, dt2 = asyncio.run(idle_ping())
        results.append(('WebSocket inactivo 10 s con proxy_read_timeout 3 s y LACRE_WS_PING_SECS=1 (P4): no se corta y sigue respondiendo', what2 == 'sigue abierta y responde', f'{what2} a los {dt2:.1f} s'))
        stop(p2); stop(srv2)
        stop(p)
    finally:
        stop(srv)
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--server', required=True, help='ruta al binario lacre-server')
    ap.add_argument('--only', nargs='*', help='nombres de escenarios a correr')
    ap.add_argument('--no-controls', action='store_true')
    ap.add_argument('--slow', action='store_true', help='la suite corre con --slow (payload de 20 MB y expiración de ≈70 s) en cada escenario')
    ap.add_argument('--json', help='guarda el resultado en este fichero')
    a = ap.parse_args()
    for tool in ('nginx', 'haproxy', 'mitmdump', 'openssl'):
        if not shutil.which(tool):
            sys.exit(f'falta {tool}')
    tls = make_cert()
    out = {'scenarios': [], 'controls': []}
    try:
        for name, desc, fn in SCENARIOS:
            if a.only and name not in a.only:
                continue
            print(f'== {name}: {desc}', flush=True)
            r = run_scenario(a.server, name, fn, tls, slow=a.slow)
            r['desc'] = desc
            out['scenarios'].append(r)
            print(f"   total {r['total']} pass {r['pass_']} fail {r['fail']} ({r['seconds']} s)", flush=True)
            if r['probe'] or True:
                print('   en el camino:', json.dumps(r['probe'], ensure_ascii=False), flush=True)
            for f in r['failures'][:6]:
                print('     FAIL', f, flush=True)
            if r['error']:
                print('   ERROR', r['error'], flush=True)
        if not a.no_controls:
            for title, fn in (('alteración', lambda: control_tamper(a.server)), ('respuestas ajenas', lambda: control_foreign(a.server, tls)),
                              ('reintento duplicado', lambda: control_replay(a.server)),
                              ('sellado por partes (P2)', lambda: control_parts(a.server, tls)),
                              ('petición comprimida, h2 sin TLS, WebSocket inactivo', lambda: control_extra(a.server))):
                print(f'== control: {title}', flush=True)
                for name, ok, detail in fn():
                    out['controls'].append(dict(group=title, name=name, ok=ok, detail=detail))
                    print(('   PASS ' if ok else '   FAIL ') + name + ' | ' + detail, flush=True)
    finally:
        for p in list(PROCS):
            stop(p)
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1, ensure_ascii=False)
    bad = [c for c in out['controls'] if not c['ok']]
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()

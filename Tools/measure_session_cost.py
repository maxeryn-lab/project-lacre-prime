#!/usr/bin/env python3
"""Measure the resident-memory cost per live session of each session store, against the REAL server.
For every scenario a fresh `lacre-server --serve` is started, N sessions are opened over HTTP, and the growth of the
process RSS (/proc/<pid>/status VmRSS) is divided by N. Output is Markdown. Uses the binary found in
Code/workspace/target/{release,debug}/lacre-server (build it first); debug and release differ, the build is printed.
Usage: python3 Tools/measure_session_cost.py [--n 200]
Not evidence about production: a sandbox measurement of one build, to size a ceiling from a measured number."""
import json, os, secrets, subprocess, sys, time, urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
N = int(sys.argv[sys.argv.index('--n') + 1]) if '--n' in sys.argv else 200
PORT = 8097
BASE = 'http://127.0.0.1:%d' % PORT


def binary():
    for b in ('release', 'debug'):
        p = os.path.join(ROOT, 'Code/workspace/target', b, 'lacre-server')
        if os.path.exists(p):
            return p, b
    sys.exit('build lacre-server first (cargo build)')


def rss_kb(pid):
    for l in open('/proc/%d/status' % pid):
        if l.startswith('VmRSS:'):
            return int(l.split()[1])


def post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    try:
        return json.load(urllib.request.urlopen(req, timeout=10)), 200
    except urllib.error.HTTPError as e:
        return e.read().decode()[:200], e.code


def scenario(name, fn):
    exe, build = binary()
    env = dict(os.environ, LACRE_HTTP_ADDR='127.0.0.1:%d' % PORT)
    p = subprocess.Popen([exe, '--serve'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE + '/v1/health', timeout=1); break
            except Exception:
                time.sleep(0.1)
        time.sleep(0.3); base = rss_kb(p.pid); codes = {}
        for i in range(N):
            _, c = fn(i); codes[c] = codes.get(c, 0) + 1
        time.sleep(0.3); grown = rss_kb(p.pid) - base
        print('| %s | %d | %s | %d | %.1f |' % (name, N, ', '.join('%d×%d' % (k, v) for k, v in codes.items()), grown, grown / N))
    finally:
        p.kill(); p.wait()
    return build


print('| Escenario | Sesiones | Respuestas HTTP | Crecimiento RSS (KB) | KB por sesión |\n|---|---|---|---|---|')
b = scenario('handshake X25519', lambda i: post('/v1/handshake', {'client_public_key_hex': secrets.token_hex(32)}))
scenario('seal vault, payload 1 byte', lambda i: post('/v1/seal', {'profile': 'vault', 'payload_hex': '41'}))
scenario('seal vault, payload 64 KB', lambda i: post('/v1/seal', {'profile': 'vault', 'payload_hex': '41' * 65536}))
scenario('toolchain: episodio vacío', lambda i: post('/v1/toolchain/episodes', {'episode_id_hex': secrets.token_hex(16), 'algo': 'sha256', 'max_node_age_ms': 60000}))
print('\nBuild medido: %s. Fecha: %s.' % (b, time.strftime('%Y-%m-%d')))

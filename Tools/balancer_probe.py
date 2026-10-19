#!/usr/bin/env python3
"""Reintentos reales de un balanceador y tiempos de WebSocket inactivo, medidos y no emulados.

Parte A, reintentos. Entre el balanceador (nginx, haproxy) y lacre-server se pone un reenviador que ENTREGA
la petición a Lacre pero PIERDE la respuesta de una petición elegida (cierra la conexión sin contestar).
Con los reintentos automáticos activados, el balanceador vuelve a enviar la misma petición: Lacre la recibe
dos veces. Se recorre el flujo completo (open, tres partes, verify y ack de cada una) perdiendo, en cada
ejecución, la respuesta de una petición distinta, y se comprueba:
  - que el flujo termina bien y cada verify da all_verified: true;
  - que la petición llegó de verdad dos veces a Lacre (si no, la prueba no probaría nada);
  - control: con los reintentos desactivados el cliente ve el fallo.

Parte B, WebSocket. Un WebSocket inactivo detrás de nginx con su proxy_read_timeout por defecto (60 s) y
detrás de haproxy con `timeout tunnel 30s`, con el ping por defecto de Lacre (25 s) y con el ping
prácticamente desactivado (LACRE_WS_PING_SECS=3600).

Uso: python3 Tools/balancer_probe.py [--server RUTA] [--solo retries|ws]
"""
import argparse, asyncio, json, os, sys, textwrap, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import intermediaries as I  # noqa: E402
import requests  # noqa: E402

DEFAULT_SERVER = os.path.join(HERE, '..', 'Code', 'workspace', 'target', 'release', 'lacre-server')


# ---------------------------------------------------------------- reenviador que pierde respuestas
class Dropper:
    """Reenvía HTTP/1.1 a `upstream`. `drop` = {(ruta, n)}: no entrega la respuesta de la n-ésima petición a esa ruta
    (la petición sí llega a Lacre). `seen` cuenta lo que llegó a Lacre por ruta."""

    def __init__(self, upstream):
        self.upstream, self.drop, self.seen, self.dropped = upstream, set(), {}, []
        self.port = I.free_port()
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        srv = self.loop.run_until_complete(asyncio.start_server(self._conn, '127.0.0.1', self.port))
        self.ready.set()
        self.loop.run_forever(); srv.close()

    @staticmethod
    async def _read_msg(r):
        head = await r.readuntil(b'\r\n\r\n')
        lines = head.decode('latin1').split('\r\n')
        n = 0
        for ln in lines[1:]:
            if ln.lower().startswith('content-length:'):
                n = int(ln.split(':', 1)[1])
        return head, (await r.readexactly(n) if n else b''), lines[0]

    async def _conn(self, cr, cw):
        try:
            while True:
                head, body, first = await self._read_msg(cr)
                path = first.split(' ')[1]
                self.seen[path] = k = self.seen.get(path, 0) + 1
                ur, uw = await asyncio.open_connection('127.0.0.1', self.upstream)
                uw.write(head + body); await uw.drain()
                rh, rb, _ = await self._read_msg(ur)
                uw.close()
                if (path, k) in self.drop:
                    self.dropped.append((path, k))
                    cw.close(); return          # respuesta perdida
                cw.write(rh + rb); await cw.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            try:
                cw.close()
            except Exception:
                pass


# ---------------------------------------------------------------- configuraciones con reintentos
def nginx_retry_conf(listen, upstream, retry=True):
    nxt = 'proxy_next_upstream error timeout non_idempotent; proxy_next_upstream_tries 3;' if retry else 'proxy_next_upstream off;'
    conf = f"""
        daemon off; user root;
        pid {I.TMP}/nginx-{listen}.pid; error_log {I.TMP}/nginx-{listen}.err warn;
        events {{ worker_connections 64; }}
        http {{
          access_log off;
          client_body_temp_path {I.TMP}/nb-{listen}; proxy_temp_path {I.TMP}/np-{listen};
          fastcgi_temp_path {I.TMP}/nf-{listen}; uwsgi_temp_path {I.TMP}/nu-{listen}; scgi_temp_path {I.TMP}/ns-{listen};
          upstream lacre {{ server 127.0.0.1:{upstream}; server 127.0.0.1:{upstream}; }}
          server {{
            listen 127.0.0.1:{listen};
            location / {{ proxy_pass http://lacre; proxy_http_version 1.1; proxy_set_header Connection ""; {nxt} }}
          }}
        }}
    """
    path = os.path.join(I.TMP, f'nginx-retry-{listen}.conf'); open(path, 'w').write(textwrap.dedent(conf)); return path


def haproxy_retry_conf(listen, upstream, retry=True):
    r = ('retries 3\n          option redispatch\n          retry-on all-retryable-errors empty-response conn-failure response-timeout') if retry else 'retries 0'
    conf = f"""
        global
          maxconn 128
        defaults
          mode http
          timeout connect 2s
          timeout client 30s
          timeout server 30s
        frontend f
          bind 127.0.0.1:{listen}
          default_backend b
        backend b
          option http-buffer-request
          {r}
          server s 127.0.0.1:{upstream}
    """
    path = os.path.join(I.TMP, f'haproxy-retry-{listen}.cfg'); open(path, 'w').write(textwrap.dedent(conf)); return path


# ---------------------------------------------------------------- flujo y comprobación
STEPS = [('/v1/seal/open', 1), ('/v1/seal/part', 1), ('/v1/seal/part', 2), ('/v1/seal/part', 3),
         ('/v1/verify', 1), ('/v1/verify', 3), ('/v1/ack', 1), ('/v1/ack', 3)]


def flow(base, parts=3):
    """open + `parts` partes (la última con is_last) + verify + ack de cada una. Devuelve (ok, detalle)."""
    s = requests.Session()

    def post(path, body):
        return s.post(base + path, json=body, timeout=20)
    try:
        o = post('/v1/seal/open', {'profile': 'core'})
        if o.status_code != 200:
            return False, f'open {o.status_code}'
        o = o.json(); wt, vt, at = (o['capabilities'][k] for k in ('write', 'verify', 'ack')); sid = o['session_id']
        for i in range(parts):
            r = post('/v1/seal/part', {'session_id': sid, 'token': wt, 'part_index': i, 'payload_hex': os.urandom(3000).hex(), 'is_last': i == parts - 1})
            if r.status_code != 200:
                return False, f'parte {i}: {r.status_code} {r.text[:60]}'
            frames = r.json()['frames']
            v = post('/v1/verify', {'profile': 'core', 'session_id': sid, 'key_id': 0, 'frames': frames, 'token': vt})
            if v.status_code != 200 or v.json().get('all_verified') is not True:
                return False, f'verify {i}: {v.status_code} {v.text[:60]}'
            a = post('/v1/ack', {'session_id': sid, 'token': at, 'indices': [f['index'] for f in frames]})
            if a.status_code != 200:
                return False, f'ack {i}: {a.status_code} {a.text[:60]}'
        return True, 'flujo completo'
    except requests.RequestException as e:
        return False, f'error de red: {type(e).__name__}'


def retries(server):
    out = []
    sp = I.free_port(); srv = I.spawn_server(server, sp)
    try:
        for name, mk, start_cmd in (
                ('nginx', nginx_retry_conf, lambda c: ['nginx', '-c', c, '-p', I.TMP]),
                ('haproxy', haproxy_retry_conf, lambda c: ['haproxy', '-f', c, '-db'])):
            for retry in (True, False):
                for path, n in (STEPS if retry else STEPS[:1] + STEPS[2:3] + STEPS[4:5]):
                    d = Dropper(sp); d.drop = {(path, n)}
                    port = I.free_port(); p = I.start(start_cmd(mk(port, d.port, retry)), f'{name}{port}'); I.wait_port(port)
                    ok, det = flow(f'http://127.0.0.1:{port}')
                    # cuántas veces llegó a Lacre la petición cuya respuesta se perdió
                    arrived = d.seen.get(path, 0)
                    base_n = 3 if path in ('/v1/seal/part', '/v1/verify', '/v1/ack') else 1
                    dup = arrived - base_n
                    out.append(dict(balancer=name, retries=retry, lost=f'{path} #{n}', dropped=bool(d.dropped), ok=ok,
                                    extra_deliveries=dup, detail=det))
                    I.stop(p)
    finally:
        I.stop(srv)
    return out


# ---------------------------------------------------------------- WebSocket
def ws_idle(server, secs_idle, ping, kind):
    import websockets
    sp = I.free_port(); srv = I.spawn_server(server, sp, {'LACRE_WS_PING_SECS': str(ping)})
    port = I.free_port()
    if kind == 'nginx':
        p = I.start(['nginx', '-c', I.nginx_conf(port, sp, read_timeout='60s'), '-p', I.TMP], f'nginx{port}')
    else:
        p = I.start(['haproxy', '-f', _haproxy30(port, sp), '-db'], f'haproxy{port}')
    I.wait_port(port)

    async def run():
        async with websockets.connect(f'ws://127.0.0.1:{port}/v1/ws', ping_interval=None, close_timeout=2) as w:
            t = time.time()
            try:
                await asyncio.wait_for(w.recv(), timeout=secs_idle)
                return 'recibió un mensaje de datos', time.time() - t
            except websockets.ConnectionClosed:
                return 'cortada por el intermediario', time.time() - t
            except asyncio.TimeoutError:
                await w.send(json.dumps({'kind': 'seal', 'payload': {'profile': 'core', 'payload_hex': '00'}}))
                m = await asyncio.wait_for(w.recv(), timeout=10)
                return ('sigue abierta y responde' if json.loads(m).get('kind') == 'seal_response' else 'abierta, respuesta rara'), time.time() - t
    try:
        return asyncio.run(run())
    finally:
        I.stop(p); I.stop(srv)


def _haproxy30(listen, upstream):
    conf = f"""
        global
          maxconn 128
        defaults
          mode http
          timeout connect 5s
          timeout client 30s
          timeout server 30s
          timeout tunnel 30s
        frontend f
          bind 127.0.0.1:{listen}
          default_backend b
        backend b
          server s 127.0.0.1:{upstream}
    """
    path = os.path.join(I.TMP, f'haproxy-ws-{listen}.cfg'); open(path, 'w').write(textwrap.dedent(conf)); return path


def ws(server):
    cases = [('nginx (proxy_read_timeout 60 s, su valor por defecto)', 'nginx', 75, 25, 'ping por defecto (25 s)'),
             ('nginx (proxy_read_timeout 60 s, su valor por defecto)', 'nginx', 75, 3600, 'ping casi desactivado'),
             ('haproxy (timeout tunnel 30 s)', 'haproxy', 45, 25, 'ping por defecto (25 s)'),
             ('haproxy (timeout tunnel 30 s)', 'haproxy', 45, 3600, 'ping casi desactivado')]
    res = [None] * len(cases)

    def go(i):
        c = cases[i]; res[i] = ws_idle(server, c[2], c[3], c[1])
    th = [threading.Thread(target=go, args=(i,)) for i in range(len(cases))]
    [t.start() for t in th]; [t.join() for t in th]
    return [dict(intermediary=c[0], idle_s=c[2], ping=c[4], result=r[0], at_s=round(r[1], 1)) for c, r in zip(cases, res)]


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--server', default=DEFAULT_SERVER)
    ap.add_argument('--solo', choices=['retries', 'ws'])
    a = ap.parse_args()
    out = {}
    try:
        if a.solo in (None, 'retries'):
            out['retries'] = retries(a.server)
        if a.solo in (None, 'ws'):
            out['ws'] = ws(a.server)
    finally:
        for pr in list(I.PROCS):
            I.stop(pr)
    print(json.dumps(out, indent=1, ensure_ascii=False))

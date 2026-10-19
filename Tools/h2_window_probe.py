"""Reproduce, sin httpx, las esperas de haproxy con HTTP/2 y cuerpos grandes (ver LACRE-WIRE-v2.md §11).
Cliente h2 mínimo que escribe una trama por escritura y cierra con una trama vacía aparte (el patrón de httpcore),
frente a haproxy con distintos ajustes. Uso: python3 Tools/h2_window_probe.py   (necesita haproxy y el binario release de lacre-server)."""
import importlib.util, os, sys, socket, time, json
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('I', os.path.join(HERE, 'intermediaries.py'))
I = importlib.util.module_from_spec(spec); sys.argv = ['x']; spec.loader.exec_module(I)
import h2.connection, h2.config, h2.events
SERVER = os.environ.get('LACRE_SERVER') or os.path.join(os.path.dirname(HERE), 'Code/workspace/target/release/lacre-server')
BODY = json.dumps({'session_id': '00' * 16, 'token': 'x', 'part_index': 0, 'payload_hex': os.urandom(200 * 1024).hex(), 'is_last': False}).encode()


def run(port, mode, nodelay, n=8):
    s = socket.create_connection(('127.0.0.1', port)); s.settimeout(10)
    if nodelay:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True)); c.initiate_connection(); s.sendall(c.data_to_send())
    times = []
    for _ in range(n):
        sid = c.get_next_available_stream_id()
        c.send_headers(sid, [(':method', 'POST'), (':path', '/v1/seal/part'), (':scheme', 'http'), (':authority', 'x'),
                             ('content-type', 'application/json'), ('content-length', str(len(BODY)))])
        s.sendall(c.data_to_send())
        t0 = time.perf_counter(); sent = 0; ended = False; done = False
        while not done:
            if mode == 'httpcore':
                # una escritura por trama; END_STREAM como trama vacía aparte; lee solo con ventana 0 o al terminar
                while sent < len(BODY):
                    room = min(c.local_flow_control_window(sid), c.max_outbound_frame_size, len(BODY) - sent)
                    if room <= 0:
                        break
                    c.send_data(sid, BODY[sent:sent + room]); sent += room; s.sendall(c.data_to_send())
                if sent == len(BODY) and not ended:
                    c.end_stream(sid); s.sendall(c.data_to_send()); ended = True
            else:
                while sent < len(BODY):
                    room = min(c.local_flow_control_window(sid), c.max_outbound_frame_size, len(BODY) - sent)
                    if room <= 0:
                        break
                    c.send_data(sid, BODY[sent:sent + room], end_stream=(sent + room == len(BODY))); sent += room
                s.sendall(c.data_to_send())
            data = s.recv(65536)
            if not data:
                break
            for ev in c.receive_data(data):
                if isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                    done = True
            s.sendall(c.data_to_send())
        times.append(round((time.perf_counter() - t0) * 1000, 1))
    print(f'{mode:9s} nodelay={nodelay!s:5s} {times}')


def stalls(h, n=24):
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run(h, 'httpcore', True, n)
    ts = json.loads(buf.getvalue().split('] ')[0].split('True ')[1] + ']') if False else eval(buf.getvalue().split('nodelay=True ')[1])
    return sum(1 for t in ts if t > 30), round(sum(ts) / len(ts), 1), max(ts)

sp = I.free_port(); I.spawn_server(SERVER, sp)
try:
    for label, glob in (('defecto', ''), ('tune.rcvbuf.client 4 MiB', 'tune.rcvbuf.client 4194304'),
                        ('tune.h2.initial-window-size 1 MiB', 'tune.h2.initial-window-size 1048576'),
                        ('rcvbuf 4MiB + ventana 1MiB', 'tune.rcvbuf.client 4194304\n          tune.h2.initial-window-size 1048576'),
                        ('tune.h2.be.* / fe.initial-window 256K', 'tune.h2.fe.initial-window-size 262144')):
        for rep in range(2):
            h = I.free_port(); path = I.haproxy_conf(h, sp)
            cfg = open(path).read().replace(f'bind 127.0.0.1:{h}', f'bind 127.0.0.1:{h} proto h2').replace('maxconn 512', 'maxconn 512\n          ' + glob, 1)
            open(path, 'w').write(cfg)
            pr = I.start(['haproxy', '-f', path, '-db'], f'h{h}'); I.wait_port(h)
            try:
                st = stalls(h)
                print(f'{label:42s} esperas>30ms: {st[0]:2d}/24  media {st[1]:6.1f} ms  máx {st[2]:6.1f} ms', flush=True)
            except Exception as e:
                print(f'{label:42s} error {e!r}'[:120], flush=True)
            I.stop(pr)
finally:
    for p in list(I.PROCS):
        I.stop(p)

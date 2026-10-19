#!/usr/bin/env python3
"""Huella de todos los archivos de lacre-core/ (y del Cargo.toml del workspace de producción).
Sirve para probar de forma mecánica que añadir un algoritmo de un tercero (E6) no toca el Núcleo.
Uso: python3 Tools/core_hash.py [--save RUTA | --compare RUTA]"""
import hashlib, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W = os.path.join(ROOT, 'Code/workspace')
def manifest():
    rows = []
    for base, dirs, files in os.walk(os.path.join(W, 'lacre-core')):
        dirs[:] = sorted(d for d in dirs if d != 'target')
        for f in sorted(files):
            p = os.path.join(base, f)
            rows.append((os.path.relpath(p, W), hashlib.sha256(open(p, 'rb').read()).hexdigest()))
    for extra in ('Cargo.toml',):
        p = os.path.join(W, extra)
        rows.append((extra, hashlib.sha256(open(p, 'rb').read()).hexdigest()))
    rows.sort()
    total = hashlib.sha256(''.join(f'{h}  {n}\n' for n, h in rows).encode()).hexdigest()
    return rows, total
rows, total = manifest()
text = ''.join(f'{h}  {n}\n' for n, h in rows) + f'TOTAL {total} ({len(rows)} archivos)\n'
if len(sys.argv) > 2 and sys.argv[1] == '--save':
    open(sys.argv[2], 'w').write(text); print(f'guardado: {len(rows)} archivos, TOTAL {total}')
elif len(sys.argv) > 2 and sys.argv[1] == '--compare':
    old = open(sys.argv[2]).read()
    if old == text: print(f'IDÉNTICO: {len(rows)} archivos, TOTAL {total}')
    else:
        print('DIFERENTE'); 
        a = dict(l.split('  ', 1)[::-1] for l in old.splitlines() if '  ' in l)
        b = dict(l.split('  ', 1)[::-1] for l in text.splitlines() if '  ' in l)
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k): print('  cambió:', k)
        sys.exit(1)
else:
    print(text, end='')

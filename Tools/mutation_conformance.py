#!/usr/bin/env python3
"""E2: mutaciones sobre la propia suite de conformidad (lacre-seal-conformance).
Cada mutante desactiva un chequeo (lo vuelve vacuo); los controles de tests/controls.rs deben
detectarlo. Clase 'kill' = debe morir. Clase 'core' = el chequeo verifica una garantía del Núcleo
(no de un algoritmo): ningún algoritmo defectuoso puede hacerla fallar, así que su 'negativo'
real es la mutation_suite del Núcleo (E1); se reportan aparte y NO cuentan como muertos.
Restaura siempre los archivos; no ejecutar junto a otra herramienta que compile el workspace."""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
C = 'lacre-seal-conformance/src/checks.rs'
R = 'lacre-seal-conformance/src/report.rs'
def T(a, b=None, f=C, cls='kill', name=''):
    return (f, a, b if b is not None else a.replace('ensure(', 'ensure(true || ', 1), name, cls)
MUTS = [
 T('ensure(got == kat.expected, ||', name='vectores: no se compara el resultado'),
 T('ensure(k >= 1, ||', name='vectores: ya no se exige al menos uno'),
 T('ensure(kat.key.len() == m.key_len(), ||', name='vectores: no se valida largo de clave'),
 T('ensure(ok_len, ||', name='vectores: no se valida largo del tag'),
 T('ensure(a == b, || {\n                    format!("tag depends', name='largos: buffer relleno 0xAA/0x55 no se compara'),
 T('ensure(t1 == t2, ||', name='largos: determinismo'),
 T('ensure(!seen.contains(&t1), ||', name='largos: fragmentos distintos colisionan'),
 T('if n % p == 0 && t.chunks(p)', 'if false && n % p == 0 && t.chunks(p)', name='largos: periodicidad'),
 T('ensure(t[n - 8..].iter().any(|&b| b != 0), ||', name='largos: relleno de ceros'),
 T('ensure(tag(m.as_ref(), &k, &frag, &st, n) != base, ||', name='sensibilidad: bits de clave'),
 T('ensure(tag(m.as_ref(), &key, &f, &st, n) != base, || {\n                    format!("flipping fragment bit', name='sensibilidad: bits de fragmento'),
 T('ensure(tag(m.as_ref(), &key, &frag, &s, n) != base, ||', name='sensibilidad: bits de estado'),
 T('ensure(tag(m.as_ref(), &key, &f, &st, n) != base, || {\n                    format!("byte {pos} of a 1 KiB', name='sensibilidad: bytes de 1 KiB'),
 T('ensure(tag(m.as_ref(), &key, &f, &st, n) != base, || {\n                format!("byte {pos} of a 64 KiB', name='sensibilidad: bytes de 64 KiB'),
 T('ensure(a[n - 8..] != b[n - 8..], ||', name='sensibilidad: cola del tag'),
 T('ensure(z != f, ||', name='robustez: claves degeneradas'),
 T('ensure(tag(m.as_ref(), &key, &[], &st, n) != tag(m.as_ref(), &key, &[0], &st, n), ||', name='robustez: vacío vs [0]'),
 T('ensure(a1 == a2 && b1 == b2, ||', name='sin estado: llamadas intercaladas'),
 T('ensure(!bad, ||', 'ensure(true, ||', name='sin estado: hilos'),
 T('let failure = match catch_unwind(AssertUnwindSafe(f)) {', 'let failure = match Ok::<_, Box<dyn std::any::Any + Send>>(f()) {', name='runner: no captura pánicos'),
 T('ensure(avg <= budget, ||', name='coste: tiempo vs clase'),
 T('ensure(a.iter().zip(&b).all(|(x, y)| x.1 == y.1), ||', name='lentitud: mismas etiquetas con retraso'),
 T('ensure(ta != tb, ||', name='cruce: alias bajo otro id'),
 T('ensure(a1.id() != b1.id(), ||', name='cruce: ids distintos'),
 T('ensure(unique, ||', name='catálogo: ids únicos'),
 T('!self.checks.is_empty() && self.failures().is_empty()', 'self.failures().is_empty()', f=R, name='informe vacío cuenta como aprobado'),
 T('ensure(v.next_expected_index() == 5, ||', cls='core', name='viaje: el verificador avanza'),
 T('ensure(a1 == a2, || "same session and payload', name='viaje: determinismo por sesión'),
 T('ensure(mismatch(v.verify_frame(&f, key_id, &t)), || {\n                    format!("tampering not rejected', name='viaje: manipulaciones rechazadas'),
 # --- garantías del Núcleo vistas con el candidato enchufado ---
 T('Ok(_) => Err(format!("params {} were accepted", hex(&p))),', 'Ok(_) => Ok(()),', cls='core', name='parámetros: el Núcleo rechaza parámetros no permitidos'),
 T('ensure(s.tag_len() == n,', cls='core', name='parámetros: extremos aceptados'),
 T('ensure(matches!(v.verify_frame(&f, key_id, &t), Err(CoreError::SealMismatch)), || {\n            "a verifier with another', cls='core', name='parámetros: largo de tag ligado a la sesión'),
 T('ensure(\n                matches!(v.verify_frame(&frames[1].0', cls='core', name='viaje: reordenamiento'),
 T('ensure(\n                matches!(v.verify_frame(&frames[0].0', cls='core', name='viaje: replay'),
 T('ensure(v.verify_frame_signed(&f, key_id, &t, None).is_err(), || {\n                "a verifier whose descriptor', cls='core', name='viaje: firma declarada ligada a la suite'),
 T('ensure(s.seal_chunk(pat(16, 3), true).is_err(), ||', cls='core', name='lentitud: tope de buffer'),
 T('ensure(purged >= 1 && s.pending_count() == 0, ||', cls='core', name='lentitud: purga forzada'),
 T('ensure(mismatch(v.verify_frame(&f, key_id, &t)), || "frame sealed under A', cls='core', name='cruce: sesión de A rechazada por B'),
]
def main():
    only = set(sys.argv[1:]); res = {'kill': [0, 0], 'core': [0, 0]}
    for i, (f, a, b, name, cls) in enumerate(MUTS, 1):
        tag = f'C{i:02d}'
        if only and tag not in only: continue
        s = open(f).read()
        if s.count(a) < 1:
            print(f'{tag}: NO APLICA — {name}', flush=True); res[cls][1] += 1; continue
        res[cls][1] += 1
        open(f, 'w').write(s.replace(a, b, 1))
        try:
            r = subprocess.run(['cargo', 'test', '-p', 'lacre-seal-conformance', '--test', 'controls'], capture_output=True, text=True, timeout=290)
            dead = r.returncode != 0
        finally:
            open(f, 'w').write(s)
        res[cls][0] += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} [{cls}] — {name}', flush=True)
    print(f'Mutantes de la suite muertos: {res["kill"][0]}/{res["kill"][1]}')
    print(f'Garantías del Núcleo (clase core): muertos {res["core"][0]}/{res["core"][1]} (supervivientes esperados)')
main()

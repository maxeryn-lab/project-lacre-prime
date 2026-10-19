#!/usr/bin/env python3
"""E4 (wire v2 en el servidor): mutaciones sobre reglas de versión, política, cuarentena, orden de
validación, admisión, plazo, bloqueo por sesión y contención de pánicos.
Restaura siempre los archivos; no ejecutar junto a otra herramienta que compile el workspace.
Uso: python3 Tools/mutation_wire_v2.py [M01 M02 ...]"""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
V, P, D = 'lacre-domain/src/version.rs', 'lacre-domain/src/seal_policy.rs', 'lacre-domain/src/domain.rs'
A, X, ST = 'lacre-domain/src/admission.rs', 'lacre-adapter-declarative/src/lib.rs', 'lacre-domain/src/verifier_session_store.rs'
# (archivo, buscar, reemplazar, nombre) — se reemplazan TODAS las apariciones
MUTS = [
 (V, 'Some(v) if !accepted.contains(&v) =>', 'Some(v) if false =>', 'una versión fuera del conjunto aceptado pasa'),
 (V, 'Some(1) => {\n            if has_suite {', 'Some(1) => {\n            if false {', 'suite bajo version 1 aceptada'),
 (V, 'Some(2) => {\n            if !has_suite {', 'Some(2) => {\n            if false {', 'version 2 sin suite aceptada'),
 (V, 'None => {\n            if has_suite {', 'None => {\n            if false {', 'suite sin version aceptada'),
 (V, 'if !r.allow_implicit_version() {', 'if false {', 'la política no puede exigir version explícita'),
 (P, 'if mac.status() == Status::Legacy && !self.policy.allow_legacy {', 'if false {', 'un algoritmo legacy pasa sin allow_legacy'),
 (P, 'if check_quarantine && self.is_quarantined(&wire.seal) {', 'if false {', 'la cuarentena no se aplica'),
 (P, 'if check_quarantine && self.is_quarantined(&wire.seal) {', 'if self.is_quarantined(&wire.seal) && false || !check_quarantine && false {', 'la cuarentena no se aplica (otra forma)'),
 (P, 'if !entry.profiles.contains(&profile) {', 'if false {', 'la política no distingue perfiles'),
 (P, 'if n < lo || n > hi {', 'if n < lo {', 'el rango de tag de la política no tiene máximo'),
 (P, 'if n < lo || n > hi {', 'if n > hi {', 'el rango de tag de la política no tiene mínimo'),
 (P, 'if cost_rank(mac.cost()) > entry.max_cost {', 'if false {', 'el coste máximo de la política no se aplica'),
 (P, '(false, Some(_)) => {', '(false, Some(_)) if false => {', 'un esquema de firma fuera de vault se acepta (era: firma no nula antes de E5)'),
 (P, 'if n >= limit {', 'if n > limit {', 'la cuarentena por pánicos llega un pánico tarde'),
 (P, 'let Some(limit) = self.policy.quarantine_after_panics else { return false };', 'let limit = self.policy.quarantine_after_panics.unwrap_or(1);', 'cuarentena automática sin que la política la pida'),
 (D, 'let signing = profile.requires_vault_signature();', 'let signing = false;', 'vault v2 no firma (era: vault acepta version 2)'),
 (D, '            runtime.record_panic(&suite_wire.seal);\n', '', 'un pánico del algoritmo no cuenta para la cuarentena'),
 (D, 'state.verifier_sessions().fail_session(&session_id);\n                return Err(DomainError::Forbidden(why));', 'return Err(DomainError::Forbidden(why));', 'cuarentena en modo close no cierra la sesión'),
 (D, 'if state.verifier_sessions().has_live(&session_id) {', 'if true {', 'drain reabre sesiones que no estaban abiertas'),
 (D, '(lacre_core::suite::CostClass::Heavy, Some(gate))', '(lacre_core::suite::CostClass::Light, Some(gate))', 'la admisión de coste alto no se aplica'),
 (D, 'Err(_) => {\n            runtime.record_panic', 'Err(e) => {\n            std::panic::resume_unwind(e);\n            #[allow(unreachable_code)]\n            runtime.record_panic', 'el pánico del algoritmo en seal no se contiene'),
 (D, 'DomainError::Internal("internal error while sealing".to_string())', 'DomainError::Internal(format!("panic: {:?}", suite_wire))', 'el 500 de seal revela detalles'),
 (D, 'let resolved = runtime.resolve(suite_wire, profile)?;\n    let signing', 'let resolved = runtime.resolve_draining(suite_wire, profile)?;\n    let signing', 'seal v2 ignora la cuarentena (antes: no consultaba la política; esa forma ya no compila)'),
 (ST, 'StoredCore::V2(core) if core.suite().suite_hash() == &suite_hash =>', 'StoredCore::V2(core) =>', 'una sesión v2 acepta otra suite'),
 (ST, 'StoredCore::V2(_) => Err(WithVerifierError::WrongVersion),', 'StoredCore::V2(_) => Err(WithVerifierError::AtCapacity),', 'v1 sobre sesión v2 no se distingue'),
 (ST, '*slot = Slot::Failed { failed_at: Instant::now() };', '', 'una sesión con pánico no queda cerrada'),
 (ST, 'Slot::Failed { .. } => return Err(WithVerifierError::SessionFailed),', 'Slot::Failed { .. } => return Err(WithVerifierError::AtCapacity),', 'sesión fallida no se distingue'),
 (A, '(n < max).then_some(n + 1)', '(n <= max).then_some(n + 1)', 'la admisión deja pasar uno más del límite'),
 (A, 'counter.fetch_sub(1, Ordering::AcqRel);', 'counter.fetch_sub(0, Ordering::AcqRel);', 'el permiso no libera su sitio'),
 (X, '        let _permit = permit; // released', '        drop(permit); // released', 'el permiso se libera antes de que acabe el cálculo'),
 (X, 'match state.request_deadline() {', 'match None::<std::time::Duration> {', 'el plazo configurado se ignora'),
 (X, 'Some(gate) => Some(gate.try_admit()?),', 'Some(_) => None,', 'la admisión opcional no se aplica'),
 (P, '            self.emit(format!(\n                "seal policy: algorithm `{id}` entered quarantine', '            let _ = (format!(\n                "seal policy: algorithm `{id}` entered quarantine', 'la entrada en cuarentena no se registra en el log'),
 (P, 'self.emit(format!("seal policy: algorithm `{id}` put into quarantine by operator order"));', '', 'la orden de cuarentena del operador no se registra'),
 (X, 'tokio::task::spawn_blocking(move ||', 'std::future::ready((move ||', 'Seal/Verify corren en el hilo async'),
]
# Equivalentes demostrados: `SealRuntime::new` rechaza al cargar una entrada legacy sin `allow_legacy` y una entrada
# cuyo coste supera su `max_cost`, así que el chequeo equivalente en `resolve` es defensa redundante e inalcanzable.
EQUIVALENT = {'M06': 'la política no carga con legacy sin allow_legacy', 'M12': 'la política no carga si el coste supera max_cost'}

def main():
    only = set(sys.argv[1:]); killed = total = 0
    for i, (f, a, b, name) in enumerate(MUTS, 1):
        tag = f'M{i:02d}'
        if only and tag not in only: continue
        s = open(f).read()
        if a not in s:
            print(f'{tag}: NO APLICA — {name}', flush=True); continue
        total += 1
        open(f, 'w').write(s.replace(a, b))
        try:
            r = subprocess.run(['cargo', 'test', '-p', 'lacre-domain', '-p', 'lacre-adapter-declarative', '-p', 'lacre-server'],
                               capture_output=True, text=True, timeout=590)
            dead = r.returncode != 0
        except subprocess.TimeoutExpired:
            dead = True   # se colgó: lo detecta el plazo, cuenta como muerto
        finally:
            open(f, 'w').write(s)
        if not dead and tag in EQUIVALENT:
            total -= 1
            print(f'{tag}: EQUIVALENTE ({EQUIVALENT[tag]}) — {name}', flush=True); continue
        killed += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} — {name}', flush=True)
    print(f'Mutantes muertos: {killed}/{total}')
main()

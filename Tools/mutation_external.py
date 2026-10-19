#!/usr/bin/env python3
"""Valida la suite externa con MUTANTES: «una suite que no falla cuando el
código está roto no prueba nada».

Para cada mutante: copia el workspace Rust a un directorio temporal, aplica
UN defecto deliberado (cadena exacta → cadena rota, debe aparecer una sola
vez), compila el servidor en release y ejecuta `external_suite.py`. El
mutante está «MUERTO» (bien) si la suite sale con código 1 (algún FAIL), y
«SUPERVIVIENTE» (mal: punto ciego de la suite) si sale 0.
Además comprueba el control: el código sin mutar debe salir 0.

Uso:  python3 mutation_external.py [--workspace RUTA] [--only M1,M3] [--json out.json]
Coste: una compilación release por mutante (≈15–60 s cada una tras la primera).
El árbol real NO se modifica.
"""
import argparse, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITE = HERE / 'external_suite.py'

# id, descripción, fichero (relativo al workspace), antiguo, nuevo
MUTANTS = [
    ('M1', 'Toolchain: una verificación fallida vuelve a contaminar el episodio',
     'lacre-profiles/src/toolchain.rs',
     "            } else {\n                resolved.insert(current.clone(), None);\n                if first_failure.is_none() {\n                    first_failure = Some(current);\n                }\n            }\n        }",
     "            } else {\n                self.taint_and_cascade(&current);\n                resolved.insert(current.clone(), None);\n                if first_failure.is_none() {\n                    first_failure = Some(current);\n                }\n            }\n        }"),
    ('M2', 'Toolchain: la comparación de sello siempre da «coincide»',
     'lacre-profiles/src/toolchain.rs',
     "            if matches {\n                // A node that verifies successfully",
     "            if matches || true {\n                // A node that verifies successfully"),
    ('M3', 'Core: se salta la comprobación de orden/secuencia',
     'lacre-core/src/core.rs',
     "if frame.index != self.next_index {\n            return Err(CoreError::OutOfSequence {",
     "if false && frame.index != self.next_index {\n            return Err(CoreError::OutOfSequence {"),
    ('M4', 'Core: se salta la comprobación del sello',
     'lacre-core/src/core.rs',
     "if !verify_fragment(self.algo, key, &frame.payload, &self.state.0, seal) {\n            return Err(CoreError::SealMismatch);",
     "if false {\n            return Err(CoreError::SealMismatch);"),
    ('M5', 'Vault: una firma ausente/incorrecta se acepta',
     'lacre-core/src/core.rs',
     "_ => return Err(CoreError::VaultSignatureMismatch),",
     "_ => {}"),
    ('M6', 'Dominio: verify con 0 frames vuelve a ser «verdad vacía»',
     'lacre-domain/src/domain.rs',
     "if req.frames.is_empty() {",
     "if false && req.frames.is_empty() {"),
    ('M7', 'Core: cambia la constante de dominio HKDF (deriva de clave distinta)',
     'lacre-core/src/session.rs',
     "lacre-core/v1/session-key",
     "lacre-core/v1/session-kez"),
    ('M8', 'Auth: ack ya no exige el token ack (ataque 3 reabierto)',
     'lacre-domain/src/domain.rs',
     "    require(state, Scope::Ack, &session_id, req.token.as_deref())?;\n",
     "    let _ = Scope::Ack;\n"),
    ('M9', 'Auth: añadir nodos Toolchain ya no exige token write (ataque 2 reabierto)',
     'lacre-domain/src/domain.rs',
     "    require(state, Scope::Write, &session_id, req.token.as_deref())?;\n    let content = hex::decode(&req.content_hex)",
     "    let content = hex::decode(&req.content_hex)"),
    ('M10', 'Auth: verify de frames ya no exige token verify',
     'lacre-domain/src/domain.rs',
     "    require(state, Scope::Verify, &session_id, req.token.as_deref())?;\n\n    // A4",
     "    // A4"),
    ('M11', 'Auth: los recibos ya no exigen token',
     'lacre-domain/src/domain.rs',
     "    require(state, Scope::Write, &session_id, token)?;\n",
     "    let _ = token;\n"),
    ('M12', 'Auth: continuar una sesión de handshake ya no exige token write',
     'lacre-domain/src/domain.rs',
     "            require(state, Scope::Write, &session_id, req.token.as_deref())?;\n            let ring",
     "            let ring"),
    ('M13', 'Auth: el alcance deja de entrar en el HMAC (write == verify == ack)',
     'lacre-domain/src/capability.rs',
     "        mac.update(scope.label());\n",
     "        let _ = scope.label();\n"),
    ('M14', 'Auth: la sesión deja de entrar en el HMAC (un token sirve en cualquier sesión)',
     'lacre-domain/src/capability.rs',
     "        mac.update(session_id);\n",
     "        let _ = session_id;\n"),
    ('M15', 'Auth: la comparación acepta cualquier token que empiece por el mismo byte',
     'lacre-domain/src/capability.rs',
     "bytes.len() == 32 && bool::from(expected.ct_eq(&bytes[..]))",
     "!bytes.is_empty() && expected[0] == bytes[0]"),
    ('M16', 'Auth: se quita el límite de verificaciones fallidas de Toolchain',
     'lacre-domain/src/domain.rs',
     "if episode.failed_verifications() >= MAX_FAILED_TOOLCHAIN_VERIFICATIONS {",
     "if false && episode.failed_verifications() >= MAX_FAILED_TOOLCHAIN_VERIFICATIONS {"),
    ('M17', 'Auth: un token ausente se acepta si la sesión no existe (oráculo de existencia)',
     'lacre-domain/src/capability.rs',
     "let Some(p) = presented_hex else { return false };",
     "let Some(p) = presented_hex else { return session_id[0] == 0 };"),
    ('M18', 'Dominio: el token del cuerpo se ignora y solo vale la cabecera (el HTTP sigue, el WS se rompe)',
     'lacre-adapter-declarative/src/lib.rs',
     "let token = payload.get(\"token\").and_then(|v| v.as_str()).map(str::to_string);",
     "let token: Option<String> = None;"),
    ('M19', 'Reglas: un rechazo del Rule Engine se informa como «passed»',
     'lacre-domain/src/rulesets.rs',
     'Evaluation { outcome: "rejected", failing_rule_id: Some(failing_rule_id) }',
     'Evaluation { outcome: "passed", failing_rule_id: Some(failing_rule_id) }'),
    ('M20', 'Reglas: sellar ignora el rechazo del conjunto de reglas',
     'lacre-domain/src/domain.rs',
     "        if !proceeds {\n            return Err(DomainError::Unprocessable(format!(\n                \"payload not sealed",
     "        if false && !proceeds {\n            return Err(DomainError::Unprocessable(format!(\n                \"payload not sealed"),
    ('M21', 'Reglas: verify libera el payload aunque el conjunto de reglas lo rechace',
     'lacre-domain/src/domain.rs',
     "                if proceeds {\n                    payload_hex = Some(hex::encode(&payload));",
     "                if proceeds || true {\n                    payload_hex = Some(hex::encode(&payload));"),
    ('M22', 'Taxonomía: se pierde el diagnóstico de reenvíos',
     'lacre-domain/src/domain.rs',
     "if received < expected =>",
     "if false && received < expected =>"),
    ('M23', 'Reensamblado: nunca devuelve el payload',
     'lacre-domain/src/domain.rs',
     "reassembly.as_mut().and_then(|r| r.try_reassemble())",
     "None::<Vec<u8>>"),
    ('M24', 'Rule Engine: un payload no UTF-8 cuenta como «cero coincidencias» en vez de fallar',
     'lacre-profiles/src/rule_engine.rs',
     "let text = std::str::from_utf8(payload).map_err(|_| RuleError::PayloadNotUtf8)?;",
     'let text = std::str::from_utf8(payload).unwrap_or("");'),
    ('M25', 'Reglas: si el conjunto no puede juzgar el payload, se libera igualmente',
     'lacre-domain/src/domain.rs',
     "                failing_rule_id: Some(detail),\n            },\n            false,",
     "                failing_rule_id: Some(detail),\n            },\n            true,"),
    ('M26', 'Reglas: una cuarentena se trata como aprobada',
     'lacre-domain/src/rulesets.rs',
     'matches!(self.outcome, "passed" | "passed_with_flag")',
     'matches!(self.outcome, "passed" | "passed_with_flag" | "quarantined")'),
    ('M27', 'Reglas: verify con ruleset sin reassemble se acepta en silencio',
     'lacre-domain/src/domain.rs',
     "        Some(_) if !req.reassemble => {",
     "        Some(_) if false && !req.reassemble => {"),
    ('M28', 'Versión (A8): sellar ya no comprueba la versión declarada',
     'lacre-domain/src/domain.rs',
     "pub fn seal(state: &AppState, req: &SealRequest) -> Result<SealResponse, DomainError> {\n    let version = crate::version::check(req.version)?;",
     "pub fn seal(state: &AppState, req: &SealRequest) -> Result<SealResponse, DomainError> {\n    let version = crate::version::PROTOCOL_VERSION;"),
    ('M29', 'Versión (A8): verify ya no comprueba la versión declarada',
     'lacre-domain/src/domain.rs',
     ") -> Result<VerifyResponse, DomainError> {\n    let version = crate::version::check(req.version)?;",
     ") -> Result<VerifyResponse, DomainError> {\n    let version = crate::version::PROTOCOL_VERSION;"),
    ('M30', 'Versión (A8): el handshake ya no comprueba la versión declarada',
     'lacre-domain/src/domain.rs',
     "Result<HandshakeResponse, DomainError> {\n    let version = crate::version::check(req.version)?;",
     "Result<HandshakeResponse, DomainError> {\n    let version = crate::version::PROTOCOL_VERSION;"),
    ('M31', 'Versión (A8): crear un episodio Toolchain ya no comprueba la versión declarada',
     'lacre-domain/src/domain.rs',
     "-> Result<crate::wire::ToolchainEpisodeResponse, DomainError> {\n    let version = crate::version::check(req.version)?;",
     "-> Result<crate::wire::ToolchainEpisodeResponse, DomainError> {\n    let version = crate::version::PROTOCOL_VERSION;"),
    ('M32', 'Versión (A8): el verificador acepta cualquier versión (la desconocida pasa como aceptada)',
     'lacre-domain/src/version.rs',
     "Some(v) if ACCEPTED_VERSIONS.contains(&v) => Ok(v),",
     "Some(v) if ACCEPTED_VERSIONS.contains(&v) || true => Ok(v),"),
    ('M33', 'Versión (A8): una versión desconocida se degrada en silencio a la actual',
     'lacre-domain/src/version.rs',
     "Some(v) => Err(DomainError::BadRequest(format!(\n            \"unsupported protocol version {v}; this node accepts {ACCEPTED_VERSIONS:?}\"\n        ))),",
     "Some(_) => Ok(PROTOCOL_VERSION),"),
]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def build(ws, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    rustbin = '/usr/lib/rust-1.91/bin'
    if os.path.isdir(rustbin):
        env['PATH'] = rustbin + ':' + env['PATH']
    r = sh(['cargo', 'build', '--release', '-p', 'lacre-server'], cwd=ws, env=env)
    return r.returncode == 0, r.stderr[-400:]


def run_suite(binary):
    r = sh([sys.executable, str(SUITE), '--spawn', str(binary)], timeout=900)
    fails = [l for l in r.stdout.splitlines() if l.startswith('FAIL ')]
    return r.returncode, fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--workspace', default=str(HERE.parent / 'Code' / 'workspace'))
    ap.add_argument('--only')
    ap.add_argument('--json')
    a = ap.parse_args()
    src = Path(a.workspace)
    only = set(a.only.split(',')) if a.only else None
    tmp = Path(tempfile.mkdtemp(prefix='lacre-mut-'))
    target = tmp / 'target'
    out = []
    try:
        # control: sin mutar
        ws = tmp / 'ws'
        shutil.copytree(src, ws, ignore=shutil.ignore_patterns('target'), copy_function=shutil.copy)
        ok, err = build(ws, target)
        if not ok:
            print('control no compila:', err); sys.exit(2)
        rc, fails = run_suite(target / 'release' / 'lacre-server')
        print(f'CONTROL (sin mutar): suite exit={rc} -> {"OK" if rc == 0 else "FALLA, no se puede validar"}')
        if rc != 0:
            print('\n'.join(fails)); sys.exit(2)
        for mid, desc, rel, old, new in MUTANTS:
            if only and mid not in only:
                continue
            shutil.rmtree(ws); shutil.copytree(src, ws, ignore=shutil.ignore_patterns('target'), copy_function=shutil.copy)
            p = ws / rel; text = p.read_text()
            n = text.count(old)
            if n < 1:
                print(f'{mid}: PATRÓN NO ENCONTRADO en {rel} (el mutante está desactualizado)'); out.append((mid, 'PATRON-PERDIDO', desc, [])); continue
            p.write_text(text.replace(old, new))
            ok, err = build(ws, target)
            if not ok:
                print(f'{mid}: el mutante no compila ({err.strip()[-200:]})'); out.append((mid, 'NO-COMPILA', desc, [])); continue
            rc, fails = run_suite(target / 'release' / 'lacre-server')
            state = 'MUERTO' if rc != 0 else 'SUPERVIVIENTE'
            print(f'{mid}: {state} — {desc}')
            for f in fails[:4]:
                print('      ' + f[:150])
            out.append((mid, state, desc, fails))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    dead = sum(1 for o in out if o[1] == 'MUERTO'); tot = len(out)
    print(f'\nMutantes muertos: {dead}/{tot}')
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1, ensure_ascii=False)
    sys.exit(0 if dead == tot else 1)


if __name__ == '__main__':
    main()

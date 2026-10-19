#!/usr/bin/env python3
"""E4: mutaciones sobre touches_payload y la neutralidad del Núcleo. Restaura siempre los
archivos; no ejecutar junto a otra herramienta que compile el workspace."""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
# (paquete, filtro de test, archivo, buscar, reemplazar, nombre)
MUTS = [
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/profile.rs', 'impl Profile for ReassembleProfile {\n    type Access = FullContent;', 'impl Profile for ReassembleProfile {\n    type Access = NoContent;', 'Reassemble declara none aunque lee contenido (no compila)'),
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/certifier.rs', 'impl crate::profile::Profile for CertifierProfile {\n    type Access = lacre_core::access::FullContent;\n}\n', '', 'Certifier sin declaración'),
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/declaration.rs', '    declare::<GuardianProfile>(', '    declare::<RuleEngineProfile>(', 'Guardian falta en el registro (y RuleEngine duplicado)'),
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/declaration.rs', 'ProfileDeclaration { name, access: P::ACCESS, touches_payload: P::TOUCHES_PAYLOAD, justification }', 'ProfileDeclaration { name, access: P::ACCESS, touches_payload: false, justification }', 'el registro ignora la constante del tipo'),
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/declaration.rs', '"matches regular expressions against the payload bytes"', '""', 'justificación vacía en un perfil que toca contenido'),
 ('lacre-core', 'neutrality', 'lacre-core/Cargo.toml', '[dependencies]\n', '[dependencies]\nregex = "1"\n', 'el Núcleo depende de regex'),
 ('lacre-core', 'neutrality', 'lacre-core/src/hmac_seal.rs', 'fn seal_sha256(', 'fn _peek(b: &[u8]) -> bool { std::str::from_utf8(b).is_ok() }\nfn seal_sha256(', 'el Núcleo interpreta bytes como texto'),
 ('lacre-core', 'neutrality', 'lacre-core/src/frame.rs', 'pub struct LacreFrame', 'const _X: &str = "lacre_profiles";\npub struct LacreFrame', 'el Núcleo referencia lacre_profiles'),
 ('lacre-adapter-http', 'profiles_endpoint', 'lacre-domain/src/wire.rs', 'core_touches_payload: false,', 'core_touches_payload: true,', 'el nodo publica que el Núcleo toca contenido'),
 ('lacre-adapter-http', 'profiles_endpoint', 'lacre-domain/src/wire.rs', '.map(|d| ProfileDeclarationWire {\n                name: d.name.to_string(),\n                content_access: d.access.name().to_string(),\n                touches_payload: d.touches_payload,', '.map(|d| ProfileDeclarationWire {\n                name: d.name.to_string(),\n                content_access: d.access.name().to_string(),\n                touches_payload: false,', 'la ruta publica touches_payload=false para todos'),
 # --- acceso por tipos ---
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/declaration.rs', 'access: P::ACCESS,', 'access: lacre_core::access::ContentAccess::None,', 'el registro publica none para todos'),
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/profile.rs', '    const TOUCHES_PAYLOAD: bool = <Self::Access as AccessLevel>::LEVEL.reads_bytes();', '    const TOUCHES_PAYLOAD: bool = false;', 'touches_payload deja de derivarse del nivel'),
 ('lacre-profiles', 'touches_payload', 'lacre-profiles/src/guardian.rs', 'self.engine.evaluate(view, content)', 'self.engine.evaluate(&lacre_core::access::ContentView::caller_supplied(&lacre_core::frame::LacreFrame { session_id: lacre_core::session::SessionId([0; 16]), index: 0, total_fragments: None, is_last: true, payload: vec![] }), content)', 'un Profile fabrica su propia vista'),
 ('lacre-core', 'access_compile', 'lacre-core/src/access.rs', '    pub(crate) fn new(frame: &\'a LacreFrame) -> Self {', '    pub fn new(frame: &\'a LacreFrame) -> Self {', 'cualquiera puede fabricar un VerifiedFrame'),
 ('lacre-core', 'access_compile', 'lacre-core/src/access.rs', 'impl ContentView<\'_, FullContent> {', 'impl<A: AccessLevel> ContentView<\'_, A> {', 'content_bytes disponible en todos los niveles'),
 ('lacre-core', '--doc', 'lacre-core/src/access.rs', 'pub trait AccessLevel: sealed::Sealed {', 'pub trait AccessLevel {', 'los niveles dejan de estar sellados'),
 ('lacre-core', 'verified_view', 'lacre-core/src/core.rs', '        self.verify_frame(frame, key_id, seal, vault_signature)?;\n        Ok(crate::access::VerifiedFrame::new(frame))', '        Ok(crate::access::VerifiedFrame::new(frame))', 'verify_frame_view entrega la vista sin verificar'),
]
def main():
    only = set(sys.argv[1:]); killed = total = 0
    for i, (pk, flt, f, a, b, name) in enumerate(MUTS, 1):
        tag = f'T{i:02d}'
        if only and tag not in only: continue
        s = open(f).read()
        if a not in s:
            print(f'{tag}: NO APLICA — {name}', flush=True); continue
        total += 1
        open(f, 'w').write(s.replace(a, b, 1))
        try:
            args = ['--test', flt] if flt in ('touches_payload', 'neutrality', 'access_compile', 'verified_view') else [flt]
            r = subprocess.run(['cargo', 'test', '-p', pk] + args, capture_output=True, text=True, timeout=290)
            dead = r.returncode != 0
        finally:
            open(f, 'w').write(s)
        killed += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} — {name}', flush=True)
    print(f'Mutantes muertos: {killed}/{total}')
main()

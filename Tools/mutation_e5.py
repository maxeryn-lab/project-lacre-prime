#!/usr/bin/env python3
"""E5 (firmas y vault bajo wire v2): mutaciones sobre la capa de firma del Núcleo, los recibos v2, la política
(`signatures`), la regla vault <-> esquema y el dominio. Restaura siempre los archivos; no ejecutar junto a otra
herramienta que compile el workspace. Uso: python3 Tools/mutation_e5.py [M01 M02 ...]"""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
C, S, P, D = 'lacre-core/src/core_v2.rs', 'lacre-core/src/suite.rs', 'lacre-domain/src/seal_policy.rs', 'lacre-domain/src/domain.rs'
ST, WI, SE = 'lacre-domain/src/sealer_session_store.rs', 'lacre-domain/src/wire.rs', 'lacre-seals/src/signatures.rs'
# (archivo, buscar, reemplazar, nombre) — se reemplazan TODAS las apariciones
MUTS = [
 (C, 'if sig.len() != scheme.signature_len() || !scheme.verify(public, &input, sig) {', 'if sig.len() != scheme.signature_len() {', 'la firma no se verifica, solo su longitud'),
 (C, 'if sig.len() != scheme.signature_len() || !scheme.verify(public, &input, sig) {', 'if !scheme.verify(public, &input, sig) {', 'la longitud de la firma no se exige antes de verificar'),
 (C, 'let input = SignInput::new(self.suite.suite_hash(), &self.session_id.0, frame.index, tag.as_bytes());', 'let input = SignInput::new(self.suite.suite_hash(), &self.session_id.0, 0, tag.as_bytes());', 'la firma no cubre el índice (verificador)'),
 (C, 'let input = SignInput::new(self.suite.suite_hash(), &self.session_id.0, index, tag.as_bytes());', 'let input = SignInput::new(self.suite.suite_hash(), &self.session_id.0, 0, tag.as_bytes());', 'la firma no cubre el índice (sellador)'),
 (C, '(None, _, None) => {}', '(None, _, _) => {}', 'una suite sin esquema acepta una firma'),
 (C, '            _ => return Err(CoreError::VaultSignatureMismatch),\n        }\n\n        self.buffer.insert_tagged', '            (Some(_), _, None) => {}\n            _ => return Err(CoreError::VaultSignatureMismatch),\n        }\n\n        self.buffer.insert_tagged', 'la firma deja de ser obligatoria con esquema'),
 (C, 'let r = derive_receipt_v2(self.suite.suite_hash(), index, tag);', 'let r = derive_receipt_v2(&[0u8; 32], index, tag);', 'el recibo v2 no liga la suite'),
 (C, '        self.buffer.purge_on_ack(index)\n    }\n\n    /// Receipts issued', '        let purged = self.buffer.purge_on_ack(index);\n        if let Some(signer) = self.signer.as_mut() { let _ = signer; }\n        purged\n    }\n\n    /// Receipts issued', 'mutación neutra de control (debe SOBREVIVIR)'),
 (C, 'if sig.len() != scheme.signature_len() {\n            return Err(CoreError::VaultSignatureMismatch);\n        }\n        Ok(sig)', 'Ok(sig)', 'sign_for devuelve una firma de longitud errónea'),
 (S, 'if named != sc.id() {', 'if false {', 'el descriptor y el esquema pueden no coincidir'),
 (S, 'if sl == 0 || sl > MAX_SIGNATURE_LEN {', 'if sl == 0 {', 'la longitud máxima de firma no se acota'),
 (S, 'if k == 0 || k > MAX_SIGNATURE_KEY_LEN {', 'if k == 0 {', 'la longitud máxima de clave de firma no se acota'),
 (P, 'if p == "vault" && signatures.is_empty() {', 'if false {', 'la política permite vault sin ningún esquema'),
 (P, '(true, None) => {\n                return Err(DomainError::BadRequest(\n                    "profile `vault` requires', '(true, None) if false => {\n                return Err(DomainError::BadRequest(\n                    "profile `vault` requires', 'vault sin esquema de firma se acepta'),
 (P, '(false, Some(_)) => {', '(false, Some(_)) if false => {', 'un esquema fuera de vault se acepta'),
 (P, 'if !self.policy.signatures.contains_key(sig_id) {', 'if false {', 'un esquema compilado pero no listado se acepta'),
 (P, 'if sg.expect_status != real {', 'if false {', 'el estado esperado del esquema no se comprueba'),
 (P, 'return refuse(format!("signature scheme `{id}` appears twice"));', '', 'un esquema repetido en la política se acepta'),
 (D, 'let signing = profile.requires_vault_signature();', 'let signing = false;', 'vault v2 no firma'),
 (D, 'if signing {\n        state.sealer_sessions().insert(session_id, sealer)', 'if false {\n        state.sealer_sessions().insert(session_id, sealer)', 'el sellador vault v2 no se guarda para ack'),
 (D, 'if named.is_some() && named != declared {', 'if false {', 'una firma con el nombre de otro esquema no se rechaza por nombre'),
 (D, 'v.verify_frame_view_signed(&frame, key_id, t, sg.as_ref().map(|(_, b)| b.as_slice()))', 'v.verify_frame_view_signed(&frame, key_id, t, None)', 'el dominio descarta la firma al verificar'),
 (WI, 'if self.signature.is_some() {\n            return Err(WireDecodeError::SignatureNotAllowedInV1);', 'if false {\n            return Err(WireDecodeError::SignatureNotAllowedInV1);', 'un campo signature de v2 se acepta en v1'),
 (WI, 'if self.vault_signature_hex.is_some() {\n            return Err(WireDecodeError::SignatureNotAllowedInV2);', 'if false {\n            return Err(WireDecodeError::SignatureNotAllowedInV2);', 'vault_signature_hex de v1 se acepta en v2'),
 (ST, 'AnySealer::V2(s) => s.receipts(),', 'AnySealer::V2(_) => None,', 'ack/receipts ignoran el sellador v2'),
 (SE, 'vk.verify_strict(', 'vk.verify(', 'Ed25519 sin verificación estricta (neutro si el vector no cubre maleabilidad)'),
]
# M08 es una mutación neutra de control: debe sobrevivir.
CONTROL = {'M08': 'mutación neutra: si muere, el arnés es defectuoso'}

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
            r = subprocess.run(['cargo', 'test', '-p', 'lacre-core', '-p', 'lacre-seals', '-p', 'lacre-domain',
                                '-p', 'lacre-adapter-declarative', '-p', 'lacre-server'],
                               capture_output=True, text=True, timeout=590)
            dead = r.returncode != 0
        except subprocess.TimeoutExpired:
            dead = True
        finally:
            open(f, 'w').write(s)
        if tag in CONTROL:
            total -= 1
            print(f'{tag}: CONTROL {"FALLA: el arnés mata hasta lo neutro" if dead else "ok (sobrevive)"} — {name}', flush=True); continue
        killed += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} — {name}', flush=True)
    print(f'Mutantes muertos: {killed}/{total}')
main()

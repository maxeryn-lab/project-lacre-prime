#!/usr/bin/env python3
"""E3: mutaciones del Core/dominio que los property tests (lacre-core/tests/properties.rs,
lacre-domain/tests/properties.rs) deben matar. Edita el código y lo RESTAURA siempre;
no ejecutar a la vez que otra herramienta que compile el workspace."""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
MUTS = [
 ('lacre-core', 'lacre-core/src/core.rs', 'if frame.index != self.next_index {', 'if false && frame.index != self.next_index {', 'verify_frame ya no exige el índice esperado'),
 ('lacre-core', 'lacre-core/src/core.rs', 'self.next_index += 1;\n\n        // Receipt captured', 'self.next_index += 0;\n\n        // Receipt captured', 'verify_frame no avanza el índice'),
 ('lacre-core', 'lacre-core/src/core.rs', 'self.state = self.state.next(key, &frame.payload);\n        self.next_index += 1;', 'self.next_index += 1;', 'verify_frame no avanza el estado'),
 ('lacre-core', 'lacre-core/src/hmac_seal.rs', 'expected.0.ct_eq(&received.0).into()', 'expected.0[..16].ct_eq(&received.0[..16]).into()', 'el sello solo se compara en 16 de 32 bytes'),
 ('lacre-core', 'lacre-core/src/hmac_seal.rs', '    mac.update(fragment);\n    mac.update(session_state);\n    let result = mac.finalize().into_bytes();\n    let mut out = [0u8; SEAL_LEN];\n    out.copy_from_slice(&result);\n    Seal(out)\n}\n\nfn seal_blake3', '    mac.update(fragment);\n    let result = mac.finalize().into_bytes();\n    let mut out = [0u8; SEAL_LEN];\n    out.copy_from_slice(&result);\n    Seal(out)\n}\n\nfn seal_blake3', 'el sello sha256 no liga el estado'),
 ('lacre-core', 'lacre-core/src/core.rs', '.ok_or(CoreError::UnknownKeyId)?;', '.unwrap_or_else(|| self.key.clone());', 'un key_id desconocido cae a la clave de la sesión'),
 ('lacre-core', 'lacre-core/src/session.rs', 'Hkdf::<Sha256>::new(Some(&session_id.0), ikm);\n    let mut okm = [0u8; SESSION_KEY_LEN];', 'Hkdf::<Sha256>::new(None, ikm);\n    let mut okm = [0u8; SESSION_KEY_LEN];', 'HKDF sin salt de sesión (v1)'),
 ('lacre-core', 'lacre-core/src/core.rs', 'let index = self.next_index;\n        let result = self.seal_one(chunk, index, None, is_last)?;', 'let index = self.next_index;\n        let result = self.seal_one(chunk, index + 0, Some(1), is_last)?;', 'seal_chunk declara total_fragments'),
 ('lacre-domain', 'lacre-domain/src/wire.rs', '.try_into()\n            .map_err(|_| WireDecodeError::InvalidSealLength)?;', '.unwrap_or_default().try_into().unwrap_or([0u8; 32]);\n        let _ = WireDecodeError::InvalidSealLength;', 'el decoder tolera un sello de longitud errónea'),
 ('lacre-domain', 'lacre-domain/src/wire.rs', 'bytes.try_into().ok()?;\n    Some(SessionId(arr))', 'bytes.try_into().unwrap_or([0u8; 16]);\n    Some(SessionId(arr))', 'session_id inválido se convierte en ceros'),
 ('lacre-domain', 'lacre-domain/src/capability.rs', 'bytes.len() == 32 && bool::from(expected.ct_eq(&bytes[..]))', 'bytes.len() >= 8 && bool::from(expected[..8].ct_eq(&bytes[..8]))', 'el token se compara solo en 8 bytes'),
]
def main():
    only = set(sys.argv[1:])
    killed = 0; total = 0; neutral = []
    for i, (crate, f, a, b, name) in enumerate(MUTS, 1):
        tag = f'P{i:02d}'
        if only and tag not in only: continue
        s = open(f).read()
        if a not in s:
            print(f'{tag}: NO APLICA (patrón no encontrado) — {name}', flush=True); continue
        total += 1
        open(f, 'w').write(s.replace(a, b, 1))
        try:
            r = subprocess.run(['cargo', 'test', '-p', crate, '--test', 'properties'], capture_output=True, text=True, timeout=280)
            dead = r.returncode != 0
        finally:
            open(f, 'w').write(s)
        killed += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} — {name}', flush=True)
    print(f'Mutantes muertos: {killed}/{total}')
main()

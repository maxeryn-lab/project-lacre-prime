#!/usr/bin/env python3
"""E1 (wire v2): mutaciones sobre el camino genérico de Core (contrato, descriptor, derivación, núcleo v2, buffer).
Restaura siempre los archivos; no ejecutar junto a otra herramienta que compile el workspace.
Uso: python3 Tools/mutation_suite.py [M01 M02 ...]"""
import subprocess, os, sys
W = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Code/workspace')
os.chdir(W)
S, C, B, K = 'lacre-core/src/suite.rs', 'lacre-core/src/core_v2.rs', 'lacre-core/src/buffer.rs', 'lacre-core/src/session.rs'
TESTS = ['--lib', '--test', 'suite_vectors', '--test', 'suite_v2_flow', '--test', 'suite_v2_properties',
         '--test', 'suite_structure', '--test', 'wire_vectors']
# (archivo, buscar, reemplazar, nombre)
MUTS = [
 (S, 'bytes.is_empty() || bytes.len() > MAX_TAG_LEN', 'bytes.is_empty() || bytes.len() > MAX_TAG_LEN + 1', 'el tope de tag admite 1025 bytes'),
 (S, 'self.0.len() == expected.len() && bool::from(self.0.ct_eq(expected))', 'self.0.len() <= expected.len() && bool::from(self.0.ct_eq(&expected[..self.0.len()]))', 'un prefijo del tag se acepta'),
 (S, 'bool::from(self.0.ct_eq(expected))', 'self.0 == expected', 'comparación del tag sin tiempo constante'),
 (S, '        if !rest.is_empty() {\n            return Err(SuiteError::DescriptorMalformed);\n        }\n', '', 'el descriptor admite bytes sobrantes'),
 (S, 'if tag != expected_tag || r.len() < len as usize', 'if r.len() < len as usize', 'el descriptor no exige el orden de campos'),
 (S, 'b"lacre/v2/suite"', 'b"lacre/v2/suite-x"', 'cambia el dominio del hash de suite'),
 (S, 'h.update(self.canonical());', 'h.update(&self.canonical()[..4]);', 'el hash de suite ignora casi todo el descriptor'),
 (S, 'c.is_ascii_lowercase() || c.is_ascii_digit()', 'c.is_ascii_alphabetic() || c.is_ascii_digit()', 'los ids admiten mayúsculas'),
 (S, '                if !descriptor.params().is_empty() {\n                    return Err(SuiteError::ParamsInvalid);\n                }\n', '', 'parámetros aceptados en un algoritmo de salida fija'),
 (S, 'if n < min || n > max {', 'if n < min {', 'tag XOF por encima del máximo del algoritmo'),
 (S, '(MIN_KEY_LEN..=MAX_KEY_LEN).contains(&key_len)', '(MIN_KEY_LEN..=MAX_KEY_LEN + 1000).contains(&key_len)', 'clave de longitud absurda aceptada'),
 (S, 'if required > cap {', 'if required > cap + 1 {', 'el presupuesto de memoria admite un byte de más'),
 (S, '.and_then(|per_slot| per_slot.checked_mul(slot_count))', '.and_then(|per_slot| Some(per_slot.wrapping_mul(slot_count)))', 'el presupuesto de memoria desborda sin error'),
 (S, 'len_prefix: (fragment.len() as u64).to_be_bytes()', 'len_prefix: [0u8; 8]', 'la entrada del sello pierde el prefijo de longitud'),
 (S, '[&self.len_prefix, self.fragment, self.state]', '[&self.len_prefix, self.state, self.fragment]', 'partes de la entrada del sello en otro orden'),
 (S, '        if descriptor.seal_id() != mac.id() {\n            return Err(SuiteError::IdMismatch);\n        }\n', '', 'descriptor y algoritmo con ids distintos'),
 (S, '        if version != VERSION_V2 {', '        if false {', 'versión desconocida aceptada'),
 (S, '        if bytes.len() > MAX_DESCRIPTOR_LEN {', '        if false {', 'descriptor sin tope de tamaño'),
 (S, '_ => Err(SuiteError::UnsupportedChain),', '_ => Ok(ChainSuite::HmacSha256),', 'cualquier cadena se toma como hmac-sha256'),
 (S, '    fn mac(&self, key: &[u8], input: &SealInput<\'_>, out: &mut [u8]);', '    fn verify(&self) -> bool { true }\n    fn mac(&self, key: &[u8], input: &SealInput<\'_>, out: &mut [u8]);', 'el contrato ofrece verify al algoritmo'),
 (S, 'pub const VERSION_V2: u8 = 2;', 'pub const VERSION_V2: u8 = 2;\npub const X: &str = "lacre_seals";', 'Core referencia el catálogo'),
 (K, '&[LABEL_V2_SEAL_KEY, suite_hash]', '&[LABEL_V2_SEAL_KEY]', 'la clave del sello no liga la suite'),
 (K, '&[LABEL_V2_CHAIN_KEY, suite_hash]', '&[LABEL_V2_CHAIN_KEY]', 'la clave de la cadena no liga la suite'),
 (K, '&[LABEL_V2_CHAIN_KEY, suite_hash]', '&[LABEL_V2_SEAL_KEY, suite_hash]', 'clave de sello y de cadena con la misma etiqueta'),
 (K, '        self.retiring\n            .get(&key_id)\n            .and_then(|e| derive_v2(key_id, &e.ikm, session_id, suite_hash, seal_key_len))', '        derive_v2(key_id, &self.active.ikm, session_id, suite_hash, seal_key_len)', 'clave desconocida cae a la clave activa'),
 (K, 'key_id == self.active.key_id || self.retiring.contains_key(&key_id)', 'true', 'knows_key siempre verdadero'),
 (K, 'Hkdf::<Sha256>::new(Some(&session_id.0), ikm);\n    let mut seal = vec![0u8; seal_key_len];', 'Hkdf::<Sha256>::new(None, ikm);\n    let mut seal = vec![0u8; seal_key_len];', 'HKDF v2 sin salt de sesión'),
 (C, '        mac.update(INITIAL_STATE_CONTEXT_V2);\n        mac.update(suite_hash);', '        mac.update(INITIAL_STATE_CONTEXT_V2);', 'Es(0) no incluye el hash de suite'),
 (C, '        mac.update(&self.0);\n        mac.update(fragment);', '        mac.update(fragment);', 'Es(i) ignora el estado anterior'),
 (C, '        self.state = self.state.next(&self.chain_key, &frame.payload);', '', 'el verificador no avanza la cadena'),
 (C, '        self.next_index += 1;\n        // Purged right after', '        // Purged right after', 'el verificador no avanza el índice'),
 (C, '        let ok = tag.matches(&expected);', '        let ok = true;', 'el verificador no compara el tag'),
 (C, '        if frame.index != self.next_index {', '        if false {', 'el verificador no exige el orden'),
 (C, '        if key_id != self.key_id {', '        if false {', 'el verificador ignora el key_id'),
 (C, '        check_memory_budget(spec.slot_size, spec.slot_count, suite.tag_len(), spec.memory_cap)?;\n        let keys = derive(&key_ring, None,', '        let keys = derive(&key_ring, None,', 'el emisor no comprueba el presupuesto de memoria'),
 (C, '        check_memory_budget(spec.slot_size, spec.slot_count, suite.tag_len(), spec.memory_cap)?;\n        let keys = derive(&key_ring, Some(key_id),', '        let keys = derive(&key_ring, Some(key_id),', 'el verificador no comprueba el presupuesto de memoria'),
 (C, 'let mut out = vec![0u8; suite.tag_len()];', 'let mut out = vec![0u8; suite.key_len()];', 'Core dimensiona la salida con la longitud de la clave'),
 (B, '            zeroize::Zeroize::zeroize(&mut self.tags[t_off..t_off + self.tag_len]);\n', '', 'el buffer no borra el tag al liberar'),
 (B, '        if self.tag_len == 0 || tag.len() != self.tag_len {', '        if self.tag_len == 0 {', 'el buffer acepta un tag de otra longitud'),
 ('lacre-core/src/core.rs', 'use crate::receipt::ReceiptLog;', 'use crate::receipt::ReceiptLog;\n#[allow(unused_imports)]\nuse crate::suite::MAX_TAG_LEN;', 'un módulo v1 importa el v2'),
 ('spec/vectors/wire-v1.json', '"seal_len": 32', '"seal_len": 33', 'cambia un byte de los vectores v1'),
]
def main():
    only = set(sys.argv[1:]); killed = total = 0
    for i, (f, a, b, name) in enumerate(MUTS, 1):
        tag = f'M{i:02d}'
        if only and tag not in only: continue
        s = open(f).read()
        if a not in s:
            print(f'{tag}: NO APLICA — {name}', flush=True); continue
        total += 1
        open(f, 'w').write(s.replace(a, b, 1))
        try:
            r = subprocess.run(['cargo', 'test', '-p', 'lacre-core'] + TESTS, capture_output=True, text=True, timeout=590)
            dead = r.returncode != 0
        finally:
            open(f, 'w').write(s)
        killed += dead
        print(f'{tag}: {"MUERTO" if dead else "SUPERVIVIENTE"} — {name}', flush=True)
    print(f'Mutantes muertos: {killed}/{total}')
main()

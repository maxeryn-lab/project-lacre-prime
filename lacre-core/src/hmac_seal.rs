//! Generación y verificación del sello por fragmento.
//!
//! δᵢ = HMAC(fᵢ ∥ Sᵢ, k)
//!
//! Soporta SHA-256 (perfil Core, estándar de facto) y Blake3 (perfiles
//! Lite/Lightning, más rápido en CPU). La elección de algoritmo es un
//! parámetro de perfil, no una decisión de código.
//!
//! Sᵢ (estado de sesión) se pasa como parámetro explícito en vez de
//! guardarse como campo mutable: esto obliga a quien llama a decidir
//! conscientemente qué estado corresponde a cada fragmento, en vez de
//! confiar en que el objeto se actualizó correctamente en el paso previo.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::session::SessionKey;

pub const SEAL_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgo {
    Sha256,
    Blake3,
}

/// El sello de un fragmento: siempre 32 bytes, sea cual sea el algoritmo.
/// El algoritmo usado viaja aparte (en la cabecera del perfil), no dentro
/// del sello mismo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seal(pub [u8; SEAL_LEN]);

/// Genera δᵢ = HMAC(fᵢ ∥ Sᵢ, k) para un fragmento dado.
///
/// `session_state` es Sᵢ: el estado de sesión en el paso i. Se concatena
/// con el fragmento antes de aplicar HMAC, de modo que un sello válido
/// para la posición i no es válido para la posición j ≠ i, aunque el
/// contenido del fragmento sea idéntico (cubre reordenamiento/sustitución,
/// ver Bloque IV.1 de la especificación).
pub fn seal_fragment(
    algo: HmacAlgo,
    key: &SessionKey,
    fragment: &[u8],
    session_state: &[u8],
) -> Seal {
    match algo {
        HmacAlgo::Sha256 => seal_sha256(key, fragment, session_state),
        HmacAlgo::Blake3 => seal_blake3(key, fragment, session_state),
    }
}

/// Verifica δᵢ contra un fragmento recibido. Comparación en tiempo
/// constante: comparar el HMAC recalculado contra el recibido con `==`
/// filtra información de timing que un atacante remoto puede explotar
/// para forjar el sello byte a byte. Esto no está en el documento de
/// especificación original y es la clase de detalle que separa un
/// diseño correcto en el papel de una implementación segura de verdad.
pub fn verify_fragment(
    algo: HmacAlgo,
    key: &SessionKey,
    fragment: &[u8],
    session_state: &[u8],
    received: &Seal,
) -> bool {
    let expected = seal_fragment(algo, key, fragment, session_state);
    expected.0.ct_eq(&received.0).into()
}

fn seal_sha256(key: &SessionKey, fragment: &[u8], session_state: &[u8]) -> Seal {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC acepta claves de cualquier longitud");
    mac.update(fragment);
    mac.update(session_state);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; SEAL_LEN];
    out.copy_from_slice(&result);
    Seal(out)
}

fn seal_blake3(key: &SessionKey, fragment: &[u8], session_state: &[u8]) -> Seal {
    // blake3::keyed_hash requiere clave de exactamente 32 bytes.
    // SESSION_KEY_LEN ya es 32, así que esto nunca falla en la práctica,
    // pero lo hacemos explícito en vez de silenciarlo con un truncado.
    let key_bytes: [u8; 32] = key
        .as_bytes()
        .try_into()
        .expect("SessionKey siempre tiene SESSION_KEY_LEN=32 bytes");
    let mut hasher = blake3::Hasher::new_keyed(&key_bytes);
    hasher.update(fragment);
    hasher.update(session_state);
    let result = hasher.finalize();
    Seal(*result.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{MasterKeyRing, SessionId};
    use std::time::Duration;

    fn test_key() -> SessionKey {
        let ring = MasterKeyRing::new(0, b"clave-maestra-de-prueba-minimo-32b".to_vec(), Duration::from_secs(60));
        let sid = SessionId::generate();
        ring.derive_for_sealing(&sid)
    }

    #[test]
    fn valid_seal_verifies_sha256() {
        let key = test_key();
        let fragment = b"contenido del fragmento";
        let state = b"estado-sesion-paso-3";
        let seal = seal_fragment(HmacAlgo::Sha256, &key, fragment, state);
        assert!(verify_fragment(HmacAlgo::Sha256, &key, fragment, state, &seal));
    }

    #[test]
    fn valid_seal_verifies_blake3() {
        let key = test_key();
        let fragment = b"contenido del fragmento";
        let state = b"estado-sesion-paso-3";
        let seal = seal_fragment(HmacAlgo::Blake3, &key, fragment, state);
        assert!(verify_fragment(HmacAlgo::Blake3, &key, fragment, state, &seal));
    }

    /// Prueba 1 del Bloque IV: fragmento alterado, sello sin modificar.
    #[test]
    fn altered_fragment_fails_verification() {
        let key = test_key();
        let original = b"contenido del fragmento".to_vec();
        let state = b"estado-sesion-paso-3";
        let seal = seal_fragment(HmacAlgo::Sha256, &key, &original, state);

        let mut tampered = original.clone();
        tampered[0] ^= 0x01; // invierte un solo bit

        assert!(!verify_fragment(HmacAlgo::Sha256, &key, &tampered, state, &seal));
    }

    /// Reordenamiento: mismo contenido, distinto estado de sesión (posición).
    #[test]
    fn same_fragment_different_session_state_fails() {
        let key = test_key();
        let fragment = b"contenido identico";
        let seal_at_step_3 = seal_fragment(HmacAlgo::Sha256, &key, fragment, b"estado-paso-3");

        assert!(!verify_fragment(
            HmacAlgo::Sha256,
            &key,
            fragment,
            b"estado-paso-7",
            &seal_at_step_3
        ));
    }

    /// Prueba 2 del Bloque IV: fragmento fabricado sin conocer la clave.
    #[test]
    fn forged_seal_without_key_fails() {
        let key = test_key();
        let fragment = b"contenido del fragmento";
        let state = b"estado-sesion-paso-3";

        // Atacante sin la clave: usa un hash simple (sin componente HMAC).
        let fake = blake3::hash(fragment).as_bytes().to_owned();
        let forged_seal = Seal(fake);

        assert!(!verify_fragment(HmacAlgo::Sha256, &key, fragment, state, &forged_seal));
        assert!(!verify_fragment(HmacAlgo::Blake3, &key, fragment, state, &forged_seal));
    }

    #[test]
    fn different_algo_families_are_incompatible() {
        // Un sello generado con Blake3 no debe verificar bajo SHA-256 y
        // viceversa: confirma que el algoritmo debe negociarse explícitamente
        // por perfil y no se puede inferir del sello mismo.
        let key = test_key();
        let fragment = b"contenido";
        let state = b"estado";
        let seal_blake3 = seal_fragment(HmacAlgo::Blake3, &key, fragment, state);
        assert!(!verify_fragment(HmacAlgo::Sha256, &key, fragment, state, &seal_blake3));
    }
}

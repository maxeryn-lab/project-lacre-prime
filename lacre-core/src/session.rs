//! Gestión de claves de sesión para el sellado HMAC.
//!
//! Cierra el punto ABIERTO 1 del documento de especificación: la clave k
//! nunca se usa "pelada" a nivel de sesión. Cada sesión deriva su propia
//! clave mediante HKDF a partir de una clave maestra, usando el session_id
//! (no secreto) como salt. Esto significa que comprometer la clave de una
//! sesión no compromete a las demás, sin pagar el costo de latencia de un
//! intercambio Diffie-Hellman por sesión.
//!
//! Rotación: la clave maestra tiene un `key_id`. Al rotar, se genera una
//! nueva maestra con key_id incrementado; la anterior se mantiene activa
//! como fallback durante una ventana corta para no invalidar sesiones en
//! curso. No hay fallback silencioso a un key_id no reconocido: si el
//! verificador no tiene la maestra correspondiente, se rechaza.

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Longitud de la clave de sesión derivada, en bytes (256 bits).
pub const SESSION_KEY_LEN: usize = 32;

/// Longitud del session_id (salt de HKDF), en bytes. No es secreto.
pub const SESSION_ID_LEN: usize = 16;

/// Contexto fijo de dominio para el "info" de HKDF. Separa este uso de
/// cualquier otro derivado eventual de la misma maestra (evita colisión
/// de propósito, ver RFC 5869 §3.2).
const HKDF_INFO: &[u8] = b"lacre-core/v1/session-key";

/// Identificador de clave maestra. Viaja en cabecera junto al sello para
/// que el verificador sepa qué maestra usar sin tener que probar todas.
pub type KeyId = u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);

impl SessionId {
    pub fn generate() -> Self {
        let mut buf = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        SessionId(buf)
    }
}

/// Clave de sesión ya derivada, lista para usarse en HMAC.
/// No implementa Debug/Display a propósito: nunca debe terminar en un log.
#[derive(Clone)]
pub struct SessionKey {
    pub key_id: KeyId,
    bytes: [u8; SESSION_KEY_LEN],
}

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Una clave maestra con su identificador y el momento en que fue registrada.
/// Las mantiene MasterKeyRing; nunca se expone directamente fuera del ring.
struct MasterKeyEntry {
    key_id: KeyId,
    ikm: Vec<u8>,
    registered_at: Instant,
}

/// Mantiene la clave maestra activa y, durante la ventana de rotación,
/// la anterior como fallback. Es la única estructura que ve material de
/// clave maestro "en crudo".
pub struct MasterKeyRing {
    active: MasterKeyEntry,
    /// Claves retiradas pero aún válidas para verificar sesiones en curso.
    retiring: HashMap<KeyId, MasterKeyEntry>,
    /// Cuánto tiempo una clave retirada sigue siendo válida antes de purgarse.
    retirement_window: Duration,
}

impl MasterKeyRing {
    /// Crea un ring con una única clave maestra activa (uso inicial, H1).
    /// `ikm` debe venir de una fuente de alta entropía (config.toml con
    /// bytes generados por CSPRNG, o un almacén de secretos). El ring no
    /// valida entropía; eso es responsabilidad de quien genera el valor.
    pub fn new(key_id: KeyId, ikm: Vec<u8>, retirement_window: Duration) -> Self {
        MasterKeyRing {
            active: MasterKeyEntry {
                key_id,
                ikm,
                registered_at: Instant::now(),
            },
            retiring: HashMap::new(),
            retirement_window,
        }
    }

    pub fn active_key_id(&self) -> KeyId {
        self.active.key_id
    }

    /// Rota a una nueva clave maestra. La anterior pasa a `retiring` y
    /// sigue siendo válida para verificación (no para sellado nuevo)
    /// durante `retirement_window`.
    pub fn rotate(&mut self, new_key_id: KeyId, new_ikm: Vec<u8>) {
        let old = std::mem::replace(
            &mut self.active,
            MasterKeyEntry {
                key_id: new_key_id,
                ikm: new_ikm,
                registered_at: Instant::now(),
            },
        );
        self.retiring.insert(old.key_id, old);
        self.purge_expired();
    }

    fn purge_expired(&mut self) {
        let window = self.retirement_window;
        self.retiring
            .retain(|_, entry| entry.registered_at.elapsed() < window);
    }

    /// Deriva la clave de sesión para sellar un fragmento nuevo. Siempre
    /// usa la maestra activa.
    pub fn derive_for_sealing(&self, session_id: &SessionId) -> SessionKey {
        derive_session_key(self.active.key_id, &self.active.ikm, session_id)
    }

    /// Deriva la clave de sesión para verificar un fragmento recibido con
    /// un key_id determinado. Busca primero en la activa, luego en las
    /// retiring. Si no encuentra el key_id, devuelve None: no hay
    /// fallback silencioso a otra clave.
    pub fn derive_for_verifying(
        &self,
        key_id: KeyId,
        session_id: &SessionId,
    ) -> Option<SessionKey> {
        if key_id == self.active.key_id {
            return Some(derive_session_key(key_id, &self.active.ikm, session_id));
        }
        self.retiring
            .get(&key_id)
            .map(|entry| derive_session_key(key_id, &entry.ikm, session_id))
    }
}

fn derive_session_key(key_id: KeyId, ikm: &[u8], session_id: &SessionId) -> SessionKey {
    // HKDF-Extract usa session_id como salt (no secreto, único por sesión).
    // HKDF-Expand liga el resultado al contexto fijo HKDF_INFO.
    let hk = Hkdf::<Sha256>::new(Some(&session_id.0), ikm);
    let mut okm = [0u8; SESSION_KEY_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("SESSION_KEY_LEN es válido para HKDF-SHA256 (máx 8160 bytes)");
    SessionKey {
        key_id,
        bytes: okm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_session_id_same_master_yields_same_key() {
        let ring = MasterKeyRing::new(0, b"clave-maestra-de-prueba-minimo-32b".to_vec(), Duration::from_secs(60));
        let sid = SessionId::generate();
        let k1 = ring.derive_for_sealing(&sid);
        let k2 = ring.derive_for_sealing(&sid);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_session_ids_yield_different_keys() {
        let ring = MasterKeyRing::new(0, b"clave-maestra-de-prueba-minimo-32b".to_vec(), Duration::from_secs(60));
        let sid_a = SessionId::generate();
        let sid_b = SessionId::generate();
        let ka = ring.derive_for_sealing(&sid_a);
        let kb = ring.derive_for_sealing(&sid_b);
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn rotation_keeps_old_key_verifiable_during_window() {
        let mut ring = MasterKeyRing::new(0, b"maestra-v0-minimo-32-bytes-aaaaa".to_vec(), Duration::from_secs(60));
        let sid = SessionId::generate();
        let sealed_with_v0 = ring.derive_for_sealing(&sid);

        ring.rotate(1, b"maestra-v1-minimo-32-bytes-bbbbb".to_vec());

        // La sesión sellada con key_id=0 debe seguir siendo verificable.
        let verified = ring
            .derive_for_verifying(0, &sid)
            .expect("key_id=0 debe estar en la ventana de retiring");
        assert_eq!(sealed_with_v0.as_bytes(), verified.as_bytes());
    }

    #[test]
    fn rotation_rejects_unknown_key_id() {
        let ring = MasterKeyRing::new(0, b"maestra-v0-minimo-32-bytes-aaaaa".to_vec(), Duration::from_secs(60));
        let sid = SessionId::generate();
        assert!(ring.derive_for_verifying(99, &sid).is_none());
    }

    #[test]
    fn expired_retiring_key_is_purged() {
        let mut ring = MasterKeyRing::new(0, b"maestra-v0-minimo-32-bytes-aaaaa".to_vec(), Duration::from_millis(50));
        ring.rotate(1, b"maestra-v1-minimo-32-bytes-bbbbb".to_vec());
        std::thread::sleep(Duration::from_millis(80));
        ring.rotate(2, b"maestra-v2-minimo-32-bytes-ccccc".to_vec());
        // key_id=0 ya debería haber expirado y ser purgado en este rotate.
        let sid = SessionId::generate();
        assert!(ring.derive_for_verifying(0, &sid).is_none());
    }
}

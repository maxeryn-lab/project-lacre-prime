//! Firma Ed25519 para no repudio — Sección 9.5 y 15.3 del documento
//! Lacre Prime.
//!
//! # Qué resuelve esto que el HMAC no resuelve
//!
//! 15.3 es explícito: un HMAC de clave compartida certifica integridad
//! y autenticidad frente a un tercero que no posee la clave, pero *no*
//! certifica origen frente a la contraparte que sí la posee — cualquiera
//! de las dos partes pudo haber generado el sello. La firma asimétrica
//! resuelve ese caso: solo quien posee la clave privada puede producir
//! una firma válida, así que ni siquiera el verificador (que solo tiene
//! la clave pública) puede haberla fabricado él mismo.
//!
//! # Decisión de ingeniería no especificada por el documento
//!
//! El documento (9.5) fija el algoritmo (Ed25519) y el motivo, pero no
//! especifica QUÉ se firma exactamente. Esta implementación firma el
//! `Seal` (HMAC) del fragmento, no el fragmento en sí — decisión
//! nuestra, no del documento, por dos razones:
//!   1. El HMAC ya depende criptográficamente del fragmento completo
//!      (Bloque 8.2: δᵢ = HMAC(fᵢ ∥ Sᵢ, k)), así que firmar el HMAC
//!      certifica transitivamente el fragmento sin repetir el trabajo
//!      de procesarlo completo una segunda vez.
//!   2. El tamaño de la firma resultante es fijo (64 bytes) sin importar
//!      el tamaño del fragmento — coherente con A2 (el sello vive en
//!      cabecera, de tamaño acotado, no proporcional al cuerpo).
//!
//! Si esta decisión demuestra ser incorrecta en la práctica (por
//! ejemplo, si un caso de uso real necesita que la firma cubra el
//! fragmento de forma independiente del HMAC), el documento se
//! actualiza para reflejar lo aprendido — no al revés.

use crate::hmac_seal::Seal;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const VAULT_SIGNATURE_LEN: usize = 64;

/// Clave privada Ed25519 del sellador. No implementa Debug/Clone: nunca
/// debe terminar en un log, y compartirla implícitamente por un clone
/// descuidado sería exactamente el tipo de error que el no-repudio
/// pretende hacer imposible en primer lugar.
pub struct VaultSigningKey(SigningKey);

impl VaultSigningKey {
    /// Genera una clave nueva. La generación de claves Ed25519 no
    /// requiere aleatoriedad de calidad especial más allá de lo que
    /// cualquier CSPRNG estándar ya provee (9.5: a diferencia de ECDSA,
    /// Ed25519 no depende de aleatoriedad de alta calidad durante la
    /// FIRMA — la generación de la clave en sí sigue necesitando un
    /// buen CSPRNG, que es lo que rand::thread_rng() provee).
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        VaultSigningKey(SigningKey::generate(&mut csprng))
    }

    /// Reconstruye una clave de firma a partir de sus 32 bytes crudos —
    /// agregado en la fase de Adaptador HTTP (7.4/15.3): un Adaptador
    /// necesita persistir la clave de firma del servidor entre
    /// reinicios del proceso, no generar una nueva cada vez que
    /// arranca. Generar una nueva en cada arranque rompería el
    /// propósito de no-repudio a largo plazo que 15.3 describe: un
    /// verificador externo que ya conoce la clave pública de una
    /// sesión anterior dejaría de poder verificar firmas hechas antes
    /// de un reinicio del servidor. Simétrico a
    /// `VaultVerifyingKey::from_bytes`, que ya existía.
    ///
    /// No implementa `Debug` sobre los bytes de entrada en ningún
    /// punto de la firma — el llamador es responsable de no loguear el
    /// valor que le pasa a esta función, de la misma manera en que ya
    /// es responsable de eso con cualquier otro secreto (`LACRE_MASTER_KEY`,
    /// por ejemplo).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        VaultSigningKey(SigningKey::from_bytes(bytes))
    }

    /// Expone los 32 bytes crudos de la clave — necesario para que un
    /// Adaptador pueda persistirla (por ejemplo, en una variable de
    /// entorno o un archivo de configuración) entre reinicios. El
    /// llamador asume la misma responsabilidad de manejo de secretos
    /// que ya tiene sobre cualquier otro material de clave del
    /// proyecto: este método no decide dónde va a parar el resultado.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verifying_key(&self) -> VaultVerifyingKey {
        VaultVerifyingKey(self.0.verifying_key())
    }

    /// Firma el `Seal` (HMAC) de un fragmento — no el fragmento en sí,
    /// ver el razonamiento en el comentario de cabecera del módulo.
    pub fn sign_seal(&self, seal: &Seal) -> VaultSignature {
        VaultSignature(self.0.sign(&seal.0))
    }
}

/// Clave pública Ed25519 del verificador — se distribuye libremente,
/// a diferencia de `VaultSigningKey`.
#[derive(Clone, Copy)]
pub struct VaultVerifyingKey(VerifyingKey);

impl VaultVerifyingKey {
    pub fn verify_seal(&self, seal: &Seal, signature: &VaultSignature) -> bool {
        self.0.verify(&seal.0, &signature.0).is_ok()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, VaultKeyError> {
        VerifyingKey::from_bytes(bytes)
            .map(VaultVerifyingKey)
            .map_err(|_| VaultKeyError::InvalidPublicKeyBytes)
    }
}

#[derive(Debug)]
pub enum VaultKeyError {
    InvalidPublicKeyBytes,
}

/// Firma sobre un `Seal`, no sobre el fragmento. Tamaño fijo (64 bytes)
/// independiente del tamaño del fragmento firmado.
#[derive(Clone, Copy)]
pub struct VaultSignature(Signature);

impl VaultSignature {
    pub fn to_bytes(&self) -> [u8; VAULT_SIGNATURE_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; VAULT_SIGNATURE_LEN]) -> Self {
        VaultSignature(Signature::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal() -> Seal {
        Seal([0x42u8; SEAL_LEN])
    }

    #[test]
    fn valid_signature_verifies() {
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let seal = dummy_seal();

        let signature = signing_key.sign_seal(&seal);
        assert!(verifying_key.verify_seal(&seal, &signature));
    }

    /// No repudio en la práctica: una firma hecha con una clave no
    /// verifica bajo la clave pública de otra — a diferencia del HMAC
    /// de clave compartida, no hay forma de que el verificador (que
    /// solo tiene la clave pública) hubiera podido producir esta firma
    /// él mismo.
    #[test]
    fn signature_from_different_key_fails_verification() {
        let signer_a = VaultSigningKey::generate();
        let signer_b = VaultSigningKey::generate();
        let seal = dummy_seal();

        let signature = signer_a.sign_seal(&seal);
        let verifying_key_b = signer_b.verifying_key();

        assert!(!verifying_key_b.verify_seal(&seal, &signature));
    }

    /// Prueba 1 del Bloque IV, extendida a la firma: un sello alterado
    /// tras firmarse también debe fallar la verificación de la firma,
    /// no solo la del HMAC.
    #[test]
    fn tampered_seal_fails_signature_verification() {
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let original_seal = dummy_seal();
        let signature = signing_key.sign_seal(&original_seal);

        let mut tampered_seal = original_seal;
        tampered_seal.0[0] ^= 0x01;

        assert!(!verifying_key.verify_seal(&tampered_seal, &signature));
    }

    #[test]
    fn verifying_key_round_trips_through_bytes() {
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_bytes();
        let restored = VaultVerifyingKey::from_bytes(&bytes).unwrap();

        let seal = dummy_seal();
        let signature = signing_key.sign_seal(&seal);
        assert!(restored.verify_seal(&seal, &signature));
    }

    /// `VaultSigningKey::from_bytes`/`to_bytes` deben producir
    /// exactamente la misma clave privada — no solo "una clave válida
    /// cualquiera" — porque el caso de uso real (persistir la clave de
    /// firma del servidor entre reinicios, ver comentario de cabecera)
    /// exige que un verificador que ya conoce la clave pública de antes
    /// de un reinicio siga pudiendo verificar firmas hechas después de
    /// ese reinicio.
    #[test]
    fn signing_key_round_trips_through_bytes_producing_the_same_key() {
        let original = VaultSigningKey::generate();
        let original_verifying_key_bytes = original.verifying_key().to_bytes();
        let seal = dummy_seal();
        let signature_before_round_trip = original.sign_seal(&seal);

        let bytes = original.to_bytes();
        let restored = VaultSigningKey::from_bytes(&bytes);

        // La clave pública derivada de la clave restaurada debe ser
        // IDÉNTICA a la original — no una clave distinta que también
        // resulte válida.
        assert_eq!(restored.verifying_key().to_bytes(), original_verifying_key_bytes);

        // Una firma hecha con la clave restaurada debe verificar bajo
        // la clave pública original, y viceversa.
        let signature_after_round_trip = restored.sign_seal(&seal);
        let verifying_key = original.verifying_key();
        assert!(verifying_key.verify_seal(&seal, &signature_before_round_trip));
        assert!(verifying_key.verify_seal(&seal, &signature_after_round_trip));
    }
}

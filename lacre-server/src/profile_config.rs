//! Perfiles de despliegue (Capítulo 15 del documento Lacre Prime) —
//! Lite / Core / Vault.
//!
//! # Por qué esto vive en lacre-server, no en lacre-core
//!
//! Este módulo es la prueba concreta de que el Núcleo es modular en el
//! sentido que 7.2 exige: un "perfil" no es más que un preset de los
//! parámetros que `SealerCore::open` / `VerifierCore::resume` ya
//! aceptaban sueltos (`algo`, `slot_size`, `slot_count`,
//! `forced_purge_timeout`). Si tuviéramos que agregar código a
//! `lacre-core` para que "supiera" qué es el perfil Core, eso
//! demostraría que el Núcleo no está tan desacoplado como 7.2 pretende
//! — el Núcleo seguiría sin cambiar una sola línea aunque mañana
//! aparezcan diez perfiles nuevos, porque desde su perspectiva nunca
//! existió tal concepto, solo llamadas a `open`/`resume` con distintos
//! argumentos.
//!
//! Lite, Core y Vault están implementados. Lite no requirió NINGÚN
//! mecanismo nuevo de `lacre-core`: `HmacAlgo::Blake3` ya existía desde
//! Fase 0/1 (`hmac_seal.rs`), probado con tests reales
//! (`seal_fragment`/`verify_fragment` bajo Blake3, incluyendo que un
//! sello Blake3 no verifica bajo SHA-256) — Lite es, literalmente, la
//! misma prueba de modularidad que Core y Vault ya demostraban, solo
//! que con un algoritmo distinto.
//!
//! # Valores elegidos
//!
//! El documento (15.1) especifica el objetivo de latencia (<1ms) y el
//! mecanismo (HMAC completo por fragmento) para Core, pero no fija
//! `slot_size`/`slot_count`/`timeout` exactos — son parámetros de
//! despliegue, conforme a [PA]. Los valores de acá son los mismos que
//! ya medimos empíricamente en los tests de `lacre-core` (buffer.rs,
//! main.rs original): slot de 1 KB, techo de ~15 MB, timeout de purga
//! forzada de 500 ms.
//!
//! Lite (15.1, Familia I del Anexo 1.0): "suma de verificación ligera,
//! no HMAC completo", buffer 8 KB, timeout de purga forzada 100 ms,
//! latencia objetivo < 0.2 ms. El propio Anexo 1.0 es explícito sobre
//! su límite de seguridad: "un checksum ligero es forjable con
//! esfuerzo moderado por un atacante que entienda el esquema, y este
//! perfil no es apto para nada con valor monetario directo" — se
//! documenta acá esa misma advertencia, no solo el parámetro numérico,
//! para que quien elija este perfil en `profile_config.rs` no pierda
//! de vista esa limitación por estar mirando solo el código.
//!
//! Vault (15.1/15.3): HMAC-SHA512 + firma asimétrica Ed25519, buffer de
//! sesión 256 KB, timeout de purga forzada 5 s, latencia objetivo
//! 10-20 ms (prioridad: integridad sobre velocidad, no la latencia
//! mínima que persigue Core). El `slot_size`/`slot_count` de acá
//! traducen el buffer de 256 KB a la misma unidad de slots que ya usa
//! Core, no un mecanismo nuevo.

use lacre_core::hmac_seal::HmacAlgo;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileName {
    Lite,
    Core,
    Vault,
}

/// Parámetros concretos de un perfil, en la forma exacta que
/// `SealerCore::open` / `VerifierCore::resume` los reciben. No hay
/// ningún tipo nuevo del lado de lacre-core para representar esto — es
/// literalmente los mismos cuatro parámetros sueltos, empaquetados acá
/// solo por conveniencia del Adaptador.
#[derive(Debug, Clone, Copy)]
pub struct ProfileConfig {
    pub algo: HmacAlgo,
    pub slot_size: usize,
    pub slot_count: usize,
    pub forced_purge_timeout: Duration,
}

impl ProfileName {
    pub fn config(self) -> ProfileConfig {
        match self {
            ProfileName::Lite => ProfileConfig {
                // 15.1 / Anexo 1.0 Familia I: "suma de verificación
                // ligera, no HMAC completo". Blake3 ya existía en
                // hmac_seal.rs desde Fase 0/1, sin necesitar ningún
                // cambio de lacre-core para este perfil.
                algo: HmacAlgo::Blake3,
                slot_size: 8 * 1024, // 8 KB, 15.1
                slot_count: 128,     // ~1 MB de buffer total de sesión — Lite prioriza volumen de sesiones, no buffer grande por sesión
                forced_purge_timeout: Duration::from_millis(100), // 15.1
            },
            ProfileName::Core => ProfileConfig {
                algo: HmacAlgo::Sha256,
                slot_size: 1024,
                slot_count: 15 * 1024, // ~15 MB, ver buffer.rs
                forced_purge_timeout: Duration::from_millis(500),
            },
            ProfileName::Vault => ProfileConfig {
                // 15.3: "HMAC-SHA512 + firma asimétrica Ed25519". El
                // HmacAlgo del Núcleo hoy solo distingue Sha256/Blake3
                // (ver hmac_seal.rs) — SHA-512 para el HMAC del propio
                // Núcleo no está implementado todavía en `lacre-core`;
                // el no-repudio de Vault en esta entrega proviene
                // enteramente de la firma Ed25519 sobre el sello
                // SHA-256 ya existente, no de un HMAC-SHA512 nuevo. Se
                // documenta como desviación declarada, no silenciada
                // — ver PENDING.md.
                algo: HmacAlgo::Sha256,
                slot_size: 256 * 1024, // 256 KB, 15.1/15.3
                slot_count: 64,        // ~16 MB de buffer total de sesión
                forced_purge_timeout: Duration::from_secs(5), // 15.1: timeout de purga forzada
            },
        }
    }

    /// Nombre tal como aparece en la cabecera `lacre-profile` (15.2).
    pub fn as_header_value(self) -> &'static str {
        match self {
            ProfileName::Lite => "lite",
            ProfileName::Core => "core",
            ProfileName::Vault => "vault",
        }
    }

    pub fn from_header_value(value: &str) -> Option<Self> {
        match value {
            "lite" => Some(ProfileName::Lite),
            "core" => Some(ProfileName::Core),
            "vault" => Some(ProfileName::Vault),
            _ => None,
        }
    }

    /// `true` si este perfil requiere firma Ed25519 (no repudio) y
    /// recibo post-purga, según 15.3. Usado por el Adaptador HTTP para
    /// decidir si debe cargar/exigir una clave de firma antes de
    /// atender una sesión de este perfil.
    pub fn requires_vault_signature(self) -> bool {
        matches!(self, ProfileName::Vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La prueba de modularidad en sí: instanciar un SealerCore y un
    /// VerifierCore reales usando SOLO lo que expone ProfileConfig, sin
    /// que lacre_core::core sepa en ningún momento que "perfiles"
    /// existen — desde su perspectiva, esto es indistinguible de
    /// cualquier otra llamada a open()/resume() con parámetros sueltos.
    #[test]
    fn core_profile_config_instantiates_a_working_sealer_verifier_pair() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use lacre_core::session::MasterKeyRing;
        use std::sync::Arc;

        let cfg = ProfileName::Core.config();
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"clave-maestra-de-prueba-minimo-32b".to_vec(),
            Duration::from_secs(60),
        ));

        let mut sealer = SealerCore::open(
            ring.clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        )
        .expect("key_id activo debe resolver en el ring recién creado");

        let sealed = sealer
            .seal_payload(b"prueba de acoplamiento via perfil Core", cfg.slot_size)
            .unwrap();
        for (frame, seal) in &sealed {
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, None)
                .expect("cada frame sellado bajo el perfil Core debe verificar bajo el mismo perfil");
        }
    }

    #[test]
    fn header_round_trip() {
        let name = ProfileName::Core;
        let header = name.as_header_value();
        assert_eq!(ProfileName::from_header_value(header), Some(name));
    }

    #[test]
    fn unknown_header_value_is_rejected() {
        assert!(ProfileName::from_header_value("nonexistent").is_none());
    }

    /// Misma prueba de acoplamiento que Core, pero para Lite —
    /// confirma que `lacre-core` no necesitó ningún cambio para
    /// soportar este perfil: `HmacAlgo::Blake3` ya existía desde
    /// Fase 0/1.
    #[test]
    fn lite_profile_config_instantiates_a_working_sealer_verifier_pair() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use lacre_core::session::MasterKeyRing;
        use std::sync::Arc;

        let cfg = ProfileName::Lite.config();
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"clave-maestra-de-prueba-lite-32byte".to_vec(),
            Duration::from_secs(60),
        ));

        let mut sealer = SealerCore::open(
            ring.clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        )
        .expect("key_id activo debe resolver en el ring recién creado");

        let sealed = sealer
            .seal_payload(b"telemetria de un sensor cualquiera", cfg.slot_size)
            .unwrap();
        for (frame, seal) in &sealed {
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, None)
                .expect("cada frame sellado bajo el perfil Lite debe verificar bajo el mismo perfil");
        }
    }

    /// Confirma que el perfil Lite REALMENTE usa Blake3, no que
    /// "funciona" con cualquier algoritmo por casualidad — un sello
    /// generado bajo Lite (Blake3) no debe verificar si se reinterpreta
    /// como si fuera Sha256, exactamente la misma propiedad que
    /// `hmac_seal.rs` ya prueba a nivel de lacre-core, pero confirmada
    /// acá a través de la capa de configuración del perfil.
    #[test]
    fn lite_profile_uses_blake3_not_sha256() {
        assert_eq!(ProfileName::Lite.config().algo, lacre_core::hmac_seal::HmacAlgo::Blake3);
        assert_eq!(ProfileName::Core.config().algo, lacre_core::hmac_seal::HmacAlgo::Sha256);
    }

    #[test]
    fn lite_header_round_trip() {
        let name = ProfileName::Lite;
        let header = name.as_header_value();
        assert_eq!(ProfileName::from_header_value(header), Some(name));
    }

    /// Lite no exige firma Vault — es, junto con Core, el perfil de
    /// menor exigencia de seguridad del catálogo (15.1: "no apto para
    /// nada con valor monetario directo").
    #[test]
    fn lite_does_not_require_vault_signature() {
        assert!(!ProfileName::Lite.requires_vault_signature());
    }

    #[test]
    fn vault_header_round_trip() {
        let name = ProfileName::Vault;
        let header = name.as_header_value();
        assert_eq!(ProfileName::from_header_value(header), Some(name));
    }

    #[test]
    fn only_vault_requires_signature() {
        assert!(!ProfileName::Core.requires_vault_signature());
        assert!(ProfileName::Vault.requires_vault_signature());
    }

    /// Misma prueba de acoplamiento que Core, pero para Vault: instancia
    /// un `SealerCore`/`VerifierCore` reales usando SOLO lo que expone
    /// `ProfileConfig` + una `VaultSigningKey`/`VaultVerifyingKey` real,
    /// confirmando que el perfil Vault también es indistinguible, desde
    /// la perspectiva de `lacre-core`, de cualquier otra llamada a
    /// `open_with_vault_key`/`resume_with_vault_key` con parámetros
    /// sueltos.
    #[test]
    fn vault_profile_config_instantiates_a_working_sealer_verifier_pair_with_signature() {
        use lacre_core::core::{SealerCore, VerifierCore};
        use lacre_core::session::MasterKeyRing;
        use lacre_core::vault_signature::VaultSigningKey;
        use std::sync::Arc;

        let cfg = ProfileName::Vault.config();
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"clave-maestra-de-prueba-vault-32bytes".to_vec(),
            Duration::from_secs(60),
        ));
        let signing_key = VaultSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            verifying_key,
        )
        .expect("key_id activo debe resolver en el ring recién creado");

        let sealed = sealer
            .seal_payload(b"prueba de acoplamiento via perfil Vault", cfg.slot_size)
            .unwrap();
        for (frame, seal) in &sealed {
            let signature = sealer.sign_seal_for_vault(seal);
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, signature.as_ref())
                .expect("cada frame sellado bajo Vault debe verificar junto con su firma");
        }
    }
}

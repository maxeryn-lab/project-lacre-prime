//! `LacreFrame`: la unidad de transporte del protocolo Lacre.
//!
//! # Frame inmutable, estado separado
//!
//! `LacreFrame` es identidad + datos, y nunca cambia una vez creado.
//! Lo que progresa no es el frame — es lo que cada rol *sabe* sobre él.
//! Esa separación evita repetir el problema que ya encontramos con
//! `Session` en server.rs: mezclar "quién es esto" con "qué estamos
//! haciendo con esto ahora" produjo un bug real (sellador y verificador
//! confundidos en una sola entidad). Acá el mismo dato — el frame — puede
//! tener dos trazas de evidencia independientes (`SealerFrameState` y
//! `VerifierFrameState`) sin que ninguna de las dos posea ni mute al
//! frame que describen.
//!
//! # Solo transporte, no mensaje
//!
//! El ciclo de vida de un `LacreFrame` termina en `Purged`: es una
//! unidad de transporte, no el mensaje completo. El concepto de
//! "commit" pertenece al `Payload` reensamblado (ver protocol.rs), no a
//! cada fragmento — dos niveles de granularidad distintos que no se
//! mezclan en el mismo enum.
//!
//! # Por qué el estado referencia al frame por clave, no por posesión
//!
//! `SealerFrameState`/`VerifierFrameState` no envuelven un `LacreFrame`
//! ni lo poseen: lo identifican por `(session_id, index)`. Envolverlo
//! rompería la premisa de que el frame es un dato compartido, no
//! propiedad exclusiva de un estado — dos roles (o dos observadores,
//! p. ej. para auditoría) pueden tener su propia traza de estado sobre
//! el mismo frame sin clonarlo ni pelear por su dueño.

use crate::hmac_seal::Seal;
use crate::session::SessionId;

/// Identidad + datos de un fragmento del protocolo Lacre. Inmutable: una
/// vez construido, ningún campo cambia. Lo que cambia con el tiempo es
/// el estado que cada rol registra *sobre* este frame (ver
/// `SealerFrameState` / `VerifierFrameState`), nunca el frame mismo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LacreFrame {
    pub session_id: SessionId,
    /// Posición en la secuencia. Coincide con el índice que `engine.rs`
    /// usa como parte de Sᵢ — Bloque II.3 del documento.
    pub index: u64,
    /// Si se conoce el número total de fragmentos en el momento de
    /// crear este frame. `None` es válido y esperado en streaming
    /// continuo (perfil Stream, Bloque III), donde el total no se sabe
    /// hasta que aparece el último fragmento.
    pub total_fragments: Option<u64>,
    /// Si este es el último fragmento de la secuencia. A diferencia de
    /// `total_fragments`, siempre es determinable en el momento de
    /// emitir el frame, en cualquier perfil.
    pub is_last: bool,
    pub payload: Vec<u8>,
}

impl LacreFrame {
    /// Clave de identidad de este frame, usada para indexar su estado
    /// en los mapas de `protocol.rs`. No es un id nuevo: es literalmente
    /// `(session_id, index)`, que ya identifica al frame de forma única
    /// dentro de una sesión.
    pub fn key(&self) -> (SessionId, u64) {
        (self.session_id, self.index)
    }
}

/// Ciclo de vida de un `LacreFrame` desde la perspectiva del sellador.
/// Nunca visita un estado de verificación: el sellador no verifica su
/// propio sello, solo lo produce y espera confirmación de entrega.
///
/// Transiciones válidas, solo hacia adelante:
///   Raw → Sealed → Committed → Purged
///
/// Cada método de transición consume `self` y solo existe en el estado
/// desde el que es legal partir — el compilador rechaza un retroceso o
/// un salto de estado, no una convención de quien llama.
#[derive(Debug, Clone)]
pub enum SealerFrameState {
    /// El frame fue producido (fragmentado) pero aún no sellado.
    Raw,
    /// Sellado y a la espera de ACK. Guarda el sello para que el
    /// transporte lo envíe en cabecera junto al payload.
    Sealed { seal: Seal },
    /// ACK recibido: el receptor confirmó recepción íntegra.
    Committed,
    /// Liberado del buffer — por ACK o por timeout de purga forzada.
    Purged,
}

impl SealerFrameState {
    pub fn new() -> Self {
        SealerFrameState::Raw
    }

    /// Raw → Sealed. Solo válido desde `Raw`.
    pub fn seal(self, seal: Seal) -> Result<Self, FrameStateError> {
        match self {
            SealerFrameState::Raw => Ok(SealerFrameState::Sealed { seal }),
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "seal",
            }),
        }
    }

    /// Sealed → Committed. Solo válido desde `Sealed`.
    pub fn commit(self) -> Result<Self, FrameStateError> {
        match self {
            SealerFrameState::Sealed { .. } => Ok(SealerFrameState::Committed),
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "commit",
            }),
        }
    }

    /// Sealed → Purged (timeout) o Committed → Purged (tras ACK).
    /// `Raw → Purged` no es válido: no tiene sentido purgar algo que
    /// nunca se selló ni se intentó entregar.
    pub fn purge(self) -> Result<Self, FrameStateError> {
        match self {
            SealerFrameState::Sealed { .. } | SealerFrameState::Committed => {
                Ok(SealerFrameState::Purged)
            }
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "purge",
            }),
        }
    }
}

impl Default for SealerFrameState {
    fn default() -> Self {
        SealerFrameState::new()
    }
}

/// Ciclo de vida de un `LacreFrame` desde la perspectiva del
/// verificador. Nunca visita un estado de sellado: el verificador
/// recibe el frame ya sellado desde afuera; lo que hace es verificar,
/// no producir el sello.
///
/// Transiciones válidas, solo hacia adelante:
///   Raw → Verified → Purged
///
/// No hay `Committed` a nivel de frame — eso pertenece al `Payload`
/// reensamblado completo (protocol.rs), no a cada fragmento individual.
#[derive(Debug, Clone)]
pub enum VerifierFrameState {
    /// El frame llegó pero todavía no se verificó su sello.
    Raw,
    /// El sello fue verificado con éxito contra Sᵢ.
    Verified,
    /// Liberado del buffer tras haber sido incorporado al reensamblado
    /// (o por timeout si nunca llegó a verificarse).
    Purged,
}

impl VerifierFrameState {
    pub fn new() -> Self {
        VerifierFrameState::Raw
    }

    /// Raw → Verified. Solo válido desde `Raw`.
    pub fn verify(self) -> Result<Self, FrameStateError> {
        match self {
            VerifierFrameState::Raw => Ok(VerifierFrameState::Verified),
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "verify",
            }),
        }
    }

    /// Raw → Purged (nunca llegó a verificarse, p. ej. timeout con el
    /// sello corrupto) o Verified → Purged (caso normal, tras
    /// incorporarse al reensamblado).
    pub fn purge(self) -> Result<Self, FrameStateError> {
        match self {
            VerifierFrameState::Raw | VerifierFrameState::Verified => {
                Ok(VerifierFrameState::Purged)
            }
            other => Err(FrameStateError::InvalidTransition {
                from: format!("{:?}", other),
                attempted: "purge",
            }),
        }
    }
}

impl Default for VerifierFrameState {
    fn default() -> Self {
        VerifierFrameState::new()
    }
}

#[derive(Debug)]
pub enum FrameStateError {
    InvalidTransition {
        from: String,
        attempted: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal() -> Seal {
        Seal([0u8; SEAL_LEN])
    }

    #[test]
    fn sealer_happy_path_advances_through_all_states() {
        let s = SealerFrameState::new();
        let s = s.seal(dummy_seal()).unwrap();
        let s = s.commit().unwrap();
        let s = s.purge().unwrap();
        assert!(matches!(s, SealerFrameState::Purged));
    }

    #[test]
    fn sealer_cannot_skip_sealed_to_commit() {
        let s = SealerFrameState::new();
        let res = s.commit();
        assert!(res.is_err());
    }

    #[test]
    fn sealer_cannot_purge_raw() {
        let s = SealerFrameState::new();
        let res = s.purge();
        assert!(res.is_err());
    }

    #[test]
    fn sealer_can_purge_directly_from_sealed_on_timeout() {
        // No todo Sealed llega a Committed: un timeout de purga forzada
        // puede liberar un frame que nunca recibió ACK.
        let s = SealerFrameState::new().seal(dummy_seal()).unwrap();
        let res = s.purge();
        assert!(res.is_ok());
    }

    #[test]
    fn sealer_cannot_seal_twice() {
        let s = SealerFrameState::new().seal(dummy_seal()).unwrap();
        let res = s.seal(dummy_seal());
        assert!(res.is_err());
    }

    #[test]
    fn verifier_happy_path_advances_through_all_states() {
        let s = VerifierFrameState::new();
        let s = s.verify().unwrap();
        let s = s.purge().unwrap();
        assert!(matches!(s, VerifierFrameState::Purged));
    }

    #[test]
    fn verifier_cannot_verify_twice() {
        let s = VerifierFrameState::new().verify().unwrap();
        let res = s.verify();
        assert!(res.is_err());
    }

    #[test]
    fn verifier_can_purge_directly_from_raw_on_timeout() {
        // Un frame cuyo sello nunca llegó a verificarse (p. ej. timeout,
        // o descartado antes de intentar) también puede purgarse.
        let s = VerifierFrameState::new();
        let res = s.purge();
        assert!(res.is_ok());
    }

    #[test]
    fn frame_is_immutable_and_key_matches_identity() {
        let frame = LacreFrame {
            session_id: SessionId([0u8; crate::session::SESSION_ID_LEN]),
            index: 7,
            total_fragments: Some(10),
            is_last: false,
            payload: vec![1, 2, 3],
        };
        assert_eq!(frame.key(), (frame.session_id, 7));
    }
}

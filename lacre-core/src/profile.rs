//! Profiles — Capítulo 7.3 de Lacre Prime.
//!
//! Componentes de extensión que operan sobre frames **ya verificados
//! por el Núcleo**. A diferencia del Núcleo (invariante, 7.2), no se
//! espera que los Profiles permanezcan estables: son la superficie de
//! extensibilidad del sistema. Cada Profile declara `TOUCHES_PAYLOAD`
//! (7.3.1) — si su función implica acceder al contenido del fragmento,
//! no solo a su cabecera de identidad.
//!
//! # ReassembleProfile: el primer Profile concreto
//!
//! Reconstruye el payload completo a partir de una secuencia de frames
//! ya verificados. Es la migración directa de lo que en la iteración
//! anterior vivía dentro de `protocol::VerifierProtocol`
//! (`pending_ahead`, `verified_payloads`, `try_reassemble`) — la lógica
//! no cambió, cambió su ubicación: 8.1 es explícito en que el
//! reensamblado "no corresponde al Núcleo sino a una capa de Profile
//! específica", así que se reclasifica como Profile en vez de como
//! parte del flujo central de verificación.
//!
//! `TOUCHES_PAYLOAD = true`: literalmente reconstruye el contenido a
//! partir de sus fragmentos — es la definición misma de tocar el
//! payload.

use crate::frame::LacreFrame;
use std::collections::{BTreeMap, HashMap};

pub trait Profile {
    const TOUCHES_PAYLOAD: bool;
}

/// Frame ya verificado por el Núcleo, pero que este Profile todavía no
/// puede incorporar al reensamblado porque llegó antes que un índice
/// anterior. El Núcleo certificó su integridad (`verify_frame` ya
/// devolvió Ok antes de que este frame llegue acá) — lo que falta no es
/// verificación, es orden de llegada para el propósito de este Profile.
struct HeldFrame {
    payload: Vec<u8>,
    is_last: bool,
}

/// Reconstruye un payload completo a partir de frames ya verificados
/// por `core::VerifierCore`. No repite verificación de ningún tipo —
/// asume que todo lo que recibe en `accept` ya pasó por
/// `VerifierCore::verify_frame` con éxito. Su única responsabilidad es
/// ordenar y concatenar.
pub struct ReassembleProfile {
    verified_payloads: BTreeMap<u64, Vec<u8>>,
    /// Frames verificados por el Núcleo pero que llegaron a este
    /// Profile con índice mayor al esperado — puede ocurrir si el
    /// Adaptador de transporte entrega frames al Profile en un orden
    /// distinto al que el Núcleo los verificó (p. ej. paralelismo en el
    /// transporte). Se retienen aquí, no en el Núcleo.
    held_ahead: HashMap<u64, HeldFrame>,
    next_expected: u64,
    total_fragments: Option<u64>,
    reassembled: bool,
}

impl Profile for ReassembleProfile {
    const TOUCHES_PAYLOAD: bool = true;
}

pub enum AcceptOutcome {
    /// El frame se incorporó a la secuencia reensamblada.
    Accepted,
    /// Ya se había incorporado antes (índice < next_expected).
    DuplicateIgnored,
    /// Llegó antes de que le tocara el turno; retenido para más tarde.
    HeldAhead,
}

impl ReassembleProfile {
    pub fn new() -> Self {
        ReassembleProfile {
            verified_payloads: BTreeMap::new(),
            held_ahead: HashMap::new(),
            next_expected: 0,
            total_fragments: None,
            reassembled: false,
        }
    }

    /// Incorpora un frame ya verificado por el Núcleo. `frame` debe
    /// haber pasado por `VerifierCore::verify_frame` con éxito antes de
    /// llegar acá — este método no verifica nada, solo ordena.
    pub fn accept(&mut self, frame: LacreFrame) -> AcceptOutcome {
        if frame.index < self.next_expected {
            return AcceptOutcome::DuplicateIgnored;
        }
        if frame.index > self.next_expected {
            self.held_ahead.insert(
                frame.index,
                HeldFrame {
                    payload: frame.payload,
                    is_last: frame.is_last,
                },
            );
            return AcceptOutcome::HeldAhead;
        }

        self.insert_one(frame.index, frame.payload, frame.is_last);

        // Procesar en cadena cualquier frame retenido que ahora es el
        // próximo esperado.
        loop {
            match self.held_ahead.remove(&self.next_expected) {
                Some(HeldFrame { payload, is_last }) => {
                    self.insert_one(self.next_expected, payload, is_last)
                }
                None => break,
            }
        }

        AcceptOutcome::Accepted
    }

    fn insert_one(&mut self, index: u64, payload: Vec<u8>, is_last: bool) {
        if is_last {
            self.total_fragments = Some(index + 1);
        }
        self.verified_payloads.insert(index, payload);
        self.next_expected = index + 1;
    }

    /// Reensambla el payload completo si la secuencia está contigua y
    /// completa; `None` si todavía faltan frames. Reensambla una sola
    /// vez: llamadas posteriores tras un éxito devuelven `None`.
    pub fn try_reassemble(&mut self) -> Option<Vec<u8>> {
        if self.reassembled {
            return None;
        }
        let total = self.total_fragments?;
        if self.verified_payloads.len() as u64 != total {
            return None;
        }
        self.reassembled = true;
        Some(self.verified_payloads.values().cloned().flatten().collect())
    }
}

impl Default for ReassembleProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{SealerCore, VerifierCore};
    use crate::hmac_seal::HmacAlgo;
    use crate::session::{MasterKeyRing, SessionId};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"clave-maestra-de-prueba-minimo-32b".to_vec(),
            Duration::from_secs(60),
        ))
    }

    /// Flujo completo real: Núcleo sella y verifica, Profile reensambla
    /// — confirmando que la separación de capas efectivamente funciona
    /// de punta a punta, no solo en aislamiento.
    #[test]
    fn core_verifies_then_profile_reassembles() {
        let ring = test_ring();
        let mut sealer = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
        )
        .unwrap();

        let original = b"el zorro veloz salta sobre el perro perezoso".to_vec();
        let sealed = sealer.seal_payload(&original, 8).unwrap();

        let mut profile = ReassembleProfile::new();
        for (frame, seal) in sealed {
            verifier
                .verify_frame(&frame, ring.active_key_id(), &seal, None)
                .expect("el Núcleo debe verificar cada frame");
            let outcome = profile.accept(frame);
            assert!(matches!(outcome, AcceptOutcome::Accepted));
        }

        let reassembled = profile.try_reassemble().expect("secuencia completa");
        assert_eq!(reassembled, original);
        assert!(profile.try_reassemble().is_none());
    }

    #[test]
    fn out_of_order_frames_are_held_then_chained() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(2),
            is_last: false,
            payload: b"primera".to_vec(),
        };
        let frame1 = LacreFrame {
            session_id: sid,
            index: 1,
            total_fragments: Some(2),
            is_last: true,
            payload: b"segunda".to_vec(),
        };

        let mut profile = ReassembleProfile::new();
        assert!(matches!(
            profile.accept(frame1.clone()),
            AcceptOutcome::HeldAhead
        ));
        assert!(matches!(
            profile.accept(frame0.clone()),
            AcceptOutcome::Accepted
        ));

        let reassembled = profile.try_reassemble().expect("secuencia completa");
        assert_eq!(reassembled, b"primerasegunda".to_vec());
    }

    #[test]
    fn duplicate_frame_is_ignored() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"unico".to_vec(),
        };

        let mut profile = ReassembleProfile::new();
        assert!(matches!(
            profile.accept(frame0.clone()),
            AcceptOutcome::Accepted
        ));
        assert!(matches!(
            profile.accept(frame0),
            AcceptOutcome::DuplicateIgnored
        ));
    }

    #[test]
    fn reassembly_refuses_while_gap_remains() {
        let sid = SessionId::generate();
        let frame0 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: Some(3),
            is_last: false,
            payload: b"aaaa".to_vec(),
        };
        let frame2 = LacreFrame {
            session_id: sid,
            index: 2,
            total_fragments: Some(3),
            is_last: true,
            payload: b"cccc".to_vec(),
        };

        let mut profile = ReassembleProfile::new();
        profile.accept(frame0);
        profile.accept(frame2); // queda HeldAhead, falta el índice 1

        assert!(profile.try_reassemble().is_none());
    }

    /// Streaming: frames con total_fragments=None (como los produce
    /// SealerCore::seal_chunk, ver core.rs) hasta que llega el marcado
    /// is_last. El Profile no debe intentar reensamblar mientras el
    /// total sea desconocido, ni siquiera tras aceptar varios frames
    /// consecutivos sin huecos.
    #[test]
    fn streaming_frames_with_unknown_total_do_not_reassemble_early() {
        let sid = SessionId::generate();
        let token1 = LacreFrame {
            session_id: sid,
            index: 0,
            total_fragments: None, // desconocido, como en streaming real
            is_last: false,
            payload: b"El".to_vec(),
        };
        let token2 = LacreFrame {
            session_id: sid,
            index: 1,
            total_fragments: None,
            is_last: false,
            payload: b" cielo".to_vec(),
        };
        let token3 = LacreFrame {
            session_id: sid,
            index: 2,
            total_fragments: None,
            is_last: true, // recién acá se sabe que el stream terminó
            payload: b" es azul".to_vec(),
        };

        let mut profile = ReassembleProfile::new();
        profile.accept(token1);
        // Tras el primer token, ni siquiera hay total_fragments
        // conocido — no debe haber nada que reensamblar todavía.
        assert!(profile.try_reassemble().is_none());

        profile.accept(token2);
        assert!(profile.try_reassemble().is_none());

        profile.accept(token3);
        let reassembled = profile
            .try_reassemble()
            .expect("is_last en el tercer token debe habilitar el reensamblado");
        assert_eq!(reassembled, b"El cielo es azul".to_vec());
    }
}

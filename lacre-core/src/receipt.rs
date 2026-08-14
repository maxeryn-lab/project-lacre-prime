//! Recibo post-purga — Sección 7.5 del documento Lacre Prime, `[DO]`.
//!
//! Cita textual del requisito: "un valor derivado del sello del
//! fragmento — no del contenido mismo, ni recuperable hacia él — que se
//! conserva en un registro de solo adición (append-only) tras la purga
//! del fragmento y su sello original."
//!
//! # Decisión de ingeniería no especificada por el documento
//!
//! 7.5 no fija el mecanismo exacto de derivación. Esta implementación
//! usa `receipt = SHA-256(seal)` — un hash simple de los 32 bytes del
//! sello, sin tocar `frame.payload` en ningún momento. Cumple los tres
//! requisitos literales del texto:
//!   - "derivado del sello": la entrada es exclusivamente `Seal::0`.
//!   - "no del contenido mismo": el fragmento nunca entra a esta función.
//!   - "no recuperable hacia él": SHA-256 es de un solo sentido; no hay
//!     forma de reconstruir el `Seal` original a partir del recibo, y
//!     mucho menos el fragmento que ese sello certificaba.
//!
//! Si la práctica revela que se necesita un mecanismo distinto (por
//! ejemplo, un HMAC con clave de auditoría separada en vez de un hash
//! simple, para que el recibo mismo no sea falsificable por quien no
//! tiene esa clave), el documento se actualiza para reflejarlo — no al
//! revés (mismo criterio que ya se aplicó a la firma Ed25519 en
//! vault_signature.rs).

use crate::hmac_seal::Seal;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub const RECEIPT_LEN: usize = 32;

/// El recibo en sí: 32 bytes derivados del sello, sin relación
/// recuperable hacia el fragmento original.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt(pub [u8; RECEIPT_LEN]);

pub fn derive_receipt(seal: &Seal) -> Receipt {
    let mut hasher = Sha256::new();
    hasher.update(seal.0);
    let result = hasher.finalize();
    let mut out = [0u8; RECEIPT_LEN];
    out.copy_from_slice(&result);
    Receipt(out)
}

/// Una entrada del registro: el recibo más el índice de fragmento al
/// que corresponde (para poder ubicarlo dentro de la secuencia de la
/// sesión sin necesitar el fragmento ni el sello originales) y el
/// momento en que se generó, relativo al inicio del registro — mismo
/// criterio de compacidad que ya se usó en `buffer::Slot`
/// (milisegundos en `u32`, no un `Instant` completo de 16 bytes).
#[derive(Debug, Clone, Copy)]
pub struct ReceiptEntry {
    pub fragment_index: u64,
    pub receipt: Receipt,
    pub purged_at_ms: u32,
}

/// Registro append-only de recibos. Solo tiene una operación de
/// escritura (`record`) y una de lectura completa (`entries`) — no hay
/// forma de eliminar ni modificar una entrada ya registrada, lo cual es
/// literalmente lo que "de solo adición" significa en 7.5: si hiciera
/// falta borrar un recibo, eso ya no sería un registro de auditoría.
pub struct ReceiptLog {
    entries: Vec<ReceiptEntry>,
    epoch: Instant,
}

impl ReceiptLog {
    pub fn new() -> Self {
        ReceiptLog {
            entries: Vec::new(),
            epoch: Instant::now(),
        }
    }

    /// Registra el recibo de un fragmento en el momento de su purga.
    /// Se llama exclusivamente desde el punto de purga del Núcleo — no
    /// existe una vía para registrar un recibo de un fragmento que
    /// todavía no se purgó, porque el propósito del recibo es
    /// específicamente sobrevivir a la purga, no anticiparse a ella.
    pub fn record(&mut self, fragment_index: u64, seal: &Seal) {
        let receipt = derive_receipt(seal);
        let elapsed_ms = self.epoch.elapsed().as_millis().min(u32::MAX as u128) as u32;
        self.entries.push(ReceiptEntry {
            fragment_index,
            receipt,
            purged_at_ms: elapsed_ms,
        });
    }

    pub fn entries(&self) -> &[ReceiptEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReceiptLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal(byte: u8) -> Seal {
        Seal([byte; SEAL_LEN])
    }

    #[test]
    fn same_seal_produces_same_receipt() {
        let seal = dummy_seal(0x42);
        let r1 = derive_receipt(&seal);
        let r2 = derive_receipt(&seal);
        assert_eq!(r1.0, r2.0);
    }

    #[test]
    fn different_seals_produce_different_receipts() {
        let seal_a = dummy_seal(0x01);
        let seal_b = dummy_seal(0x02);
        assert_ne!(derive_receipt(&seal_a).0, derive_receipt(&seal_b).0);
    }

    /// El recibo nunca es igual al sello del que se derivó — si lo
    /// fuera, "no recuperable hacia él" no tendría sentido (el sello
    /// mismo ya sería el recibo, exponiendo directamente el HMAC
    /// original en el registro de auditoría).
    #[test]
    fn receipt_is_not_the_seal_itself() {
        let seal = dummy_seal(0x77);
        let receipt = derive_receipt(&seal);
        assert_ne!(receipt.0, seal.0);
    }

    #[test]
    fn log_records_entries_in_order() {
        let mut log = ReceiptLog::new();
        log.record(0, &dummy_seal(0x01));
        log.record(1, &dummy_seal(0x02));
        log.record(2, &dummy_seal(0x03));

        assert_eq!(log.len(), 3);
        let entries = log.entries();
        assert_eq!(entries[0].fragment_index, 0);
        assert_eq!(entries[1].fragment_index, 1);
        assert_eq!(entries[2].fragment_index, 2);
    }

    #[test]
    fn empty_log_starts_empty() {
        let log = ReceiptLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }
}

//! Post-purge receipt — Section 7.5 of the Lacre Prime document, `[DO]`.
//!
//! Literal quote of the requirement: "a value derived from the
//! fragment's seal — not from the content itself, nor recoverable
//! back to it — that is kept in an append-only log after the purge of
//! the fragment and its original seal."
//!
//! # Engineering decision not specified by the document
//!
//! 7.5 does not fix the exact derivation mechanism. This
//! implementation uses `receipt = SHA-256(seal)` — a simple hash of
//! the seal's 32 bytes, never touching `frame.payload` at any point.
//! It satisfies the text's three literal requirements:
//!   - "derived from the seal": the input is exclusively `Seal::0`.
//!   - "not from the content itself": the fragment never enters this
//!     function.
//!   - "not recoverable back to it": SHA-256 is one-way; there is no
//!     way to reconstruct the original `Seal` from the receipt, let
//!     alone the fragment that seal certified.
//!
//! If practice reveals a different mechanism is needed (for example,
//! an HMAC with a separate audit key instead of a simple hash, so the
//! receipt itself isn't forgeable by someone without that key), the
//! document gets updated to reflect it — not the other way around
//! (same principle already applied to the Ed25519 signature in
//! `vault_signature.rs`).

use crate::hmac_seal::Seal;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub const RECEIPT_LEN: usize = 32;

/// The receipt itself: 32 bytes derived from the seal, with no
/// recoverable relationship to the original fragment.
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

/// A single log entry: the receipt plus the fragment index it
/// corresponds to (so it can be located within the session's sequence
/// without needing the original fragment or seal) and the moment it
/// was generated, relative to the log's own start — same compactness
/// criterion already used in `buffer::Slot` (milliseconds as `u32`,
/// not a full 16-byte `Instant`).
#[derive(Debug, Clone, Copy)]
pub struct ReceiptEntry {
    pub fragment_index: u64,
    pub receipt: Receipt,
    pub purged_at_ms: u32,
}

/// Append-only receipt log. Only has one write operation (`record`)
/// and one full-read operation (`entries`) — there is no way to
/// delete or modify an already-recorded entry, which is literally what
/// "append-only" means in 7.5: if it were ever necessary to delete a
/// receipt, this would no longer be an audit log.
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

    /// Records a fragment's receipt at the moment of its purge. Called
    /// exclusively from the Core's own purge point — there is no path
    /// to record a receipt for a fragment that hasn't been purged yet,
    /// because the receipt's whole purpose is specifically to survive
    /// the purge, not to anticipate it.
    /// Records a receipt already derived by the caller (wire v2: the receipt
    /// depends on the suite and the tag length, not on a 32-byte `Seal`).
    pub fn record_receipt(&mut self, fragment_index: u64, receipt: Receipt) {
        let elapsed_ms = self.epoch.elapsed().as_millis().min(u32::MAX as u128) as u32;
        self.entries.push(ReceiptEntry { fragment_index, receipt, purged_at_ms: elapsed_ms });
    }

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

    /// The receipt is never equal to the seal it was derived from — if
    /// it were, "not recoverable back to it" would be meaningless (the
    /// seal itself would already be the receipt, directly exposing the
    /// original HMAC in the audit log).
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

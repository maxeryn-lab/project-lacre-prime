//! In-RAM circular buffer for in-flight fragments, with explicit purge.
//!
//! Two quantified promises from the document live here, and both are
//! measured in this module, not just declared:
//!   - B ≤ 15 MB per session (safety ceiling raised from the original
//!     10 MB for better tolerance; the buffer is preallocated, never
//!     grows beyond that value).
//!   - Synchronous purge on ACK: `Erase(δᵢ, fᵢ)` happens in the same
//!     flow, not in a separate cleanup cycle.
//!
//! # From HashMap to a preallocated slab
//!
//! The first version of this module used a `HashMap<FragmentIndex,
//! PendingFragment>` with its own `Vec<u8>` per fragment. Measured in
//! practice (see the smoke test in main.rs), a buffer with
//! `used_bytes` at its logical ceiling cost ~19% more real RSS: each
//! fragment carried its own heap allocation plus the hash table's
//! overhead.
//!
//! This version preallocates a single `Vec<u8>` of `capacity_bytes` at
//! construction time (`vec![0u8; capacity_bytes]`, a single
//! allocation) and subdivides it into fixed-size slots (`slot_size`).
//! Each slot holds one whole fragment; free indices are tracked in a
//! free-list (`Vec<usize>`) instead of a hash map. This is what
//! "circular buffer with read/write pointers" describes in Block II of
//! the document — the previous version had the right name but a
//! sparse-map structure.
//!
//! Cost of the change: fragments must fit within `slot_size` (rejected
//! if they don't, same as before when they exceeded total capacity),
//! and there's internal fragmentation if the real fragment is smaller
//! than the slot. This is acceptable because fragment size is already
//! a fixed parameter per profile (Block III): this isn't a buffer of
//! arbitrary sizes, it's a buffer of one profile's fragments with a
//! size known in advance.

use crate::hmac_seal::Seal;
use std::time::{Duration, Instant};

/// Fragment identifier within a session. Corresponds to index i in
/// fᵢ — not a global ID, it's the position in the sequence.
pub type FragmentIndex = u64;

#[derive(Debug)]
pub enum BufferError {
    /// The fragment doesn't fit in one of this buffer's slots.
    FragmentTooLarge { fragment_len: usize, slot_size: usize },
    /// Every preallocated slot is occupied; no new one is created.
    NoSlotsAvailable,
    /// A fragment with this index is already pending: the index is the
    /// lookup key, so accepting it twice would orphan the first slot.
    DuplicateIndex { index: FragmentIndex },
    /// A v2 tag whose length differs from the one this buffer was built for.
    /// The buffer never truncates or pads a tag.
    TagLengthMismatch { expected: usize, got: usize },
}

/// "Free slot" marker for `occupant`. FragmentIndex is u64; reserving
/// the maximum value as a sentinel avoids the 16 bytes of an
/// `Option<u64>` (Rust has no niche optimization for an arbitrary u64)
/// at the cost of losing a single index value that in practice is
/// never used — 2⁶⁴-1 fragments in a session isn't a real scenario.
const EMPTY_SLOT: FragmentIndex = FragmentIndex::MAX;

/// Empty slot or one holding a fragment pending ACK. `occupant ==
/// EMPTY_SLOT` is the "free, ready for the next insert" state.
///
/// Size chosen deliberately to minimize per-slot metadata (measured:
/// dropped from 72 to 48 bytes versus an unadjusted version with
/// `usize`/`Instant`/`Option<u64>` — see the smoke test in main.rs for
/// the real RSS impact). Each field uses the smallest type the problem
/// actually needs, not a compression algorithm: there's no redundancy
/// to compress in a timestamp or a length that already occupy their
/// minimum.
struct Slot {
    /// How many bytes of `region` (from the start of the slot) are
    /// real fragment data. u32 is more than enough: the largest slot
    /// size of any profile (Block III, Space profile: 1 MB) fits many
    /// times over in 4 GB.
    len: u32,
    seal: Seal,
    /// Milliseconds elapsed since the buffer was created, not an
    /// absolute system timestamp. A full `Instant` (16 bytes) is
    /// overkill: a buffer with a forced purge timeout on the order of
    /// seconds needs neither nanosecond precision nor a range of
    /// years; u32 in milliseconds covers ~49 days of continuous
    /// session, well above any defined profile timeout (500 ms–30 s).
    inserted_at_ms: u32,
    occupant: FragmentIndex,
}

/// Preallocated circular buffer for a single active session.
///
/// Real preallocation: `region` is a single `Vec<u8>` of
/// `slot_size * slot_count` bytes, allocated once in `new`. No
/// subsequent operation grows `region` — an insert that doesn't fit
/// into a free slot is rejected, not handled by allocating more
/// memory.
pub struct PendingBuffer {
    region: Vec<u8>,
    slot_size: usize,
    slots: Vec<Slot>,
    /// Indices of free slots, used as a stack (LIFO): the next insert
    /// takes the most recently freed one, keeping hot access on the
    /// same memory pages instead of scattering it.
    free_slots: Vec<usize>,
    /// Index → slot lookup, so ACK and `seal_of` are O(1) instead of a
    /// linear scan over every slot. Preallocated to `slot_count`: it never
    /// holds more entries than there are slots, so it never reallocates.
    by_index: std::collections::HashMap<FragmentIndex, usize>,
    forced_purge_timeout: Duration,
    /// Time reference for `inserted_at_ms`. Every timestamp in this
    /// buffer is relative to this instant.
    epoch: Instant,
    /// Length of the variable-length tags (wire v2) kept per slot; 0 for the
    /// v1 buffer, which keeps its fixed `Seal` in the slot instead.
    tag_len: usize,
    /// `slot_count * tag_len` bytes, preallocated like `region`. Empty when
    /// `tag_len == 0`.
    tags: Vec<u8>,
}

impl PendingBuffer {
    /// Preallocates a buffer for `slot_count` fragments of up to
    /// `slot_size` bytes each (`slot_size * slot_count` bytes total, a
    /// single allocation). Must not exceed the 15 MB safety ceiling
    /// (Core profile); different profiles pass their own values
    /// (Lite: 64 KB, Vault: 256 KB, see Block III).
    pub fn new(slot_size: usize, slot_count: usize, forced_purge_timeout: Duration) -> Self {
        Self::with_tag_len(slot_size, slot_count, forced_purge_timeout, 0)
    }

    /// Same as `new`, plus a preallocated area of `slot_count * tag_len` bytes
    /// for the variable-length tags of wire v2. `tag_len == 0` is exactly the
    /// v1 buffer. The caller (the v2 cores) has already checked the total
    /// against the memory budget, so the multiplication here cannot overflow.
    pub fn with_tag_len(
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        tag_len: usize,
    ) -> Self {
        let tags = vec![0u8; slot_count * tag_len];
        let region = vec![0u8; slot_size * slot_count];
        let mut slots = Vec::with_capacity(slot_count);
        let mut free_slots = Vec::with_capacity(slot_count);
        for i in 0..slot_count {
            slots.push(Slot {
                len: 0,
                seal: Seal([0u8; crate::hmac_seal::SEAL_LEN]),
                inserted_at_ms: 0,
                occupant: EMPTY_SLOT,
            });
            free_slots.push(i);
        }
        PendingBuffer {
            region,
            slot_size,
            slots,
            free_slots,
            by_index: std::collections::HashMap::with_capacity(slot_count),
            forced_purge_timeout,
            epoch: Instant::now(),
            tag_len,
            tags,
        }
    }

    /// Milliseconds elapsed since the buffer's creation, saturating at
    /// u32::MAX in the extreme case of a session lasting more than
    /// ~49 days (not a real scenario given that profile timeouts are
    /// in seconds, but it saturates instead of silently wrapping).
    fn elapsed_ms(&self) -> u32 {
        self.epoch.elapsed().as_millis().min(u32::MAX as u128) as u32
    }

    /// Total preallocated capacity, in bytes. Fixed since construction.
    pub fn capacity_bytes(&self) -> usize {
        self.region.len()
    }

    /// Real fragment bytes currently in use (doesn't count the padding
    /// of partially occupied slots).
    pub fn used_bytes(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.occupant != EMPTY_SLOT)
            .map(|s| s.len as usize)
            .sum()
    }

    /// Inserts a sealed fragment into the first available free slot.
    /// Fails if the fragment doesn't fit in a slot, or if there are no
    /// free slots — `region` is never lengthened to accommodate it in
    /// either case.
    pub fn insert(
        &mut self,
        index: FragmentIndex,
        bytes: &[u8],
        seal: Seal,
    ) -> Result<(), BufferError> {
        self.insert_inner(index, bytes, seal, None)
    }

    /// Wire v2 insert: the tag is stored in the slot's tag area and must be
    /// exactly the length this buffer was built for.
    pub fn insert_tagged(
        &mut self,
        index: FragmentIndex,
        bytes: &[u8],
        tag: &[u8],
    ) -> Result<(), BufferError> {
        if self.tag_len == 0 || tag.len() != self.tag_len {
            return Err(BufferError::TagLengthMismatch { expected: self.tag_len, got: tag.len() });
        }
        self.insert_inner(index, bytes, Seal([0u8; crate::hmac_seal::SEAL_LEN]), Some(tag))
    }

    fn insert_inner(
        &mut self,
        index: FragmentIndex,
        bytes: &[u8],
        seal: Seal,
        tag: Option<&[u8]>,
    ) -> Result<(), BufferError> {
        if index == EMPTY_SLOT {
            // The one FragmentIndex value that can't be represented,
            // since it's the "free slot" sentinel. See the comment on
            // EMPTY_SLOT.
            return Err(BufferError::FragmentTooLarge {
                fragment_len: bytes.len(),
                slot_size: self.slot_size,
            });
        }
        if bytes.len() > self.slot_size {
            return Err(BufferError::FragmentTooLarge {
                fragment_len: bytes.len(),
                slot_size: self.slot_size,
            });
        }
        if self.by_index.contains_key(&index) {
            return Err(BufferError::DuplicateIndex { index });
        }
        let slot_idx = self.free_slots.pop().ok_or(BufferError::NoSlotsAvailable)?;

        let offset = slot_idx * self.slot_size;
        self.region[offset..offset + bytes.len()].copy_from_slice(bytes);
        if let Some(tag) = tag {
            let t_off = slot_idx * self.tag_len;
            self.tags[t_off..t_off + self.tag_len].copy_from_slice(tag);
        }

        let now_ms = self.elapsed_ms();
        let slot = &mut self.slots[slot_idx];
        slot.len = bytes.len() as u32;
        slot.seal = seal;
        slot.inserted_at_ms = now_ms;
        slot.occupant = index;
        self.by_index.insert(index, slot_idx);

        Ok(())
    }

    fn find_slot(&self, index: FragmentIndex) -> Option<usize> {
        if index == EMPTY_SLOT {
            return None;
        }
        self.by_index.get(&index).copied()
    }

    /// ACK purge rule: `Status(fᵢ) == ACK ⟹ Erase(δᵢ, fᵢ)`. Synchronous:
    /// the slot goes back to the free list within this same call.
    /// Returns false if the index wasn't pending (duplicate ACK, or
    /// already purged).
    pub fn purge_on_ack(&mut self, index: FragmentIndex) -> bool {
        match self.find_slot(index) {
            Some(slot_idx) => {
                self.release_slot(slot_idx);
                true
            }
            None => false,
        }
    }

    fn release_slot(&mut self, slot_idx: usize) {
        let slot = &mut self.slots[slot_idx];
        self.by_index.remove(&slot.occupant);
        // The slot's content is overwritten on release (not just the
        // `occupant` marker), so a later memory dump doesn't find the
        // already-purged fragment still sitting in `region`.
        let offset = slot_idx * self.slot_size;
        let len = slot.len as usize;
        // Volatile wipe (zeroize): a plain `fill(0)` on memory that is never read
        // again is something an optimizer is allowed to drop.
        zeroize::Zeroize::zeroize(&mut self.region[offset..offset + len]);
        if self.tag_len > 0 {
            let t_off = slot_idx * self.tag_len;
            zeroize::Zeroize::zeroize(&mut self.tags[t_off..t_off + self.tag_len]);
        }
        slot.len = 0;
        slot.occupant = EMPTY_SLOT;
        self.free_slots.push(slot_idx);
    }

    /// Forced purge timeout: walks occupied slots and releases those
    /// that exceeded `forced_purge_timeout` without an ACK. Returns how
    /// many slots were purged this way (for metrics).
    pub fn purge_expired(&mut self) -> u64 {
        self.purge_expired_indices().len() as u64
    }

    /// Same sweep as `purge_expired`, but returns the fragment indices it
    /// released, so the owner can drop any per-fragment bookkeeping it keeps
    /// (the sealer's frame states). Allocates only when something expired.
    pub fn purge_expired_indices(&mut self) -> Vec<FragmentIndex> {
        let timeout_ms: u32 = self
            .forced_purge_timeout
            .as_millis()
            .min(u32::MAX as u128) as u32;
        let now_ms = self.elapsed_ms();
        let expired: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.occupant != EMPTY_SLOT && now_ms.saturating_sub(s.inserted_at_ms) > timeout_ms
            })
            .map(|(i, _)| i)
            .collect();

        let mut indices = Vec::with_capacity(expired.len());
        for slot_idx in expired {
            indices.push(self.slots[slot_idx].occupant);
            self.release_slot(slot_idx);
        }
        indices
    }

    /// How many fragments are still pending ACK right now.
    pub fn pending_count(&self) -> usize {
        self.slots.len() - self.free_slots.len()
    }

    /// Checks a pending fragment's seal without purging it — the
    /// decision to purge belongs to the caller, so verification and
    /// memory release aren't coupled into a single step.
    pub fn seal_of(&self, index: FragmentIndex) -> Option<&Seal> {
        self.find_slot(index).map(|i| &self.slots[i].seal)
    }

    /// The v2 tag of a pending fragment, if this buffer keeps tags.
    pub fn tag_of(&self, index: FragmentIndex) -> Option<&[u8]> {
        if self.tag_len == 0 {
            return None;
        }
        self.find_slot(index).map(|i| &self.tags[i * self.tag_len..(i + 1) * self.tag_len])
    }

    /// Bytes preallocated for tags (0 for the v1 buffer).
    pub fn tag_capacity_bytes(&self) -> usize {
        self.tags.len()
    }
}

impl Drop for PendingBuffer {
    /// Every fragment still pending when the buffer goes away is wiped, the
    /// same purge the ACK path applies (axiom A3), so dropping a session does
    /// not leave payload bytes behind in freed memory.
    fn drop(&mut self) {
        // Only the slots still occupied can hold payload bytes (a released slot
        // was wiped when it was released), so wiping the whole preallocated
        // region (up to 15 MB) on every drop would cost far more than needed.
        for (slot_idx, slot) in self.slots.iter().enumerate() {
            if slot.occupant != EMPTY_SLOT {
                let offset = slot_idx * self.slot_size;
                zeroize::Zeroize::zeroize(&mut self.region[offset..offset + slot.len as usize]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal() -> Seal {
        Seal([0u8; SEAL_LEN])
    }

    #[test]
    fn insert_within_slot_size_succeeds() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        let res = buf.insert(0, &[0u8; 100], dummy_seal());
        assert!(res.is_ok());
        assert_eq!(buf.used_bytes(), 100);
    }

    #[test]
    fn insert_exceeding_slot_size_is_rejected() {
        let mut buf = PendingBuffer::new(100, 4, Duration::from_millis(500));
        let res = buf.insert(0, &[0u8; 200], dummy_seal());
        assert!(matches!(res, Err(BufferError::FragmentTooLarge { .. })));
        assert_eq!(buf.used_bytes(), 0);
    }

    #[test]
    fn insert_beyond_slot_count_is_rejected_not_grown() {
        let mut buf = PendingBuffer::new(100, 2, Duration::from_millis(500));
        let capacity_before = buf.capacity_bytes();
        buf.insert(0, &[0u8; 50], dummy_seal()).unwrap();
        buf.insert(1, &[0u8; 50], dummy_seal()).unwrap();

        let res = buf.insert(2, &[0u8; 50], dummy_seal());
        assert!(matches!(res, Err(BufferError::NoSlotsAvailable)));
        // The preallocated region never changed size.
        assert_eq!(buf.capacity_bytes(), capacity_before);
    }

    #[test]
    fn ack_purges_synchronously() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        assert_eq!(buf.used_bytes(), 100);

        let purged = buf.purge_on_ack(0);
        assert!(purged);
        assert_eq!(buf.used_bytes(), 0);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn duplicate_ack_is_a_noop_not_an_error() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        assert!(buf.purge_on_ack(0));
        assert!(!buf.purge_on_ack(0));
        assert_eq!(buf.used_bytes(), 0);
    }

    #[test]
    fn purged_slot_is_immediately_reusable() {
        let mut buf = PendingBuffer::new(100, 1, Duration::from_millis(500));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        // Only one slot exists: a second fragment doesn't fit.
        assert!(matches!(
            buf.insert(1, &[0u8; 1], dummy_seal()),
            Err(BufferError::NoSlotsAvailable)
        ));

        buf.purge_on_ack(0);
        // After the purge, the same slot is reused without reallocating
        // the region.
        assert!(buf.insert(1, &[0u8; 100], dummy_seal()).is_ok());
    }

    #[test]
    fn purged_slot_content_is_zeroed() {
        // The residual state must not retain the raw fragment after
        // purging it — this carries the non-invertibility property of
        // Block II.6 down to the physical buffer level, not just the
        // Es(i) state.
        let mut buf = PendingBuffer::new(16, 1, Duration::from_millis(500));
        buf.insert(0, &[0xAAu8; 16], dummy_seal()).unwrap();
        buf.purge_on_ack(0);
        assert!(buf.region.iter().all(|&b| b == 0));
    }

    #[test]
    fn forced_timeout_purges_without_ack() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(20));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        std::thread::sleep(Duration::from_millis(40));

        let purged = buf.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(buf.used_bytes(), 0);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn non_expired_fragments_survive_purge_sweep() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(200));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();

        let purged = buf.purge_expired();
        assert_eq!(purged, 0);
        assert_eq!(buf.pending_count(), 1);
    }

    /// Edge case introduced by the EMPTY_SLOT sentinel: the value
    /// reserved for "free slot" cannot be used as a real fragment
    /// index. Documented with an explicit test instead of leaving it
    /// as implicit behavior.
    #[test]
    fn sentinel_value_is_rejected_as_fragment_index() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        let res = buf.insert(FragmentIndex::MAX, &[0u8; 10], dummy_seal());
        assert!(res.is_err());
    }

    /// Confirms the Core profile's 15 MB ceiling as a real use case,
    /// with 1 KB slots (typical Core size, Block III).
    #[test]
    fn fifteen_megabyte_ceiling_via_fixed_slots() {
        const FIFTEEN_MB: usize = 15 * 1024 * 1024;
        const SLOT_SIZE: usize = 1024;
        let slot_count = FIFTEEN_MB / SLOT_SIZE;
        let mut buf = PendingBuffer::new(SLOT_SIZE, slot_count, Duration::from_millis(500));

        assert_eq!(buf.capacity_bytes(), FIFTEEN_MB);

        for i in 0..slot_count as u64 {
            buf.insert(i, &[0x42u8; SLOT_SIZE], dummy_seal()).unwrap();
        }
        assert_eq!(buf.used_bytes(), FIFTEEN_MB);
        assert!(matches!(
            buf.insert(slot_count as u64, &[0x42u8; SLOT_SIZE], dummy_seal()),
            Err(BufferError::NoSlotsAvailable)
        ));
    }

    #[test]
    fn duplicate_index_is_rejected_and_does_not_orphan_a_slot() {
        let mut buf = PendingBuffer::new(100, 4, Duration::from_millis(500));
        buf.insert(7, &[1u8; 10], dummy_seal()).unwrap();
        assert!(matches!(
            buf.insert(7, &[2u8; 10], dummy_seal()),
            Err(BufferError::DuplicateIndex { index: 7 })
        ));
        assert_eq!(buf.pending_count(), 1);
        assert!(buf.purge_on_ack(7));
        assert_eq!(buf.pending_count(), 0);
        assert!(buf.insert(7, &[3u8; 10], dummy_seal()).is_ok(), "index is reusable after its purge");
    }

    #[test]
    fn lookup_by_index_survives_out_of_order_purges() {
        let mut buf = PendingBuffer::new(8, 6, Duration::from_millis(500));
        for i in 0..6u64 {
            buf.insert(i, &[i as u8; 8], Seal([i as u8; SEAL_LEN])).unwrap();
        }
        assert!(buf.purge_on_ack(3));
        assert!(buf.purge_on_ack(0));
        assert!(buf.seal_of(3).is_none());
        assert_eq!(buf.seal_of(5).unwrap().0[0], 5);
        buf.insert(9, &[9u8; 8], Seal([9u8; SEAL_LEN])).unwrap();
        assert_eq!(buf.seal_of(9).unwrap().0[0], 9);
        assert_eq!(buf.seal_of(4).unwrap().0[0], 4);
    }

    #[test]
    fn purge_expired_indices_reports_exactly_the_released_fragments() {
        let mut buf = PendingBuffer::new(8, 4, Duration::from_millis(1));
        buf.insert(10, &[1u8; 8], dummy_seal()).unwrap();
        buf.insert(11, &[1u8; 8], dummy_seal()).unwrap();
        std::thread::sleep(Duration::from_millis(15));
        let mut got = buf.purge_expired_indices();
        got.sort();
        assert_eq!(got, vec![10, 11]);
        assert_eq!(buf.pending_count(), 0);
        assert!(buf.purge_expired_indices().is_empty());
    }

    #[test]
    fn tagged_insert_keeps_the_tag_until_the_slot_is_released() {
        let mut buf = PendingBuffer::with_tag_len(16, 2, Duration::from_secs(5), 5);
        assert_eq!(buf.tag_capacity_bytes(), 10);
        buf.insert_tagged(1, &[1u8; 4], &[9, 8, 7, 6, 5]).unwrap();
        assert_eq!(buf.tag_of(1), Some(&[9u8, 8, 7, 6, 5][..]));
        assert!(buf.tag_of(2).is_none());
        assert!(buf.purge_on_ack(1));
        assert!(buf.tag_of(1).is_none());
        // The released slot's tag area was wiped (white-box: the API cannot
        // see a released slot, memory can).
        assert!(buf.tags.iter().all(|b| *b == 0), "tag bytes must be wiped on release");
        buf.insert_tagged(2, &[1u8; 4], &[1, 1, 1, 1, 1]).unwrap();
        assert_eq!(buf.tag_of(2), Some(&[1u8, 1, 1, 1, 1][..]));
    }

    #[test]
    fn a_tag_of_another_length_is_refused_never_padded_or_truncated() {
        let mut buf = PendingBuffer::with_tag_len(16, 2, Duration::from_secs(5), 5);
        for bad in [&[0u8; 4][..], &[0u8; 6][..], &[][..]] {
            assert!(matches!(
                buf.insert_tagged(1, &[1u8; 4], bad),
                Err(BufferError::TagLengthMismatch { expected: 5, got: _ })
            ));
        }
        assert_eq!(buf.pending_count(), 0);
        // A v1 buffer keeps no tags at all.
        let mut v1 = PendingBuffer::new(16, 2, Duration::from_secs(5));
        assert!(matches!(v1.insert_tagged(1, &[1u8; 4], &[0u8; 5]), Err(BufferError::TagLengthMismatch { .. })));
        assert_eq!(v1.tag_capacity_bytes(), 0);
    }
}

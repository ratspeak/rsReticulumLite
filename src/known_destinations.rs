use crate::constants::{DESTINATION_LENGTH, PUBLIC_KEY_LENGTH};
use crate::identity::{LXMF_DELIVERY_NAME, destination_hash_from_name, identity_hash};

pub const KNOWN_DESTINATIONS_SMALL: usize = 128;
pub const KNOWN_DESTINATIONS_MICRO: usize = 64;

const BLOB_MAGIC: [u8; 4] = *b"RKD1";
const BLOB_VERSION_V1: u8 = 1;
/// v2 appends each entry's link-request cost (`0xFFFF` when none).
const BLOB_VERSION: u8 = 2;
const BLOB_HEADER_LEN: usize = 7;
const ENTRY_LEN_V1: usize = DESTINATION_LENGTH + PUBLIC_KEY_LENGTH + 8;
const ENTRY_LEN: usize = ENTRY_LEN_V1 + 2;
const NO_LR_COST: u16 = u16::MAX;
/// Recency shares one word with the link-request cost; 48 bits of milliseconds is ~8900 years.
pub const RECENCY_MAX: u64 = (1 << 48) - 1;

/// One remembered delivery destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownDestination {
    pub destination_hash: [u8; DESTINATION_LENGTH],
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Eviction recency, at most [`RECENCY_MAX`].
    pub last_seen: u64,
    /// Fixed-point link-request cost from the last announce, set only when its
    /// stamp validated (Identity.py:866-870, 109-124@1.6.0).
    pub lr_cost_fp: Option<u16>,
}

/// Stored form: recency in the high 48 bits, link-request cost in the low 16,
/// so an entry stays 88 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Slot {
    destination_hash: [u8; DESTINATION_LENGTH],
    public_key: [u8; PUBLIC_KEY_LENGTH],
    recency_lr_cost: u64,
}

impl Slot {
    const fn new(
        destination_hash: [u8; DESTINATION_LENGTH],
        public_key: [u8; PUBLIC_KEY_LENGTH],
        last_seen: u64,
        lr_cost_fp: Option<u16>,
    ) -> Self {
        let lr = match lr_cost_fp {
            Some(fp) => fp,
            None => NO_LR_COST,
        };
        let recency = if last_seen > RECENCY_MAX {
            RECENCY_MAX
        } else {
            last_seen
        };
        Self {
            destination_hash,
            public_key,
            recency_lr_cost: (recency << 16) | lr as u64,
        }
    }

    const fn last_seen(&self) -> u64 {
        self.recency_lr_cost >> 16
    }

    fn set_last_seen(&mut self, last_seen: u64) {
        *self = Self::new(
            self.destination_hash,
            self.public_key,
            last_seen,
            self.lr_cost_fp(),
        );
    }

    fn lr_cost_fp(&self) -> Option<u16> {
        let lr = self.recency_lr_cost as u16;
        (lr != NO_LR_COST).then_some(lr)
    }

    fn view(&self) -> KnownDestination {
        KnownDestination {
            destination_hash: self.destination_hash,
            public_key: self.public_key,
            last_seen: self.last_seen(),
            lr_cost_fp: self.lr_cost_fp(),
        }
    }
}

const EMPTY_ENTRY: Slot = Slot::new([0; DESTINATION_LENGTH], [0; PUBLIC_KEY_LENGTH], 0, None);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownDestinationError {
    EmptyCapacity,
    KeyConflict,
    OutputTooSmall,
    InvalidHeader,
    UnsupportedVersion,
    CountTooLarge,
    InvalidLength,
    DestinationHashMismatch,
    DuplicateDestination,
    /// A v2 entry's link-request cost is above 25600 and not the "none" marker.
    InvalidLinkCost,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownDestinations<const N: usize> {
    entries: [Slot; N],
    len: usize,
}

impl<const N: usize> KnownDestinations<N> {
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; N],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn blob_capacity() -> usize {
        BLOB_HEADER_LEN + N * ENTRY_LEN
    }

    pub fn peek(
        &self,
        destination_hash: &[u8; DESTINATION_LENGTH],
    ) -> Option<&[u8; PUBLIC_KEY_LENGTH]> {
        self.entries[..self.len]
            .iter()
            .find(|entry| &entry.destination_hash == destination_hash)
            .map(|entry| &entry.public_key)
    }

    /// The stored entry for `destination_hash`, without refreshing its recency.
    pub fn peek_entry(
        &self,
        destination_hash: &[u8; DESTINATION_LENGTH],
    ) -> Option<KnownDestination> {
        self.entries[..self.len]
            .iter()
            .find(|entry| &entry.destination_hash == destination_hash)
            .map(Slot::view)
    }

    /// Fixed-point link-request cost last announced by `destination_hash`
    /// (`Identity.recall_link_cost`, Identity.py:201-212@1.6.0).
    pub fn link_cost_fp(&self, destination_hash: &[u8; DESTINATION_LENGTH]) -> Option<u16> {
        self.peek_entry(destination_hash)?.lr_cost_fp
    }

    pub fn recall(
        &mut self,
        destination_hash: &[u8; DESTINATION_LENGTH],
    ) -> Option<[u8; PUBLIC_KEY_LENGTH]> {
        let index = self.entries[..self.len]
            .iter()
            .position(|entry| &entry.destination_hash == destination_hash)?;
        let public_key = self.entries[index].public_key;
        let recency = self.next_recency();
        self.entries[index].set_last_seen(recency);
        Some(public_key)
    }

    /// Learn a delivery destination. Returns `true` only when the table changed.
    /// Re-observing the same key is a strict no-op; a conflicting key is rejected.
    /// A new key must derive the supplied delivery hash, but authenticating its
    /// announcement belongs to the caller. A full table evicts the least recent entry.
    pub fn learn(
        &mut self,
        destination_hash: [u8; DESTINATION_LENGTH],
        public_key: [u8; PUBLIC_KEY_LENGTH],
        now: u64,
    ) -> Result<bool, KnownDestinationError> {
        self.learn_inner(destination_hash, public_key, now, None)
    }

    /// Learn from a validated announce, as [`Self::learn`], and record the
    /// link-request cost it carried. Every announce replaces the stored cost,
    /// so `None` clears it (Identity.remember, Identity.py:109-124@1.6.0).
    /// Returns `true` when the table changed.
    pub fn learn_announce(
        &mut self,
        destination_hash: [u8; DESTINATION_LENGTH],
        public_key: [u8; PUBLIC_KEY_LENGTH],
        now: u64,
        lr_cost_fp: Option<u16>,
    ) -> Result<bool, KnownDestinationError> {
        self.learn_inner(destination_hash, public_key, now, Some(lr_cost_fp))
    }

    fn learn_inner(
        &mut self,
        destination_hash: [u8; DESTINATION_LENGTH],
        public_key: [u8; PUBLIC_KEY_LENGTH],
        now: u64,
        lr_cost_fp: Option<Option<u16>>,
    ) -> Result<bool, KnownDestinationError> {
        if N == 0 {
            return Err(KnownDestinationError::EmptyCapacity);
        }
        if let Some(entry) = self.entries[..self.len]
            .iter_mut()
            .find(|entry| entry.destination_hash == destination_hash)
        {
            if entry.public_key != public_key {
                return Err(KnownDestinationError::KeyConflict);
            }
            return Ok(match lr_cost_fp {
                Some(lr_cost_fp) if lr_cost_fp != entry.lr_cost_fp() => {
                    *entry = Slot::new(
                        entry.destination_hash,
                        entry.public_key,
                        entry.last_seen(),
                        lr_cost_fp,
                    );
                    true
                }
                _ => false,
            });
        }
        if delivery_destination_hash(&public_key) != destination_hash {
            return Err(KnownDestinationError::DestinationHashMismatch);
        }

        let entry = Slot::new(
            destination_hash,
            public_key,
            now.max(self.next_recency()),
            lr_cost_fp.flatten(),
        );
        if self.len < N {
            self.entries[self.len] = entry;
            self.len += 1;
        } else {
            let oldest = self.entries[..self.len]
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_seen())
                .map(|(index, _)| index)
                .unwrap_or(0);
            self.entries[oldest] = entry;
        }
        Ok(true)
    }

    pub fn export_into(&self, out: &mut [u8]) -> Result<usize, KnownDestinationError> {
        let needed = BLOB_HEADER_LEN + self.len * ENTRY_LEN;
        if out.len() < needed {
            return Err(KnownDestinationError::OutputTooSmall);
        }

        out[..4].copy_from_slice(&BLOB_MAGIC);
        out[4] = BLOB_VERSION;
        out[5..7].copy_from_slice(&(self.len as u16).to_be_bytes());
        let mut pos = BLOB_HEADER_LEN;
        for entry in &self.entries[..self.len] {
            out[pos..pos + DESTINATION_LENGTH].copy_from_slice(&entry.destination_hash);
            pos += DESTINATION_LENGTH;
            out[pos..pos + PUBLIC_KEY_LENGTH].copy_from_slice(&entry.public_key);
            pos += PUBLIC_KEY_LENGTH;
            out[pos..pos + 8].copy_from_slice(&entry.last_seen().to_be_bytes());
            pos += 8;
            let lr = entry.lr_cost_fp().unwrap_or(NO_LR_COST);
            out[pos..pos + 2].copy_from_slice(&lr.to_be_bytes());
            pos += 2;
        }
        Ok(pos)
    }

    /// Import a complete v2 blob, or a v1 blob whose entries carry no link cost. Validation is non-mutating: every entry is
    /// destination-bound and duplicate-free before live state is replaced.
    /// Stored recency values are clamped to `now`. Hash binding does not prove
    /// announcement authenticity; use trusted stored input.
    pub fn import(&mut self, blob: &[u8], now: u64) -> Result<(), KnownDestinationError> {
        if blob.len() < BLOB_HEADER_LEN || blob[..4] != BLOB_MAGIC {
            return Err(KnownDestinationError::InvalidHeader);
        }
        let entry_len = match blob[4] {
            BLOB_VERSION => ENTRY_LEN,
            BLOB_VERSION_V1 => ENTRY_LEN_V1,
            _ => return Err(KnownDestinationError::UnsupportedVersion),
        };
        let count = u16::from_be_bytes([blob[5], blob[6]]) as usize;
        if count > N {
            return Err(KnownDestinationError::CountTooLarge);
        }
        let expected = BLOB_HEADER_LEN + count * entry_len;
        if blob.len() != expected {
            return Err(KnownDestinationError::InvalidLength);
        }

        for index in 0..count {
            let entry = decode_entry(blob, entry_len, index, now)?;
            if delivery_destination_hash(&entry.public_key) != entry.destination_hash {
                return Err(KnownDestinationError::DestinationHashMismatch);
            }
            for prior in 0..index {
                if decode_entry(blob, entry_len, prior, now)?.destination_hash
                    == entry.destination_hash
                {
                    return Err(KnownDestinationError::DuplicateDestination);
                }
            }
        }

        self.entries = [EMPTY_ENTRY; N];
        self.len = count;
        for index in 0..count {
            self.entries[index] = decode_entry(blob, entry_len, index, now)?;
        }
        Ok(())
    }

    fn next_recency(&self) -> u64 {
        self.entries[..self.len]
            .iter()
            .map(Slot::last_seen)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }
}

impl<const N: usize> Default for KnownDestinations<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_entry(
    blob: &[u8],
    entry_len: usize,
    index: usize,
    now: u64,
) -> Result<Slot, KnownDestinationError> {
    let mut pos = BLOB_HEADER_LEN + index * entry_len;
    let mut destination_hash = [0u8; DESTINATION_LENGTH];
    destination_hash.copy_from_slice(&blob[pos..pos + DESTINATION_LENGTH]);
    pos += DESTINATION_LENGTH;
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&blob[pos..pos + PUBLIC_KEY_LENGTH]);
    pos += PUBLIC_KEY_LENGTH;
    let mut last_seen = [0u8; 8];
    last_seen.copy_from_slice(&blob[pos..pos + 8]);
    pos += 8;
    let lr_cost_fp = if entry_len == ENTRY_LEN {
        match u16::from_be_bytes([blob[pos], blob[pos + 1]]) {
            NO_LR_COST => None,
            fp if fp <= crate::stamps::STAMP_COST_CAP_FP => Some(fp),
            _ => return Err(KnownDestinationError::InvalidLinkCost),
        }
    } else {
        None
    };
    Ok(Slot::new(
        destination_hash,
        public_key,
        u64::from_be_bytes(last_seen).min(now),
        lr_cost_fp,
    ))
}

fn delivery_destination_hash(public_key: &[u8; PUBLIC_KEY_LENGTH]) -> [u8; DESTINATION_LENGTH] {
    let identity_hash = identity_hash(public_key);
    destination_hash_from_name(LXMF_DELIVERY_NAME, Some(&identity_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    fn identity(seed: u8) -> ([u8; DESTINATION_LENGTH], [u8; PUBLIC_KEY_LENGTH]) {
        let local = LocalIdentity::from_private_key(&[seed; 64]);
        (local.lxmf_delivery_hash(), *local.public_key())
    }

    #[test]
    fn insert_and_recall() {
        let mut table = KnownDestinations::<2>::new();
        let (dest, key) = identity(1);
        assert_eq!(table.learn(dest, key, 10), Ok(true));
        assert_eq!(table.recall(&dest), Some(key));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn full_table_evicts_least_recent_entry() {
        let mut table = KnownDestinations::<2>::new();
        let (old_dest, old_key) = identity(1);
        let (newer_dest, newer_key) = identity(2);
        let (newest_dest, newest_key) = identity(3);
        table.learn(old_dest, old_key, 10).unwrap();
        table.learn(newer_dest, newer_key, 20).unwrap();
        table.learn(newest_dest, newest_key, 30).unwrap();
        assert!(table.peek(&old_dest).is_none());
        assert_eq!(table.peek(&newer_dest), Some(&newer_key));
        assert_eq!(table.peek(&newest_dest), Some(&newest_key));
    }

    #[test]
    fn recall_refreshes_lru_order() {
        let mut table = KnownDestinations::<2>::new();
        let (first_dest, first_key) = identity(9);
        let (second_dest, second_key) = identity(10);
        let (third_dest, third_key) = identity(11);
        table.learn(first_dest, first_key, 10).unwrap();
        table.learn(second_dest, second_key, 20).unwrap();
        assert_eq!(table.recall(&first_dest), Some(first_key));
        table.learn(third_dest, third_key, 30).unwrap();
        assert_eq!(table.peek(&first_dest), Some(&first_key));
        assert!(table.peek(&second_dest).is_none());
        assert_eq!(table.peek(&third_dest), Some(&third_key));
    }

    #[test]
    fn same_key_is_noop_and_conflict_is_rejected() {
        let mut table = KnownDestinations::<2>::new();
        let (dest, key) = identity(4);
        let (_, other_key) = identity(5);
        assert_eq!(table.learn(dest, key, 10), Ok(true));
        assert_eq!(table.learn(dest, key, 99), Ok(false));
        assert_eq!(
            table.learn(dest, other_key, 100),
            Err(KnownDestinationError::KeyConflict)
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn export_import_roundtrip_is_byte_exact() {
        let mut table = KnownDestinations::<3>::new();
        for seed in 1..=3 {
            let (dest, key) = identity(seed);
            table.learn(dest, key, seed as u64 * 10).unwrap();
        }
        let mut first = [0u8; KnownDestinations::<3>::blob_capacity()];
        let first_len = table.export_into(&mut first).unwrap();

        let mut restored = KnownDestinations::<3>::new();
        restored.import(&first[..first_len], 100).unwrap();
        let mut second = [0u8; KnownDestinations::<3>::blob_capacity()];
        let second_len = restored.export_into(&mut second).unwrap();
        assert_eq!(&first[..first_len], &second[..second_len]);
    }

    #[test]
    fn import_rejects_tampered_key_without_mutating_live_table() {
        let mut source = KnownDestinations::<2>::new();
        let (dest, key) = identity(6);
        source.learn(dest, key, 10).unwrap();
        let mut blob = [0u8; KnownDestinations::<2>::blob_capacity()];
        let len = source.export_into(&mut blob).unwrap();
        blob[BLOB_HEADER_LEN + DESTINATION_LENGTH] ^= 0x01;

        let mut live = KnownDestinations::<2>::new();
        let (live_dest, live_key) = identity(7);
        live.learn(live_dest, live_key, 20).unwrap();
        assert_eq!(
            live.import(&blob[..len], 100),
            Err(KnownDestinationError::DestinationHashMismatch)
        );
        assert_eq!(live.peek(&live_dest), Some(&live_key));
    }

    #[test]
    fn import_rejects_truncated_oversized_and_trailing_blobs() {
        let mut table = KnownDestinations::<1>::new();
        let (dest, key) = identity(8);
        table.learn(dest, key, 10).unwrap();
        let mut blob = [0u8; KnownDestinations::<1>::blob_capacity() + 1];
        let len = table.export_into(&mut blob).unwrap();

        let mut target = KnownDestinations::<1>::new();
        assert_eq!(
            target.import(&blob[..len - 1], 100),
            Err(KnownDestinationError::InvalidLength)
        );
        assert_eq!(
            target.import(&blob[..len + 1], 100),
            Err(KnownDestinationError::InvalidLength)
        );
        blob[5..7].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            target.import(&blob[..len], 100),
            Err(KnownDestinationError::CountTooLarge)
        );
    }

    #[test]
    fn announce_link_cost_is_replaced_by_every_announce_and_persisted() {
        let mut table = KnownDestinations::<2>::new();
        let (dest, key) = identity(12);
        assert_eq!(table.learn_announce(dest, key, 10, Some(832)), Ok(true));
        assert_eq!(table.link_cost_fp(&dest), Some(832));
        assert_eq!(table.learn_announce(dest, key, 20, Some(832)), Ok(false));
        assert_eq!(table.learn(dest, key, 30), Ok(false));
        assert_eq!(table.link_cost_fp(&dest), Some(832));

        let mut blob = [0u8; KnownDestinations::<2>::blob_capacity()];
        let len = table.export_into(&mut blob).unwrap();
        assert_eq!(blob[4], BLOB_VERSION);
        let mut restored = KnownDestinations::<2>::new();
        restored.import(&blob[..len], 100).unwrap();
        assert_eq!(restored.peek_entry(&dest), table.peek_entry(&dest));

        assert_eq!(table.learn_announce(dest, key, 40, None), Ok(true));
        assert_eq!(table.link_cost_fp(&dest), None);
        assert_eq!(table.peek(&dest), Some(&key));
    }

    #[test]
    fn version_one_blob_imports_without_link_costs() {
        let (dest, key) = identity(13);
        let mut v1 = [0u8; BLOB_HEADER_LEN + ENTRY_LEN_V1];
        v1[..4].copy_from_slice(&BLOB_MAGIC);
        v1[4] = BLOB_VERSION_V1;
        v1[5..7].copy_from_slice(&1u16.to_be_bytes());
        v1[7..23].copy_from_slice(&dest);
        v1[23..87].copy_from_slice(&key);
        v1[87..95].copy_from_slice(&55u64.to_be_bytes());
        let mut table = KnownDestinations::<1>::new();
        table.import(&v1, 100).unwrap();
        assert_eq!(
            table.peek_entry(&dest),
            Some(KnownDestination {
                destination_hash: dest,
                public_key: key,
                last_seen: 55,
                lr_cost_fp: None,
            })
        );
    }

    #[test]
    fn import_rejects_link_cost_above_the_cap() {
        let mut table = KnownDestinations::<1>::new();
        let (dest, key) = identity(14);
        table.learn_announce(dest, key, 10, Some(25600)).unwrap();
        let mut blob = [0u8; KnownDestinations::<1>::blob_capacity()];
        let len = table.export_into(&mut blob).unwrap();
        let mut target = KnownDestinations::<1>::new();
        target.import(&blob[..len], 100).unwrap();
        blob[len - 2..len].copy_from_slice(&25601u16.to_be_bytes());
        assert_eq!(
            target.import(&blob[..len], 100),
            Err(KnownDestinationError::InvalidLinkCost)
        );
        assert_eq!(target.link_cost_fp(&dest), Some(25600));
    }

    #[test]
    fn profile_table_sizes_are_pinned() {
        assert_eq!(
            core::mem::size_of::<KnownDestinations<KNOWN_DESTINATIONS_MICRO>>(),
            5_640
        );
        assert_eq!(
            core::mem::size_of::<KnownDestinations<KNOWN_DESTINATIONS_SMALL>>(),
            11_272
        );
    }
}

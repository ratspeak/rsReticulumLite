use crate::constants::{DESTINATION_LENGTH, PUBLIC_KEY_LENGTH};
use crate::identity::{LXMF_DELIVERY_NAME, destination_hash_from_name, identity_hash};

pub const KNOWN_DESTINATIONS_SMALL: usize = 128;
pub const KNOWN_DESTINATIONS_MICRO: usize = 64;

const BLOB_MAGIC: [u8; 4] = *b"RKD1";
const BLOB_VERSION: u8 = 1;
const BLOB_HEADER_LEN: usize = 7;
const ENTRY_LEN: usize = DESTINATION_LENGTH + PUBLIC_KEY_LENGTH + 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownDestination {
    pub destination_hash: [u8; DESTINATION_LENGTH],
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    pub last_seen: u64,
}

const EMPTY_ENTRY: KnownDestination = KnownDestination {
    destination_hash: [0; DESTINATION_LENGTH],
    public_key: [0; PUBLIC_KEY_LENGTH],
    last_seen: 0,
};

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownDestinations<const N: usize> {
    entries: [KnownDestination; N],
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

    pub fn recall(
        &mut self,
        destination_hash: &[u8; DESTINATION_LENGTH],
    ) -> Option<[u8; PUBLIC_KEY_LENGTH]> {
        let index = self.entries[..self.len]
            .iter()
            .position(|entry| &entry.destination_hash == destination_hash)?;
        let public_key = self.entries[index].public_key;
        self.entries[index].last_seen = self.next_recency();
        Some(public_key)
    }

    /// Learn a delivery destination. Returns `true` only when the table changed.
    /// Re-observing the same key is a strict no-op; a conflicting key is rejected.
    pub fn learn(
        &mut self,
        destination_hash: [u8; DESTINATION_LENGTH],
        public_key: [u8; PUBLIC_KEY_LENGTH],
        now: u64,
    ) -> Result<bool, KnownDestinationError> {
        if N == 0 {
            return Err(KnownDestinationError::EmptyCapacity);
        }
        if let Some(entry) = self.entries[..self.len]
            .iter()
            .find(|entry| entry.destination_hash == destination_hash)
        {
            return if entry.public_key == public_key {
                Ok(false)
            } else {
                Err(KnownDestinationError::KeyConflict)
            };
        }
        if delivery_destination_hash(&public_key) != destination_hash {
            return Err(KnownDestinationError::DestinationHashMismatch);
        }

        let entry = KnownDestination {
            destination_hash,
            public_key,
            last_seen: now.max(self.next_recency()),
        };
        if self.len < N {
            self.entries[self.len] = entry;
            self.len += 1;
        } else {
            let oldest = self.entries[..self.len]
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_seen)
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
            out[pos..pos + 8].copy_from_slice(&entry.last_seen.to_be_bytes());
            pos += 8;
        }
        Ok(pos)
    }

    /// Import a complete v1 blob. Validation is non-mutating: every entry is
    /// destination-bound and duplicate-free before live state is replaced.
    pub fn import(&mut self, blob: &[u8], now: u64) -> Result<(), KnownDestinationError> {
        if blob.len() < BLOB_HEADER_LEN || blob[..4] != BLOB_MAGIC {
            return Err(KnownDestinationError::InvalidHeader);
        }
        if blob[4] != BLOB_VERSION {
            return Err(KnownDestinationError::UnsupportedVersion);
        }
        let count = u16::from_be_bytes([blob[5], blob[6]]) as usize;
        if count > N {
            return Err(KnownDestinationError::CountTooLarge);
        }
        let expected = BLOB_HEADER_LEN + count * ENTRY_LEN;
        if blob.len() != expected {
            return Err(KnownDestinationError::InvalidLength);
        }

        for index in 0..count {
            let entry = decode_entry(blob, index, now);
            if delivery_destination_hash(&entry.public_key) != entry.destination_hash {
                return Err(KnownDestinationError::DestinationHashMismatch);
            }
            for prior in 0..index {
                if decode_entry(blob, prior, now).destination_hash == entry.destination_hash {
                    return Err(KnownDestinationError::DuplicateDestination);
                }
            }
        }

        self.entries = [EMPTY_ENTRY; N];
        self.len = count;
        for index in 0..count {
            self.entries[index] = decode_entry(blob, index, now);
        }
        Ok(())
    }

    fn next_recency(&self) -> u64 {
        self.entries[..self.len]
            .iter()
            .map(|entry| entry.last_seen)
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

fn decode_entry(blob: &[u8], index: usize, now: u64) -> KnownDestination {
    let mut pos = BLOB_HEADER_LEN + index * ENTRY_LEN;
    let mut destination_hash = [0u8; DESTINATION_LENGTH];
    destination_hash.copy_from_slice(&blob[pos..pos + DESTINATION_LENGTH]);
    pos += DESTINATION_LENGTH;
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&blob[pos..pos + PUBLIC_KEY_LENGTH]);
    pos += PUBLIC_KEY_LENGTH;
    let mut last_seen = [0u8; 8];
    last_seen.copy_from_slice(&blob[pos..pos + 8]);
    KnownDestination {
        destination_hash,
        public_key,
        last_seen: u64::from_be_bytes(last_seen).min(now),
    }
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

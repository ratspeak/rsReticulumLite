use crate::constants::{PACKET_HASH_LENGTH, PUBLIC_KEY_LENGTH, RANDOM_HASH_LENGTH};
use crate::packet_buffer::PacketBuffer;

pub type InterfaceId = u8;
pub type Hash16 = [u8; 16];
pub type Hash32 = [u8; PACKET_HASH_LENGTH];

/// PLACEMENT CONTRACT (here and on every table below): the storage fields are
/// `#[doc(hidden)] pub` so the FFI crate's in-place `LiteNode` constructor can write them
/// per-element via raw projections (this crate forbids unsafe; safe construction is
/// by-value — a stack hazard at node size). Not public API: never touch fields directly;
/// invariants (`len <= N`, `head < N`, ring occupancy) are maintained by the methods only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Queue<T: Copy, const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<T>; N],
    #[doc(hidden)]
    pub head: usize,
    #[doc(hidden)]
    pub len: usize,
}

impl<T: Copy, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            head: 0,
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push `value`; on a full queue, overwrite the OLDEST entry (FIFO head). Returns `true` if
    /// an entry was evicted (so callers can account for the dropped item).
    pub fn push_drop_oldest(&mut self, value: T) -> bool {
        if N == 0 {
            return false;
        }
        if self.len == N {
            self.entries[self.head] = Some(value);
            self.head = (self.head + 1) % N;
            true
        } else {
            let idx = (self.head + self.len) % N;
            self.entries[idx] = Some(value);
            self.len += 1;
            false
        }
    }

    /// Borrow the front entry without removing it (so a consumer can size a buffer before popping).
    pub fn peek(&self) -> Option<&T> {
        if self.len == 0 || N == 0 {
            return None;
        }
        self.entries[self.head].as_ref()
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 || N == 0 {
            return None;
        }
        let value = self.entries[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        value
    }
}

impl<T: Copy, const N: usize> Default for Queue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHashEntry {
    hash: Hash32,
    expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHashTable<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<PacketHashEntry>; N],
}

impl<const N: usize> PacketHashTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn insert(&mut self, hash: Hash32, expires_ms: u64, now_ms: u64) -> bool {
        self.expire(now_ms);
        for entry in self.entries.iter().flatten() {
            if entry.hash == hash {
                return false;
            }
        }

        let replacement = self
            .entries
            .iter()
            .position(Option::is_none)
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(PacketHashEntry { hash, expires_ms });
        }
        true
    }

    /// Non-inserting membership check, so duplicate detection can precede a fallible
    /// send while the hash is only consumed after the send succeeds.
    pub fn contains(&mut self, hash: &Hash32, now_ms: u64) -> bool {
        self.expire(now_ms);
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.hash == *hash)
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| now_ms >= entry.expires_ms) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for PacketHashTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEntry {
    pub destination_hash: Hash16,
    pub next_hop: Option<Hash16>,
    pub hops: u8,
    pub interface_id: InterfaceId,
    pub expires_ms: u64,
    pub last_seen_ms: u64,
    pub packet_hash: Hash32,
    pub random_hash: [u8; RANDOM_HASH_LENGTH],
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl PathEntry {
    pub fn is_live(self, now_ms: u64) -> bool {
        now_ms < self.expires_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathTable<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<PathEntry>; N],
}

impl<const N: usize> PathTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn get(&self, destination_hash: &Hash16) -> Option<&PathEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| &entry.destination_hash == destination_hash)
    }

    pub fn get_live(&self, destination_hash: &Hash16, now_ms: u64) -> Option<&PathEntry> {
        self.get(destination_hash)
            .and_then(|entry| entry.is_live(now_ms).then_some(entry))
    }

    pub fn known_public_key(&self, destination_hash: &Hash16) -> Option<&[u8; PUBLIC_KEY_LENGTH]> {
        self.get(destination_hash).map(|entry| &entry.public_key)
    }

    pub fn live_count(&self, now_ms: u64) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.is_live(now_ms))
            .count()
    }

    pub fn insert_or_update(&mut self, entry: PathEntry, now_ms: u64) -> bool {
        self.expire(now_ms);
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|old| old.destination_hash == entry.destination_hash))
        {
            let old = slot.unwrap();
            // Emission-timebase freshness / anti-replay gate (upstream Transport.py:1750-1811,
            // rns-transport actor/inbound.rs:365-382). `announce_emitted` is the big-endian timestamp in
            // random_hash[5:10]. NOTE: the lite keeps a 1-deep blob history per path (the bounded
            // random_blob ring is a deliberate MCU memory trade-off); the emission-timebase
            // comparison is the primary replay defense, so a replayed announce (emitted <= stored)
            // cannot pin or evict a live path even with single-blob history.
            let new_emitted = announce_emitted(&entry.random_hash);
            let old_emitted = announce_emitted(&old.random_hash);
            let random_seen = entry.random_hash == old.random_hash;
            let should_replace = if entry.hops <= old.hops {
                // Equal-or-closer hop: accept only an unseen, more-recently-emitted announce.
                !random_seen && new_emitted > old_emitted
            } else if !old.is_live(now_ms) || new_emitted > old_emitted {
                // Farther hop: accept only if the path expired or the announce is newer.
                !random_seen
            } else {
                // Same emission (lite has no unresponsive-path tracking) or older: ignore.
                false
            };
            if should_replace {
                *slot = Some(entry);
            }
            return should_replace;
        }

        let replacement = self
            .entries
            .iter()
            .position(Option::is_none)
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(entry);
            true
        } else {
            false
        }
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| !entry.is_live(now_ms)) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for PathTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachedAnnounce {
    pub destination_hash: Hash16,
    pub raw: PacketBuffer,
    pub hops: u8,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnounceCache<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<CachedAnnounce>; N],
}

impl<const N: usize> AnnounceCache<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn get(&self, destination_hash: &Hash16, now_ms: u64) -> Option<&CachedAnnounce> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| &entry.destination_hash == destination_hash && now_ms < entry.expires_ms)
    }

    pub fn insert(&mut self, entry: CachedAnnounce, now_ms: u64) {
        self.expire(now_ms);
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|old| old.destination_hash == entry.destination_hash))
        {
            *slot = Some(entry);
            return;
        }
        let replacement = self
            .entries
            .iter()
            .position(Option::is_none)
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(entry);
        }
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| now_ms >= entry.expires_ms) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for AnnounceCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduledAnnounce {
    pub destination_hash: Hash16,
    pub packet: PacketBuffer,
    pub interface_id: InterfaceId,
    pub due_ms: u64,
    pub expires_ms: u64,
    pub block_rebroadcast: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnounceSchedule<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<ScheduledAnnounce>; N],
}

impl<const N: usize> AnnounceSchedule<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn insert(&mut self, entry: ScheduledAnnounce, now_ms: u64) {
        self.expire(now_ms);
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|old| old.destination_hash == entry.destination_hash))
        {
            *slot = Some(entry);
            return;
        }

        let replacement = self
            .entries
            .iter()
            .position(Option::is_none)
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(entry);
        }
    }

    pub fn pop_due(&mut self, now_ms: u64) -> Option<ScheduledAnnounce> {
        self.expire(now_ms);
        let idx = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| now_ms >= entry.due_ms))?;
        self.entries[idx].take()
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| now_ms >= entry.expires_ms) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for AnnounceSchedule<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReverseEntry {
    pub proof_hash: Hash16,
    pub receiving_interface: InterfaceId,
    pub outbound_interface: InterfaceId,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReverseTable<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<ReverseEntry>; N],
}

impl<const N: usize> ReverseTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn insert(&mut self, entry: ReverseEntry, now_ms: u64) {
        self.expire(now_ms);
        let replacement = self
            .entries
            .iter()
            .position(|slot| {
                slot.is_none() || slot.is_some_and(|old| old.proof_hash == entry.proof_hash)
            })
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(entry);
        }
    }

    pub fn remove(&mut self, proof_hash: &Hash16, now_ms: u64) -> Option<ReverseEntry> {
        self.expire(now_ms);
        let idx = self
            .entries
            .iter()
            .position(|slot| slot.is_some_and(|entry| &entry.proof_hash == proof_hash))?;
        self.entries[idx].take()
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| now_ms >= entry.expires_ms) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for ReverseTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkEntry {
    pub link_id: Hash16,
    pub destination_hash: Hash16,
    pub receiving_interface: InterfaceId,
    pub outbound_interface: InterfaceId,
    pub next_hop: Option<Hash16>,
    pub remaining_hops: u8,
    pub taken_hops: u8,
    pub validated: bool,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkTable<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<LinkEntry>; N],
}

impl<const N: usize> LinkTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn insert(&mut self, entry: LinkEntry, now_ms: u64) {
        self.expire(now_ms);
        let replacement = self
            .entries
            .iter()
            .position(|slot| slot.is_none() || slot.is_some_and(|old| old.link_id == entry.link_id))
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(entry);
        }
    }

    pub fn get(&self, link_id: &Hash16, now_ms: u64) -> Option<&LinkEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| &entry.link_id == link_id && now_ms < entry.expires_ms)
    }

    pub fn contains_live(&self, link_id: &Hash16, now_ms: u64) -> bool {
        self.get(link_id, now_ms).is_some()
    }

    pub fn mark_validated(&mut self, link_id: &Hash16, expires_ms: u64, now_ms: u64) {
        self.expire(now_ms);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| &entry.link_id == link_id)
        {
            entry.validated = true;
            entry.expires_ms = expires_ms;
        }
    }

    pub fn touch(&mut self, link_id: &Hash16, expires_ms: u64, now_ms: u64) {
        self.expire(now_ms);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| &entry.link_id == link_id)
        {
            entry.expires_ms = expires_ms;
        }
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| now_ms >= entry.expires_ms) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for LinkTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestTagEntry {
    pub key: [u8; 32],
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestTagTable<const N: usize> {
    #[doc(hidden)]
    pub entries: [Option<RequestTagEntry>; N],
}

impl<const N: usize> RequestTagTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn insert_if_new(&mut self, key: [u8; 32], expires_ms: u64, now_ms: u64) -> bool {
        self.expire(now_ms);
        if self.entries.iter().flatten().any(|entry| entry.key == key) {
            return false;
        }
        let replacement = self
            .entries
            .iter()
            .position(Option::is_none)
            .or_else(|| oldest_index(&self.entries, |entry| entry.expires_ms));
        if let Some(idx) = replacement {
            self.entries[idx] = Some(RequestTagEntry { key, expires_ms });
        }
        true
    }

    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| now_ms >= entry.expires_ms) {
                *slot = None;
            }
        }
    }
}

impl<const N: usize> Default for RequestTagTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Announce emission timebase: the big-endian integer in `random_hash[5:10]`, matching
/// upstream `Transport.timebase_from_random_blobs` / `int.from_bytes(blob[5:10], "big")`.
fn announce_emitted(random_hash: &[u8; RANDOM_HASH_LENGTH]) -> u64 {
    let mut buf = [0u8; 8];
    buf[3..8].copy_from_slice(&random_hash[5..10]);
    u64::from_be_bytes(buf)
}

fn oldest_index<T: Copy, F: Fn(T) -> u64>(entries: &[Option<T>], age: F) -> Option<usize> {
    let mut oldest: Option<(usize, u64)> = None;
    for (idx, entry) in entries.iter().enumerate() {
        if let Some(entry) = *entry {
            let value = age(entry);
            if oldest.is_none_or(|(_, old_value)| value < old_value) {
                oldest = Some((idx, value));
            }
        }
    }
    oldest.map(|(idx, _)| idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn path(destination: u8, expires_ms: u64) -> PathEntry {
        PathEntry {
            destination_hash: [destination; 16],
            next_hop: Some([0x11; 16]),
            hops: 1,
            interface_id: 1,
            expires_ms,
            last_seen_ms: 0,
            packet_hash: hash(destination),
            random_hash: [destination; RANDOM_HASH_LENGTH],
            public_key: [destination; PUBLIC_KEY_LENGTH],
        }
    }

    fn cached_announce(destination: u8, expires_ms: u64) -> CachedAnnounce {
        CachedAnnounce {
            destination_hash: [destination; 16],
            raw: PacketBuffer::new(),
            hops: 1,
            expires_ms,
        }
    }

    fn scheduled_announce(destination: u8, due_ms: u64, expires_ms: u64) -> ScheduledAnnounce {
        ScheduledAnnounce {
            destination_hash: [destination; 16],
            packet: PacketBuffer::new(),
            interface_id: 1,
            due_ms,
            expires_ms,
            block_rebroadcast: false,
        }
    }

    #[test]
    fn queue_drops_oldest_when_full() {
        let mut queue: Queue<u8, 2> = Queue::new();
        queue.push_drop_oldest(1);
        queue.push_drop_oldest(2);
        queue.push_drop_oldest(3);

        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn packet_hash_table_rejects_duplicates_until_expiry() {
        let mut table: PacketHashTable<2> = PacketHashTable::new();
        let hash = [0xAB; 32];

        assert!(table.insert(hash, 10, 0));
        assert!(!table.insert(hash, 10, 5));
        assert!(table.insert(hash, 20, 10));
    }

    #[test]
    fn packet_hash_table_evicts_oldest_when_full() {
        let mut table: PacketHashTable<2> = PacketHashTable::new();
        assert!(table.insert(hash(1), 100, 0));
        assert!(table.insert(hash(2), 200, 0));
        assert!(table.insert(hash(3), 300, 0));

        assert!(
            !table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.hash == hash(1))
        );
        assert!(
            table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.hash == hash(2))
        );
        assert!(
            table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.hash == hash(3))
        );
    }

    #[test]
    fn path_table_evicts_oldest_when_full() {
        let mut table: PathTable<2> = PathTable::new();
        assert!(table.insert_or_update(path(1, 100), 0));
        assert!(table.insert_or_update(path(2, 200), 0));
        assert!(table.insert_or_update(path(3, 300), 0));

        assert!(table.get(&[1; 16]).is_none());
        assert!(table.get(&[2; 16]).is_some());
        assert!(table.get(&[3; 16]).is_some());
    }

    #[test]
    fn announce_cache_evicts_oldest_when_full() {
        let mut table: AnnounceCache<2> = AnnounceCache::new();
        table.insert(cached_announce(1, 100), 0);
        table.insert(cached_announce(2, 200), 0);
        table.insert(cached_announce(3, 300), 0);

        assert!(table.get(&[1; 16], 0).is_none());
        assert!(table.get(&[2; 16], 0).is_some());
        assert!(table.get(&[3; 16], 0).is_some());
    }

    #[test]
    fn announce_schedule_evicts_oldest_when_full() {
        let mut table: AnnounceSchedule<2> = AnnounceSchedule::new();
        table.insert(scheduled_announce(1, 1000, 100), 0);
        table.insert(scheduled_announce(2, 1000, 200), 0);
        table.insert(scheduled_announce(3, 1000, 300), 0);

        assert!(
            !table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.destination_hash == [1; 16])
        );
        assert!(
            table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.destination_hash == [2; 16])
        );
        assert!(
            table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.destination_hash == [3; 16])
        );
    }

    #[test]
    fn reverse_table_evicts_oldest_when_full() {
        let mut table: ReverseTable<2> = ReverseTable::new();
        table.insert(
            ReverseEntry {
                proof_hash: [1; 16],
                receiving_interface: 1,
                outbound_interface: 2,
                expires_ms: 100,
            },
            0,
        );
        table.insert(
            ReverseEntry {
                proof_hash: [2; 16],
                receiving_interface: 1,
                outbound_interface: 2,
                expires_ms: 200,
            },
            0,
        );
        table.insert(
            ReverseEntry {
                proof_hash: [3; 16],
                receiving_interface: 1,
                outbound_interface: 2,
                expires_ms: 300,
            },
            0,
        );

        assert!(table.remove(&[1; 16], 0).is_none());
        assert!(table.remove(&[2; 16], 0).is_some());
        assert!(table.remove(&[3; 16], 0).is_some());
    }

    #[test]
    fn link_table_evicts_oldest_when_full() {
        let mut table: LinkTable<2> = LinkTable::new();
        table.insert(
            LinkEntry {
                link_id: [1; 16],
                destination_hash: [0xAA; 16],
                receiving_interface: 1,
                outbound_interface: 2,
                next_hop: Some([0x11; 16]),
                remaining_hops: 1,
                taken_hops: 1,
                validated: true,
                expires_ms: 100,
            },
            0,
        );
        table.insert(
            LinkEntry {
                link_id: [2; 16],
                destination_hash: [0xBB; 16],
                receiving_interface: 1,
                outbound_interface: 2,
                next_hop: Some([0x22; 16]),
                remaining_hops: 1,
                taken_hops: 1,
                validated: true,
                expires_ms: 200,
            },
            0,
        );
        table.insert(
            LinkEntry {
                link_id: [3; 16],
                destination_hash: [0xCC; 16],
                receiving_interface: 1,
                outbound_interface: 2,
                next_hop: Some([0x33; 16]),
                remaining_hops: 1,
                taken_hops: 1,
                validated: true,
                expires_ms: 300,
            },
            0,
        );

        assert!(table.get(&[1; 16], 0).is_none());
        assert!(table.get(&[2; 16], 0).is_some());
        assert!(table.get(&[3; 16], 0).is_some());
    }

    #[test]
    fn request_tag_table_evicts_oldest_when_full() {
        let mut table: RequestTagTable<2> = RequestTagTable::new();
        assert!(table.insert_if_new([1; 32], 100, 0));
        assert!(table.insert_if_new([2; 32], 200, 0));
        assert!(table.insert_if_new([3; 32], 300, 0));

        assert!(
            !table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.key == [1; 32])
        );
        assert!(
            table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.key == [2; 32])
        );
        assert!(
            table
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.key == [3; 32])
        );
    }
}

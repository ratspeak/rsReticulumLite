//! Announce ratchets — bounded `no_std` adaptation of the trusted Rust stack.
//!
//! The wire and cryptographic behavior matches Reticulum ratchets: X25519
//! private keys are retained newest-first, receivers try the retained ring
//! before the base identity key, and learned peer ratchets are preferred for
//! opportunistic sends. Embedded-only policy is explicit here: clocks and
//! entropy are host supplied, capacity is fixed, uptime ages become unknown
//! after restore, and a full ring never evicts a private key whose expiry
//! cannot be proven.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::constants::DESTINATION_LENGTH;

/// Retained own ratchet private keys.
pub const RATCHET_RING_MAX: usize = 64;
/// Embedded rotation cadence. Sixty-four keys cover 32 days, longer than the
/// 30-day peer memory window.
pub const RATCHET_INTERVAL_SECS: u64 = 60 * 60 * 12;
/// Upstream `Identity.RATCHET_EXPIRY` (30 days).
pub const RATCHET_EXPIRY_SECS: u64 = 60 * 60 * 24 * 30;
const _: () = assert!(RATCHET_RING_MAX as u64 * RATCHET_INTERVAL_SECS >= RATCHET_EXPIRY_SECS);

/// Remembered peer ratchet slots.
pub const PEER_RATCHETS_MAX: usize = 32;

// v2 ring: version | count | count * (age-kind | age-seconds | private-key)
pub const RATCHET_RING_BLOB_MAX: usize = 2 + RATCHET_RING_MAX * (1 + 8 + 32);
// v2 peer table: version | count | count * (dest | public-key | age-kind | age-seconds)
pub const PEER_RATCHETS_BLOB_MAX: usize = 2 + PEER_RATCHETS_MAX * (DESTINATION_LENGTH + 32 + 1 + 8);
const _: () = assert!(RATCHET_RING_BLOB_MAX <= 3 * 1024);
const _: () = assert!(PEER_RATCHETS_BLOB_MAX <= 2 * 1024);

const RING_BLOB_VERSION: u8 = 2;
const LEGACY_RING_BLOB_VERSION: u8 = 1;
const PEER_BLOB_VERSION: u8 = 2;
const LEGACY_PEER_BLOB_VERSION: u8 = 1;

const AGE_UNKNOWN: u8 = 0;
const AGE_WALL: u8 = 1;
const AGE_UPTIME: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RatchetError {
    /// Serialized blob is malformed, truncated, or a different version.
    InvalidBlob,
    /// Output buffer too small.
    OutputTooSmall,
    /// Candidate does not represent a valid transition from the live ring.
    InvalidCandidate,
}

/// Host-provided clocks used only for local rotation and expiry policy.
///
/// Neither value is placed on the wire. `uptime_secs` must be monotonic within
/// the current boot. A persisted uptime stamp is deliberately restored as
/// unknown because uptime has no meaning across boots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RatchetClock {
    pub wall_secs: Option<u64>,
    pub uptime_secs: u64,
}

impl RatchetClock {
    pub const fn new(wall_secs: Option<u64>, uptime_secs: u64) -> Self {
        Self {
            wall_secs,
            uptime_secs,
        }
    }

    /// Adapter for the C ABI convention where wall time zero means unavailable.
    pub const fn from_host(wall_secs: u64, uptime_secs: u64) -> Self {
        Self::new(
            if wall_secs == 0 {
                None
            } else {
                Some(wall_secs)
            },
            uptime_secs,
        )
    }

    const fn anchor(self) -> (u8, u64) {
        match self.wall_secs {
            Some(wall) => (AGE_WALL, wall),
            None => (AGE_UPTIME, self.uptime_secs),
        }
    }
}

fn age_kind_valid(kind: u8) -> bool {
    matches!(kind, AGE_UNKNOWN | AGE_WALL | AGE_UPTIME)
}

fn age_comparable(kind: u8, then: u64, clock: RatchetClock) -> bool {
    match kind {
        AGE_WALL => clock.wall_secs.is_some_and(|now| now >= then),
        AGE_UPTIME => clock.uptime_secs >= then,
        _ => false,
    }
}

fn age_elapsed_at_least(kind: u8, then: u64, clock: RatchetClock, interval: u64) -> bool {
    match kind {
        AGE_WALL => clock
            .wall_secs
            .is_some_and(|now| now >= then && now.saturating_sub(then) >= interval),
        AGE_UPTIME => {
            clock.uptime_secs >= then && clock.uptime_secs.saturating_sub(then) >= interval
        }
        _ => false,
    }
}

fn age_expired(kind: u8, then: u64, clock: RatchetClock) -> bool {
    match kind {
        AGE_WALL => clock
            .wall_secs
            .is_some_and(|now| now >= then && now.saturating_sub(then) > RATCHET_EXPIRY_SECS),
        AGE_UPTIME => {
            clock.uptime_secs >= then
                && clock.uptime_secs.saturating_sub(then) > RATCHET_EXPIRY_SECS
        }
        _ => false,
    }
}

fn effective_age(kind: u8, then: u64, clock: RatchetClock) -> (u8, u64) {
    if age_comparable(kind, then, clock) {
        (kind, then)
    } else {
        clock.anchor()
    }
}

/// What a caller should do before the next ratcheted announce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RatchetRotationAction {
    /// Current key is usable and no durable metadata change is needed.
    Unchanged,
    /// Persist re-anchored age metadata, but keep the current key.
    PersistMetadata,
    /// Generate entropy and prepare a new key.
    Rotate,
    /// Rotation is due, but a full ring cannot safely evict its oldest key.
    FullRingProtected,
}

/// Result of serializing a non-mutating candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RatchetPreparation {
    Unchanged,
    PersistMetadata {
        blob_len: usize,
    },
    Rotated {
        blob_len: usize,
        public_key: [u8; 32],
    },
    FullRingProtected,
}

impl RatchetPreparation {
    pub const fn blob_len(self) -> Option<usize> {
        match self {
            Self::PersistMetadata { blob_len } | Self::Rotated { blob_len, .. } => Some(blob_len),
            Self::Unchanged | Self::FullRingProtected => None,
        }
    }
}

/// Bounded history of own X25519 ratchet private keys, newest first.
pub struct RatchetRing {
    keys: [[u8; 32]; RATCHET_RING_MAX],
    age_kinds: [u8; RATCHET_RING_MAX],
    age_secs: [u64; RATCHET_RING_MAX],
    len: usize,
}

impl RatchetRing {
    pub const fn new() -> Self {
        Self {
            keys: [[0u8; 32]; RATCHET_RING_MAX],
            age_kinds: [AGE_UNKNOWN; RATCHET_RING_MAX],
            age_secs: [0; RATCHET_RING_MAX],
            len: 0,
        }
    }

    pub fn rotation_action(&self, clock: RatchetClock) -> RatchetRotationAction {
        if self.len == 0 {
            return RatchetRotationAction::Rotate;
        }

        let needs_anchor = (0..self.len)
            .any(|index| !age_comparable(self.age_kinds[index], self.age_secs[index], clock));
        let rotation_due = age_elapsed_at_least(
            self.age_kinds[0],
            self.age_secs[0],
            clock,
            RATCHET_INTERVAL_SECS,
        );

        if !rotation_due {
            return if needs_anchor {
                RatchetRotationAction::PersistMetadata
            } else {
                RatchetRotationAction::Unchanged
            };
        }

        if self.len < RATCHET_RING_MAX
            || age_expired(
                self.age_kinds[self.len - 1],
                self.age_secs[self.len - 1],
                clock,
            )
        {
            RatchetRotationAction::Rotate
        } else if needs_anchor {
            RatchetRotationAction::PersistMetadata
        } else {
            RatchetRotationAction::FullRingProtected
        }
    }

    /// Serialize the next candidate directly into caller storage without
    /// cloning the ~2.6 KiB ring or mutating live key material.
    ///
    /// The host must durably store `out[..blob_len]`, read/verify it as needed,
    /// and only then call [`Self::commit_prepared_blob`]. Abandoning the bytes
    /// leaves the live ring and advertised key unchanged.
    pub fn prepare_rotation_into(
        &self,
        mut fresh_private: [u8; 32],
        clock: RatchetClock,
        out: &mut [u8],
    ) -> Result<RatchetPreparation, RatchetError> {
        let result = self.prepare_rotation_inner(&fresh_private, clock, out);
        fresh_private.zeroize();
        result
    }

    fn prepare_rotation_inner(
        &self,
        fresh_private: &[u8; 32],
        clock: RatchetClock,
        out: &mut [u8],
    ) -> Result<RatchetPreparation, RatchetError> {
        let action = self.rotation_action(clock);
        if action == RatchetRotationAction::Unchanged {
            return Ok(RatchetPreparation::Unchanged);
        }
        if action == RatchetRotationAction::FullRingProtected {
            return Ok(RatchetPreparation::FullRingProtected);
        }

        let rotating = action == RatchetRotationAction::Rotate;
        let candidate_len = if rotating {
            core::cmp::min(self.len + 1, RATCHET_RING_MAX)
        } else {
            self.len
        };
        let need = ring_blob_len(candidate_len);
        if out.len() < need {
            return Err(RatchetError::OutputTooSmall);
        }

        out[0] = RING_BLOB_VERSION;
        out[1] = candidate_len as u8;
        let fresh_age = clock.anchor();
        for candidate_index in 0..candidate_len {
            let pos = 2 + candidate_index * 41;
            let source_index = if rotating {
                candidate_index.checked_sub(1)
            } else {
                Some(candidate_index)
            };
            let (kind, seconds, key) = match source_index {
                Some(source) => {
                    let (kind, seconds) =
                        effective_age(self.age_kinds[source], self.age_secs[source], clock);
                    (kind, seconds, &self.keys[source])
                }
                None => (fresh_age.0, fresh_age.1, fresh_private),
            };
            out[pos] = kind;
            out[pos + 1..pos + 9].copy_from_slice(&seconds.to_be_bytes());
            out[pos + 9..pos + 41].copy_from_slice(key);
        }

        if rotating {
            Ok(RatchetPreparation::Rotated {
                blob_len: need,
                public_key: ratchet_public_bytes(fresh_private),
            })
        } else {
            Ok(RatchetPreparation::PersistMetadata { blob_len: need })
        }
    }

    /// Commit exactly one valid prepared transition after persistence succeeds.
    /// Validation completes before the live ring is overwritten.
    pub fn commit_prepared_blob(&mut self, blob: &[u8]) -> Result<(), RatchetError> {
        validate_ring_blob(blob, false)?;
        if blob[0] != RING_BLOB_VERSION || !self.is_valid_candidate(blob) {
            return Err(RatchetError::InvalidCandidate);
        }
        self.apply_blob(blob, false)
    }

    fn is_valid_candidate(&self, blob: &[u8]) -> bool {
        let candidate_len = blob[1] as usize;
        if self.len == 0 {
            return candidate_len == 1;
        }

        // Metadata-only candidate: exact key sequence, age fields may only be
        // re-anchored by the non-mutating preparation step.
        if candidate_len == self.len
            && (0..self.len).all(|index| ring_blob_key(blob, index) == self.keys[index])
        {
            return true;
        }

        let expected_len = core::cmp::min(self.len + 1, RATCHET_RING_MAX);
        candidate_len == expected_len
            && (1..candidate_len).all(|index| ring_blob_key(blob, index) == self.keys[index - 1])
    }

    pub fn current_public_key(&self) -> Option<[u8; 32]> {
        self.private_key(0).map(ratchet_public_bytes)
    }

    /// Retained private keys, newest first, for bounded decrypt attempts.
    pub fn private_keys(&self) -> &[[u8; 32]] {
        &self.keys[..self.len]
    }

    /// One retained key for a previously validated decrypt hint.
    pub fn private_key(&self, index: usize) -> Option<&[u8; 32]> {
        (index < self.len).then(|| &self.keys[index])
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Serialize current live state in the bounded v2 format.
    pub fn serialize_into(&self, out: &mut [u8]) -> Result<usize, RatchetError> {
        let need = ring_blob_len(self.len);
        if out.len() < need {
            return Err(RatchetError::OutputTooSmall);
        }
        out[0] = RING_BLOB_VERSION;
        out[1] = self.len as u8;
        for index in 0..self.len {
            let pos = 2 + index * 41;
            out[pos] = self.age_kinds[index];
            out[pos + 1..pos + 9].copy_from_slice(&self.age_secs[index].to_be_bytes());
            out[pos + 9..pos + 41].copy_from_slice(&self.keys[index]);
        }
        Ok(need)
    }

    /// Restore host-persisted state in place. The live ring remains unchanged
    /// if the blob fails complete bounds/shape validation.
    pub fn load_persisted(&mut self, blob: &[u8]) -> Result<(), RatchetError> {
        validate_ring_blob(blob, true)?;
        self.apply_blob(blob, true)
    }

    pub fn deserialize(blob: &[u8]) -> Result<Self, RatchetError> {
        let mut ring = Self::new();
        ring.load_persisted(blob)?;
        Ok(ring)
    }

    fn apply_blob(&mut self, blob: &[u8], persisted: bool) -> Result<(), RatchetError> {
        let version = blob[0];
        let len = blob[1] as usize;
        self.zeroize();
        self.len = len;

        if version == LEGACY_RING_BLOB_VERSION {
            let mut encoded = [0u8; 8];
            encoded.copy_from_slice(&blob[2..10]);
            let last_rotation = u64::from_be_bytes(encoded);
            if len > 0 && last_rotation != 0 {
                self.age_kinds[0] = AGE_WALL;
                self.age_secs[0] = last_rotation;
            }
            for index in 0..len {
                let pos = 10 + index * 32;
                self.keys[index].copy_from_slice(&blob[pos..pos + 32]);
            }
            return Ok(());
        }

        for index in 0..len {
            let pos = 2 + index * 41;
            let stored_kind = blob[pos];
            self.age_kinds[index] = if persisted && stored_kind == AGE_UPTIME {
                AGE_UNKNOWN
            } else {
                stored_kind
            };
            let mut encoded = [0u8; 8];
            encoded.copy_from_slice(&blob[pos + 1..pos + 9]);
            self.age_secs[index] = if self.age_kinds[index] == AGE_UNKNOWN {
                0
            } else {
                u64::from_be_bytes(encoded)
            };
            self.keys[index].copy_from_slice(&blob[pos + 9..pos + 41]);
        }
        Ok(())
    }
}

fn ring_blob_len(len: usize) -> usize {
    2 + len * 41
}

fn ring_blob_key(blob: &[u8], index: usize) -> &[u8] {
    let pos = 2 + index * 41;
    &blob[pos + 9..pos + 41]
}

fn validate_ring_blob(blob: &[u8], allow_legacy: bool) -> Result<(), RatchetError> {
    if blob.len() < 2 {
        return Err(RatchetError::InvalidBlob);
    }
    let len = blob[1] as usize;
    if len > RATCHET_RING_MAX {
        return Err(RatchetError::InvalidBlob);
    }
    match blob[0] {
        RING_BLOB_VERSION => {
            if blob.len() != ring_blob_len(len) {
                return Err(RatchetError::InvalidBlob);
            }
            for index in 0..len {
                let pos = 2 + index * 41;
                if !age_kind_valid(blob[pos])
                    || (blob[pos] == AGE_UNKNOWN
                        && blob[pos + 1..pos + 9].iter().any(|byte| *byte != 0))
                {
                    return Err(RatchetError::InvalidBlob);
                }
            }
            Ok(())
        }
        LEGACY_RING_BLOB_VERSION if allow_legacy && blob.len() == 10 + len * 32 => Ok(()),
        _ => Err(RatchetError::InvalidBlob),
    }
}

impl Default for RatchetRing {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for RatchetRing {
    fn zeroize(&mut self) {
        self.keys.zeroize();
        self.age_kinds.zeroize();
        self.age_secs.zeroize();
        self.len = 0;
    }
}

impl Drop for RatchetRing {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn ratchet_public_bytes(ratchet_private: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*ratchet_private)).to_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerRatchet {
    dest_hash: [u8; DESTINATION_LENGTH],
    ratchet: [u8; 32],
    age_kind: u8,
    age_secs: u64,
}

impl PeerRatchet {
    const EMPTY: Self = Self {
        dest_hash: [0; DESTINATION_LENGTH],
        ratchet: [0; 32],
        age_kind: AGE_UNKNOWN,
        age_secs: 0,
    };

    fn is_expired(self, clock: RatchetClock) -> bool {
        age_expired(self.age_kind, self.age_secs, clock)
    }
}

/// Latest announced ratchet per peer destination, newest first.
pub struct PeerRatchets {
    entries: [PeerRatchet; PEER_RATCHETS_MAX],
    len: usize,
}

impl PeerRatchets {
    pub const fn new() -> Self {
        Self {
            entries: [PeerRatchet::EMPTY; PEER_RATCHETS_MAX],
            len: 0,
        }
    }

    /// Remember a new ratchet. Re-observing the same key is a strict no-op and
    /// therefore cannot refresh its expiry. Returns whether state changed.
    pub fn remember(
        &mut self,
        dest_hash: [u8; DESTINATION_LENGTH],
        ratchet: [u8; 32],
        clock: RatchetClock,
    ) -> bool {
        if let Some(index) = (0..self.len).find(|index| self.entries[*index].dest_hash == dest_hash)
        {
            if self.entries[index].ratchet == ratchet {
                return false;
            }
            self.remove(index);
        }

        self.purge_expired(clock);
        if self.len == PEER_RATCHETS_MAX {
            self.remove(self.len - 1);
        }
        let mut index = self.len;
        while index > 0 {
            self.entries[index] = self.entries[index - 1];
            index -= 1;
        }
        let (age_kind, age_secs) = clock.anchor();
        self.entries[0] = PeerRatchet {
            dest_hash,
            ratchet,
            age_kind,
            age_secs,
        };
        self.len += 1;
        true
    }

    /// Conservatively anchor restored/rollback ages at the current local
    /// clock. Callers should persist the table when this returns true.
    pub fn anchor_unknown_ages(&mut self, clock: RatchetClock) -> bool {
        let anchor = clock.anchor();
        let mut changed = false;
        for entry in &mut self.entries[..self.len] {
            if !age_comparable(entry.age_kind, entry.age_secs, clock) {
                entry.age_kind = anchor.0;
                entry.age_secs = anchor.1;
                changed = true;
            }
        }
        changed
    }

    /// Latest non-expired ratchet for `dest_hash`.
    pub fn get(
        &self,
        dest_hash: &[u8; DESTINATION_LENGTH],
        clock: RatchetClock,
    ) -> Option<[u8; 32]> {
        self.entries[..self.len].iter().find_map(|entry| {
            (entry.dest_hash == *dest_hash && !entry.is_expired(clock)).then_some(entry.ratchet)
        })
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn remove(&mut self, index: usize) {
        let mut cursor = index;
        while cursor + 1 < self.len {
            self.entries[cursor] = self.entries[cursor + 1];
            cursor += 1;
        }
        self.len -= 1;
        self.entries[self.len] = PeerRatchet::EMPTY;
    }

    fn purge_expired(&mut self, clock: RatchetClock) {
        let mut index = 0;
        while index < self.len {
            if self.entries[index].is_expired(clock) {
                self.remove(index);
            } else {
                index += 1;
            }
        }
    }

    pub fn serialize_into(&self, out: &mut [u8]) -> Result<usize, RatchetError> {
        let need = peer_blob_len(self.len);
        if out.len() < need {
            return Err(RatchetError::OutputTooSmall);
        }
        out[0] = PEER_BLOB_VERSION;
        out[1] = self.len as u8;
        for (index, entry) in self.entries[..self.len].iter().enumerate() {
            let pos = 2 + index * 57;
            out[pos..pos + 16].copy_from_slice(&entry.dest_hash);
            out[pos + 16..pos + 48].copy_from_slice(&entry.ratchet);
            out[pos + 48] = entry.age_kind;
            out[pos + 49..pos + 57].copy_from_slice(&entry.age_secs.to_be_bytes());
        }
        Ok(need)
    }

    /// Restore a v1/v2 table in place after complete validation. Persisted
    /// uptime ages become unknown and must be re-anchored by the host.
    pub fn load_persisted(&mut self, blob: &[u8]) -> Result<(), RatchetError> {
        validate_peer_blob(blob)?;
        let version = blob[0];
        let len = blob[1] as usize;
        self.zeroize();
        self.len = len;
        for index in 0..len {
            let (pos, age_kind, age_secs) = if version == LEGACY_PEER_BLOB_VERSION {
                let pos = 2 + index * 56;
                let mut encoded = [0u8; 8];
                encoded.copy_from_slice(&blob[pos + 48..pos + 56]);
                let seconds = u64::from_be_bytes(encoded);
                (
                    pos,
                    if seconds == 0 { AGE_UNKNOWN } else { AGE_WALL },
                    seconds,
                )
            } else {
                let pos = 2 + index * 57;
                let stored_kind = blob[pos + 48];
                let mut encoded = [0u8; 8];
                encoded.copy_from_slice(&blob[pos + 49..pos + 57]);
                let seconds = u64::from_be_bytes(encoded);
                (
                    pos,
                    if stored_kind == AGE_UPTIME {
                        AGE_UNKNOWN
                    } else {
                        stored_kind
                    },
                    if stored_kind == AGE_UPTIME {
                        0
                    } else {
                        seconds
                    },
                )
            };
            self.entries[index]
                .dest_hash
                .copy_from_slice(&blob[pos..pos + 16]);
            self.entries[index]
                .ratchet
                .copy_from_slice(&blob[pos + 16..pos + 48]);
            self.entries[index].age_kind = age_kind;
            self.entries[index].age_secs = age_secs;
        }
        Ok(())
    }

    pub fn deserialize(blob: &[u8]) -> Result<Self, RatchetError> {
        let mut table = Self::new();
        table.load_persisted(blob)?;
        Ok(table)
    }
}

fn peer_blob_len(len: usize) -> usize {
    2 + len * 57
}

fn validate_peer_blob(blob: &[u8]) -> Result<(), RatchetError> {
    if blob.len() < 2 {
        return Err(RatchetError::InvalidBlob);
    }
    let count = blob[1] as usize;
    if count > PEER_RATCHETS_MAX {
        return Err(RatchetError::InvalidBlob);
    }
    match blob[0] {
        PEER_BLOB_VERSION => {
            if blob.len() != peer_blob_len(count) {
                return Err(RatchetError::InvalidBlob);
            }
            for index in 0..count {
                let pos = 2 + index * 57;
                if !age_kind_valid(blob[pos + 48])
                    || (blob[pos + 48] == AGE_UNKNOWN
                        && blob[pos + 49..pos + 57].iter().any(|byte| *byte != 0))
                {
                    return Err(RatchetError::InvalidBlob);
                }
            }
            Ok(())
        }
        LEGACY_PEER_BLOB_VERSION if blob.len() == 2 + count * 56 => Ok(()),
        _ => Err(RatchetError::InvalidBlob),
    }
}

impl Default for PeerRatchets {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for PeerRatchets {
    fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.dest_hash.zeroize();
            entry.ratchet.zeroize();
            entry.age_kind = AGE_UNKNOWN;
            entry.age_secs = 0;
        }
        self.len = 0;
    }
}

impl Drop for PeerRatchets {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn wall(seconds: u64) -> RatchetClock {
        RatchetClock::new(Some(seconds), seconds)
    }

    fn uptime(seconds: u64) -> RatchetClock {
        RatchetClock::new(None, seconds)
    }

    fn prepare_commit(
        ring: &mut RatchetRing,
        private: [u8; 32],
        clock: RatchetClock,
    ) -> RatchetPreparation {
        let mut blob = [0u8; RATCHET_RING_BLOB_MAX];
        let prepared = ring
            .prepare_rotation_into(private, clock, &mut blob)
            .unwrap();
        if let Some(len) = prepared.blob_len() {
            ring.commit_prepared_blob(&blob[..len]).unwrap();
        }
        prepared
    }

    #[test]
    fn rotation_is_prepare_persist_commit_and_newest_first() {
        let mut ring = RatchetRing::new();
        let mut blob = [0u8; RATCHET_RING_BLOB_MAX];
        let prepared = ring
            .prepare_rotation_into(key(1), wall(100), &mut blob)
            .unwrap();
        let RatchetPreparation::Rotated {
            blob_len,
            public_key,
        } = prepared
        else {
            panic!("empty ring must rotate");
        };
        assert!(ring.is_empty(), "preparation cannot mutate live secrets");
        assert_eq!(public_key, ratchet_public_bytes(&key(1)));

        // Simulated persistence failure: abandoning candidate leaves base mode.
        assert_eq!(ring.current_public_key(), None);
        ring.commit_prepared_blob(&blob[..blob_len]).unwrap();
        assert_eq!(ring.private_keys(), &[key(1)]);

        assert_eq!(
            prepare_commit(&mut ring, key(2), wall(100 + RATCHET_INTERVAL_SECS)),
            RatchetPreparation::Rotated {
                blob_len: ring_blob_len(2),
                public_key: ratchet_public_bytes(&key(2)),
            }
        );
        assert_eq!(ring.private_keys(), &[key(2), key(1)]);
    }

    #[test]
    fn unknown_age_anchors_then_rotates_into_free_capacity() {
        let mut ring = RatchetRing::new();
        prepare_commit(&mut ring, key(1), uptime(10));
        let mut persisted = [0u8; RATCHET_RING_BLOB_MAX];
        let n = ring.serialize_into(&mut persisted).unwrap();
        let mut restored = RatchetRing::deserialize(&persisted[..n]).unwrap();

        assert_eq!(
            restored.rotation_action(uptime(1)),
            RatchetRotationAction::PersistMetadata
        );
        assert!(matches!(
            prepare_commit(&mut restored, key(9), uptime(1)),
            RatchetPreparation::PersistMetadata { .. }
        ));
        assert_eq!(restored.private_keys(), &[key(1)]);
        assert_eq!(
            restored.rotation_action(uptime(RATCHET_INTERVAL_SECS)),
            RatchetRotationAction::Unchanged
        );
        assert_eq!(
            restored.rotation_action(uptime(1 + RATCHET_INTERVAL_SECS)),
            RatchetRotationAction::Rotate
        );
        prepare_commit(&mut restored, key(2), uptime(1 + RATCHET_INTERVAL_SECS));
        assert_eq!(restored.private_keys(), &[key(2), key(1)]);
    }

    #[test]
    fn full_unknown_ring_never_evicts_until_oldest_expiry_is_proven() {
        let mut ring = RatchetRing::new();
        for index in 0..RATCHET_RING_MAX {
            prepare_commit(
                &mut ring,
                key(index as u8),
                uptime(index as u64 * RATCHET_INTERVAL_SECS),
            );
        }
        let oldest = ring.private_keys()[RATCHET_RING_MAX - 1];

        let mut persisted = [0u8; RATCHET_RING_BLOB_MAX];
        let n = ring.serialize_into(&mut persisted).unwrap();
        let mut restored = RatchetRing::deserialize(&persisted[..n]).unwrap();
        assert!(matches!(
            prepare_commit(&mut restored, key(0xee), uptime(10)),
            RatchetPreparation::PersistMetadata { .. }
        ));
        assert_eq!(restored.private_keys()[RATCHET_RING_MAX - 1], oldest);

        assert_eq!(
            restored.rotation_action(uptime(10 + RATCHET_INTERVAL_SECS)),
            RatchetRotationAction::FullRingProtected
        );
        assert_eq!(
            prepare_commit(&mut restored, key(0xee), uptime(10 + RATCHET_INTERVAL_SECS)),
            RatchetPreparation::FullRingProtected
        );
        assert_eq!(restored.private_keys()[RATCHET_RING_MAX - 1], oldest);

        prepare_commit(
            &mut restored,
            key(0xee),
            uptime(10 + RATCHET_EXPIRY_SECS + 1),
        );
        assert_eq!(restored.private_keys()[0], key(0xee));
        assert_ne!(restored.private_keys()[RATCHET_RING_MAX - 1], oldest);
    }

    #[test]
    fn ring_blob_migrates_v1_and_rejects_malformed_without_mutating_live() {
        let mut legacy = [0u8; 10 + 2 * 32];
        legacy[0] = LEGACY_RING_BLOB_VERSION;
        legacy[1] = 2;
        legacy[2..10].copy_from_slice(&1234u64.to_be_bytes());
        legacy[10..42].copy_from_slice(&key(7));
        legacy[42..74].copy_from_slice(&key(8));
        let ring = RatchetRing::deserialize(&legacy).unwrap();
        assert_eq!(ring.private_keys(), &[key(7), key(8)]);
        assert_eq!(
            ring.rotation_action(wall(1234)),
            RatchetRotationAction::PersistMetadata
        );

        let mut live = RatchetRing::new();
        prepare_commit(&mut live, key(3), wall(50));
        assert!(live.load_persisted(&legacy[..73]).is_err());
        assert_eq!(live.private_keys(), &[key(3)]);

        let mut blob = [0u8; RATCHET_RING_BLOB_MAX];
        let n = live.serialize_into(&mut blob).unwrap();
        blob[2] = 0xff;
        assert!(RatchetRing::deserialize(&blob[..n]).is_err());
        blob[2] = AGE_UNKNOWN;
        blob[3] = 1;
        assert!(RatchetRing::deserialize(&blob[..n]).is_err());
    }

    #[test]
    fn candidate_commit_rejects_stale_or_unrelated_key_sequences() {
        let mut ring = RatchetRing::new();
        prepare_commit(&mut ring, key(1), wall(1));
        let mut blob = [0u8; RATCHET_RING_BLOB_MAX];
        let n = ring.serialize_into(&mut blob).unwrap();
        blob[2 + 9] ^= 1;
        assert_eq!(
            ring.commit_prepared_blob(&blob[..n]),
            Err(RatchetError::InvalidCandidate)
        );
        assert_eq!(ring.private_keys(), &[key(1)]);
    }

    #[test]
    fn peer_same_key_is_noop_and_changed_key_is_newest() {
        let mut table = PeerRatchets::new();
        let dest = [0xaa; 16];
        assert!(table.remember(dest, key(1), wall(1_000)));
        assert!(!table.remember(dest, key(1), wall(2_000)));
        assert_eq!(
            table.get(&dest, wall(1_000 + RATCHET_EXPIRY_SECS + 1)),
            None,
            "replayed announce cannot refresh expiry"
        );
        assert!(table.remember(dest, key(2), wall(2_000)));
        assert_eq!(table.get(&dest, wall(2_000)), Some(key(2)));
    }

    #[test]
    fn peer_table_evicts_by_insertion_order_not_incomparable_clock_values() {
        let mut table = PeerRatchets::new();
        for index in 0..PEER_RATCHETS_MAX {
            assert!(table.remember([index as u8; 16], key(index as u8), uptime(index as u64)));
        }
        assert!(table.remember([0xee; 16], key(0xee), wall(10_000)));
        assert_eq!(table.get(&[0; 16], wall(10_000)), None);
        assert_eq!(table.get(&[1; 16], wall(10_000)), Some(key(1)));
        assert_eq!(table.get(&[0xee; 16], wall(10_000)), Some(key(0xee)));
    }

    #[test]
    fn persisted_uptime_peer_age_is_anchored_then_expires() {
        let mut table = PeerRatchets::new();
        let dest = [0xc1; 16];
        table.remember(dest, key(8), uptime(500));
        let mut blob = [0u8; PEER_RATCHETS_BLOB_MAX];
        let n = table.serialize_into(&mut blob).unwrap();
        let mut restored = PeerRatchets::deserialize(&blob[..n]).unwrap();

        assert_eq!(restored.get(&dest, uptime(1)), Some(key(8)));
        assert!(restored.anchor_unknown_ages(uptime(1)));
        assert!(!restored.anchor_unknown_ages(uptime(2)));
        assert_eq!(
            restored.get(&dest, uptime(1 + RATCHET_EXPIRY_SECS)),
            Some(key(8))
        );
        assert_eq!(restored.get(&dest, uptime(2 + RATCHET_EXPIRY_SECS)), None);
    }

    #[test]
    fn peer_blob_roundtrips_migrates_v1_and_rejects_bad_counts() {
        let mut table = PeerRatchets::new();
        table.remember([0x11; 16], key(3), wall(5_000));
        table.remember([0x22; 16], key(4), wall(6_000));
        let mut blob = [0u8; PEER_RATCHETS_BLOB_MAX];
        let n = table.serialize_into(&mut blob).unwrap();
        let restored = PeerRatchets::deserialize(&blob[..n]).unwrap();
        assert_eq!(restored.get(&[0x11; 16], wall(6_000)), Some(key(3)));
        assert_eq!(restored.get(&[0x22; 16], wall(6_000)), Some(key(4)));
        assert!(PeerRatchets::deserialize(&blob[..n - 1]).is_err());

        let mut legacy = [0u8; 2 + 56];
        legacy[0] = LEGACY_PEER_BLOB_VERSION;
        legacy[1] = 1;
        legacy[2..18].copy_from_slice(&[0x33; 16]);
        legacy[18..50].copy_from_slice(&key(9));
        legacy[50..58].copy_from_slice(&7_000u64.to_be_bytes());
        let migrated = PeerRatchets::deserialize(&legacy).unwrap();
        assert_eq!(migrated.get(&[0x33; 16], wall(7_000)), Some(key(9)));

        blob[1] = (PEER_RATCHETS_MAX + 1) as u8;
        assert!(PeerRatchets::deserialize(&blob[..n]).is_err());
    }

    #[test]
    fn embedded_state_and_blobs_stay_inside_explicit_memory_budgets() {
        assert!(
            core::mem::size_of::<RatchetRing>() <= 3 * 1024,
            "ring state grew to {} bytes",
            core::mem::size_of::<RatchetRing>()
        );
        assert!(
            core::mem::size_of::<PeerRatchets>() <= 3 * 1024,
            "peer table grew to {} bytes",
            core::mem::size_of::<PeerRatchets>()
        );
    }
}

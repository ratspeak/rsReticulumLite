//! Bounded adaptation of trusted rns-transport actor/recursive_discovery.rs.
//! A mask indexes the embedding owner's stable interface slots. The owner MUST
//! retire a slot before changing its registration generation or reusing it.
//! This holds no packet bytes and is independent of queued-egress admission.

pub const REQUESTERS: usize = 8;
pub const REQUEST_GATE_MS: u64 = 15_000;

/// Canonical MTU round trip, rounded upwards to integral milliseconds. Unknown
/// rates add no allowance; a reported rate below5bps cannot grant infinite state.
pub const fn round_trip_ms(bitrate_bps: u64) -> u64 {
    if bitrate_bps == 0 {
        return 0;
    }
    let rate = if bitrate_bps < 5 { 5 } else { bitrate_bps };
    let bits_ms = 2 * crate::constants::MTU as u64 * 8 * 1000;
    bits_ms.div_ceil(rate)
}

pub const fn link_deadline(now: u64, hops: u8, bitrate_bps: u64) -> u64 {
    let hops = if hops == 0 { 1 } else { hops };
    now.saturating_add(6_000 * hops as u64)
        .saturating_add(round_trip_ms(bitrate_bps))
}

pub const fn discovery_timeout(bitrate_bps: u64) -> u64 {
    let sampled = 6_000u64.saturating_add(round_trip_ms(bitrate_bps));
    if sampled > REQUEST_GATE_MS {
        sampled
    } else {
        REQUEST_GATE_MS
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryEntry {
    pub destination: [u8; 16],
    pub expires_ms: u64,
    pub identity: u64,
    pub requesters: u8,
}
impl DiscoveryEntry {
    pub const EMPTY: Self = Self {
        destination: [0; 16],
        expires_ms: 0,
        identity: 0,
        requesters: 0,
    };
    fn live(self, now: u64) -> bool {
        self.identity != 0 && self.requesters != 0 && now < self.expires_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginDiscovery {
    New(u64),
    Joined,
    Refused,
}

#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discoveries<const N: usize> {
    // Exposed solely for the handheld FFI placement initializer.
    pub entries: [DiscoveryEntry; N],
    pub last_identity: u64,
}
impl<const N: usize> Discoveries<N> {
    pub const fn new() -> Self {
        Self {
            entries: [DiscoveryEntry::EMPTY; N],
            last_identity: 0,
        }
    }
    pub fn clear(&mut self) {
        self.entries.fill(DiscoveryEntry::EMPTY);
    }
    pub fn expire(&mut self, now: u64) {
        for entry in &mut self.entries {
            if !entry.live(now) {
                *entry = DiscoveryEntry::EMPTY;
            }
        }
    }
    pub fn retire_requester(&mut self, slot: usize) {
        if slot >= REQUESTERS {
            return;
        }
        for entry in &mut self.entries {
            entry.requesters &= !(1 << slot);
            if entry.requesters == 0 {
                *entry = DiscoveryEntry::EMPTY;
            }
        }
    }
    pub fn begin(
        &mut self,
        destination: [u8; 16],
        slot: usize,
        now: u64,
        timeout: u64,
    ) -> BeginDiscovery {
        if slot >= REQUESTERS {
            return BeginDiscovery::Refused;
        }
        self.expire(now);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.identity != 0 && e.destination == destination)
        {
            entry.requesters |= 1 << slot;
            return BeginDiscovery::Joined;
        }
        let Some(entry) = self.entries.iter_mut().find(|e| e.identity == 0) else {
            return BeginDiscovery::Refused;
        };
        let Some(identity) = self.last_identity.checked_add(1) else {
            return BeginDiscovery::Refused;
        };
        let expires_ms = now.saturating_add(timeout);
        if expires_ms <= now {
            return BeginDiscovery::Refused;
        }
        self.last_identity = identity;
        *entry = DiscoveryEntry {
            destination,
            expires_ms,
            identity,
            requesters: 1 << slot,
        };
        BeginDiscovery::New(identity)
    }
    pub fn live(&self, identity: u64, now: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.identity == identity && e.live(now))
    }
    pub fn deadline(&self, identity: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.identity != 0 && e.identity == identity)
            .map(|e| e.expires_ms)
    }
    pub fn take(&mut self, destination: &[u8; 16], now: u64) -> Option<DiscoveryEntry> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.identity != 0 && &e.destination == destination)?;
        let taken = *entry;
        *entry = DiscoveryEntry::EMPTY;
        taken.live(now).then_some(taken)
    }
}
impl<const N: usize> Default for Discoveries<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_rounding_bounds_and_strictness() {
        assert_eq!(round_trip_ms(0), 0);
        assert_eq!(round_trip_ms(1), 1_600_000);
        assert_eq!(round_trip_ms(5), 1_600_000);
        assert_eq!(round_trip_ms(61), 131_148);
        assert_eq!(round_trip_ms(u64::MAX), 1);
        assert_eq!(discovery_timeout(0), 15_000);
        assert_eq!(link_deadline(0, 0, 0), 6_000);
        let mut d = Discoveries::<1>::new();
        assert_eq!(d.begin([1; 16], 0, 0, 15_000), BeginDiscovery::New(1));
        assert_eq!(d.begin([1; 16], 1, 14_999, 900_000), BeginDiscovery::Joined);
        assert_eq!(d.deadline(1), Some(15_000));
        assert!(d.live(1, 14_999));
        assert!(!d.live(1, 15_000));
        assert_eq!(d.begin([1; 16], 0, 15_000, 15_000), BeginDiscovery::New(2));
        assert!(!d.live(1, 15_000));
        assert!(d.live(2, 15_000));
        assert_eq!(
            d.begin([2; 16], 0, u64::MAX, 15_000),
            BeginDiscovery::Refused
        );
        assert_eq!(d.last_identity, 2);
    }
    #[test]
    fn all_requester_bits_retire_before_reuse() {
        let mut d = Discoveries::<2>::new();
        assert_eq!(d.begin([1; 16], 0, 1000, 15_000), BeginDiscovery::New(1));
        for slot in 1..8 {
            assert_eq!(d.begin([1; 16], slot, 2000, 99_999), BeginDiscovery::Joined);
        }
        for slot in 0..7 {
            d.retire_requester(slot);
            assert!(d.live(1, 3000));
        }
        assert_eq!(d.entries[0].requesters, 128);
        d.retire_requester(7);
        assert!(!d.live(1, 3000));
        assert_eq!(d.begin([1; 16], 7, 3000, 15_000), BeginDiscovery::New(2));
        assert_eq!(d.take(&[1; 16], 3001).unwrap().requesters, 128);
        assert!(!d.live(2, 3001));
        d.last_identity = u64::MAX;
        assert_eq!(d.begin([1; 16], 0, 3002, 15_000), BeginDiscovery::Refused);
        assert_eq!(d.begin([1; 16], 8, 3002, 15_000), BeginDiscovery::Refused);
    }
}

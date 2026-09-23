use ed25519_dalek::Verifier;

use crate::announce_admission::AnnounceAdmission;
use crate::config::{InterfaceMode, LiteConfig};
use crate::constants::{
    AP_PATH_TIME_SECS, LINK_TIMEOUT_SECS, PATH_REQUEST_DUPLICATE_GATE_SECS, PATHFINDER_E_SECS,
    PATHFINDER_M, QUEUED_ANNOUNCE_LIFE_SECS, REVERSE_TIMEOUT_SECS, ROAMING_PATH_TIME_SECS,
};
use crate::discovery::{
    BeginDiscovery, Discoveries, REQUEST_GATE_MS, REQUESTERS, discovery_timeout, link_deadline,
};
use crate::identity::{
    AnnounceError, AnnounceView, LXMF_DELIVERY_NAME, SIGNED_DATA_MAX, destination_hash_from_name,
    name_hash,
};
use crate::ifac::{IfacError, has_ifac_flag, ifac_sign_into, ifac_verify_into};
use crate::known_destinations::{
    KNOWN_DESTINATIONS_MICRO, KNOWN_DESTINATIONS_SMALL, KnownDestinationError, KnownDestinations,
};
use crate::packet_buffer::{BufferError, PacketBuffer, WireBuffer};
use crate::tables::{
    AnnounceCache, AnnounceSchedule, CachedAnnounce, Hash16, InterfaceId, LinkEntry, LinkTable,
    PacketHashTable, PathEntry, PathTable, Queue, RequestTagTable, ReverseEntry, ReverseTable,
    ScheduledAnnounce,
};
use crate::wire::{
    DestinationType, HeaderType, PacketContext, PacketFlags, PacketHeader, PacketType, PacketView,
    TransportType, WireError, build_packet, link_id_from_raw, packet_hash, rewrite_with_header,
    truncated_packet_hash,
};

pub type SmallNode = LiteNode<256, 512, 64, 64, 32, 64, 64, KNOWN_DESTINATIONS_SMALL>;
pub type Esp32PsramNode = LiteNode<1024, 2048, 128, 128, 64, 256, 128, KNOWN_DESTINATIONS_SMALL>;
/// Cardputer-class profile (no PSRAM): sized for [`LiteConfig::ESP32_LORA_TRANSPORT_MICRO`];
/// whole node <= 32 KB (asserted in tests) so it fits the internal heap.
pub type MicroNode = LiteNode<48, 64, 8, 8, 4, 8, 8, KNOWN_DESTINATIONS_MICRO>;

/// Fixed slot count for a node's own registered destination hashes (endpoint destinations
/// living on the same device as the relay, e.g. lxmf.delivery — one per local identity).
pub const OWN_DESTINATIONS_MAX: usize = 4;

const HASHLIST_LIFETIME_MS: u64 = 120_000;
// Upstream PATHFINDER_RW = 0.5s: announce rebroadcast jitter window is [0,500)ms.
// (The deterministic packet-hash-derived selection is a sound no-RNG MCU adaptation.)
const DEFAULT_ANNOUNCE_JITTER_MS: u64 = 500;
// Sized to the full single-packet announce signed_data (incl. wire-max app_data), shared with the
// endpoint path so the relay can't reject a long-display-name announce the endpoint would accept.
const ANNOUNCE_SCRATCH_MAX: usize = SIGNED_DATA_MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxMeta {
    pub interface_id: InterfaceId,
    /// Mode of the interface that received this packet. Hosts with an interface
    /// registry should supply it so learned-path expiry follows that interface;
    /// `None` retains the node-wide compatibility fallback.
    pub interface_mode: Option<InterfaceMode>,
    pub rssi: Option<i16>,
    pub snr_quarter_db: Option<i8>,
}

impl RxMeta {
    pub const fn new(interface_id: InterfaceId) -> Self {
        Self {
            interface_id,
            interface_mode: None,
            rssi: None,
            snr_quarter_db: None,
        }
    }

    pub const fn with_mode(interface_id: InterfaceId, interface_mode: InterfaceMode) -> Self {
        Self {
            interface_id,
            interface_mode: Some(interface_mode),
            rssi: None,
            snr_quarter_db: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundFrame {
    pub interface_id: InterfaceId,
    /// Wire bytes: a plain packet, or an IFAC-wrapped frame up to MTU + tag.
    pub packet: WireBuffer,
    pub reason: OutboundReason,
    pub lifetime: OutboundLifetime,
}

/// Internal handheld adapter metadata. Not a wire or public packet representation.
#[doc(hidden)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundDelivery {
    pub identity: u64,
    pub interface_generations: [u32; 7],
    /// Before binding, allowed targets; afterwards, only still-unadmitted targets.
    pub pending_targets: u8,
    pub initialized: bool,
}

/// Internal queue entry; legacy consumers still receive the unchanged OutboundFrame.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedOutbound {
    pub frame: OutboundFrame,
    pub delivery: OutboundDelivery,
}

/// Immutable local queue-wait ceiling, checked before a driver starts a packet.
/// Discovery operation timers, deduplication retention and on-air completion are
/// separate policies. Once started, an atomic radio burst may finish after this
/// queue deadline; route, reverse and link state is never extended by waiting.
pub const OUTBOUND_MAX_AGE_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundLifetime {
    pub enqueued_ms: u64,
    pub expires_ms: u64,
    path: u64,
    state: OutboundState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundState {
    Independent,
    Reverse(u64),
    Link(u64),
    Discovery(u64),
}

impl OutboundLifetime {
    /// Portable owner-to-driver token. This is process-local metadata, never a
    /// Reticulum packet or persistent format. Explicit bytes avoid exposing Rust
    /// enum/Option layout across a C ABI. Hosts must retain the original token.
    pub const TOKEN_BYTES: usize = 88;

    pub fn to_token(self) -> [u8; Self::TOKEN_BYTES] {
        let mut token = [0; Self::TOKEN_BYTES];
        token[..4].copy_from_slice(b"RTX\x02");
        token[4] = u8::from(self.path != 0);
        token[8..16].copy_from_slice(&self.enqueued_ms.to_le_bytes());
        token[16..24].copy_from_slice(&self.expires_ms.to_le_bytes());
        token[24..32].copy_from_slice(&self.path.to_le_bytes());
        let (kind, generation) = match self.state {
            OutboundState::Independent => (0, 0),
            OutboundState::Reverse(generation) => (1, generation),
            OutboundState::Link(generation) => (2, generation),
            OutboundState::Discovery(identity) => (3, identity),
        };
        token[5] = kind;
        token[32..40].copy_from_slice(&generation.to_le_bytes());
        token
    }

    /// Decode only the defined token version and discriminants. The token is
    /// not authentication; in-process callers still obey the ownership contract.
    /// Version 1 hash snapshots do not identify a state incarnation and are
    /// deliberately rejected. The remaining fixed-size bytes are reserved zero.
    pub fn from_token(token: &[u8; Self::TOKEN_BYTES]) -> Option<Self> {
        if &token[..4] != b"RTX\x02"
            || token[4] > 1
            || token[6..8] != [0; 2]
            || token[40..].iter().any(|&byte| byte != 0)
        {
            return None;
        }
        let enqueued_ms = u64::from_le_bytes(token[8..16].try_into().ok()?);
        let expires_ms = u64::from_le_bytes(token[16..24].try_into().ok()?);
        if expires_ms < enqueued_ms || expires_ms > enqueued_ms.saturating_add(OUTBOUND_MAX_AGE_MS)
        {
            return None;
        }
        let path = u64::from_le_bytes(token[24..32].try_into().ok()?);
        if (token[4] == 1) != (path != 0) {
            return None;
        }
        let generation = u64::from_le_bytes(token[32..40].try_into().ok()?);
        let state = match token[5] {
            0 if generation == 0 => OutboundState::Independent,
            1 if generation != 0 => OutboundState::Reverse(generation),
            2 if generation != 0 => OutboundState::Link(generation),
            3 if generation != 0 => OutboundState::Discovery(generation),
            _ => return None,
        };
        Some(Self {
            enqueued_ms,
            expires_ms,
            path,
            state,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundReason {
    AnnounceRebroadcast,
    PathResponse,
    /// A path request this node FORWARDED on behalf of another (relay role).
    PathRequestForward,
    /// A path request this node ORIGINATED as an endpoint ([`LiteNode::request_path`]).
    PathRequest,
    TransportForward,
    ProofReturn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestAction {
    Accepted,
    Duplicate,
    LearnedAnnounce,
    /// Signature-valid announce rejected by path freshness/quality policy.
    /// Hosts must not commit its peer ratchet or mutate a KeyMap from it.
    AnnounceIgnored,
    ScheduledAnnounce,
    AnsweredPathRequest,
    ForwardedPathRequest,
    ForwardedTransport,
    ForwardedProof,
    Dropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct TransportStats {
    pub accepted: u64,
    pub duplicates: u64,
    pub learned_announces: u64,
    pub queued_outbound: u64,
    pub dropped: u64,
    pub validation_failures: u64,
    /// Outbound frames evicted (oldest-dropped) because the TX queue was full — backpressure loss.
    pub outbound_dropped: u64,
    /// Queued or driver-held frames discarded after their deadline/state became stale.
    pub outbound_expired: u64,
    /// Announces rejected by the pre-verify admission limiter.
    pub announces_rate_dropped: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidConfig,
    CapacityTooSmall,
    Wire(WireError),
    Buffer(BufferError),
    Announce(AnnounceError),
    Ifac(IfacError),
    KnownDestination(KnownDestinationError),
}

impl From<WireError> for TransportError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<BufferError> for TransportError {
    fn from(value: BufferError) -> Self {
        Self::Buffer(value)
    }
}

impl From<AnnounceError> for TransportError {
    fn from(value: AnnounceError) -> Self {
        Self::Announce(value)
    }
}

impl From<IfacError> for TransportError {
    fn from(value: IfacError) -> Self {
        Self::Ifac(value)
    }
}

impl From<KnownDestinationError> for TransportError {
    fn from(value: KnownDestinationError) -> Self {
        Self::KnownDestination(value)
    }
}

/// Private host facts; no IFAC keys, driver pointers or packet storage. IDs are
/// mapped to at most8 stable requester slots, independent of their u8 value.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceFacts {
    pub generation: u32,
    pub bitrate_bps: u32,
    pub id: u8,
    pub mode: InterfaceMode,
    // occupied1, outbound2, explicit host registration4, local client8.
    pub flags: u8,
}
impl InterfaceFacts {
    pub const EMPTY: Self = Self {
        generation: 0,
        bitrate_bps: 0,
        id: 0,
        mode: InterfaceMode::Full,
        flags: 0,
    };
    fn outbound(self) -> bool {
        self.flags & 2 != 0 && self.generation != 0
    }
}

/// PLACEMENT CONTRACT: fields are `#[doc(hidden)] pub` so the FFI crate's in-place
/// constructor can initialize a caller-provided buffer via raw field projections —
/// this crate forbids unsafe, and every safe construction path takes `Self` BY VALUE
/// (a SmallNode is ~173 KB: a guaranteed-elision-free stack hazard on MCU tasks).
/// Not public API: construct via [`LiteNode::new`]/[`LiteNode::new_const`], never
/// read or write fields directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteNode<
    const PATHS: usize,
    const HASHES: usize,
    const ANNOUNCES: usize,
    const REVERSE: usize,
    const LINKS: usize,
    const TAGS: usize,
    const OUTBOUND: usize,
    const KNOWN_DESTINATIONS: usize = KNOWN_DESTINATIONS_SMALL,
    const SCHEDULED: usize = ANNOUNCES,
> {
    #[doc(hidden)]
    pub config: LiteConfig,
    #[doc(hidden)]
    pub clock_ms: u64,
    #[doc(hidden)]
    pub transport_id: Hash16,
    #[doc(hidden)]
    pub own_destinations: [Option<Hash16>; OWN_DESTINATIONS_MAX],
    #[doc(hidden)]
    pub announce_admission: AnnounceAdmission,
    #[doc(hidden)]
    pub known_destinations: KnownDestinations<KNOWN_DESTINATIONS>,
    #[doc(hidden)]
    pub packet_hashes: PacketHashTable<HASHES>,
    #[doc(hidden)]
    pub paths: PathTable<PATHS>,
    #[doc(hidden)]
    pub announce_cache: AnnounceCache<ANNOUNCES>,
    #[doc(hidden)]
    pub announce_schedule: AnnounceSchedule<SCHEDULED>,
    #[doc(hidden)]
    pub reverse: ReverseTable<REVERSE>,
    #[doc(hidden)]
    pub links: LinkTable<LINKS>,
    #[doc(hidden)]
    pub request_tags: RequestTagTable<TAGS>,
    #[doc(hidden)]
    pub outbound: Queue<QueuedOutbound, OUTBOUND>,
    #[doc(hidden)]
    pub last_delivery_identity: u64,
    #[doc(hidden)]
    pub retained_owner_mode: bool,
    #[doc(hidden)]
    pub discoveries: Discoveries<LINKS>,
    #[doc(hidden)]
    pub interface_facts: [InterfaceFacts; REQUESTERS],
    #[doc(hidden)]
    pub stats: TransportStats,
}

impl<
    const PATHS: usize,
    const HASHES: usize,
    const ANNOUNCES: usize,
    const REVERSE: usize,
    const LINKS: usize,
    const TAGS: usize,
    const OUTBOUND: usize,
    const KNOWN_DESTINATIONS: usize,
    const SCHEDULED: usize,
>
    LiteNode<
        PATHS,
        HASHES,
        ANNOUNCES,
        REVERSE,
        LINKS,
        TAGS,
        OUTBOUND,
        KNOWN_DESTINATIONS,
        SCHEDULED,
    >
{
    pub fn new(config: LiteConfig, transport_id: Hash16) -> Result<Self, TransportError> {
        Self::validate_config(&config)?;
        Ok(Self::new_const(config, transport_id))
    }

    /// The exact pre-construction checks [`LiteNode::new`] runs (config validity + caps vs the
    /// const-generic capacities), exposed so an external in-place constructor (FFI placement
    /// init) validates identically before touching caller memory.
    pub fn validate_config(config: &LiteConfig) -> Result<(), TransportError> {
        config
            .validate()
            .map_err(|_| TransportError::InvalidConfig)?;
        if config.table_caps.path_entries > PATHS
            || config.table_caps.packet_hashes > HASHES
            || config.table_caps.announce_entries > ANNOUNCES
            || config.table_caps.reverse_entries > REVERSE
            || config.table_caps.link_entries > LINKS
            || config.table_caps.path_request_tags > TAGS
            || config.table_caps.queued_announces_per_interface > OUTBOUND
            || config.table_caps.tx_queue_depth > OUTBOUND
        {
            return Err(TransportError::CapacityTooSmall);
        }
        Ok(())
    }

    /// Const constructor for firmware targets that place the node directly in
    /// static storage. The caller must keep `config.table_caps` within the
    /// const-generic capacities; use [`LiteNode::new`] where runtime validation
    /// and stack budget permit.
    pub const fn new_const(config: LiteConfig, transport_id: Hash16) -> Self {
        Self {
            config,
            clock_ms: 0,
            transport_id,
            own_destinations: [None; OWN_DESTINATIONS_MAX],
            announce_admission: AnnounceAdmission::new(),
            known_destinations: KnownDestinations::new(),
            packet_hashes: PacketHashTable::new(),
            paths: PathTable::new(),
            announce_cache: AnnounceCache::new(),
            announce_schedule: AnnounceSchedule::new(),
            reverse: ReverseTable::new(),
            links: LinkTable::new(),
            request_tags: RequestTagTable::new(),
            outbound: Queue::new(),
            last_delivery_identity: 0,
            retained_owner_mode: false,
            discoveries: Discoveries::new(),
            interface_facts: [InterfaceFacts::EMPTY; REQUESTERS],
            stats: TransportStats {
                accepted: 0,
                duplicates: 0,
                learned_announces: 0,
                queued_outbound: 0,
                dropped: 0,
                validation_failures: 0,
                outbound_dropped: 0,
                outbound_expired: 0,
                announces_rate_dropped: 0,
            },
        }
    }

    pub const fn transport_id(&self) -> Hash16 {
        self.transport_id
    }

    /// Whether this node owns the packet's next-hop address. Endpoint adapters must
    /// retain this decision when surfacing a non-forwardable packet for local delivery.
    /// Announce transport IDs advertise a route rather than name their recipient.
    pub fn accepts_transport_address(&self, header: &PacketHeader) -> bool {
        header.flags.packet_type == PacketType::Announce
            || header.transport_id.is_none()
            || header.transport_id == Some(self.transport_id)
    }

    /// Register one of this node's OWN destination hashes (e.g. its lxmf.delivery destination)
    /// so a relay-echoed copy of its own announce is never learned as a path or rebroadcast
    /// (trusted rns-transport inbound.rs "dropping own announce" — the phantom self-path hazard
    /// when `transport_enabled`). Idempotent; returns false if all slots are taken.
    pub fn register_own_destination(&mut self, destination_hash: Hash16) -> bool {
        if self.is_own_destination(&destination_hash) {
            return true;
        }
        for slot in self.own_destinations.iter_mut() {
            if slot.is_none() {
                *slot = Some(destination_hash);
                return true;
            }
        }
        false
    }

    pub fn is_own_destination(&self, destination_hash: &Hash16) -> bool {
        self.own_destinations
            .iter()
            .any(|slot| slot.as_ref() == Some(destination_hash))
    }

    /// Clear every registered own destination. Registered dests belong to the ACTIVE
    /// identity — call before re-registering after an identity switch.
    pub fn clear_own_destinations(&mut self) {
        self.own_destinations = [None; OWN_DESTINATIONS_MAX];
    }

    pub const fn stats(&self) -> TransportStats {
        self.stats
    }

    pub fn set_announce_budget(&mut self, steady_per_sec: u16, grace_per_sec: u16) {
        if self.config.announce_admission.steady_per_sec == steady_per_sec
            && self.config.announce_admission.grace_per_sec == grace_per_sec
        {
            return;
        }
        self.config.announce_admission.steady_per_sec = steady_per_sec;
        self.config.announce_admission.grace_per_sec = grace_per_sec;
        self.announce_admission = AnnounceAdmission::new();
    }

    pub fn known_destination_recall(&mut self, destination_hash: &Hash16) -> Option<[u8; 64]> {
        self.known_destinations.recall(destination_hash)
    }

    pub fn known_destination_learn(
        &mut self,
        destination_hash: Hash16,
        public_key: [u8; 64],
        now: u64,
    ) -> Result<bool, KnownDestinationError> {
        self.known_destinations
            .learn(destination_hash, public_key, now)
    }

    pub const fn known_destination_count(&self) -> usize {
        self.known_destinations.len()
    }

    pub fn known_destinations_export_into(
        &self,
        out: &mut [u8],
    ) -> Result<usize, KnownDestinationError> {
        self.known_destinations.export_into(out)
    }

    pub fn known_destinations_import(
        &mut self,
        blob: &[u8],
        now: u64,
    ) -> Result<(), KnownDestinationError> {
        self.known_destinations.import(blob, now)
    }

    pub fn has_path(&self, destination_hash: &Hash16, now_ms: u64) -> bool {
        self.paths.get_live(destination_hash, now_ms).is_some()
    }

    /// Read-only view of the live path entry for `destination_hash` (the same row `has_path`
    /// consults): hops / next_hop / interface / announced public key, for endpoint originate
    /// decisions (Python `Transport.outbound` HEADER_2 wrap + `Identity.recall`).
    pub fn path(&self, destination_hash: &Hash16, now_ms: u64) -> Option<&PathEntry> {
        self.paths.get_live(destination_hash, now_ms)
    }

    /// Number of live (unexpired) learned paths.
    pub fn path_count(&self, now_ms: u64) -> usize {
        self.paths.live_count(now_ms)
    }

    /// Forget a failed route before rediscovery without forgetting the peer's
    /// identity or cached announce. Adapted from trusted TransportQuery::DropPath.
    pub fn drop_path(&mut self, destination_hash: &Hash16) -> bool {
        self.paths.drop_path(destination_hash)
    }

    /// Originate a path request for `destination_hash` (the endpoint operation): build the wire
    /// packet and enqueue it for transmission on `interface_id`. `tag` is a caller-supplied 16-byte
    /// request tag (random per Reticulum; no_std has no RNG). Wire-identical to Python
    /// `Transport.request_path` (`dest_hash || [transport_id] || tag` to `rnstransport.path.request`).
    /// The tag is registered so an echoed copy of our own request is deduped, not re-forwarded.
    pub fn request_path(
        &mut self,
        destination_hash: &Hash16,
        tag: &[u8; 16],
        interface_id: InterfaceId,
        now_ms: u64,
    ) -> Result<(), TransportError> {
        self.clock_ms = now_ms;
        self.expire_outbound(now_ms);
        let request = self.build_path_request(*destination_hash, tag)?;
        // Send before recording: a request that never queued must not burn the
        // duplicate gate or register its tag (trusted send-before-record ordering).
        if !self.enqueue(interface_id, request, OutboundReason::PathRequest) {
            return Ok(());
        }
        let mut tag_key = [0u8; 32];
        tag_key[..16].copy_from_slice(destination_hash);
        tag_key[16..].copy_from_slice(tag);
        self.request_tags.insert_if_new(
            tag_key,
            now_ms.saturating_add((PATH_REQUEST_DUPLICATE_GATE_SECS as u64) * 1000),
            now_ms,
        );
        Ok(())
    }

    /// The clock is advanced by ingest, request_path, and tick. Drivers retaining
    /// a popped frame must recheck this predicate immediately before admission.
    pub fn outbound_lifetime_is_live(
        &self,
        interface_id: InterfaceId,
        lifetime: OutboundLifetime,
        now_ms: u64,
    ) -> bool {
        if now_ms < lifetime.enqueued_ms
            || now_ms >= lifetime.expires_ms
            || !self.outbound_interface_online(interface_id)
        {
            return false;
        }
        if lifetime.path != 0
            && !self
                .paths
                .get_generation(lifetime.path, now_ms)
                .is_some_and(|path| self.outbound_interface_online(path.interface_id))
        {
            return false;
        }
        match lifetime.state {
            OutboundState::Independent => true,
            OutboundState::Discovery(identity) => {
                self.config.transport_enabled && self.discoveries.live(identity, now_ms)
            }
            OutboundState::Reverse(generation) => self
                .reverse
                .get_generation(generation, now_ms)
                .is_some_and(|entry| {
                    entry.outbound_interface == interface_id
                        && self.outbound_interface_online(entry.receiving_interface)
                }),
            OutboundState::Link(generation) => self
                .links
                .get_generation(generation, now_ms)
                .is_some_and(|entry| {
                    (entry.outbound_interface == interface_id
                        || entry.receiving_interface == interface_id)
                        && self.outbound_interface_online(entry.outbound_interface)
                        && self.outbound_interface_online(entry.receiving_interface)
                }),
        }
    }

    /// Snapshot a locally constructed packet before a host driver retains it.
    /// The selected table incarnation identifies a learned route; endpoint Link
    /// membership is owned by the host's local Link registry, not the relay table.
    /// No reverse-route entry is fabricated for local outgoing application data.
    pub fn local_outbound_lifetime(
        &self,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<OutboundLifetime, TransportError> {
        let header = PacketView::parse(packet)?.header;
        let mut lifetime = OutboundLifetime {
            enqueued_ms: now_ms,
            expires_ms: now_ms.saturating_add(OUTBOUND_MAX_AGE_MS),
            path: 0,
            state: OutboundState::Independent,
        };
        if header.flags.destination_type == DestinationType::Single {
            if let Some(path) = self.paths.get_live(&header.destination_hash, now_ms) {
                lifetime.path = self
                    .paths
                    .generation(&path.destination_hash, now_ms)
                    .unwrap_or(0);
                lifetime.expires_ms = lifetime.expires_ms.min(path.expires_ms);
            }
        }
        Ok(lifetime)
    }

    pub fn record_expired_outbound(&mut self) {
        self.stats.outbound_expired = self.stats.outbound_expired.saturating_add(1);
        self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
    }

    pub fn outbound_oldest_age_ms(&self, now_ms: u64) -> u64 {
        self.outbound
            .iter()
            .map(|queued| now_ms.saturating_sub(queued.frame.lifetime.enqueued_ms))
            .max()
            .unwrap_or(0)
    }

    fn expire_outbound(&mut self, now_ms: u64) {
        loop {
            let stale = self.outbound.iter().position(|frame| {
                !self.outbound_lifetime_is_live(
                    frame.frame.interface_id,
                    frame.frame.lifetime,
                    now_ms,
                )
            });
            let Some(offset) = stale else { break };
            self.outbound.remove(offset);
            self.record_expired_outbound();
        }
    }

    fn packet_lifetime(&self, packet: &PacketBuffer, reason: OutboundReason) -> OutboundLifetime {
        let now_ms = self.clock_ms;
        let mut lifetime = OutboundLifetime {
            enqueued_ms: now_ms,
            expires_ms: now_ms.saturating_add(OUTBOUND_MAX_AGE_MS),
            path: 0,
            state: OutboundState::Independent,
        };
        let Ok(view) = PacketView::parse(packet.as_slice()) else {
            return lifetime;
        };
        let header = view.header;
        let path_dependent = header.flags.packet_type == PacketType::Announce
            || (header.flags.destination_type == DestinationType::Single
                && reason == OutboundReason::TransportForward);
        if let Some(path) = self
            .paths
            .get_live(&header.destination_hash, now_ms)
            .filter(|_| path_dependent)
        {
            lifetime.path = self
                .paths
                .generation(&path.destination_hash, now_ms)
                .unwrap_or(0);
            lifetime.expires_ms = lifetime.expires_ms.min(path.expires_ms);
            if header.flags.packet_type == PacketType::LinkRequest {
                // handle_link_request supplies the checked generation reserved
                // for the insertion after successful queue admission.
                lifetime.state = OutboundState::Link(0);
                lifetime.expires_ms = lifetime.expires_ms.min(link_deadline(
                    now_ms,
                    path.hops,
                    u64::from(self.interface_bitrate(path.interface_id)),
                ));
            } else if header.flags.packet_type == PacketType::Data {
                // handle_transport_forward supplies the checked generation
                // for the insertion after successful queue admission.
                lifetime.state = OutboundState::Reverse(0);
                lifetime.expires_ms = lifetime
                    .expires_ms
                    .min(now_ms.saturating_add(u64::from(REVERSE_TIMEOUT_SECS) * 1000));
            }
        }
        if header.flags.destination_type == DestinationType::Link
            || header.context == PacketContext::Lrproof
        {
            lifetime.state = OutboundState::Link(
                self.links
                    .generation(&header.destination_hash, now_ms)
                    .unwrap_or(0),
            );
            if let Some(link) = self.links.get(&header.destination_hash, now_ms) {
                // Successful admission promotes a verified establishment proof or
                // refreshes an already validated link's idle timeout. Snapshot that
                // resulting deadline, not the old idle deadline that this very frame
                // renews. Pending links retain their original establishment deadline.
                let link_deadline = if link.validated || header.context == PacketContext::Lrproof {
                    now_ms.saturating_add(u64::from(LINK_TIMEOUT_SECS) * 1000)
                } else {
                    link.expires_ms
                };
                lifetime.expires_ms = lifetime.expires_ms.min(link_deadline);
            }
        }
        lifetime
    }

    fn interface_slot(&self, id: u8) -> Option<usize> {
        self.interface_facts
            .iter()
            .position(|f| f.flags & 1 != 0 && f.id == id)
    }

    /// Private owner metadata. Call before ingest/tick; generation changes or
    /// loss of outbound availability retire requester bits before slot reuse.
    /// Rates are sampled only when a new operation begins, never on retry/join.
    #[doc(hidden)]
    pub fn update_interface(
        &mut self,
        id: u8,
        generation: u32,
        mode: InterfaceMode,
        bitrate_bps: u32,
        outbound: bool,
        local_client: bool,
    ) -> bool {
        let slot = self
            .interface_slot(id)
            .or_else(|| self.interface_facts.iter().position(|f| f.flags & 1 == 0));
        let Some(slot) = slot else {
            return false;
        };
        let previous = self.interface_facts[slot];
        if previous.flags & 1 != 0 && (previous.generation != generation || !outbound) {
            self.retained_outbound_retire_interface(id);
        }
        self.interface_facts[slot] = InterfaceFacts {
            id,
            generation,
            mode,
            bitrate_bps,
            flags: 1
                | 4
                | if outbound && generation != 0 { 2 } else { 0 }
                | if local_client { 8 } else { 0 },
        };
        true
    }

    fn observe_interface(&mut self, meta: RxMeta) {
        if let Some(slot) = self.interface_slot(meta.interface_id) {
            if self.interface_facts[slot].flags & 4 == 0 {
                self.interface_facts[slot].mode = meta.interface_mode.unwrap_or(self.config.mode);
            }
        } else if let Some(slot) = self.interface_facts.iter().position(|f| f.flags & 1 == 0) {
            self.interface_facts[slot] = InterfaceFacts {
                id: meta.interface_id,
                generation: 1,
                mode: meta.interface_mode.unwrap_or(self.config.mode),
                bitrate_bps: 0,
                flags: 1 | 2,
            };
        }
    }

    fn interface_bitrate(&self, id: u8) -> u32 {
        self.interface_slot(id)
            .map(|s| self.interface_facts[s])
            .filter(|f| f.outbound())
            .map_or(0, |f| f.bitrate_bps)
    }
    fn slowest_outbound_bitrate(&self, requester: u8) -> u64 {
        self.interface_facts
            .iter()
            .filter(|f| f.id != requester && f.outbound() && f.bitrate_bps > 0)
            .map(|f| u64::from(f.bitrate_bps))
            .min()
            .unwrap_or(0)
    }
    fn finish_discovery(
        &mut self,
        raw: &[u8],
        header: PacketHeader,
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<(), TransportError> {
        if !self.config.transport_enabled {
            return Ok(());
        }
        let Some(owner) = self.discoveries.take(&header.destination_hash, now_ms) else {
            return Ok(());
        };
        let Ok(response) =
            self.path_response_from_cached_announce(raw, header.destination_hash, header.hops)
        else {
            self.stats.outbound_dropped = self
                .stats
                .outbound_dropped
                .saturating_add(u64::from(owner.requesters.count_ones()));
            return Ok(());
        };
        for slot in 0..REQUESTERS {
            let target = self.interface_facts[slot];
            if owner.requesters & (1 << slot) != 0
                && target.outbound()
                && (target.id != meta.interface_id
                    || (target.flags & 8 == 0 && target.mode != InterfaceMode::Roaming))
            {
                // One bounded admission attempt. Existing enqueue accounts loss;
                // no packet or retry queue is introduced by the requester ledger.
                self.enqueue(target.id, response, OutboundReason::PathResponse);
            }
        }
        Ok(())
    }

    fn outbound_interface_online(&self, _interface_id: InterfaceId) -> bool {
        true
    }

    pub fn poll_tx(&mut self) -> Option<OutboundFrame> {
        // A legacy consumer cannot reinterpret partially admitted target bits.
        if self.retained_owner_mode {
            return None;
        }
        self.expire_outbound(self.clock_ms);
        self.outbound.pop().map(|queued| queued.frame)
    }

    /// Byte length of the next queued outbound packet without consuming it, so a consumer can size
    /// its buffer before [`Self::poll_tx`] (avoids destructively popping a frame that won't fit).
    pub fn outbound_peek_len(&self) -> Option<usize> {
        if self.retained_owner_mode {
            return None;
        }
        self.outbound.peek().map(|f| f.frame.packet.len())
    }

    /// Private handheld owner API. Copies leave this borrow before driver callbacks.
    /// Seven target bits map to the existing handheld interface registry only.
    #[doc(hidden)]
    pub fn retained_outbound_select(
        &mut self,
        after: u64,
        blocked: u8,
        generations: [u32; 7],
    ) -> Option<&QueuedOutbound> {
        self.retained_owner_mode = true;
        self.expire_outbound(self.clock_ms);
        for queued in self.outbound.iter_mut() {
            let delivery = &mut queued.delivery;
            if !delivery.initialized {
                let selected = match queued.frame.reason {
                    OutboundReason::PathResponse
                    | OutboundReason::TransportForward
                    | OutboundReason::ProofReturn => {
                        if queued.frame.interface_id < 7 {
                            1u8 << queued.frame.interface_id
                        } else {
                            0
                        }
                    }
                    OutboundReason::AnnounceRebroadcast | OutboundReason::PathRequestForward => {
                        if queued.frame.interface_id < 7 {
                            0x7f & !(1u8 << queued.frame.interface_id)
                        } else {
                            0x7f
                        }
                    }
                    OutboundReason::PathRequest => 0x7f,
                };
                delivery.pending_targets &= selected;
                delivery.interface_generations = generations;
                delivery.initialized = true;
            }
            for (id, generation) in generations.iter().enumerate() {
                if *generation == 0 || *generation != delivery.interface_generations[id] {
                    delivery.pending_targets &= !(1u8 << id);
                }
            }
        }
        loop {
            let offset = self
                .outbound
                .iter()
                .position(|q| q.delivery.pending_targets == 0);
            let Some(offset) = offset else {
                break;
            };
            self.outbound.remove(offset);
            // Fully acknowledged rows are removed by ack. Reaching this path
            // means the remaining delivery permission was retired or no live
            // target existed; expose that terminal loss through the existing
            // saturating queue-drop counter.
            self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
        }
        self.outbound
            .iter()
            .find(|q| q.delivery.identity > after && q.delivery.pending_targets & !blocked != 0)
    }

    #[doc(hidden)]
    pub fn retained_outbound_ack(&mut self, identity: u64, completed: u8) -> bool {
        if !self.retained_owner_mode || identity == 0 {
            return false;
        }
        let offset = self
            .outbound
            .iter()
            .position(|q| q.delivery.identity == identity);
        let Some(offset) = offset else {
            return false;
        };
        let queued = self
            .outbound
            .get_mut(offset)
            .expect("located occupied queue slot");
        if !queued.delivery.initialized {
            return false;
        }
        queued.delivery.pending_targets &= !completed;
        if queued.delivery.pending_targets == 0 {
            self.outbound.remove(offset);
        }
        true
    }

    #[doc(hidden)]
    pub fn retained_outbound_take(&mut self, identity: u64) -> bool {
        if !self.retained_owner_mode || identity == 0 {
            return false;
        }
        let offset = self
            .outbound
            .iter()
            .position(|q| q.delivery.identity == identity);
        offset
            .and_then(|offset| self.outbound.remove(offset))
            .is_some()
    }

    /// Also retire permission on rows that have never been peeked. Re-registering
    /// this physical interface cannot bind its replacement to old queued bytes.
    #[doc(hidden)]
    pub fn retained_outbound_retire_interface(&mut self, interface: u8) {
        if let Some(slot) = self.interface_slot(interface) {
            self.discoveries.retire_requester(slot);
            self.interface_facts[slot].flags &= !2;
        }
        if interface >= 7 {
            return;
        }
        for queued in self.outbound.iter_mut() {
            queued.delivery.pending_targets &= !(1u8 << interface);
        }
    }

    pub const fn outbound_len(&self) -> usize {
        self.outbound.len()
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.clock_ms = now_ms;
        if !self.config.transport_enabled {
            self.discoveries.clear();
        }
        self.discoveries.expire(now_ms);
        self.packet_hashes.expire(now_ms);
        self.paths.expire(now_ms);
        self.announce_cache.expire(now_ms);
        self.announce_cache.retain_paths(&self.paths, now_ms);
        self.announce_schedule.expire(now_ms);
        self.reverse.expire(now_ms);
        self.links.expire(now_ms);
        self.request_tags.expire(now_ms);
        self.expire_outbound(now_ms);

        while let Some(announce) = self.announce_schedule.pop_due(now_ms) {
            let Some(path) = self.paths.get_live(&announce.destination_hash, now_ms) else {
                continue;
            };
            if !announce.block_rebroadcast
                && PacketView::parse(announce.packet.as_slice()).map_or(true, |view| {
                    packet_hash(announce.packet.as_slice(), view.header.flags.header_type)
                        != path.packet_hash
                })
            {
                continue;
            }
            self.enqueue(
                announce.interface_id,
                announce.packet,
                if announce.block_rebroadcast {
                    OutboundReason::PathResponse
                } else {
                    OutboundReason::AnnounceRebroadcast
                },
            );
        }
    }

    pub fn ingest(
        &mut self,
        raw: &[u8],
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
        self.ingest_with_local_link(raw, meta, now_ms, None)
    }

    /// Ingest with an endpoint Link owned outside the relay's transit Link table.
    ///
    /// `local_link` must come from the caller's live endpoint registry, not from
    /// untrusted packet bytes alone. Only a matching Link destination defers
    /// global duplicate admission to that endpoint's interface/authentication and
    /// message-dedup owner. All normal ingress checks and relay policy still run.
    /// This mirrors rns-transport's registered-local-Link hashlist deferral without
    /// adding endpoint entries to the bounded transit table.
    pub fn ingest_with_local_link(
        &mut self,
        raw: &[u8],
        meta: RxMeta,
        now_ms: u64,
        local_link: Option<&Hash16>,
    ) -> Result<IngestAction, TransportError> {
        self.clock_ms = now_ms;
        self.observe_interface(meta);
        if !self.config.transport_enabled {
            self.discoveries.clear();
        }
        self.discoveries.expire(now_ms);
        self.expire_outbound(now_ms);
        let mut ifac_plain = PacketBuffer::new();
        let raw = if let Some(ifac) = self.config.ifac {
            match ifac_verify_into(raw, &ifac.key, ifac.size, &mut ifac_plain) {
                Ok(()) => ifac_plain.as_slice(),
                Err(_) => {
                    self.stats.validation_failures =
                        self.stats.validation_failures.saturating_add(1);
                    self.stats.dropped = self.stats.dropped.saturating_add(1);
                    return Ok(IngestAction::Dropped);
                }
            }
        } else {
            // Python parity (Transport.py:1433): without IFAC configured, a flagged
            // packet is another network's masked traffic — drop before parse so
            // garbage never reaches the hashlist or routing tables.
            if has_ifac_flag(raw) {
                self.stats.validation_failures = self.stats.validation_failures.saturating_add(1);
                self.stats.dropped = self.stats.dropped.saturating_add(1);
                return Ok(IngestAction::Dropped);
            }
            raw
        };

        let view = PacketView::parse(raw)?;
        self.stats.accepted = self.stats.accepted.saturating_add(1);

        // Python 1.3.8 (Packet.py:247) / trusted actor/inbound.rs: reject an on-wire hop count
        // >= PATHFINDER_M for EVERY packet type, checked on the RAW hops byte before the
        // transport increment. Pre-1.3.8 only announces were capped.
        if view.header.hops >= PATHFINDER_M {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        // The canonical hash omits transport_id: an overheard copy for another
        // relay must not suppress the later copy routed to us. Check ownership
        // before hashlist deferral for known Links and repeating contexts too.
        // Adapted from trusted rsReticulum actor/inbound.rs (62e144e).
        if !self.accepts_transport_address(&view.header) {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        // Upstream packet_filter (Transport.py:1397-1410): PLAIN and GROUP
        // announces are invalid and must not be learned or rebroadcast.
        if view.header.flags.packet_type == PacketType::Announce
            && matches!(
                view.header.flags.destination_type,
                DestinationType::Plain | DestinationType::Group
            )
        {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        // Upstream packet_filter (Transport.py:1340-1357): PLAIN/GROUP non-announce packets may
        // travel at most one hop, so a copy that has already been forwarded (wire hops >= 1, i.e.
        // upstream's post-increment hops > 1) is dropped. Path requests are PLAIN DATA, so this
        // bounds their propagation reach to match upstream; SINGLE/LINK packets route by
        // transport_id and are not subject to it.
        if view.header.flags.packet_type != PacketType::Announce
            && matches!(
                view.header.flags.destination_type,
                DestinationType::Plain | DestinationType::Group
            )
            && view.header.hops >= 1
        {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        let defer_hashlist = self
            .links
            .contains_live(&view.header.destination_hash, now_ms)
            || view.header.context == PacketContext::Lrproof
            || (view.header.flags.destination_type == DestinationType::Link
                && local_link == Some(&view.header.destination_hash));
        if !view.header.context.skip_hashlist() && !defer_hashlist {
            let hash = packet_hash(raw, view.header.flags.header_type);
            let inserted = self.packet_hashes.insert(
                hash,
                now_ms.saturating_add(HASHLIST_LIFETIME_MS),
                now_ms,
            );
            if !inserted {
                // Upstream carve-out (Transport.py:1362-1369): a duplicate SINGLE announce is NOT
                // dropped — SINGLE destinations re-announce to refresh paths, so an exact duplicate
                // must reach handle_announce. The emission-timebase gate there decides whether to
                // replace/rebroadcast, so a true duplicate cannot amplify.
                let single_announce = view.header.flags.packet_type == PacketType::Announce
                    && view.header.flags.destination_type == DestinationType::Single;
                if !single_announce {
                    self.stats.duplicates = self.stats.duplicates.saturating_add(1);
                    return Ok(IngestAction::Duplicate);
                }
            }
        }

        let mut header = view.header;
        header.hops = header.hops.saturating_add(1);

        let result = match header.flags.packet_type {
            PacketType::Announce => self.handle_announce(raw, view, header, meta, now_ms),
            PacketType::Data => {
                if self.route_link_packet(
                    raw,
                    header,
                    meta,
                    now_ms,
                    OutboundReason::TransportForward,
                )? {
                    Ok(IngestAction::ForwardedTransport)
                } else if header.destination_hash == path_request_destination() {
                    self.handle_path_request(view.payload, meta, now_ms)
                } else {
                    self.handle_transport_forward(raw, view.header, header, meta, now_ms)
                }
            }
            PacketType::LinkRequest => {
                self.handle_link_request(raw, view.header, header, meta, now_ms)
            }
            PacketType::Proof => self.handle_proof(raw, view.header, header, meta, now_ms),
        };

        if matches!(result, Err(TransportError::Announce(_))) {
            self.stats.validation_failures = self.stats.validation_failures.saturating_add(1);
        }
        result
    }

    fn handle_announce(
        &mut self,
        raw: &[u8],
        view: PacketView<'_>,
        header: PacketHeader,
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
        // Our own announce echoed back by another relay (trusted inbound.rs "dropping own
        // announce"): learning it would create a phantom self-path and rebroadcast our
        // announce as if transported.
        if self.is_own_destination(&header.destination_hash) {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }
        // Trusted inbound.rs announce gate on POST-INCREMENT hops (fix-registry S138-F01,
        // a deliberate 1.3.8 tightening beyond Python's `< M+1`): a path stored at
        // PATHFINDER_M hops is provably dead under the parse cap every 1.3.8 peer applies.
        if header.hops >= PATHFINDER_M {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }
        if !self.announce_admission.admit(
            self.config.announce_admission,
            header.context == PacketContext::PathResponse,
            now_ms,
        ) {
            self.stats.announces_rate_dropped = self.stats.announces_rate_dropped.saturating_add(1);
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }
        let announce = AnnounceView::parse(
            view.payload,
            view.header.flags.context_flag,
            self.config.max_announce_app_data,
        )?;
        let known_public_key = self
            .known_destinations
            .peek(&header.destination_hash)
            .or_else(|| self.paths.known_public_key(&header.destination_hash));
        let mut scratch = [0u8; ANNOUNCE_SCRATCH_MAX];
        let identity_hash =
            announce.validate(&header.destination_hash, known_public_key, &mut scratch)?;

        let packet_hash = packet_hash(raw, view.header.flags.header_type);
        // Path expiry belongs to the receiving interface (trusted PathEntry::new), not the
        // node as a whole. Hosts predating the interface-scoped metadata retain the configured
        // node-wide mode as a compatibility fallback.
        let path_expiry_secs =
            announce_path_expiry_secs(meta.interface_mode.unwrap_or(self.config.mode));
        let path_entry = PathEntry {
            destination_hash: header.destination_hash,
            next_hop: view.header.transport_id,
            hops: header.hops,
            interface_id: meta.interface_id,
            expires_ms: now_ms.saturating_add((path_expiry_secs as u64) * 1000),
            last_seen_ms: now_ms,
            packet_hash,
            random_hash: announce.random_hash,
            public_key: announce.public_key,
        };

        let learned = self.paths.insert_or_update(path_entry, now_ms);

        if learned {
            let _ = identity_hash;
            if announce.name_hash == name_hash(LXMF_DELIVERY_NAME) {
                self.known_destinations.learn(
                    header.destination_hash,
                    announce.public_key,
                    now_ms,
                )?;
            }
            self.stats.learned_announces = self.stats.learned_announces.saturating_add(1);

            // Cache the announce only when the path was actually learned/replaced. Upstream caches
            // inside `if should_add` (Transport.py:1998); caching unconditionally would let a
            // freshness-rejected (replayed/older/higher-hop) announce poison the path-response
            // cache that handle_path_request answers from, while the path table kept the fresh entry.
            self.announce_cache.retain_paths(&self.paths, now_ms);
            self.announce_cache.insert(
                CachedAnnounce {
                    destination_hash: header.destination_hash,
                    raw: PacketBuffer::from_slice(raw)?,
                    hops: header.hops,
                    expires_ms: path_entry.expires_ms,
                },
                now_ms,
            );

            // Trusted recursive discovery completion is independent of ordinary
            // announce rebroadcast. In particular PATH_RESPONSE must reach each
            // retained requester, without becoming a general broadcast.
            self.finish_discovery(raw, header, meta, now_ms)?;

            // Rebroadcast only when the announce actually updated the path (upstream rebroadcasts
            // only on should_add) — a duplicate/older announce that did not replace must not amplify.
            // Reframing for forwarding adds the HEADER_2 transport_id (16 B); a single-packet
            // announce large enough that the reframed packet would exceed MTU is still LEARNED (the
            // path/contact is kept) but is NOT rebroadcast — skip gracefully instead of erroring
            // after the path was already inserted. (Conformant senders keep announces <= MDU, so
            // this only fires for an over-large directly-received announce.)
            if self.config.transport_enabled && header.context != PacketContext::PathResponse {
                if let Ok(packet) = self.transport_announce_from_raw(
                    raw,
                    header.destination_hash,
                    header.hops,
                    PacketContext::None,
                ) {
                    let jitter = announce_jitter_ms(&packet_hash);
                    self.announce_schedule.insert(
                        ScheduledAnnounce {
                            destination_hash: header.destination_hash,
                            packet,
                            interface_id: meta.interface_id,
                            due_ms: now_ms.saturating_add(jitter),
                            expires_ms: now_ms
                                .saturating_add((QUEUED_ANNOUNCE_LIFE_SECS as u64) * 1000),
                            block_rebroadcast: false,
                        },
                        now_ms,
                    );
                    return Ok(IngestAction::ScheduledAnnounce);
                }
            }
        }

        Ok(if learned {
            IngestAction::LearnedAnnounce
        } else {
            IngestAction::AnnounceIgnored
        })
    }

    fn handle_path_request(
        &mut self,
        payload: &[u8],
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
        let interface_id = meta.interface_id;
        let mode = meta.interface_mode.unwrap_or(self.config.mode);
        if payload.len() <= 16 {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        let mut requested = [0u8; 16];
        requested.copy_from_slice(&payload[..16]);

        let requestor_transport_id = if payload.len() > 32 {
            let mut id = [0u8; 16];
            id.copy_from_slice(&payload[16..32]);
            Some(id)
        } else {
            None
        };

        let tag = if payload.len() > 32 {
            &payload[32..payload.len().min(48)]
        } else {
            &payload[16..payload.len().min(32)]
        };
        if tag.is_empty() {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        let mut tag_key = [0u8; 32];
        tag_key[..16].copy_from_slice(&requested);
        tag_key[16..16 + tag.len()].copy_from_slice(tag);
        let is_new = self.request_tags.insert_if_new(
            tag_key,
            now_ms.saturating_add((PATH_REQUEST_DUPLICATE_GATE_SECS as u64) * 1000),
            now_ms,
        );
        if !is_new {
            self.stats.duplicates = self.stats.duplicates.saturating_add(1);
            return Ok(IngestAction::Duplicate);
        }

        // Trusted outbound.rs / Python 1.3.8 Transport.py:2969: a path request for one of
        // our OWN destinations is answered by the HOST (fresh signed announce), never
        // forwarded. Returning Dropped lets the FFI's own-path-request post-check fire in
        // both transport postures.
        if self.is_own_destination(&requested) {
            return Ok(IngestAction::Dropped);
        }

        if let Some(path) = self.paths.get_live(&requested, now_ms) {
            if requestor_transport_id.is_some_and(|requestor| path.next_hop == Some(requestor)) {
                return Ok(IngestAction::Dropped);
            }
            // Roaming self-loop suppression: don't answer for a path learned from the same
            // interface the request arrived on (upstream Transport.py:2941-2942).
            if mode == crate::config::InterfaceMode::Roaming && path.interface_id == interface_id {
                return Ok(IngestAction::Dropped);
            }
            // Only answer cached path requests when acting as a transport node (upstream gates the
            // cached answer on transport_enabled || is_from_local_client; lite has no local clients).
            if self.config.transport_enabled {
                if let Some(cached) = self.announce_cache.get(&requested, now_ms) {
                    let response = self.path_response_from_cached_announce(
                        cached.raw.as_slice(),
                        requested,
                        cached.hops,
                    )?;
                    if !self.enqueue(interface_id, response, OutboundReason::PathResponse) {
                        return Ok(IngestAction::Dropped);
                    }
                    return Ok(IngestAction::AnsweredPathRequest);
                }
            }
            // Trusted Rust outbound.rs deliberately falls through to the ordinary
            // discovery gates when signed cache material is unavailable. Python
            // ignores this case; the September 2026 canon adjudication retains the
            // trusted Rust recovery behavior without bypassing discovery policy.
        }

        if self.config.transport_enabled && mode_discovers_unknown_paths(mode) {
            let Some(slot) = self
                .interface_slot(interface_id)
                .filter(|&slot| self.interface_facts[slot].outbound())
            else {
                return Ok(IngestAction::Dropped);
            };
            let timeout = discovery_timeout(self.slowest_outbound_bitrate(interface_id));
            match self.discoveries.begin(requested, slot, now_ms, timeout) {
                BeginDiscovery::Joined => return Ok(IngestAction::Accepted),
                BeginDiscovery::Refused => {
                    self.stats.dropped = self.stats.dropped.saturating_add(1);
                    return Ok(IngestAction::Dropped);
                }
                BeginDiscovery::New(identity) => {
                    let request = self.build_path_request(requested, tag)?;
                    let lifetime = OutboundLifetime {
                        enqueued_ms: now_ms,
                        expires_ms: now_ms
                            .saturating_add(REQUEST_GATE_MS)
                            .min(self.discoveries.deadline(identity).unwrap_or(now_ms)),
                        path: 0,
                        state: OutboundState::Discovery(identity),
                    };
                    if !self.enqueue_with_lifetime(
                        interface_id,
                        request,
                        OutboundReason::PathRequestForward,
                        lifetime,
                    ) {
                        return Ok(IngestAction::Dropped);
                    }
                    return Ok(IngestAction::ForwardedPathRequest);
                }
            }
        }

        Ok(IngestAction::Dropped)
    }

    fn handle_transport_forward(
        &mut self,
        raw: &[u8],
        original_header: PacketHeader,
        header: PacketHeader,
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
        if !self.config.transport_enabled {
            return Ok(IngestAction::Dropped);
        }
        if original_header.transport_id != Some(self.transport_id) {
            return Ok(IngestAction::Dropped);
        }

        let Some((target_interface, forwarded)) =
            self.rewrite_forwarded_transport_packet(raw, original_header, header, now_ms)?
        else {
            return Ok(IngestAction::Dropped);
        };

        let proof_hash = truncated_packet_hash(raw, original_header.flags.header_type);
        // Check the next non-reused incarnation before accepting a forward.
        // enqueue_with_lifetime only wraps/pushes bytes and cannot mutate tables;
        // insertion below therefore commits exactly this generation. Failed
        // queue admission creates no reverse entry and consumes no generation.
        let Some(generation) = self.reverse.next_generation() else {
            return Ok(IngestAction::Dropped);
        };
        let mut lifetime = self.packet_lifetime(&forwarded, OutboundReason::TransportForward);
        lifetime.state = OutboundState::Reverse(generation);
        if !self.enqueue_with_lifetime(
            target_interface,
            forwarded,
            OutboundReason::TransportForward,
            lifetime,
        ) {
            return Ok(IngestAction::Dropped);
        }
        self.reverse.insert(
            ReverseEntry {
                proof_hash,
                receiving_interface: meta.interface_id,
                outbound_interface: target_interface,
                expires_ms: now_ms.saturating_add((REVERSE_TIMEOUT_SECS as u64) * 1000),
            },
            now_ms,
        );
        Ok(IngestAction::ForwardedTransport)
    }

    fn handle_link_request(
        &mut self,
        raw: &[u8],
        original_header: PacketHeader,
        header: PacketHeader,
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
        if !self.config.transport_enabled {
            return Ok(IngestAction::Dropped);
        }
        // Upstream (Transport.py:1597, rns-transport actor/inbound.rs:912)
        // forwards LINKREQUESTs only when explicitly addressed to this
        // transport instance. A Header1 broadcast overheard from a direct
        // conversation must not be re-transmitted or enter the link table.
        if original_header.transport_id != Some(self.transport_id) {
            return Ok(IngestAction::Dropped);
        }

        let link_id = link_id_from_raw(raw, original_header.flags.header_type);
        // Signalling suffixes change packet hashes, but not Link ID. A pending
        // or validated owner cannot be replaced/renewed by another suffix.
        if self.links.contains_live(&link_id, now_ms) {
            return Ok(IngestAction::Dropped);
        }

        let Some((target_interface, forwarded)) =
            self.rewrite_forwarded_transport_packet(raw, original_header, header, now_ms)?
        else {
            return Ok(IngestAction::Dropped);
        };

        let entry = self
            .paths
            .get_live(&header.destination_hash, now_ms)
            .map(|path| {
                let link_id = link_id_from_raw(raw, original_header.flags.header_type);
                LinkEntry {
                    link_id,
                    destination_hash: header.destination_hash,
                    receiving_interface: meta.interface_id,
                    outbound_interface: target_interface,
                    next_hop: path.next_hop,
                    remaining_hops: path.hops,
                    taken_hops: header.hops,
                    validated: false,
                    expires_ms: link_deadline(
                        now_ms,
                        path.hops,
                        u64::from(self.interface_bitrate(target_interface)),
                    ),
                }
            });

        let Some(entry) = entry else {
            return Ok(IngestAction::Dropped);
        };
        let Some(generation) = self.links.next_generation() else {
            return Ok(IngestAction::Dropped);
        };
        // As for reverse entries, queue success precedes state insertion, and
        // the checked generation is bound before any frame can leave the node.
        let mut lifetime = self.packet_lifetime(&forwarded, OutboundReason::TransportForward);
        lifetime.state = OutboundState::Link(generation);
        if !self.enqueue_with_lifetime(
            target_interface,
            forwarded,
            OutboundReason::TransportForward,
            lifetime,
        ) {
            return Ok(IngestAction::Dropped);
        }
        self.links.insert(entry, now_ms);
        Ok(IngestAction::ForwardedTransport)
    }

    fn handle_proof(
        &mut self,
        raw: &[u8],
        _original_header: PacketHeader,
        header: PacketHeader,
        meta: RxMeta,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
        if header.context == PacketContext::Lrproof {
            if let Some(link) = self.links.get(&header.destination_hash, now_ms).copied() {
                if link.outbound_interface == meta.interface_id
                    && link.remaining_hops == header.hops
                {
                    if !self.validate_transit_lrproof(raw, header, link) {
                        return Ok(IngestAction::Dropped);
                    }
                    let hash = packet_hash(raw, header.flags.header_type);
                    if self.packet_hashes.contains(&hash, now_ms) {
                        self.stats.duplicates = self.stats.duplicates.saturating_add(1);
                        return Ok(IngestAction::Duplicate);
                    }
                    let packet = PacketBuffer::from_slice(raw)?.copy_with_hops(header.hops);
                    // Send before recording: only a queued proof consumes the packet
                    // hash and promotes the link to validated.
                    if !self.enqueue(
                        link.receiving_interface,
                        packet,
                        OutboundReason::ProofReturn,
                    ) {
                        return Ok(IngestAction::Dropped);
                    }
                    self.packet_hashes.insert(
                        hash,
                        now_ms.saturating_add(HASHLIST_LIFETIME_MS),
                        now_ms,
                    );
                    self.links.mark_validated(
                        &header.destination_hash,
                        now_ms.saturating_add((LINK_TIMEOUT_SECS as u64) * 1000),
                        now_ms,
                    );
                    return Ok(IngestAction::ForwardedProof);
                }
            }
        }

        if header.context == PacketContext::Lrproof {
            // A transit LRPROOF is terminal: it is only forwarded via the validated link-table
            // path above. If it did not match (unknown link / wrong interface / wrong hop count),
            // drop it — never forward an unvalidated proof through the generic routers. This
            // mirrors upstream, where the Lrproof block ends with an unconditional return so the
            // generic link router is unreachable for proofs.
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(IngestAction::Dropped);
        }

        if self.route_link_packet(raw, header, meta, now_ms, OutboundReason::ProofReturn)? {
            return Ok(IngestAction::ForwardedProof);
        }

        if let Some(reverse) = self.reverse.remove(&header.destination_hash, now_ms) {
            if reverse.outbound_interface == meta.interface_id {
                let packet = PacketBuffer::from_slice(raw)?.copy_with_hops(header.hops);
                if !self.enqueue_with_lifetime(
                    reverse.receiving_interface,
                    packet,
                    OutboundReason::ProofReturn,
                    OutboundLifetime {
                        expires_ms: reverse
                            .expires_ms
                            .min(now_ms.saturating_add(OUTBOUND_MAX_AGE_MS)),
                        ..self.packet_lifetime(&packet, OutboundReason::ProofReturn)
                    },
                ) {
                    // Restore the consumed entry with its original deadline.
                    self.reverse.insert(reverse, now_ms);
                    return Ok(IngestAction::Dropped);
                }
                return Ok(IngestAction::ForwardedProof);
            }
        }

        Ok(IngestAction::Dropped)
    }

    fn route_link_packet(
        &mut self,
        raw: &[u8],
        header: PacketHeader,
        meta: RxMeta,
        now_ms: u64,
        reason: OutboundReason,
    ) -> Result<bool, TransportError> {
        if !self.config.transport_enabled
            || header.flags.destination_type != DestinationType::Link
            || header.flags.packet_type == PacketType::LinkRequest
            || header.context == PacketContext::Lrproof
        {
            return Ok(false);
        }

        let Some(link) = self.links.get(&header.destination_hash, now_ms).copied() else {
            return Ok(false);
        };

        let target_interface = if link.outbound_interface == link.receiving_interface {
            if header.hops == link.remaining_hops || header.hops == link.taken_hops {
                link.outbound_interface
            } else {
                return Ok(true);
            }
        } else if meta.interface_id == link.receiving_interface {
            if header.hops == link.taken_hops {
                link.outbound_interface
            } else {
                return Ok(true);
            }
        } else if meta.interface_id == link.outbound_interface {
            if header.hops == link.remaining_hops {
                link.receiving_interface
            } else {
                return Ok(true);
            }
        } else {
            return Ok(false);
        };

        let tracked_hash = if header.context.skip_hashlist() {
            None
        } else {
            let hash = packet_hash(raw, header.flags.header_type);
            if self.packet_hashes.contains(&hash, now_ms) {
                self.stats.duplicates = self.stats.duplicates.saturating_add(1);
                return Ok(true);
            }
            Some(hash)
        };

        let packet = PacketBuffer::from_slice(raw)?.copy_with_hops(header.hops);
        // Send before recording: a dropped forward must not consume the hash or
        // extend the link lifetime.
        if !self.enqueue(target_interface, packet, reason) {
            return Ok(true);
        }
        if let Some(hash) = tracked_hash {
            self.packet_hashes
                .insert(hash, now_ms.saturating_add(HASHLIST_LIFETIME_MS), now_ms);
        }
        if link.validated {
            self.links.touch(
                &link.link_id,
                now_ms.saturating_add((LINK_TIMEOUT_SECS as u64) * 1000),
                now_ms,
            );
        }
        Ok(true)
    }

    fn validate_transit_lrproof(&self, raw: &[u8], header: PacketHeader, link: LinkEntry) -> bool {
        let payload_offset = header.size();
        if raw.len() < payload_offset {
            return false;
        }

        let proof = &raw[payload_offset..];
        if proof.len() != 96 && proof.len() != 99 {
            return false;
        }

        let Some(public_key) = self.paths.known_public_key(&link.destination_hash) else {
            return false;
        };

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&proof[..64]);
        let mut destination_ed25519 = [0u8; 32];
        destination_ed25519.copy_from_slice(&public_key[32..]);
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&destination_ed25519) else {
            return false;
        };

        let mut signed = [0u8; 16 + 32 + 32 + 3];
        let mut pos = 0;
        signed[pos..pos + 16].copy_from_slice(&header.destination_hash);
        pos += 16;
        signed[pos..pos + 32].copy_from_slice(&proof[64..96]);
        pos += 32;
        signed[pos..pos + 32].copy_from_slice(&destination_ed25519);
        pos += 32;
        if proof.len() == 99 {
            signed[pos..pos + 3].copy_from_slice(&proof[96..99]);
            pos += 3;
        }

        let signature = ed25519_dalek::Signature::from_bytes(&signature);
        // Permissive verify() to match rsReticulum/Python (see identity.rs): a relay must accept
        // exactly what the network's source-of-truth verifier accepts.
        key.verify(&signed[..pos], &signature).is_ok()
    }

    fn rewrite_forwarded_transport_packet(
        &self,
        raw: &[u8],
        original_header: PacketHeader,
        header: PacketHeader,
        now_ms: u64,
    ) -> Result<Option<(InterfaceId, PacketBuffer)>, TransportError> {
        let Some(path) = self.paths.get_live(&header.destination_hash, now_ms) else {
            return Ok(None);
        };

        let mut flags = header.flags;
        let new_header = match path.hops.cmp(&1) {
            core::cmp::Ordering::Greater => {
                let Some(next_hop) = path.next_hop else {
                    return Ok(None);
                };
                flags.header_type = HeaderType::Header2;
                flags.transport_type = TransportType::Transport;
                PacketHeader {
                    flags,
                    hops: header.hops,
                    transport_id: Some(next_hop),
                    destination_hash: header.destination_hash,
                    context: header.context,
                }
            }
            core::cmp::Ordering::Equal => {
                flags.header_type = HeaderType::Header1;
                flags.transport_type = TransportType::Broadcast;
                PacketHeader {
                    flags,
                    hops: header.hops,
                    transport_id: None,
                    destination_hash: header.destination_hash,
                    context: header.context,
                }
            }
            core::cmp::Ordering::Less => {
                return Ok(Some((
                    path.interface_id,
                    PacketBuffer::from_slice(raw)?.copy_with_hops(header.hops),
                )));
            }
        };

        Ok(Some((
            path.interface_id,
            rewrite_with_header(raw, original_header, new_header)?,
        )))
    }

    fn transport_announce_from_raw(
        &self,
        cached_raw: &[u8],
        destination_hash: Hash16,
        hops: u8,
        context: PacketContext,
    ) -> Result<PacketBuffer, TransportError> {
        let cached = PacketView::parse(cached_raw)?;
        let flags = PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: cached.header.flags.context_flag,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        };
        let header = PacketHeader {
            flags,
            hops,
            transport_id: Some(self.transport_id),
            destination_hash,
            context,
        };
        Ok(build_packet(header, cached.payload)?)
    }

    fn path_response_from_cached_announce(
        &self,
        cached_raw: &[u8],
        destination_hash: Hash16,
        hops: u8,
    ) -> Result<PacketBuffer, TransportError> {
        self.transport_announce_from_raw(
            cached_raw,
            destination_hash,
            hops,
            PacketContext::PathResponse,
        )
    }

    fn build_path_request(
        &self,
        destination_hash: Hash16,
        tag: &[u8],
    ) -> Result<PacketBuffer, TransportError> {
        let mut payload: PacketBuffer = PacketBuffer::new();
        payload.extend_from_slice(&destination_hash)?;
        if self.config.transport_enabled {
            payload.extend_from_slice(&self.transport_id)?;
        }
        let mut tag_buf = [0u8; 16];
        tag_buf[..tag.len().min(16)].copy_from_slice(&tag[..tag.len().min(16)]);
        payload.extend_from_slice(&tag_buf)?;

        let flags = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
        };
        let header = PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: path_request_destination(),
            context: PacketContext::None,
        };
        Ok(build_packet(header, payload.as_slice())?)
    }

    /// Wrap (IFAC when configured) and queue one outbound packet. Returns false when the
    /// frame could not be produced — callers must not record routing state (tags, reverse
    /// entries, link promotion, hashlist) for a packet that never queued.
    fn enqueue(
        &mut self,
        interface_id: InterfaceId,
        packet: PacketBuffer,
        reason: OutboundReason,
    ) -> bool {
        self.enqueue_with_lifetime(
            interface_id,
            packet,
            reason,
            self.packet_lifetime(&packet, reason),
        )
    }

    fn enqueue_with_lifetime(
        &mut self,
        interface_id: InterfaceId,
        packet: PacketBuffer,
        reason: OutboundReason,
        lifetime: OutboundLifetime,
    ) -> bool {
        let mut wire = WireBuffer::new();
        if let Some(ifac) = self.config.ifac {
            if ifac_sign_into(packet.as_slice(), &ifac.key, ifac.size, &mut wire).is_err() {
                self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
                self.stats.dropped = self.stats.dropped.saturating_add(1);
                return false;
            }
        } else if wire.extend_from_slice(packet.as_slice()).is_err() {
            self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return false;
        }

        let Some(identity) = self.last_delivery_identity.checked_add(1) else {
            self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
            return false;
        };
        self.last_delivery_identity = identity;
        let evicted = self.outbound.push_drop_oldest(QueuedOutbound {
            frame: OutboundFrame {
                interface_id,
                packet: wire,
                reason,
                lifetime,
            },
            delivery: OutboundDelivery {
                identity,
                interface_generations: [0; 7],
                pending_targets: 0x7f,
                initialized: false,
            },
        });
        if evicted {
            self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
        }
        self.stats.queued_outbound = self.stats.queued_outbound.saturating_add(1);
        true
    }
}

pub fn path_request_destination() -> Hash16 {
    destination_hash_from_name("rnstransport.path.request", None)
}

fn announce_jitter_ms(packet_hash: &[u8; 32]) -> u64 {
    let raw = u16::from_be_bytes([packet_hash[0], packet_hash[1]]) as u64;
    raw % DEFAULT_ANNOUNCE_JITTER_MS
}

fn mode_discovers_unknown_paths(mode: crate::config::InterfaceMode) -> bool {
    matches!(
        mode,
        crate::config::InterfaceMode::AccessPoint
            | crate::config::InterfaceMode::Gateway
            | crate::config::InterfaceMode::Roaming
    )
}

/// Learned-path expiry by interface mode (upstream Transport.py:1861-1866).
fn announce_path_expiry_secs(mode: crate::config::InterfaceMode) -> u32 {
    match mode {
        crate::config::InterfaceMode::AccessPoint => AP_PATH_TIME_SECS,
        crate::config::InterfaceMode::Roaming => ROAMING_PATH_TIME_SECS,
        crate::config::InterfaceMode::Full
        | crate::config::InterfaceMode::Gateway
        | crate::config::InterfaceMode::Boundary => PATHFINDER_E_SECS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IfacConfig, LiteConfig};
    use crate::identity::{
        MAX_ANNOUNCE_APP_DATA, destination_hash_from_parts, identity_hash, name_hash,
    };
    use crate::ifac::{has_ifac_flag, ifac_sign_into, ifac_verify_into};
    use crate::wire::{PacketView, build_packet};
    use ed25519_dalek::{Signer, SigningKey};
    use std::vec::Vec;

    #[test]
    fn recursive_capacity_and_identity_exhaustion_refuse_before_fanout() {
        let mut n = node();
        for index in 0..32u8 {
            let request = path_request([index; 16], [index; 16]);
            assert_eq!(
                n.ingest(
                    request.as_slice(),
                    RxMeta::new(IFACE),
                    1000 + u64::from(index)
                )
                .unwrap(),
                IngestAction::ForwardedPathRequest
            );
            assert!(n.poll_tx().is_some());
            while n.poll_tx().is_some() {}
        }
        let refused = path_request([99; 16], [99; 16]);
        assert_eq!(
            n.ingest(refused.as_slice(), RxMeta::new(IFACE), 1100)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(n.poll_tx().is_none());
        assert!(n.stats.dropped > 0);
        n.discoveries.last_identity = u64::MAX;
        let exhausted = path_request([100; 16], [100; 16]);
        assert_eq!(
            n.ingest(exhausted.as_slice(), RxMeta::new(IFACE), 17000)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(n.poll_tx().is_none());
        assert_eq!(n.discoveries.last_identity, u64::MAX);
        assert!(n.discoveries.entries.iter().all(|row| row.identity == 0));
    }

    #[test]
    fn recursive_micro_budget_capacity_and_disabled_retirement() {
        let mut n = MicroNode::new(LiteConfig::ESP32_LORA_TRANSPORT_MICRO, TRANSPORT_ID).unwrap();
        assert!(core::mem::size_of_val(&n) <= 32768);
        for index in 0..4u8 {
            let request = path_request([index; 16], [index; 16]);
            assert_eq!(
                n.ingest(request.as_slice(), RxMeta::new(IFACE), 1000)
                    .unwrap(),
                IngestAction::ForwardedPathRequest
            );
            assert!(n.poll_tx().is_some());
        }
        let request = path_request([99; 16], [99; 16]);
        assert_eq!(
            n.ingest(request.as_slice(), RxMeta::new(IFACE), 1001)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(n.poll_tx().is_none());
        n.config.transport_enabled = false;
        n.tick(1002);
        assert!(
            n.discoveries
                .entries
                .iter()
                .all(|entry| entry.identity == 0)
        );
        n.config.transport_enabled = true;
        let request = path_request([100; 16], [100; 16]);
        assert_eq!(
            n.ingest(request.as_slice(), RxMeta::new(IFACE), 1003)
                .unwrap(),
            IngestAction::ForwardedPathRequest
        );
        assert_eq!(n.discoveries.last_identity, 5);
    }

    const TRANSPORT_ID: [u8; 16] = [0x42; 16];
    const IFACE: InterfaceId = 1;

    struct SignedAnnounce {
        destination_hash: [u8; 16],
        raw: PacketBuffer,
        signing_seed: [u8; 32],
    }

    fn signed_announce(seed: [u8; 32], app_name: &str, app_data: &[u8]) -> SignedAnnounce {
        signed_announce_rh(seed, app_name, app_data, [0xBC; 10])
    }

    // `random_hash[5..10]` (big-endian) is the announce emission timebase used by the freshness
    // gate; vary it to craft fresher / replayed announces for the same destination.
    fn signed_announce_rh(
        seed: [u8; 32],
        app_name: &str,
        app_data: &[u8],
        random_hash: [u8; 10],
    ) -> SignedAnnounce {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying = signing_key.verifying_key();

        let mut public_key = [0u8; 64];
        public_key[..32].copy_from_slice(&[0xA7; 32]);
        public_key[32..].copy_from_slice(verifying.as_bytes());

        let identity_hash = identity_hash(&public_key);
        let name_hash = name_hash(app_name);
        let destination_hash = destination_hash_from_parts(&name_hash, Some(&identity_hash));

        let mut signed = Vec::new();
        signed.extend_from_slice(&destination_hash);
        signed.extend_from_slice(&public_key);
        signed.extend_from_slice(&name_hash);
        signed.extend_from_slice(&random_hash);
        signed.extend_from_slice(app_data);
        let signature = signing_key.sign(&signed).to_bytes();

        let mut payload = Vec::new();
        payload.extend_from_slice(&public_key);
        payload.extend_from_slice(&name_hash);
        payload.extend_from_slice(&random_hash);
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(app_data);

        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash,
            context: PacketContext::None,
        };
        SignedAnnounce {
            destination_hash,
            raw: build_packet(header, &payload).unwrap(),
            signing_seed: seed,
        }
    }

    fn path_request(destination_hash: [u8; 16], tag: [u8; 16]) -> PacketBuffer {
        let mut payload = Vec::new();
        payload.extend_from_slice(&destination_hash);
        payload.extend_from_slice(&tag);
        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: path_request_destination(),
            context: PacketContext::None,
        };
        build_packet(header, &payload).unwrap()
    }

    #[test]
    fn endpoint_request_path_builds_wire_packet_and_enqueues() {
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let dest = [0x11u8; 16];
        let tag = [0x22u8; 16];
        node.request_path(&dest, &tag, IFACE, 1000).unwrap();

        let frame = node.poll_tx().expect("path request queued");
        assert_eq!(frame.reason, OutboundReason::PathRequest);
        assert_eq!(frame.interface_id, IFACE);
        let view = PacketView::parse(frame.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.packet_type, PacketType::Data);
        assert_eq!(view.header.flags.destination_type, DestinationType::Plain);
        assert_eq!(view.header.flags.header_type, HeaderType::Header1);
        assert_eq!(view.header.destination_hash, path_request_destination());
        // payload = dest(16) || transport_id(16, transport_enabled) || tag(16)
        assert_eq!(&view.payload[..16], &dest);
        assert_eq!(&view.payload[16..32], &TRANSPORT_ID);
        assert_eq!(&view.payload[32..48], &tag);
    }

    #[test]
    fn relay_accepts_announce_with_large_app_data() {
        // app_data above the OLD relay caps (128 SMALL / 256) but within the single-packet wire
        // max — must be learned, not black-holed by the relay.
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let app_data = [0x5au8; 300];
        let ann = signed_announce([0x9u8; 32], "lxmf.delivery", &app_data);
        let action = node
            .ingest(ann.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert!(matches!(
            action,
            IngestAction::ScheduledAnnounce | IngestAction::LearnedAnnounce
        ));
        assert!(node.has_path(&ann.destination_hash, 1000));
    }

    #[test]
    fn relay_learns_unforwardable_announce_without_erroring() {
        // app_data at the single-packet receive max (333) but above the HEADER_2-forwardable bound
        // (~317): the path is LEARNED, ingest does NOT error, and nothing is rebroadcast (the
        // reframed HEADER_2 announce would exceed MTU). Guards the "Err after learning" regression.
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let app_data = [0x5au8; 333];
        let ann = signed_announce([0xA1u8; 32], "lxmf.delivery", &app_data);
        let action = node
            .ingest(ann.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::LearnedAnnounce);
        assert!(node.has_path(&ann.destination_hash, 1000));
        node.tick(5000);
        assert!(
            node.poll_tx().is_none(),
            "unforwardable announce must not rebroadcast"
        );
    }

    #[test]
    fn raw_hops_at_or_above_pathfinder_m_drop_for_every_packet_type() {
        // Python 1.3.8 Packet.py:247 / trusted actor/inbound.rs: parse-reject raw hops >=
        // PATHFINDER_M for ALL packet types, before dedup — a second copy is still Dropped
        // (never Duplicate), proving the packet never reached the hashlist.
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let ann = signed_announce([0x77u8; 32], "lxmf.delivery", b"");
        let mut packets = [
            ann.raw,
            link_request([0x31u8; 16], 0),
            link_packet([0x32u8; 16], 0, PacketContext::None),
            link_proof([0x33u8; 16], 0, PacketContext::None),
            path_request([0x34u8; 16], [0x35u8; 16]),
        ];
        for pkt in packets.iter_mut() {
            pkt.as_mut_slice()[1] = PATHFINDER_M; // raw hops byte
            for _ in 0..2 {
                let action = node
                    .ingest(pkt.as_slice(), RxMeta::new(IFACE), 1000)
                    .unwrap();
                assert_eq!(action, IngestAction::Dropped);
            }
        }
        assert!(!node.has_path(&ann.destination_hash, 1000));
        // Announce boundary (S138-F01 tightened form, trusted parity): raw PATHFINDER_M - 1
        // post-increments to M and is dropped; raw M - 2 is the last accepted announce.
        let mut at_m_minus_1 = ann.raw;
        at_m_minus_1.as_mut_slice()[1] = PATHFINDER_M - 1;
        let action = node
            .ingest(at_m_minus_1.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::Dropped);
        let mut ok = ann.raw;
        ok.as_mut_slice()[1] = PATHFINDER_M - 2;
        let action = node
            .ingest(ok.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert!(matches!(
            action,
            IngestAction::LearnedAnnounce | IngestAction::ScheduledAnnounce
        ));
        // Non-announce packets are NOT subject to the post-increment gate: a link request
        // at raw M - 1 still reaches processing (dedup on re-ingest proves it).
        let lr = link_request([0x36u8; 16], PATHFINDER_M - 1);
        let first = node
            .ingest(lr.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_ne!(first, IngestAction::Duplicate);
        let second = node
            .ingest(lr.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(second, IngestAction::Duplicate);
    }

    #[test]
    fn own_destination_path_request_is_dropped_for_host_answer_not_forwarded() {
        // Trusted outbound.rs / Python Transport.py:2969: a path request for our OWN
        // destination is never forwarded, even as a transport node — Dropped is the
        // signal the FFI turns into the host re-announce.
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        assert!(node.config.transport_enabled);
        let own = [0x51u8; 16];
        assert!(node.register_own_destination(own));
        let req = path_request(own, [0x66u8; 16]);
        let action = node
            .ingest(req.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::Dropped);
        node.tick(5000);
        assert!(
            node.poll_tx().is_none(),
            "no spurious self path-request forward"
        );
    }

    #[test]
    fn clear_own_destinations_resets_registration() {
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let a = [0x71u8; 16];
        assert!(node.register_own_destination(a));
        assert!(node.is_own_destination(&a));
        node.clear_own_destinations();
        assert!(!node.is_own_destination(&a));
        let b = [0x72u8; 16];
        assert!(node.register_own_destination(b));
        assert!(node.is_own_destination(&b) && !node.is_own_destination(&a));
    }

    #[test]
    fn own_destination_announce_echo_is_dropped_not_learned() {
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let ann = signed_announce([0x21u8; 32], "lxmf.delivery", b"self");
        assert!(node.register_own_destination(ann.destination_hash));
        // Our announce echoed back by a neighbouring relay (hops bumped): dropped — no
        // phantom self-path, nothing scheduled for rebroadcast.
        let mut echoed = ann.raw;
        echoed.as_mut_slice()[1] = 1;
        let action = node
            .ingest(echoed.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::Dropped);
        assert!(!node.has_path(&ann.destination_hash, 1000));
        node.tick(5000);
        assert!(node.poll_tx().is_none());
        // Other destinations still learn normally.
        let other = signed_announce([0x22u8; 32], "lxmf.delivery", b"peer");
        let action = node
            .ingest(other.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert!(matches!(
            action,
            IngestAction::LearnedAnnounce | IngestAction::ScheduledAnnounce
        ));
        // Registration is idempotent and bounded to OWN_DESTINATIONS_MAX slots.
        assert!(node.register_own_destination(ann.destination_hash));
        for i in 0..(OWN_DESTINATIONS_MAX - 1) {
            assert!(node.register_own_destination([i as u8; 16]));
        }
        assert!(!node.register_own_destination([0x99u8; 16]));
    }

    #[test]
    fn plain_path_request_with_prior_hop_is_dropped() {
        // Upstream packet_filter drops a PLAIN non-announce packet that has already been forwarded
        // (wire hops >= 1). A fresh (hops 0) path request is still answered/forwarded.
        let mut node =
            SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap();
        let mut pkt = path_request([0x11; 16], [0x22; 16]);
        pkt.as_mut_slice()[1] = 1; // header hops byte -> already forwarded once
        let action = node
            .ingest(pkt.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::Dropped);
    }

    fn h2_data(destination_hash: [u8; 16], payload: &[u8]) -> PacketBuffer {
        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: Some(TRANSPORT_ID),
            destination_hash,
            context: PacketContext::None,
        };
        build_packet(header, payload).unwrap()
    }

    fn link_request(destination_hash: [u8; 16], hops: u8) -> PacketBuffer {
        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header2,
                context_flag: false,
                transport_type: TransportType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops,
            transport_id: Some(TRANSPORT_ID),
            destination_hash,
            context: PacketContext::None,
        };
        build_packet(header, &[0xA5; 64]).unwrap()
    }

    fn link_packet(link_id: [u8; 16], hops: u8, context: PacketContext) -> PacketBuffer {
        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
            },
            hops,
            transport_id: None,
            destination_hash: link_id,
            context,
        };
        build_packet(header, b"link payload").unwrap()
    }

    fn link_proof(link_id: [u8; 16], hops: u8, context: PacketContext) -> PacketBuffer {
        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops,
            transport_id: None,
            destination_hash: link_id,
            context,
        };
        build_packet(header, &[0x7A; 64]).unwrap()
    }

    fn lrproof(link_id: [u8; 16], hops: u8, signing_seed: [u8; 32]) -> PacketBuffer {
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let identity_ed25519 = signing_key.verifying_key();
        let responder_x25519 = [0xD1; 32];
        let signalling = [0x00, 0x01, 0xF4];

        let mut signed = Vec::new();
        signed.extend_from_slice(&link_id);
        signed.extend_from_slice(&responder_x25519);
        signed.extend_from_slice(identity_ed25519.as_bytes());
        signed.extend_from_slice(&signalling);
        let signature = signing_key.sign(&signed).to_bytes();

        let mut payload = Vec::new();
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(&responder_x25519);
        payload.extend_from_slice(&signalling);

        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
            },
            hops,
            transport_id: None,
            destination_hash: link_id,
            context: PacketContext::Lrproof,
        };
        build_packet(header, &payload).unwrap()
    }

    fn proof(proof_hash: [u8; 16]) -> PacketBuffer {
        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination_hash: proof_hash,
            context: PacketContext::None,
        };
        build_packet(header, &[0x99; 64]).unwrap()
    }

    fn node() -> SmallNode {
        SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).unwrap()
    }

    #[test]
    fn overheard_next_hop_does_not_consume_routed_packet_hash() {
        let announce = signed_announce([0x71; 32], "lxmf.delivery", b"receiver");
        for packet in [
            h2_data(announce.destination_hash, b"hidden receiver"),
            link_request(announce.destination_hash, 0),
        ] {
            let mut node = node();
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1_000)
                .unwrap();
            let view = PacketView::parse(packet.as_slice()).unwrap();
            let overheard = build_packet(
                PacketHeader {
                    transport_id: Some([0x99; 16]),
                    ..view.header
                },
                view.payload,
            )
            .unwrap();
            let hash = packet_hash(packet.as_slice(), HeaderType::Header2);
            assert_eq!(hash, packet_hash(overheard.as_slice(), HeaderType::Header2));

            assert_eq!(
                node.ingest(overheard.as_slice(), RxMeta::new(IFACE), 1_100)
                    .unwrap(),
                IngestAction::Dropped
            );
            assert!(node.poll_tx().is_none());
            assert_eq!(
                node.ingest(packet.as_slice(), RxMeta::new(IFACE), 1_200)
                    .unwrap(),
                IngestAction::ForwardedTransport,
                "overhearing another next hop must not suppress our routed copy"
            );
            let forwarded = node.poll_tx().unwrap();
            let view = PacketView::parse(forwarded.packet.as_slice()).unwrap();
            assert_eq!(view.header.flags.header_type, HeaderType::Header1);
            assert_eq!(view.header.transport_id, None);
            assert_eq!(view.header.hops, 1);
            assert_eq!(
                hash,
                packet_hash(forwarded.packet.as_slice(), HeaderType::Header1)
            );
            assert_eq!(node.stats().duplicates, 0);
        }
    }

    #[test]
    fn next_hop_admission_precedes_known_link_and_repeat_context_exceptions() {
        let announce = signed_announce([0x72; 32], "lxmf.delivery", b"receiver");
        for context in [
            PacketContext::None,
            PacketContext::Channel,
            PacketContext::Keepalive,
        ] {
            let mut node = node();
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1_000)
                .unwrap();
            let request = link_request(announce.destination_hash, 0);
            let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
            assert_eq!(
                node.ingest(request.as_slice(), RxMeta::new(IFACE), 1_100)
                    .unwrap(),
                IngestAction::ForwardedTransport
            );
            node.poll_tx().unwrap();
            let packet = link_packet(link_id, 0, context);
            let view = PacketView::parse(packet.as_slice()).unwrap();
            let overheard = build_packet(
                PacketHeader {
                    flags: PacketFlags {
                        header_type: HeaderType::Header2,
                        transport_type: TransportType::Transport,
                        ..view.header.flags
                    },
                    transport_id: Some([0x99; 16]),
                    ..view.header
                },
                view.payload,
            )
            .unwrap();
            assert_eq!(
                node.ingest(overheard.as_slice(), RxMeta::new(IFACE), 1_200)
                    .unwrap(),
                IngestAction::Dropped,
                "known links and repeat contexts do not bypass next-hop ownership"
            );
            assert!(node.poll_tx().is_none());
            assert_eq!(
                node.ingest(packet.as_slice(), RxMeta::new(IFACE), 1_300)
                    .unwrap(),
                IngestAction::ForwardedTransport
            );
            assert!(node.poll_tx().is_some());
        }
    }

    #[test]
    fn overheard_next_hop_proof_preserves_reverse_route() {
        let announce = signed_announce([0x73; 32], "lxmf.delivery", b"receiver");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1_000)
            .unwrap();
        let data = h2_data(announce.destination_hash, b"proof next hop");
        node.ingest(data.as_slice(), RxMeta::new(IFACE), 1_100)
            .unwrap();
        node.poll_tx().unwrap();
        let packet = proof(truncated_packet_hash(data.as_slice(), HeaderType::Header2));
        let view = PacketView::parse(packet.as_slice()).unwrap();
        let overheard = build_packet(
            PacketHeader {
                flags: PacketFlags {
                    header_type: HeaderType::Header2,
                    transport_type: TransportType::Transport,
                    ..view.header.flags
                },
                transport_id: Some([0x99; 16]),
                ..view.header
            },
            view.payload,
        )
        .unwrap();
        assert_eq!(
            node.ingest(overheard.as_slice(), RxMeta::new(IFACE), 1_200)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(node.poll_tx().is_none());
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(IFACE), 1_300)
                .unwrap(),
            IngestAction::ForwardedProof
        );
        assert_eq!(node.poll_tx().unwrap().reason, OutboundReason::ProofReturn);
    }

    #[test]
    fn endpoint_link_defers_hash_until_its_owner_accepts() {
        let id = [0x78; 16];
        let packet = link_packet(id, 0, PacketContext::None);
        let mut n = node();
        for iface in [1, 2, 2] {
            assert_eq!(
                n.ingest_with_local_link(packet.as_slice(), RxMeta::new(iface), 1000, Some(&id))
                    .unwrap(),
                IngestAction::Dropped // no relay route; endpoint owns local admission
            );
        }
        // Ending endpoint ownership immediately restores ordinary dedup policy.
        assert_eq!(
            n.ingest(packet.as_slice(), RxMeta::new(2), 1000).unwrap(),
            IngestAction::Dropped
        );
        assert_eq!(
            n.ingest(packet.as_slice(), RxMeta::new(2), 1000).unwrap(),
            IngestAction::Duplicate
        );
    }

    #[test]
    fn endpoint_link_hint_cannot_exempt_another_destination_or_kind() {
        let id = [0x79; 16];
        for flags in [0x00, 0x04, 0x08, 0x0c] {
            let mut packet = link_packet(id, 0, PacketContext::None);
            packet.as_mut_slice()[0] = flags;
            let mut n = node();
            let other = [0x80; 16];
            let registered = if flags == 0x0c { &other } else { &id };
            for expected in [IngestAction::Dropped, IngestAction::Duplicate] {
                assert_eq!(
                    n.ingest_with_local_link(
                        packet.as_slice(),
                        RxMeta::new(IFACE),
                        1000,
                        Some(registered)
                    )
                    .unwrap(),
                    expected
                );
            }
        }
        let mut packet = link_packet(id, PATHFINDER_M, PacketContext::None);
        let mut n = node();
        for _ in 0..2 {
            assert_eq!(
                n.ingest_with_local_link(packet.as_slice(), RxMeta::new(IFACE), 1000, Some(&id))
                    .unwrap(),
                IngestAction::Dropped
            );
        }
        packet.as_mut_slice()[1] = 0;
        // Rejected raw hops never poison an otherwise admissible ordinary frame.
        assert_eq!(
            n.ingest(packet.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::Dropped
        );
    }

    fn ifac_config() -> (LiteConfig, [u8; 64]) {
        let key = [0x73; 64];
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.ifac = Some(IfacConfig { key, size: 8 });
        (config, key)
    }

    #[test]
    fn ifac_config_drops_clear_packets_before_routing() {
        let announce = signed_announce([0x31; 32], "lxmf.delivery", b"node");
        let (config, _) = ifac_config();
        let mut node = SmallNode::new(config, TRANSPORT_ID).unwrap();

        assert_eq!(
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::Dropped
        );
        assert_eq!(node.stats().validation_failures, 1);
        assert!(!node.has_path(&announce.destination_hash, 1000));
    }

    #[test]
    fn endpoint_link_hint_preserves_ifac_validation() {
        let id = [0x81; 16];
        let packet = link_packet(id, 0, PacketContext::None);
        let (config, key) = ifac_config();
        let mut n = SmallNode::new(config, TRANSPORT_ID).unwrap();
        let mut wrapped = PacketBuffer::new();
        ifac_sign_into(packet.as_slice(), &key, 8, &mut wrapped).unwrap();
        assert_eq!(
            n.ingest_with_local_link(packet.as_slice(), RxMeta::new(IFACE), 1000, Some(&id))
                .unwrap(),
            IngestAction::Dropped
        );
        assert_eq!(n.stats().validation_failures, 1);
        for iface in [1, 2] {
            assert_eq!(
                n.ingest_with_local_link(wrapped.as_slice(), RxMeta::new(iface), 1000, Some(&id))
                    .unwrap(),
                IngestAction::Dropped
            );
            assert_eq!(n.stats().validation_failures, 1);
        }
        wrapped.as_mut_slice()[3] ^= 1;
        assert_eq!(
            n.ingest_with_local_link(wrapped.as_slice(), RxMeta::new(IFACE), 1000, Some(&id))
                .unwrap(),
            IngestAction::Dropped
        );
        assert_eq!(n.stats().validation_failures, 2);
    }

    #[test]
    fn ifac_config_accepts_wrapped_packets_and_wraps_egress() {
        let announce = signed_announce([0x32; 32], "lxmf.delivery", b"node");
        let (config, key) = ifac_config();
        let mut node = SmallNode::new(config, TRANSPORT_ID).unwrap();

        let mut wrapped_announce = PacketBuffer::new();
        ifac_sign_into(announce.raw.as_slice(), &key, 8, &mut wrapped_announce).unwrap();
        assert_eq!(
            node.ingest(wrapped_announce.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );
        assert!(node.has_path(&announce.destination_hash, 1000));

        node.tick(3000);
        let out = node.poll_tx().unwrap();
        assert!(has_ifac_flag(out.packet.as_slice()));

        let mut plain = PacketBuffer::new();
        ifac_verify_into(out.packet.as_slice(), &key, 8, &mut plain).unwrap();
        let view = PacketView::parse(plain.as_slice()).unwrap();
        assert_eq!(view.header.flags.header_type, HeaderType::Header2);
        assert_eq!(view.header.transport_id, Some(TRANSPORT_ID));
        assert_eq!(view.header.flags.packet_type, PacketType::Announce);
    }

    #[test]
    fn clear_node_drops_ifac_flagged_packets_before_parse() {
        let announce = signed_announce([0x33; 32], "lxmf.delivery", b"node");
        let key = [0x73; 64];
        let mut wrapped = PacketBuffer::new();
        ifac_sign_into(announce.raw.as_slice(), &key, 8, &mut wrapped).unwrap();

        let mut node = node();
        assert_eq!(
            node.ingest(wrapped.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::Dropped
        );
        assert_eq!(node.stats().validation_failures, 1);
        assert_eq!(node.stats().accepted, 0);
    }

    #[test]
    fn signed_announce_learns_path_and_rebroadcasts_header2() {
        let announce = signed_announce([0x11; 32], "lxmf.delivery", b"node");
        let mut node = node();

        let action = node
            .ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::ScheduledAnnounce);
        assert!(node.has_path(&announce.destination_hash, 1000));

        node.tick(3000);
        let out = node.poll_tx().unwrap();
        assert_eq!(out.reason, OutboundReason::AnnounceRebroadcast);

        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.header_type, HeaderType::Header2);
        assert_eq!(view.header.transport_id, Some(TRANSPORT_ID));
        assert_eq!(view.header.flags.packet_type, PacketType::Announce);
        assert_eq!(view.header.hops, 1);
    }

    #[test]
    fn duplicate_single_announce_is_not_dropped_but_does_not_amplify() {
        // Upstream lets a duplicate SINGLE announce bypass the packet-hash dedup (Transport.py:
        // 1362-1369) so it reaches path processing; the emission-timebase gate then refuses to
        // replace/rebroadcast an exact duplicate, so it cannot amplify.
        let announce = signed_announce([0x12; 32], "lxmf.delivery", b"node");
        let mut node = node();

        assert_eq!(
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );
        // Byte-identical re-announce: NOT dropped as Duplicate (reaches handle_announce), but the
        // freshness gate refuses to replace/rebroadcast (same random_hash).
        let action = node
            .ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1100)
            .unwrap();
        assert_eq!(action, IngestAction::AnnounceIgnored);
        // The duplicate was not learned (the real non-amplification guard; schedule dedup alone
        // would mask a removed `if learned` gate).
        assert_eq!(node.stats().learned_announces, 1);

        // Exactly one rebroadcast was scheduled (the duplicate did not amplify).
        node.tick(3000);
        assert_eq!(
            node.poll_tx().unwrap().reason,
            OutboundReason::AnnounceRebroadcast
        );
        assert!(node.poll_tx().is_none());
    }

    #[test]
    fn freshness_rejected_announce_does_not_poison_path_response_cache() {
        // A replayed/older announce that the freshness gate rejects must NOT overwrite the
        // path-response cache (upstream caches only on should_add): the answered path response must
        // carry the fresh announce's data, not the rejected one's.
        let mut node = node();
        let rh = |marker: u8, emitted: u64| {
            let mut h = [marker; 10];
            h[5..10].copy_from_slice(&emitted.to_be_bytes()[3..8]);
            h
        };
        let fresh = signed_announce_rh([0x44; 32], "lxmf.delivery", b"fresh", rh(0x01, 100));
        node.ingest(fresh.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _ = node.poll_tx();
        // Older-emitted re-announce for the same destination: rejected by the gate.
        let stale = signed_announce_rh([0x44; 32], "lxmf.delivery", b"stale", rh(0x02, 50));
        assert_eq!(
            node.ingest(stale.raw.as_slice(), RxMeta::new(IFACE), 1100)
                .unwrap(),
            IngestAction::AnnounceIgnored
        );

        // A path request must be answered from the FRESH cached announce, not the stale one.
        let req = path_request(fresh.destination_hash, [0x55; 16]);
        assert_eq!(
            node.ingest(req.as_slice(), RxMeta::new(9), 1200).unwrap(),
            IngestAction::AnsweredPathRequest
        );
        let out = node.poll_tx().unwrap();
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        let app_data = &view.payload[view.payload.len() - 5..];
        assert_eq!(app_data, b"fresh");
    }

    #[test]
    fn freshness_gate_rejects_replay_accepts_newer_emission() {
        // Emission-timebase anti-replay (upstream Transport.py:1750-1811): for equal-hop announces,
        // only an unseen, more-recently-emitted announce may replace the path.
        let mut node = node();
        let rh = |marker: u8, emitted: u64| {
            let mut h = [marker; 10];
            h[5..10].copy_from_slice(&emitted.to_be_bytes()[3..8]);
            h
        };
        let mk = |marker: u8, emitted: u64| {
            signed_announce_rh([0x12; 32], "lxmf.delivery", b"node", rh(marker, emitted))
        };

        // First announce (emission 10): learned + rebroadcast.
        let a = mk(0x01, 10);
        assert_eq!(
            node.ingest(a.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );
        node.tick(3000);
        assert_eq!(
            node.poll_tx().unwrap().reason,
            OutboundReason::AnnounceRebroadcast
        );

        // Replayed announce (older emission 5, equal hops, different blob): rejected, no rebroadcast.
        let replay = mk(0x02, 5);
        let action = node
            .ingest(replay.raw.as_slice(), RxMeta::new(IFACE), 1100)
            .unwrap();
        assert_eq!(action, IngestAction::AnnounceIgnored);
        node.tick(4000);
        assert!(node.poll_tx().is_none());

        // Fresher announce (newer emission 20): accepted, replaces + rebroadcasts.
        let newer = mk(0x03, 20);
        assert_eq!(
            node.ingest(newer.raw.as_slice(), RxMeta::new(IFACE), 1200)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );
        node.tick(6000);
        assert_eq!(
            node.poll_tx().unwrap().reason,
            OutboundReason::AnnounceRebroadcast
        );
    }

    #[test]
    fn queued_rebroadcast_coalesces_destination_to_freshest_announce() {
        // Trusted rsReticulum b4c0358 / Python Transport.py:1286-1308 retain one queued
        // rebroadcast per destination and replace it only when the wire emission time advances.
        // Lite obtains the same invariant from the path freshness gate plus AnnounceSchedule's
        // destination-keyed replacement; lock the composition here rather than duplicating packet
        // parsing inside the bounded schedule table.
        let mut node = node();
        let rh = |marker: u8, emitted: u64| {
            let mut h = [marker; 10];
            h[5..10].copy_from_slice(&emitted.to_be_bytes()[3..8]);
            h
        };
        let mk = |marker: u8, emitted: u64, app_data: &'static [u8]| {
            signed_announce_rh([0x5A; 32], "lxmf.delivery", app_data, rh(marker, emitted))
        };

        let initial = mk(0x01, 20, b"initial");
        assert_eq!(
            node.ingest(initial.raw.as_slice(), RxMeta::new(IFACE), 1_000)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );

        let older = mk(0x02, 19, b"older");
        assert_eq!(
            node.ingest(older.raw.as_slice(), RxMeta::new(IFACE), 1_100)
                .unwrap(),
            IngestAction::AnnounceIgnored
        );

        let newer = mk(0x03, 21, b"newer");
        assert_eq!(
            node.ingest(newer.raw.as_slice(), RxMeta::new(IFACE), 1_200)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );
        assert_eq!(
            node.announce_schedule.entries.iter().flatten().count(),
            1,
            "same-destination re-announces must occupy one schedule slot"
        );

        node.tick(10_000);
        let queued = node.poll_tx().expect("freshest announce rebroadcast");
        let view = PacketView::parse(queued.packet.as_slice()).unwrap();
        let announce =
            AnnounceView::parse(view.payload, view.header.flags.context_flag, 32).unwrap();
        assert_eq!(announce.app_data, b"newer");
        assert!(
            node.poll_tx().is_none(),
            "older copies must not remain queued"
        );
    }

    #[test]
    fn invalid_signed_announce_is_rejected_and_counted() {
        let mut announce = signed_announce([0x16; 32], "lxmf.delivery", b"node");
        let last = announce.raw.len() - 1;
        announce.raw.as_mut_slice()[last] ^= 0x01;

        let mut node = node();
        let result = node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000);
        assert!(matches!(
            result,
            Err(TransportError::Announce(AnnounceError::SignatureInvalid))
        ));
        assert_eq!(node.stats().validation_failures, 1);
        assert!(!node.has_path(&announce.destination_hash, 1000));
    }

    #[test]
    fn admission_drop_happens_before_announce_validation_and_learning() {
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.announce_admission = crate::announce_admission::AnnounceAdmissionConfig {
            steady_per_sec: 1,
            grace_per_sec: 1,
            grace_secs: 60,
        };
        let mut node = SmallNode::new(config, TRANSPORT_ID).unwrap();

        let admitted = signed_announce([0x61; 32], "lxmf.delivery", b"first");
        assert_eq!(
            node.ingest(admitted.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );

        let mut rejected = signed_announce([0x62; 32], "lxmf.delivery", b"second");
        let last = rejected.raw.len() - 1;
        rejected.raw.as_mut_slice()[last] ^= 0x01;
        assert_eq!(
            node.ingest(rejected.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::Dropped
        );
        assert_eq!(node.stats().announces_rate_dropped, 1);
        assert_eq!(node.stats().validation_failures, 0);
        assert!(!node.has_path(&rejected.destination_hash, 1000));
        assert_eq!(node.known_destination_count(), 1);
    }

    #[test]
    fn path_response_announce_is_exempt_from_admission_budget() {
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.announce_admission = crate::announce_admission::AnnounceAdmissionConfig {
            steady_per_sec: 1,
            grace_per_sec: 1,
            grace_secs: 60,
        };
        let mut node = SmallNode::new(config, TRANSPORT_ID).unwrap();
        let first = signed_announce([0x63; 32], "lxmf.delivery", b"first");
        node.ingest(first.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();

        let mut response = signed_announce([0x64; 32], "lxmf.delivery", b"response");
        let header_len = PacketView::parse(response.raw.as_slice())
            .unwrap()
            .header
            .size();
        response.raw.as_mut_slice()[header_len - 1] = PacketContext::PathResponse.to_byte();
        assert_eq!(
            node.ingest(response.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap(),
            IngestAction::LearnedAnnounce
        );
        assert!(node.has_path(&response.destination_hash, 1000));
        assert_eq!(node.stats().announces_rate_dropped, 0);
    }

    #[test]
    fn accepted_delivery_announce_populates_known_destination_table() {
        let announce = signed_announce([0x65; 32], "lxmf.delivery", b"known");
        let view = PacketView::parse(announce.raw.as_slice()).unwrap();
        let parsed = AnnounceView::parse(view.payload, false, MAX_ANNOUNCE_APP_DATA).unwrap();
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(node.known_destination_count(), 1);
        assert_eq!(
            node.known_destination_recall(&announce.destination_hash),
            Some(parsed.public_key)
        );
    }

    #[test]
    fn learned_path_expires_on_tick() {
        let announce = signed_announce([0x17; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert!(node.has_path(&announce.destination_hash, 1000));

        let expired_at = 1000 + (PATHFINDER_E_SECS as u64) * 1000 + 1;
        node.tick(expired_at);
        assert!(!node.has_path(&announce.destination_hash, expired_at));
    }

    #[test]
    fn learned_path_expiry_uses_receiving_interface_mode() {
        let roaming = signed_announce([0x71; 32], "lxmf.delivery", b"roaming");
        let full = signed_announce([0x72; 32], "lxmf.delivery", b"full");
        let mut node = node();
        node.ingest(
            roaming.raw.as_slice(),
            RxMeta::with_mode(IFACE, InterfaceMode::Roaming),
            1000,
        )
        .unwrap();
        node.ingest(
            full.raw.as_slice(),
            RxMeta::with_mode(IFACE + 1, InterfaceMode::Full),
            1000,
        )
        .unwrap();

        let after_roaming_expiry = 1000 + (ROAMING_PATH_TIME_SECS as u64) * 1000 + 1;
        node.tick(after_roaming_expiry);
        assert!(!node.has_path(&roaming.destination_hash, after_roaming_expiry));
        assert!(node.has_path(&full.destination_hash, after_roaming_expiry));
    }

    #[test]
    fn header1_link_request_is_not_forwarded() {
        // Upstream Transport.py:1597 / rns-transport actor/inbound.rs:912: a
        // broadcast (no transport_id) link request overheard from a direct
        // conversation must be ignored, not repeated on the channel.
        let announce = signed_announce([0x41; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        node.tick(3000);
        let _rebroadcast = node.poll_tx();

        let header = PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
            },
            hops: 0,
            transport_id: None,
            destination_hash: announce.destination_hash,
            context: PacketContext::None,
        };
        let request = build_packet(header, &[0xA5; 64]).unwrap();

        assert_eq!(
            node.ingest(request.as_slice(), RxMeta::new(9), 3100)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(node.poll_tx().is_none());
    }

    #[test]
    fn plain_and_group_announces_are_dropped_before_learning() {
        let announce = signed_announce([0x42; 32], "lxmf.delivery", b"node");
        let mut node = node();

        for dest_bits in [0b10u8, 0b01u8] {
            // Rewrite the destination-type bits (PLAIN=0b10, GROUP=0b01) in the
            // flags byte; the filter fires before signature validation.
            let mut raw: PacketBuffer = PacketBuffer::from_slice(announce.raw.as_slice()).unwrap();
            raw.as_mut_slice()[0] = (raw.as_slice()[0] & !(0b11 << 2)) | (dest_bits << 2);
            assert_eq!(
                node.ingest(raw.as_slice(), RxMeta::new(IFACE), 1000)
                    .unwrap(),
                IngestAction::Dropped
            );
            assert!(!node.has_path(&announce.destination_hash, 1000));
        }
    }

    #[test]
    fn path_request_for_live_path_with_evicted_cache_uses_trusted_discovery() {
        // Trusted Rust falls through to ordinary discovery when cache material is absent.
        // This intentionally differs from Python; see the internal canon adjudication.
        // One-slot announce cache so the second announce evicts the first.
        type TinyCacheNode = LiteNode<8, 16, 1, 4, 4, 8, 4>;
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.mode = crate::config::InterfaceMode::Gateway; // discovery-capable
        config.table_caps = crate::config::TableCaps {
            path_entries: 8,
            announce_entries: 1,
            reverse_entries: 4,
            link_entries: 4,
            packet_hashes: 16,
            recent_announces: 16,
            path_request_tags: 8,
            random_blobs_per_path: 8,
            queued_announces_per_interface: 1,
            tx_queue_depth: 4,
        };
        let mut node = TinyCacheNode::new(config, TRANSPORT_ID).unwrap();

        let first = signed_announce([0x43; 32], "lxmf.delivery", b"node");
        let second = signed_announce([0x44; 32], "lxmf.delivery", b"node");
        node.ingest(first.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        node.tick(3000);
        while node.poll_tx().is_some() {}
        // Second announce evicts the first from the 1-entry announce cache but
        // leaves its learned path live.
        node.ingest(second.raw.as_slice(), RxMeta::new(IFACE), 3100)
            .unwrap();
        node.tick(6000);
        while node.poll_tx().is_some() {}
        assert!(node.has_path(&first.destination_hash, 6100));

        let request = path_request(first.destination_hash, [0x51; 16]);
        assert_eq!(
            node.ingest(request.as_slice(), RxMeta::new(9), 6200)
                .unwrap(),
            IngestAction::ForwardedPathRequest
        );
        assert_eq!(
            node.poll_tx().unwrap().reason,
            OutboundReason::PathRequestForward
        );
    }

    #[test]
    fn path_request_is_answered_from_cached_announce() {
        let announce = signed_announce([0x13; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();

        let request = path_request(announce.destination_hash, [0x55; 16]);
        let action = node
            .ingest(request.as_slice(), RxMeta::new(IFACE), 1200)
            .unwrap();
        assert_eq!(action, IngestAction::AnsweredPathRequest);

        let out = node.poll_tx().unwrap();
        assert_eq!(out.reason, OutboundReason::PathResponse);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.header_type, HeaderType::Header2);
        assert_eq!(view.header.context, PacketContext::PathResponse);
        assert_eq!(view.header.transport_id, Some(TRANSPORT_ID));
        assert_eq!(view.header.destination_hash, announce.destination_hash);
    }

    #[test]
    fn unknown_path_request_is_forwarded_with_transport_id() {
        let mut node = node();
        let requested = [0x77; 16];
        let request = path_request(requested, [0x66; 16]);

        let action = node
            .ingest(request.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        assert_eq!(action, IngestAction::ForwardedPathRequest);

        let out = node.poll_tx().unwrap();
        assert_eq!(out.reason, OutboundReason::PathRequestForward);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.destination_hash, path_request_destination());
        assert_eq!(&view.payload[..16], &requested);
        assert_eq!(&view.payload[16..32], &TRANSPORT_ID);
    }

    #[test]
    fn header2_data_for_this_transport_is_unwrapped_for_direct_path() {
        let announce = signed_announce([0x14; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();

        let data = h2_data(announce.destination_hash, b"hello");
        let action = node
            .ingest(data.as_slice(), RxMeta::new(IFACE), 1300)
            .unwrap();
        assert_eq!(action, IngestAction::ForwardedTransport);

        let out = node.poll_tx().unwrap();
        assert_eq!(out.reason, OutboundReason::TransportForward);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.header_type, HeaderType::Header1);
        assert_eq!(view.header.transport_id, None);
        assert_eq!(view.header.hops, 1);
        assert_eq!(view.payload, b"hello");
    }

    #[test]
    fn header2_data_and_proof_route_between_distinct_interfaces() {
        let announce = signed_announce([0x1D; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(2), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let data = h2_data(announce.destination_hash, b"bridge payload");
        let proof_hash = truncated_packet_hash(data.as_slice(), HeaderType::Header2);
        assert_eq!(
            node.ingest(data.as_slice(), RxMeta::new(1), 1300).unwrap(),
            IngestAction::ForwardedTransport
        );

        let out = node.poll_tx().unwrap();
        assert_eq!(out.interface_id, 2);
        assert_eq!(out.reason, OutboundReason::TransportForward);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.header_type, HeaderType::Header1);
        assert_eq!(view.header.transport_id, None);
        assert_eq!(view.payload, b"bridge payload");

        let proof = proof(proof_hash);
        assert_eq!(
            node.ingest(proof.as_slice(), RxMeta::new(2), 1400).unwrap(),
            IngestAction::ForwardedProof
        );

        let out = node.poll_tx().unwrap();
        assert_eq!(out.interface_id, 1);
        assert_eq!(out.reason, OutboundReason::ProofReturn);
    }

    #[test]
    fn delivery_proof_routes_back_over_reverse_table() {
        let announce = signed_announce([0x15; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();

        let data = h2_data(announce.destination_hash, b"hello");
        let proof_hash = truncated_packet_hash(data.as_slice(), HeaderType::Header2);
        node.ingest(data.as_slice(), RxMeta::new(IFACE), 1300)
            .unwrap();
        let _forwarded = node.poll_tx().unwrap();

        let proof = proof(proof_hash);
        let action = node
            .ingest(proof.as_slice(), RxMeta::new(IFACE), 1500)
            .unwrap();
        assert_eq!(action, IngestAction::ForwardedProof);

        let out = node.poll_tx().unwrap();
        assert_eq!(out.reason, OutboundReason::ProofReturn);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.packet_type, PacketType::Proof);
        assert_eq!(view.header.destination_hash, proof_hash);
    }

    #[test]
    fn link_packet_routes_via_link_table_from_initiator_side() {
        let announce = signed_announce([0x18; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        assert_eq!(
            node.ingest(request.as_slice(), RxMeta::new(9), 1100)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        let _forwarded_request = node.poll_tx().unwrap();

        let packet = link_packet(link_id, 0, PacketContext::Channel);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(9), 1200)
                .unwrap(),
            IngestAction::ForwardedTransport
        );

        let out = node.poll_tx().unwrap();
        assert_eq!(out.interface_id, IFACE);
        assert_eq!(out.reason, OutboundReason::TransportForward);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.destination_type, DestinationType::Link);
        assert_eq!(view.header.destination_hash, link_id);
        assert_eq!(view.header.context, PacketContext::Channel);
        assert_eq!(view.header.hops, 1);
    }

    #[test]
    fn resource_packet_routes_via_link_table_from_destination_side() {
        let announce = signed_announce([0x19; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let packet = link_packet(link_id, 0, PacketContext::Resource);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(IFACE), 1200)
                .unwrap(),
            IngestAction::ForwardedTransport
        );

        let out = node.poll_tx().unwrap();
        assert_eq!(out.interface_id, 9);
        assert_eq!(out.reason, OutboundReason::TransportForward);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.destination_type, DestinationType::Link);
        assert_eq!(view.header.context, PacketContext::Resource);
        assert_eq!(view.payload, b"link payload");
    }

    #[test]
    fn link_packet_with_wrong_hops_is_claimed_and_not_forwarded() {
        let announce = signed_announce([0x1A; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let packet = link_packet(link_id, 1, PacketContext::Channel);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(9), 1200)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        assert!(node.poll_tx().is_none());
    }

    #[test]
    fn own_forwarded_link_packet_is_claimed_before_duplicate_check() {
        let announce = signed_announce([0x20; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let packet = link_packet(link_id, 0, PacketContext::None);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(9), 1200)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        let forwarded = node.poll_tx().unwrap();
        assert_eq!(forwarded.interface_id, IFACE);

        assert_eq!(
            node.ingest(forwarded.packet.as_slice(), RxMeta::new(IFACE), 1300)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        assert!(node.poll_tx().is_none());
        assert_eq!(node.stats().duplicates, 0);
    }

    #[test]
    fn resource_request_replays_are_not_deduplicated() {
        let announce = signed_announce([0x1B; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let packet = link_packet(link_id, 0, PacketContext::ResourceReq);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(IFACE), 1200)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        assert!(node.poll_tx().is_some());
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(IFACE), 1300)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        assert!(node.poll_tx().is_some());
    }

    #[test]
    fn link_proof_routes_via_link_table() {
        let announce = signed_announce([0x1C; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let proof = link_proof(link_id, 0, PacketContext::LinkProof);
        assert_eq!(
            node.ingest(proof.as_slice(), RxMeta::new(IFACE), 1200)
                .unwrap(),
            IngestAction::ForwardedProof
        );

        let out = node.poll_tx().unwrap();
        assert_eq!(out.interface_id, 9);
        assert_eq!(out.reason, OutboundReason::ProofReturn);
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.packet_type, PacketType::Proof);
        assert_eq!(view.header.flags.destination_type, DestinationType::Link);
        assert_eq!(view.header.context, PacketContext::LinkProof);
    }

    #[test]
    fn transit_lrproof_must_validate_before_extending_link_lifetime() {
        let announce = signed_announce([0x21; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let proof = lrproof(link_id, 0, announce.signing_seed);
        assert_eq!(
            node.ingest(proof.as_slice(), RxMeta::new(IFACE), 1200)
                .unwrap(),
            IngestAction::ForwardedProof
        );
        let out = node.poll_tx().unwrap();
        assert_eq!(out.interface_id, 9);
        assert_eq!(out.reason, OutboundReason::ProofReturn);

        let packet = link_packet(link_id, 0, PacketContext::None);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(9), 62_000)
                .unwrap(),
            IngestAction::ForwardedTransport
        );
        assert_eq!(node.poll_tx().unwrap().interface_id, IFACE);
    }

    #[test]
    fn invalid_transit_lrproof_does_not_establish_link() {
        let announce = signed_announce([0x22; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        let proof = lrproof(link_id, 0, [0xE1; 32]);
        assert_eq!(
            node.ingest(proof.as_slice(), RxMeta::new(IFACE), 1200)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(node.poll_tx().is_none());

        let packet = link_packet(link_id, 0, PacketContext::None);
        assert_eq!(
            node.ingest(packet.as_slice(), RxMeta::new(9), 62_000)
                .unwrap(),
            IngestAction::Dropped
        );
        assert!(node.poll_tx().is_none());
    }

    #[test]
    fn transit_lrproof_failing_strict_gate_is_dropped_not_forwarded() {
        // Regression for the fall-through security gap: an LRPROOF that does not match the
        // validated link-table gate (here it arrives on the wrong interface) must be DROPPED,
        // never forwarded unvalidated through the generic link router.
        let announce = signed_announce([0x2A; 32], "lxmf.delivery", b"node");
        let mut node = node();
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let _rebroadcast = node.poll_tx();

        let request = link_request(announce.destination_hash, 0);
        let link_id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let _forwarded_request = node.poll_tx().unwrap();

        // Correctly-signed proof, but arriving on the wrong interface (not the link's outbound
        // interface) fails the strict gate. Before the fix this fell through to the generic router
        // and was forwarded unvalidated; now it must be dropped with no outbound frame.
        let proof = lrproof(link_id, 0, announce.signing_seed);
        assert_eq!(
            node.ingest(proof.as_slice(), RxMeta::new(7), 1200).unwrap(),
            IngestAction::Dropped
        );
        assert!(node.poll_tx().is_none());
    }

    #[test]
    fn table_profile_sizes_fit_budget() {
        // Cardputer budget (no PSRAM, ~55 KB free heap): the MICRO node must stay <= 32 KB so
        // cap drift can't silently blow the internal-heap allocation.
        let micro = core::mem::size_of::<MicroNode>();
        assert_eq!(micro, 32_664, "MicroNode layout changed unexpectedly");
        assert!(micro <= 32 * 1024, "MicroNode grew to {micro} B (> 32 KB)");
        std::println!(
            "MicroNode={micro} SmallNode={} Esp32PsramNode={} OutboundFrame={} OutboundLifetime={} token={}",
            core::mem::size_of::<SmallNode>(),
            core::mem::size_of::<Esp32PsramNode>(),
            core::mem::size_of::<OutboundFrame>(),
            core::mem::size_of::<OutboundLifetime>(),
            OutboundLifetime::TOKEN_BYTES
        );
        // Profile caps must construct within their node type's const-generic capacities.
        assert!(MicroNode::new(LiteConfig::ESP32_LORA_TRANSPORT_MICRO, TRANSPORT_ID).is_ok());
        assert!(SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, TRANSPORT_ID).is_ok());
    }

    #[test]
    fn validate_config_matches_new_checks() {
        // The extracted pre-construction check must agree with new() on both outcomes.
        assert_eq!(
            MicroNode::validate_config(&LiteConfig::ESP32_LORA_TRANSPORT_MICRO),
            Ok(())
        );
        // SMALL caps exceed the MICRO const-generic capacities -> CapacityTooSmall, both paths.
        let oversized = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        assert_eq!(
            MicroNode::validate_config(&oversized),
            Err(TransportError::CapacityTooSmall)
        );
        assert_eq!(
            MicroNode::new(oversized, TRANSPORT_ID).unwrap_err(),
            TransportError::CapacityTooSmall
        );
    }

    #[test]
    fn multihop_path_forwards_header2_to_learned_next_transport() {
        let announce = signed_announce([0x2B; 32], "lxmf.delivery", b"node");
        let announce_view = PacketView::parse(announce.raw.as_slice()).unwrap();
        let next_transport = [0x44; 16];
        let transported_announce = build_packet(
            PacketHeader {
                flags: PacketFlags {
                    header_type: HeaderType::Header2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    destination_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops: 1,
                transport_id: Some(next_transport),
                destination_hash: announce.destination_hash,
                context: PacketContext::None,
            },
            announce_view.payload,
        )
        .unwrap();

        let mut node = node();
        assert_eq!(
            node.ingest(transported_announce.as_slice(), RxMeta::new(IFACE), 1_000,)
                .unwrap(),
            IngestAction::ScheduledAnnounce
        );
        let path = node
            .paths
            .get_live(&announce.destination_hash, 1_000)
            .unwrap();
        assert_eq!(path.hops, 2);
        assert_eq!(path.next_hop, Some(next_transport));

        let data = h2_data(announce.destination_hash, b"two-hop payload");
        assert_eq!(
            node.ingest(data.as_slice(), RxMeta::new(9), 1_100).unwrap(),
            IngestAction::ForwardedTransport
        );
        let out = node.poll_tx().unwrap();
        let view = PacketView::parse(out.packet.as_slice()).unwrap();
        assert_eq!(view.header.flags.header_type, HeaderType::Header2);
        assert_eq!(view.header.flags.transport_type, TransportType::Transport);
        assert_eq!(view.header.transport_id, Some(next_transport));
        assert_eq!(view.header.hops, 1);
        assert_eq!(view.payload, b"two-hop payload");
    }

    #[test]
    fn enqueue_wraps_max_ifac_at_exact_wire_budget() {
        // WIRE_MTU_MAX = MTU + IFAC_KEY_LENGTH: the worst case (full-MTU clear packet,
        // maximum 64-byte tag) fits exactly, so enqueue's failure branch is currently
        // unreachable — the fallible signature exists for canon-shape parity with the
        // rsNode copy (per-interface budgets) and for any future tighter wire budget.
        // Callers must keep the send-before-record ordering regardless.
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.ifac = Some(crate::config::IfacConfig {
            key: [0x11; 64],
            size: 64,
        });
        let mut node = SmallNode::new(config, TRANSPORT_ID).unwrap();

        let full = PacketBuffer::from_slice(&[0x5A; crate::constants::MTU]).unwrap();
        assert!(node.enqueue(1, full, OutboundReason::TransportForward));
        assert_eq!(node.outbound_len(), 1);
        let frame = node.poll_tx().unwrap();
        assert_eq!(frame.packet.len(), crate::constants::WIRE_MTU_MAX);
        assert_eq!(node.stats.outbound_dropped, 0);
    }
    #[test]
    fn queued_and_held_requests_have_immutable_wait_deadline() {
        let mut node = node();
        node.request_path(&[0x21; 16], &[0x31; 16], IFACE, 1000)
            .unwrap();
        let held = node.poll_tx().unwrap();
        assert!(node.outbound_lifetime_is_live(IFACE, held.lifetime, 120_999));
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 121_000));
        node.request_path(&[0x22; 16], &[0x32; 16], IFACE, 1000)
            .unwrap();
        assert_eq!(node.outbound_oldest_age_ms(2000), 1000);
        node.tick(121_000);
        assert_eq!(node.outbound_len(), 0);
        assert_eq!(node.stats().outbound_expired, 1);
    }

    #[test]
    fn consumed_reverse_proof_owns_original_deadline() {
        let mut node = node();
        let announce = signed_announce([0x73; 32], "lxmf.delivery", b"proof-owner");
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let data = h2_data(announce.destination_hash, b"return path");
        let hash = truncated_packet_hash(data.as_slice(), HeaderType::Header2);
        node.ingest(data.as_slice(), RxMeta::new(9), 1100).unwrap();
        node.poll_tx().unwrap();
        // A nearly expired reverse entry makes ownership transfer observable.
        let mut reverse = node.reverse.get(&hash, 1100).copied().unwrap();
        reverse.expires_ms = 2000;
        node.reverse.insert(reverse, 1100);
        let valid = proof(hash);
        assert_eq!(
            node.ingest(valid.as_slice(), RxMeta::new(IFACE), 1500)
                .unwrap(),
            IngestAction::ForwardedProof
        );
        assert!(node.reverse.get(&hash, 1500).is_none());
        let held = node.poll_tx().unwrap();
        assert_eq!(held.lifetime.expires_ms, 2000);
        assert!(node.outbound_lifetime_is_live(9, held.lifetime, 1999));
        assert!(!node.outbound_lifetime_is_live(9, held.lifetime, 2000));
    }

    #[test]
    fn incarnation_held_data_does_not_revive_after_reverse_reinsert() {
        let mut node = node();
        let announce = signed_announce([0x75; 32], "lxmf.delivery", b"route");
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let data = h2_data(announce.destination_hash, b"payload");
        let hash = truncated_packet_hash(data.as_slice(), HeaderType::Header2);
        node.ingest(data.as_slice(), RxMeta::new(9), 1100).unwrap();
        let held = node.poll_tx().unwrap();
        assert!(node.outbound_lifetime_is_live(IFACE, held.lifetime, 1200));
        let reverse = node.reverse.remove(&hash, 1200).unwrap();
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 1200));
        node.reverse.insert(reverse, 1200);
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 1200));
        let newer = signed_announce_rh([0x75; 32], "lxmf.delivery", b"route", [0xBD; 10]);
        node.ingest(newer.raw.as_slice(), RxMeta::new(2), 1300)
            .unwrap();
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 1300));
    }

    #[test]
    fn incarnation_path_relearn_from_identical_announce_does_not_revive() {
        for replacement_interface in [IFACE, 2] {
            let mut node = node();
            let announce = signed_announce([0x79; 32], "lxmf.delivery", b"same announce");
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap();
            let data = h2_data(announce.destination_hash, b"local pending");
            let held = node.local_outbound_lifetime(data.as_slice(), 1100).unwrap();
            assert!(node.outbound_lifetime_is_live(IFACE, held, 1100));
            assert!(node.drop_path(&announce.destination_hash));
            assert!(!node.outbound_lifetime_is_live(IFACE, held, 1100));
            node.ingest(
                announce.raw.as_slice(),
                RxMeta::new(replacement_interface),
                1200,
            )
            .unwrap();
            assert_eq!(
                node.path(&announce.destination_hash, 1200)
                    .unwrap()
                    .interface_id,
                replacement_interface
            );
            assert!(!node.outbound_lifetime_is_live(IFACE, held, 1200));
        }
    }

    #[test]
    fn incarnation_link_same_key_replacement_does_not_revive() {
        let mut node = node();
        let announce = signed_announce([0x7A; 32], "lxmf.delivery", b"same link");
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let request = link_request(announce.destination_hash, 0);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let held = node.poll_tx().unwrap();
        assert!(node.outbound_lifetime_is_live(IFACE, held.lifetime, 1200));
        let id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        let same_entry = *node.links.get(&id, 1200).unwrap();
        node.links.insert(same_entry, 1200);
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 1200));
    }

    #[test]
    fn pending_link_queue_never_extends_six_second_establishment_window() {
        let mut node = node();
        let announce = signed_announce([0x76; 32], "lxmf.delivery", b"link");
        node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
            .unwrap();
        let request = link_request(announce.destination_hash, 0);
        node.ingest(request.as_slice(), RxMeta::new(9), 1100)
            .unwrap();
        let held = node.poll_tx().unwrap();
        assert_eq!(held.lifetime.expires_ms, 7100);
        assert!(node.outbound_lifetime_is_live(IFACE, held.lifetime, 7099));
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 7100));
        let id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.links = LinkTable::new();
        assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 1200));
        assert!(node.links.get(&id, 1200).is_none());
    }
    #[test]
    fn sixteen_routes_keep_signed_cache_coverage_with_four_scheduled_announces() {
        type CapacityNode = LiteNode<16, 64, 16, 8, 4, 16, 8, KNOWN_DESTINATIONS_SMALL, 4>;
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.table_caps = crate::config::TableCaps {
            path_entries: 16,
            announce_entries: 16,
            reverse_entries: 8,
            link_entries: 4,
            packet_hashes: 64,
            path_request_tags: 16,
            queued_announces_per_interface: 4,
            tx_queue_depth: 8,
            ..crate::config::TableCaps::ESP32_LORA_TRANSPORT_SMALL
        };
        let mut node = CapacityNode::new(config, TRANSPORT_ID).unwrap();
        let mut destinations = [[0u8; 16]; 16];
        for (index, destination) in destinations.iter_mut().enumerate() {
            let announce = signed_announce([index as u8 + 1; 32], "lxmf.delivery", b"sixteen");
            *destination = announce.destination_hash;
            node.ingest(
                announce.raw.as_slice(),
                RxMeta::new(IFACE),
                1000 + index as u64,
            )
            .unwrap();
        }
        node.tick(2000);
        assert_eq!(
            node.outbound_len(),
            4,
            "schedule bound is independent of cache coverage"
        );
        while node.poll_tx().is_some() {}
        for (index, destination) in destinations.into_iter().enumerate() {
            assert!(node.has_path(&destination, 3000));
            let request = path_request(destination, [index as u8 + 1; 16]);
            assert_eq!(
                node.ingest(request.as_slice(), RxMeta::new(IFACE), 3000)
                    .unwrap(),
                IngestAction::AnsweredPathRequest
            );
            assert_eq!(node.poll_tx().unwrap().reason, OutboundReason::PathResponse);
        }
        // Churn evicts the matching cache slot even when mode-dependent route
        // deadlines differ; every still-retained route remains answerable.
        let extra = signed_announce([77; 32], "lxmf.delivery", b"seventeenth");
        node.ingest(extra.raw.as_slice(), RxMeta::new(IFACE), 3100)
            .unwrap();
        assert!(!node.has_path(&destinations[0], 3100));
        assert!(node.announce_cache.get(&destinations[0], 3100).is_none());
        for destination in destinations
            .into_iter()
            .skip(1)
            .chain([extra.destination_hash])
        {
            assert!(node.announce_cache.get(&destination, 3100).is_some());
        }
        std::println!(
            "node bytes={}, queue frame bytes={}",
            core::mem::size_of::<CapacityNode>(),
            core::mem::size_of::<OutboundFrame>()
        );
    }
    #[test]
    fn validated_link_activity_renews_queued_and_held_deadline() {
        for is_proof in [false, true] {
            let mut node = node();
            let announce = signed_announce([0x7B; 32], "lxmf.delivery", b"active-link");
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap();
            node.tick(1500);
            while node.poll_tx().is_some() {}
            let request = link_request(announce.destination_hash, 0);
            let id = link_id_from_raw(request.as_slice(), HeaderType::Header2);
            node.ingest(request.as_slice(), RxMeta::new(9), 1600)
                .unwrap();
            node.poll_tx().unwrap();
            node.links.mark_validated(&id, 2000, 1700);

            // Ordinary traffic arrives one millisecond before the previous idle
            // deadline. Successful admission renews the validated session.
            let packet = if is_proof {
                link_proof(id, 0, PacketContext::None)
            } else {
                link_packet(id, 0, PacketContext::Channel)
            };
            assert_eq!(
                node.ingest(packet.as_slice(), RxMeta::new(9), 1999)
                    .unwrap(),
                if is_proof {
                    IngestAction::ForwardedProof
                } else {
                    IngestAction::ForwardedTransport
                }
            );
            assert_eq!(node.links.get(&id, 1999).unwrap().expires_ms, 901_999);
            node.tick(2001);
            assert_eq!(
                node.outbound_len(),
                1,
                "renewed activity survives the previous idle deadline while queued"
            );
            let held = node.poll_tx().unwrap();
            assert_eq!(
                held.lifetime.expires_ms, 121_999,
                "renewal retains the independent 120-second queue bound"
            );
            // The runtime checks the estimated entire burst end before it
            // acquires the radio; that end can be past the old idle deadline.
            let estimated_burst_end_ms = 2001 + 8000;
            assert!(node.outbound_lifetime_is_live(IFACE, held.lifetime, estimated_burst_end_ms));
            assert!(!node.outbound_lifetime_is_live(IFACE, held.lifetime, 121_999));
        }
    }

    #[test]
    fn incarnation_forward_generation_exhaustion_drops_before_enqueue() {
        for is_link in [false, true] {
            let mut node = node();
            let announce = signed_announce([0x7C; 32], "lxmf.delivery", b"exhausted");
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap();
            node.tick(1500);
            while node.poll_tx().is_some() {}
            let packet = if is_link {
                node.links.last_generation = u64::MAX;
                link_request(announce.destination_hash, 0)
            } else {
                node.reverse.last_generation = u64::MAX;
                h2_data(announce.destination_hash, b"cannot retain")
            };
            let queued = node.stats.queued_outbound;
            assert_eq!(
                node.ingest(packet.as_slice(), RxMeta::new(9), 1600)
                    .unwrap(),
                IngestAction::Dropped
            );
            assert_eq!(node.stats.queued_outbound, queued);
            assert_eq!(node.outbound_len(), 0);
            assert!(node.reverse.entries.iter().all(Option::is_none));
            assert!(node.links.entries.iter().all(Option::is_none));
        }
    }

    #[test]
    fn retained_identity_exhaustion_rejects_forward_before_return_state() {
        for is_link in [false, true] {
            let mut node = node();
            let announce = signed_announce([0x7C; 32], "lxmf.delivery", b"exhausted");
            node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
                .unwrap();
            node.tick(1500);
            while node.poll_tx().is_some() {}
            node.last_delivery_identity = u64::MAX;
            let packet = if is_link {
                link_request(announce.destination_hash, 0)
            } else {
                h2_data(announce.destination_hash, b"cannot retain")
            };
            let queued = node.stats.queued_outbound;
            assert_eq!(
                node.ingest(packet.as_slice(), RxMeta::new(9), 1600)
                    .unwrap(),
                IngestAction::Dropped
            );
            assert_eq!(node.stats.queued_outbound, queued);
            assert_eq!(node.outbound_len(), 0);
            assert!(node.reverse.entries.iter().all(Option::is_none));
            assert!(node.links.entries.iter().all(Option::is_none));
        }
    }

    #[test]
    fn incarnation_token_v2_is_fixed_and_rejects_noncanonical_bytes() {
        assert_eq!(OutboundLifetime::TOKEN_BYTES, 88);
        for path in [0, 1, u64::MAX] {
            for state in [
                OutboundState::Independent,
                OutboundState::Reverse(1),
                OutboundState::Link(u64::MAX),
                OutboundState::Discovery(u64::MAX),
            ] {
                let lifetime = OutboundLifetime {
                    enqueued_ms: 10,
                    expires_ms: 20,
                    path,
                    state,
                };
                let token = lifetime.to_token();
                assert_eq!(OutboundLifetime::from_token(&token), Some(lifetime));
                for idx in (6..8).chain(40..88) {
                    let mut invalid = token;
                    invalid[idx] = 1;
                    assert!(
                        OutboundLifetime::from_token(&invalid).is_none(),
                        "reserved byte {idx}"
                    );
                }
            }
        }
        let good = OutboundLifetime {
            enqueued_ms: 10,
            expires_ms: 20,
            path: 1,
            state: OutboundState::Reverse(1),
        }
        .to_token();
        for (idx, value) in [(3, 1), (4, 2), (4, 0), (5, 4), (5, 0)] {
            let mut invalid = good;
            invalid[idx] = value;
            assert!(OutboundLifetime::from_token(&invalid).is_none());
        }
        for field in [24..32, 32..40] {
            let mut invalid = good;
            invalid[field].fill(0);
            assert!(OutboundLifetime::from_token(&invalid).is_none());
        }
        for expiry in [9u64, 120_011] {
            let mut invalid = good;
            invalid[16..24].copy_from_slice(&expiry.to_le_bytes());
            assert!(OutboundLifetime::from_token(&invalid).is_none());
        }
    }
}

#[cfg(test)]
mod retained_queue_tests {
    use super::*;
    type Node = LiteNode<4, 8, 2, 2, 2, 2, 4>;
    fn node() -> Node {
        Node::new_const(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, [0; 16])
    }
    fn enqueue(node: &mut Node, marker: u8, reason: OutboundReason, interface: u8) -> u64 {
        assert!(node.enqueue(
            interface,
            PacketBuffer::from_slice(&[marker]).unwrap(),
            reason
        ));
        node.last_delivery_identity
    }
    const GENERATIONS: [u32; 7] = [11, 12, 13, 14, 15, 16, 17];

    #[test]
    fn every_reason_keeps_existing_fanout_selection() {
        for (reason, interface, mask) in [
            (OutboundReason::PathRequest, 2, 0x7f),
            (OutboundReason::PathRequestForward, 2, 0x7b),
            (OutboundReason::AnnounceRebroadcast, 2, 0x7b),
            (OutboundReason::PathResponse, 2, 0x04),
            (OutboundReason::TransportForward, 2, 0x04),
            (OutboundReason::ProofReturn, 2, 0x04),
            (OutboundReason::ProofReturn, 255, 0),
        ] {
            let mut n = node();
            enqueue(&mut n, 42, reason, interface);
            let selected = n.retained_outbound_select(0, 0, GENERATIONS);
            assert_eq!(selected.map_or(0, |q| q.delivery.pending_targets), mask);
        }
    }

    #[test]
    fn healthy_target_advances_without_losing_refused_copy_or_renewing_birth() {
        let mut n = node();
        n.clock_ms = 100;
        let first = enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        n.clock_ms = 101;
        let second = enqueue(&mut n, 2, OutboundReason::PathRequest, 0);
        let a = *n
            .retained_outbound_select(0, 0, [11, 12, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(a.delivery.identity, first);
        assert!(n.retained_outbound_ack(first, 2));
        let b = *n
            .retained_outbound_select(0, 1, [11, 12, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(b.delivery.identity, second);
        assert!(n.retained_outbound_ack(second, 2));
        assert_eq!(n.outbound_len(), 2);
        assert!(
            n.retained_outbound_select(0, 1, [11, 12, 0, 0, 0, 0, 0])
                .is_none()
        );
        n.clock_ms = 500;
        let remaining = *n
            .retained_outbound_select(0, 0, [11, 12, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(remaining.frame, a.frame);
        assert_eq!(remaining.delivery.pending_targets, 1);
        assert_eq!(
            remaining.delivery.interface_generations,
            a.delivery.interface_generations
        );
        assert!(n.retained_outbound_take(first)); // transfer metadata, not fresh fanout
        assert!(!n.retained_outbound_ack(first, 1));
        assert_eq!(n.outbound_len(), 1);
    }

    #[test]
    fn retirement_before_first_peek_cannot_bind_replacement_interface() {
        let mut n = node();
        let old = enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        n.retained_outbound_retire_interface(1);
        let new = enqueue(&mut n, 2, OutboundReason::PathRequest, 0);
        let a = *n
            .retained_outbound_select(0, 0, [11, 99, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(a.delivery.identity, old);
        assert_eq!(a.delivery.pending_targets, 1);
        let b = *n
            .retained_outbound_select(old, 0, [11, 99, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(b.delivery.identity, new);
        assert_eq!(b.delivery.pending_targets, 3);
        n.retained_outbound_retire_interface(0);
        let b = *n
            .retained_outbound_select(0, 0, [44, 99, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(b.delivery.identity, new);
        assert_eq!(b.delivery.pending_targets, 2);
        // A generation change detected at select also retires rather than rebinds.
        assert!(
            n.retained_outbound_select(0, 0, [44, 100, 0, 0, 0, 0, 0])
                .is_none()
        );
    }

    #[test]
    fn overflow_and_compaction_cannot_acknowledge_a_reused_slot() {
        let mut n = node();
        let first = enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        let old = *n.retained_outbound_select(0, 0, GENERATIONS).unwrap();
        assert_eq!(first, old.delivery.identity);
        for marker in 2..=5 {
            enqueue(&mut n, marker, OutboundReason::PathRequest, 0);
        }
        assert_eq!(n.outbound_len(), 4);
        assert_eq!(n.stats.outbound_dropped, 1);
        assert!(!n.retained_outbound_ack(first, 0x7f));
        let second = n
            .retained_outbound_select(0, 0, GENERATIONS)
            .unwrap()
            .delivery
            .identity;
        assert!(second > first);
        assert!(n.retained_outbound_ack(second, 0x7f));
        assert!(!n.retained_outbound_ack(second, 0x7f));
        assert_eq!(n.outbound_len(), 3);
        let third = n
            .retained_outbound_select(0, 0, GENERATIONS)
            .unwrap()
            .delivery
            .identity;
        assert!(third > second);
    }

    #[test]
    fn terminal_target_retirement_is_counted_once_but_acknowledgment_is_not() {
        let mut n = node();
        enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        assert!(n.retained_outbound_select(0, 0, [0; 7]).is_none());
        assert_eq!(n.stats.outbound_dropped, 1);
        assert!(n.retained_outbound_select(0, 0, [0; 7]).is_none());
        assert_eq!(n.stats.outbound_dropped, 1);

        enqueue(&mut n, 2, OutboundReason::PathRequest, 0);
        n.retained_outbound_select(0, 0, [11, 0, 0, 0, 0, 0, 0]);
        n.retained_outbound_retire_interface(0);
        assert!(n.retained_outbound_select(0, 0, GENERATIONS).is_none());
        assert_eq!(n.stats.outbound_dropped, 2);

        let sent = enqueue(&mut n, 3, OutboundReason::PathRequest, 0);
        n.retained_outbound_select(0, 0, GENERATIONS);
        assert!(n.retained_outbound_ack(sent, 0x7f));
        assert!(n.retained_outbound_select(0, 0, GENERATIONS).is_none());
        assert_eq!(n.stats.outbound_dropped, 2);

        enqueue(&mut n, 4, OutboundReason::PathRequest, 0);
        n.retained_outbound_select(0, 0, [11, 0, 0, 0, 0, 0, 0]);
        assert!(
            n.retained_outbound_select(0, 0, [12, 0, 0, 0, 0, 0, 0])
                .is_none()
        );
        assert_eq!(n.stats.outbound_dropped, 3);
    }

    #[test]
    fn exclusive_expiry_prunes_all_rows_even_behind_blocked_work() {
        let mut n = node();
        n.clock_ms = 100;
        enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        n.clock_ms = 101;
        enqueue(&mut n, 2, OutboundReason::PathRequest, 0);
        n.retained_outbound_select(0, 0, GENERATIONS);
        n.clock_ms = 120100;
        let q = n.retained_outbound_select(0, 0, GENERATIONS).unwrap();
        assert_eq!(q.frame.packet.as_slice(), &[2]);
        assert_eq!(q.frame.lifetime.enqueued_ms, 101);
        n.clock_ms = 120101;
        assert!(n.retained_outbound_select(0, 0x7f, GENERATIONS).is_none());
        assert_eq!(n.outbound_len(), 0);
        assert_eq!(n.stats.outbound_expired, 2);
    }

    #[test]
    fn checked_identity_exhaustion_never_restarts_after_emptying() {
        let mut n = node();
        n.last_delivery_identity = u64::MAX - 1;
        let last = enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        assert_eq!(last, u64::MAX);
        n.retained_outbound_select(0, 0, GENERATIONS);
        assert!(n.retained_outbound_ack(last, 0x7f));
        assert!(!n.enqueue(
            0,
            PacketBuffer::from_slice(&[2]).unwrap(),
            OutboundReason::PathRequest
        ));
        assert_eq!(n.outbound_len(), 0);
        assert_eq!(n.stats.queued_outbound, 1);
        assert_eq!(n.last_delivery_identity, u64::MAX);
    }

    #[test]
    fn legacy_poll_is_unchanged_until_exclusive_retained_mode() {
        let mut n = node();
        enqueue(&mut n, 1, OutboundReason::PathRequest, 0);
        let frame: OutboundFrame = n.poll_tx().unwrap();
        assert_eq!(frame.packet.as_slice(), &[1]);
        let identity = enqueue(&mut n, 2, OutboundReason::PathRequest, 0);
        n.retained_outbound_select(0, 0, GENERATIONS);
        assert!(n.retained_outbound_ack(identity, 1));
        assert!(n.poll_tx().is_none());
        assert!(n.outbound_peek_len().is_none());
        assert_eq!(n.outbound_len(), 1);
    }
}

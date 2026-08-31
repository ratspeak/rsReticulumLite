use ed25519_dalek::Verifier;

use crate::announce_admission::AnnounceAdmission;
use crate::config::{InterfaceMode, LiteConfig};
use crate::constants::{
    AP_PATH_TIME_SECS, LINK_PROOF_TIMEOUT_PER_HOP_SECS, LINK_TIMEOUT_SECS,
    PATH_REQUEST_DUPLICATE_GATE_SECS, PATHFINDER_E_SECS, PATHFINDER_M, QUEUED_ANNOUNCE_LIFE_SECS,
    REVERSE_TIMEOUT_SECS, ROAMING_PATH_TIME_SECS,
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
> {
    #[doc(hidden)]
    pub config: LiteConfig,
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
    pub announce_schedule: AnnounceSchedule<ANNOUNCES>,
    #[doc(hidden)]
    pub reverse: ReverseTable<REVERSE>,
    #[doc(hidden)]
    pub links: LinkTable<LINKS>,
    #[doc(hidden)]
    pub request_tags: RequestTagTable<TAGS>,
    #[doc(hidden)]
    pub outbound: Queue<OutboundFrame, OUTBOUND>,
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
> LiteNode<PATHS, HASHES, ANNOUNCES, REVERSE, LINKS, TAGS, OUTBOUND, KNOWN_DESTINATIONS>
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
            stats: TransportStats {
                accepted: 0,
                duplicates: 0,
                learned_announces: 0,
                queued_outbound: 0,
                dropped: 0,
                validation_failures: 0,
                outbound_dropped: 0,
                announces_rate_dropped: 0,
            },
        }
    }

    pub const fn transport_id(&self) -> Hash16 {
        self.transport_id
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

    pub fn poll_tx(&mut self) -> Option<OutboundFrame> {
        self.outbound.pop()
    }

    /// Byte length of the next queued outbound packet without consuming it, so a consumer can size
    /// its buffer before [`Self::poll_tx`] (avoids destructively popping a frame that won't fit).
    pub fn outbound_peek_len(&self) -> Option<usize> {
        self.outbound.peek().map(|f| f.packet.len())
    }

    pub const fn outbound_len(&self) -> usize {
        self.outbound.len()
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.packet_hashes.expire(now_ms);
        self.paths.expire(now_ms);
        self.announce_cache.expire(now_ms);
        self.announce_schedule.expire(now_ms);
        self.reverse.expire(now_ms);
        self.links.expire(now_ms);
        self.request_tags.expire(now_ms);

        while let Some(announce) = self.announce_schedule.pop_due(now_ms) {
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
            || view.header.context == PacketContext::Lrproof;
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
                    self.handle_path_request(view.payload, meta.interface_id, now_ms)
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
            self.announce_cache.insert(
                CachedAnnounce {
                    destination_hash: header.destination_hash,
                    raw: PacketBuffer::from_slice(raw)?,
                    hops: header.hops,
                    expires_ms: path_entry.expires_ms,
                },
                now_ms,
            );

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
        interface_id: InterfaceId,
        now_ms: u64,
    ) -> Result<IngestAction, TransportError> {
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
            if self.config.mode == crate::config::InterfaceMode::Roaming
                && path.interface_id == interface_id
            {
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
            // Upstream Transport.py:2977-2978: a live path whose announce is no
            // longer retrievable from cache IGNORES the request; it must not
            // fall through to discovery-forwarding a path we already know.
            return Ok(IngestAction::Dropped);
        }

        if self.config.transport_enabled && mode_discovers_unknown_paths(self.config.mode) {
            let request = self.build_path_request(requested, tag)?;
            if !self.enqueue(interface_id, request, OutboundReason::PathRequestForward) {
                return Ok(IngestAction::Dropped);
            }
            return Ok(IngestAction::ForwardedPathRequest);
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
        // Send before recording: no reverse entry for a forward that never queued.
        if !self.enqueue(
            target_interface,
            forwarded,
            OutboundReason::TransportForward,
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
                    expires_ms: now_ms.saturating_add(
                        (LINK_PROOF_TIMEOUT_PER_HOP_SECS as u64)
                            .saturating_mul(1000)
                            .saturating_mul(path.hops.max(1) as u64),
                    ),
                }
            });

        // Send before recording: no link-table entry for a request that never queued.
        if !self.enqueue(
            target_interface,
            forwarded,
            OutboundReason::TransportForward,
        ) {
            return Ok(IngestAction::Dropped);
        }
        if let Some(entry) = entry {
            self.links.insert(entry, now_ms);
        }
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
                if !self.enqueue(
                    reverse.receiving_interface,
                    packet,
                    OutboundReason::ProofReturn,
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

        let evicted = self.outbound.push_drop_oldest(OutboundFrame {
            interface_id,
            packet: wire,
            reason,
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
    fn path_request_for_live_path_with_evicted_cache_is_ignored() {
        // Upstream Transport.py:2977-2978: live path + missing cached announce
        // means the request is ignored, not re-forwarded as discovery.
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
            IngestAction::Dropped
        );
        assert!(
            node.poll_tx().is_none(),
            "no discovery forward for a known path"
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
        assert_eq!(micro, 31_232, "MicroNode layout changed unexpectedly");
        assert!(micro <= 32 * 1024, "MicroNode grew to {micro} B (> 32 KB)");
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
}

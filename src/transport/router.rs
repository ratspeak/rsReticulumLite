use super::*;

/// Driver-owned router frame with the interface registration that admitted it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouterOutboundFrame {
    pub frame: OutboundFrame,
    pub target_generation: u64,
}
impl core::ops::Deref for RouterOutboundFrame {
    type Target = OutboundFrame;
    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

impl<
    const P: usize,
    const H: usize,
    const A: usize,
    const R: usize,
    const L: usize,
    const T: usize,
    const O: usize,
    const K: usize,
    const S: usize,
> LiteNode<P, H, A, R, L, T, O, K, S, Router>
{
    pub fn new_router(
        config: LiteConfig,
        id: Hash16,
        registry: InterfaceRegistry,
        modem: Option<LoraModemConfig>,
    ) -> Result<Self, TransportError> {
        Self::validate_config(&config)?;
        registry
            .validate(config.table_caps.tx_queue_depth)
            .map_err(|_| TransportError::InvalidConfig)?;
        Ok(Self::new_router_const(config, id, registry, modem))
    }

    /// Placement constructor; validate capacities and registry before first use.
    pub const fn new_router_const(
        config: LiteConfig,
        id: Hash16,
        registry: InterfaceRegistry,
        modem: Option<LoraModemConfig>,
    ) -> Self {
        let mut node = Self::new_const(config, id);
        node.interfaces = Router::new(registry, modem);
        node
    }

    pub fn interface(&self, id: InterfaceId) -> Option<InterfaceConfig> {
        self.interfaces.interface(id)
    }
    pub fn router_stats(&self) -> RouterStats {
        self.interfaces.stats
    }

    /// Replace the router configuration in place, retiring held interface tokens atomically.
    pub fn reset_router_in_place(
        &mut self,
        config: LiteConfig,
        id: Hash16,
        registry: InterfaceRegistry,
        modem: Option<LoraModemConfig>,
    ) -> Result<(), TransportError> {
        registry
            .validate(config.table_caps.tx_queue_depth)
            .map_err(|_| TransportError::InvalidConfig)?;
        self.reset_in_place(config, id)?;
        self.interfaces.registry = registry;
        self.interfaces.lora_modem = modem;
        Ok(())
    }

    /// Replace ALL own destinations with at most one, keeping registered Links. Hosts serving
    /// several destinations use `register_local_destination`/`unregister_local_destination`.
    pub fn set_own_destination(&mut self, destination: Option<Hash16>) {
        self.clear_own_destinations();
        if let Some(destination) = destination {
            self.register_local_destination(destination);
        }
    }
    /// The sole own destination: `None` when none or several are registered.
    pub fn own_destination(&self) -> Option<Hash16> {
        let mut destinations = self.own_destinations();
        match (destinations.next(), destinations.next()) {
            (Some(destination), None) => Some(destination),
            _ => None,
        }
    }

    /// Replace the destinations whose path-updating announces `ingest_endpoint` also copies to
    /// the host as [`IngestAction::WatchedAnnounce`]. Not retroactive: a path learned earlier
    /// is in [`Self::cached_announce`]. False, unchanged, beyond [`WATCHED_DESTINATIONS_MAX`].
    pub fn set_watched_destinations(&mut self, destinations: &[Hash16]) -> bool {
        if destinations.len() > WATCHED_DESTINATIONS_MAX {
            return false;
        }
        let router = &mut self.interfaces;
        router.watched = [[0; 16]; WATCHED_DESTINATIONS_MAX];
        router.watched[..destinations.len()].copy_from_slice(destinations);
        router.watched_len = destinations.len() as u8;
        true
    }
    pub fn watched_destinations(&self) -> &[Hash16] {
        self.interfaces.watched_destinations()
    }
    pub fn set_local_plain_sink(&mut self, destination: Option<Hash16>) {
        self.interfaces.plain_sink = destination;
    }
    pub fn local_plain_sink(&self) -> Option<Hash16> {
        self.interfaces.plain_sink
    }

    pub fn register_interface(&mut self, interface: InterfaceConfig) -> Result<(), ConfigError> {
        interface.validate(self.config.table_caps.tx_queue_depth)?;
        let generation = self
            .interfaces
            .last_generation
            .checked_add(1)
            .ok_or(ConfigError::InterfaceGenerationExhausted)?;
        self.interfaces.registry.register(interface)?;
        let slot = self
            .interfaces
            .registry
            .slot(interface.id)
            .ok_or(ConfigError::UnknownInterface)?;
        self.interfaces.last_generation = generation;
        self.interfaces.generations[slot] = generation;
        self.interfaces.announce_gates[slot] = crate::announce_cap::AnnounceGate::OPEN;
        self.announce_schedule.clear_target(slot);
        self.discoveries.retire_requester(slot);
        Ok(())
    }

    pub fn unregister_interface(
        &mut self,
        id: InterfaceId,
    ) -> Result<InterfaceConfig, ConfigError> {
        let slot = self
            .interfaces
            .registry
            .slot(id)
            .ok_or(ConfigError::UnknownInterface)?;
        if self.interfaces.registry.len() == 1 {
            return Err(ConfigError::CannotRemoveLastInterface);
        }
        let removed = self.interfaces.registry.unregister(id)?;
        self.retire_router_interface(id, slot);
        Ok(removed)
    }

    pub fn set_interface_online(
        &mut self,
        id: InterfaceId,
        online: bool,
    ) -> Result<(), ConfigError> {
        let slot = self
            .interfaces
            .registry
            .slot(id)
            .ok_or(ConfigError::UnknownInterface)?;
        let was_online = self.interfaces.registry.get(id).is_some_and(|i| i.online);
        if online && !was_online {
            let generation = self
                .interfaces
                .last_generation
                .checked_add(1)
                .ok_or(ConfigError::InterfaceGenerationExhausted)?;
            self.interfaces.last_generation = generation;
            self.interfaces.generations[slot] = generation;
        }
        self.interfaces.registry.set_online(id, online)?;
        if !online {
            self.retire_router_interface(id, slot);
        }
        Ok(())
    }

    pub(super) fn retire_router_interface(&mut self, id: InterfaceId, slot: usize) {
        self.interfaces.generations[slot] = 0;
        self.interfaces.announce_gates[slot] = crate::announce_cap::AnnounceGate::OPEN;
        self.discoveries.retire_requester(slot);
        self.announce_schedule.clear_target(slot);
        self.paths.remove_interface(id);
        self.reverse.remove_interface(id);
        self.links.remove_interface(id);
        self.announce_schedule.remove_interface(id);
        self.announce_cache.retain_paths(&self.paths, self.clock_ms);
        self.expire_outbound(self.clock_ms);
    }

    /// Queue endpoint-owned traffic with the ordinary residence limit. The caller owns
    /// its local Link; it must not depend on a transit-Link table entry.
    pub fn send_local(&mut self, interface: InterfaceId, packet: PacketBuffer) -> bool {
        self.enqueue_with_lifetime(
            interface,
            packet,
            OutboundReason::Local,
            OutboundLifetime {
                enqueued_ms: self.clock_ms,
                expires_ms: self.clock_ms.saturating_add(OUTBOUND_MAX_AGE_MS),
                path: 0,
                state: OutboundState::Independent,
            },
        )
    }

    pub fn router_outbound_is_live(
        &self,
        interface: InterfaceId,
        lifetime: OutboundLifetime,
        target_generation: u64,
        now_ms: u64,
    ) -> bool {
        self.interfaces
            .delivery_is_current(interface, target_generation)
            && self.outbound_lifetime_is_live(interface, lifetime, now_ms)
    }

    pub fn poll_tx_for_interface(&mut self, id: InterfaceId) -> Option<RouterOutboundFrame> {
        self.expire_outbound(self.clock_ms);
        let offset = self.interface_frame_offset(id)?;
        let queued = self.outbound.remove(offset)?;
        Some(RouterOutboundFrame {
            frame: queued.frame,
            target_generation: queued.delivery,
        })
    }
    pub(super) fn interface_frame_offset(&self, id: InterfaceId) -> Option<usize> {
        self.outbound
            .iter()
            .position(|q| q.frame.interface_id == id && !q.frame.reason.gated())
            .or_else(|| {
                self.outbound
                    .iter()
                    .position(|q| q.frame.interface_id == id)
            })
    }
    pub fn outbound_peek_for_interface(&self, id: InterfaceId) -> Option<(usize, OutboundReason)> {
        let offset = self.interface_frame_offset(id)?;
        self.outbound
            .iter()
            .nth(offset)
            .map(|q| (q.frame.packet.len(), q.frame.reason))
    }
    pub fn outbound_peek_len_for_interface(&self, id: InterfaceId) -> Option<usize> {
        self.outbound_peek_for_interface(id).map(|(len, _)| len)
    }
    pub fn outbound_len_for_interface(&self, id: InterfaceId) -> usize {
        self.outbound
            .iter()
            .filter(|q| q.frame.interface_id == id)
            .count()
    }
}

impl<
    const P: usize,
    const H: usize,
    const A: usize,
    const R: usize,
    const L: usize,
    const T: usize,
    const O: usize,
    const K: usize,
    const S: usize,
    M: Model,
> LiteNode<P, H, A, R, L, T, O, K, S, M>
{
    pub(super) fn router_ingress(
        &mut self,
        interface: InterfaceId,
        wire_len: usize,
    ) -> Result<bool, TransportError> {
        let Some(router) = self.interfaces.router_mut() else {
            return Ok(true);
        };
        let error = match router.registry.get(interface) {
            None => Some(TransportError::UnknownInterface),
            Some(i) if !i.online => Some(TransportError::InterfaceOffline),
            Some(i) if !i.direction.inbound => Some(TransportError::InterfaceNotInbound),
            Some(i) if wire_len > i.wire_mtu() => {
                router.stats.mtu_dropped = router.stats.mtu_dropped.saturating_add(1);
                self.stats.dropped = self.stats.dropped.saturating_add(1);
                return Ok(false);
            }
            _ => None,
        };
        if let Some(error) = error {
            router.stats.interface_dropped = router.stats.interface_dropped.saturating_add(1);
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            Err(error)
        } else {
            Ok(true)
        }
    }

    pub(super) fn is_local_client_interface(&self, interface: InterfaceId) -> bool {
        self.interfaces
            .slot(interface)
            .is_some_and(|slot| self.interfaces.facts(slot).flags & 8 != 0)
    }

    pub(super) fn enqueue_forwarded(
        &mut self,
        source: InterfaceId,
        target: InterfaceId,
        packet: PacketBuffer,
        reason: OutboundReason,
    ) -> bool {
        let lifetime = self.packet_lifetime(&packet, reason);
        self.enqueue_forwarded_with_lifetime(source, target, packet, reason, lifetime)
    }
    pub(super) fn enqueue_forwarded_with_lifetime(
        &mut self,
        source: InterfaceId,
        target: InterfaceId,
        packet: PacketBuffer,
        reason: OutboundReason,
        lifetime: OutboundLifetime,
    ) -> bool {
        if let Some(router) = self.interfaces.router_mut() {
            let Some(interface) = router.interface(target) else {
                router.stats.interface_dropped = router.stats.interface_dropped.saturating_add(1);
                return false;
            };
            if source == target && !interface.direction.repeat {
                router.stats.reflection_dropped = router.stats.reflection_dropped.saturating_add(1);
                return false;
            }
            if source != target && !interface.direction.forward {
                router.stats.interface_dropped = router.stats.interface_dropped.saturating_add(1);
                return false;
            }
        }
        self.enqueue_with_lifetime(target, packet, reason, lifetime)
    }

    pub(super) fn enqueue_packet_broadcast_with_lifetime(
        &mut self,
        source: InterfaceId,
        packet: PacketBuffer,
        reason: OutboundReason,
        local_only: bool,
        lifetime: OutboundLifetime,
    ) -> usize {
        if !M::ROUTER {
            return usize::from(self.enqueue_with_lifetime(source, packet, reason, lifetime));
        }
        let mut queued = 0;
        for slot in 0..REQUESTERS {
            let target = self
                .interfaces
                .router()
                .and_then(|r| r.registry.at_slot(slot))
                .copied();
            if let Some(target) = target {
                if !local_only || target.role == InterfaceRole::LocalClient {
                    queued += usize::from(self.enqueue_forwarded_with_lifetime(
                        source, target.id, packet, reason, lifetime,
                    ));
                }
            }
        }
        queued
    }
    pub(super) fn enqueue_packet_broadcast(
        &mut self,
        source: InterfaceId,
        packet: PacketBuffer,
        reason: OutboundReason,
        local_only: bool,
    ) -> usize {
        let mut lifetime = self.packet_lifetime(&packet, reason);
        if reason == OutboundReason::PathRequestForward {
            lifetime.expires_ms = lifetime
                .expires_ms
                .min(self.clock_ms.saturating_add(REQUEST_GATE_MS));
        }
        self.enqueue_packet_broadcast_with_lifetime(source, packet, reason, local_only, lifetime)
    }

    pub(super) fn reserve_router_queue(&mut self, id: InterfaceId, reason: OutboundReason) -> bool {
        let Some(router) = self.interfaces.router() else {
            return true;
        };
        let Some(interface) = router.interface(id) else {
            return false;
        };
        if !interface.online || !interface.direction.outbound {
            return false;
        }
        let queued = self
            .outbound
            .iter()
            .filter(|q| q.frame.interface_id == id)
            .count();
        if queued >= interface.tx_queue_depth {
            let offset = self
                .outbound
                .iter()
                .position(|q| q.frame.interface_id == id && q.frame.reason.gated())
                .or_else(|| {
                    if reason.gated() {
                        None
                    } else {
                        self.outbound
                            .iter()
                            .position(|q| q.frame.interface_id == id)
                    }
                });
            let Some(offset) = offset else {
                return false;
            };
            self.outbound.remove(offset);
            self.stats.outbound_dropped = self.stats.outbound_dropped.saturating_add(1);
        } else if self.outbound.len() >= self.config.table_caps.tx_queue_depth.min(O) {
            return false;
        }
        true
    }

    pub(super) fn egress_error(&self, id: InterfaceId, packet_len: usize) -> TransportError {
        if let Some(router) = self.interfaces.router() {
            let Some(interface) = router.interface(id) else {
                return TransportError::UnknownInterface;
            };
            if !interface.online {
                return TransportError::InterfaceOffline;
            }
            if !interface.direction.outbound {
                return TransportError::InterfaceNotOutbound;
            }
        }
        if packet_len > self.interface_clear_mtu(id) {
            TransportError::MtuExceeded
        } else {
            TransportError::Backpressure
        }
    }

    pub(super) fn announce_targets(&self, source: InterfaceId) -> u8 {
        let Some(router) = self.interfaces.router() else {
            return 0;
        };
        let Some(source) = router.interface(source) else {
            return 0;
        };
        (0..REQUESTERS)
            .filter(|&slot| {
                router
                    .registry
                    .at_slot(slot)
                    .is_some_and(|target| announce_egress_allowed(source, *target))
            })
            .fold(0, |targets, slot| targets | (1 << slot))
    }

    pub(super) fn release_gated_announces(&mut self, now_ms: u64) {
        if !M::ROUTER {
            return;
        }
        for slot in 0..REQUESTERS {
            let Some(router) = self.interfaces.router() else {
                return;
            };
            let Some(target) = router.registry.at_slot(slot).copied() else {
                continue;
            };
            if !router.announce_gates[slot].is_open(now_ms)
                || self
                    .outbound
                    .iter()
                    .any(|q| q.frame.interface_id == target.id && q.frame.reason.gated())
            {
                continue;
            }
            while let Some(announce) = self.announce_schedule.release_pending(slot, now_ms) {
                if !self.announce_current(&announce, now_ms) {
                    self.announce_schedule.remove(&announce.destination_hash);
                    continue;
                }
                let wire_len =
                    announce.packet.len() + target.ifac.map_or(0, |i| usize::from(i.size));
                if self.enqueue_forwarded(
                    announce.interface_id,
                    target.id,
                    announce.packet,
                    OutboundReason::AnnounceRebroadcast,
                ) {
                    let router = self.interfaces.router_mut().expect("router model");
                    let spacing = match (target.role, router.lora_modem) {
                        (InterfaceRole::LoRa, Some(modem)) => {
                            lora_spacing_ms(wire_len, modem, target.announce_cap_permille)
                        }
                        _ => bitrate_spacing_ms(
                            wire_len,
                            target.bitrate_bps,
                            target.announce_cap_permille,
                        )
                        .unwrap_or(0),
                    };
                    router.stats.announces_released =
                        router.stats.announces_released.saturating_add(1);
                    router.announce_gates[slot].charge(now_ms, spacing);
                }
                break;
            }
        }
    }

    pub(super) fn announce_current(&self, announce: &ScheduledAnnounce, now_ms: u64) -> bool {
        self.paths
            .get_live(&announce.destination_hash, now_ms)
            .is_some_and(|path| {
                PacketView::parse(announce.packet.as_slice()).is_ok_and(|view| {
                    packet_hash(announce.packet.as_slice(), view.header.flags.header_type)
                        == path.packet_hash
                })
            })
    }

    pub(super) fn bridge_plain_broadcast(
        &mut self,
        raw: &[u8],
        header: PacketHeader,
        source: InterfaceId,
    ) -> Result<IngestAction, TransportError> {
        if !M::ROUTER {
            return Ok(IngestAction::Dropped);
        }
        let packet = PacketBuffer::from_slice(raw)?.copy_with_hops(header.hops);
        let local_only = !self.is_local_client_interface(source);
        Ok(
            if self.enqueue_packet_broadcast(
                source,
                packet,
                OutboundReason::TransportForward,
                local_only,
            ) > 0
            {
                IngestAction::ForwardedTransport
            } else {
                IngestAction::Dropped
            },
        )
    }
}

fn announce_egress_allowed(source: InterfaceConfig, target: InterfaceConfig) -> bool {
    if !target.online || !target.direction.outbound {
        return false;
    }
    if source.id == target.id {
        if !target.direction.repeat {
            return false;
        }
    } else if !target.direction.forward {
        return false;
    }
    if target.role == InterfaceRole::LocalClient {
        return true;
    }
    match target.mode {
        InterfaceMode::AccessPoint => false,
        InterfaceMode::Internal => source.mode != InterfaceMode::Boundary,
        InterfaceMode::Roaming => !matches!(
            source.mode,
            InterfaceMode::Roaming | InterfaceMode::Boundary
        ),
        InterfaceMode::Boundary => source.mode != InterfaceMode::Roaming,
        InterfaceMode::Full | InterfaceMode::PointToPoint | InterfaceMode::Gateway => true,
    }
}

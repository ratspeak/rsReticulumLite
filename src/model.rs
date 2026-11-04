//! Compile-time transport storage and interface policy.
//!
//! Protocol parsing, discovery, route and proof handling remain in `LiteNode`.
//! Models select interface ownership and outbound delivery metadata without
//! charging an endpoint for a router's registry or per-interface queues.

use crate::announce_cap::AnnounceGate;
use crate::config::{IfacConfig, InterfaceConfig, InterfaceRegistry, InterfaceRole, LiteConfig};
use crate::discovery::REQUESTERS;
use crate::lora::LoraModemConfig;
use crate::tables::InterfaceId;
use crate::transport::{InterfaceFacts, OutboundDelivery, RxMeta};

mod sealed {
    pub trait Sealed {}
}

/// Model storage used by [`crate::LiteNode`].
/// Sealed to the two built-in models so interface and delivery policies cannot disagree.
pub trait Model: sealed::Sealed + Clone + core::fmt::Debug + PartialEq + Eq {
    type Delivery: Copy + core::fmt::Debug + PartialEq + Eq;
    const EMPTY: Self;
    const ROUTER: bool;
    fn delivery(&self, identity: u64, interface: InterfaceId) -> Self::Delivery;
    fn delivery_is_current(&self, interface: InterfaceId, delivery: Self::Delivery) -> bool;
    fn facts(&self, slot: usize) -> InterfaceFacts;
    fn slot(&self, id: InterfaceId) -> Option<usize> {
        (0..REQUESTERS).find(|&slot| {
            let facts = self.facts(slot);
            facts.flags & 1 != 0 && facts.id == id
        })
    }
    fn observe(&mut self, meta: RxMeta, config: &LiteConfig, clear_mtu: usize);
    fn ifac(&self, id: InterfaceId, config: &LiteConfig) -> Option<IfacConfig>;
    fn online(&self, id: InterfaceId) -> bool;
    fn router(&self) -> Option<&Router> {
        None
    }
    fn router_mut(&mut self) -> Option<&mut Router> {
        None
    }
}

/// Host-owned endpoint interfaces and retained fan-out delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    #[doc(hidden)]
    pub facts: [InterfaceFacts; REQUESTERS],
}
impl sealed::Sealed for Endpoint {}

impl Model for Endpoint {
    type Delivery = OutboundDelivery;
    const EMPTY: Self = Self {
        facts: [InterfaceFacts::EMPTY; REQUESTERS],
    };
    const ROUTER: bool = false;

    fn delivery(&self, identity: u64, _interface: InterfaceId) -> Self::Delivery {
        OutboundDelivery {
            identity,
            interface_generations: [0; 7],
            pending_targets: 0x7f,
            initialized: false,
        }
    }

    fn delivery_is_current(&self, _interface: InterfaceId, _delivery: Self::Delivery) -> bool {
        true
    }

    fn facts(&self, slot: usize) -> InterfaceFacts {
        self.facts[slot]
    }

    fn observe(&mut self, meta: RxMeta, config: &LiteConfig, clear_mtu: usize) {
        if let Some(slot) = self.slot(meta.interface_id) {
            if self.facts[slot].flags & 4 == 0 {
                self.facts[slot].mode = meta.interface_mode.unwrap_or(config.mode);
            }
        } else if let Some(slot) = self.facts.iter().position(|facts| facts.flags & 1 == 0) {
            self.facts[slot] = InterfaceFacts {
                id: meta.interface_id,
                generation: 1,
                mode: meta.interface_mode.unwrap_or(config.mode),
                bitrate_bps: 0,
                clear_mtu: clear_mtu as u16,
                flags: 1 | 2,
            };
        }
    }

    fn ifac(&self, _id: InterfaceId, config: &LiteConfig) -> Option<IfacConfig> {
        config.ifac
    }

    fn online(&self, _id: InterfaceId) -> bool {
        true
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Additional counters only stored by routers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouterStats {
    pub interface_dropped: u64,
    pub mtu_dropped: u64,
    pub reflection_dropped: u64,
    pub announces_released: u64,
    pub bulk_paths_learned: u64,
    pub bulk_paths_refused: u64,
}

/// Explicit multi-interface router storage. Endpoint nodes do not contain this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Router {
    pub(crate) registry: InterfaceRegistry,
    pub(crate) generations: [u64; REQUESTERS],
    pub(crate) last_generation: u64,
    pub(crate) announce_gates: [AnnounceGate; REQUESTERS],
    pub(crate) lora_modem: Option<LoraModemConfig>,
    pub(crate) plain_sink: Option<[u8; 16]>,
    pub(crate) stats: RouterStats,
}
impl sealed::Sealed for Router {}

impl Router {
    pub const fn new(registry: InterfaceRegistry, lora_modem: Option<LoraModemConfig>) -> Self {
        Self {
            registry,
            generations: [1; REQUESTERS],
            last_generation: 1,
            announce_gates: [AnnounceGate::OPEN; REQUESTERS],
            lora_modem,
            plain_sink: None,
            stats: RouterStats {
                interface_dropped: 0,
                mtu_dropped: 0,
                reflection_dropped: 0,
                announces_released: 0,
                bulk_paths_learned: 0,
                bulk_paths_refused: 0,
            },
        }
    }

    pub fn interface(&self, id: InterfaceId) -> Option<InterfaceConfig> {
        self.registry.get(id).copied()
    }

    pub fn generation(&self, id: InterfaceId) -> u64 {
        self.registry
            .slot(id)
            .map_or(0, |slot| self.generations[slot])
    }
}

impl Model for Router {
    type Delivery = u64;
    const EMPTY: Self = Self::new(InterfaceRegistry::new(), None);
    const ROUTER: bool = true;
    fn delivery(&self, _identity: u64, interface: InterfaceId) -> Self::Delivery {
        self.generation(interface)
    }
    fn delivery_is_current(&self, interface: InterfaceId, delivery: Self::Delivery) -> bool {
        delivery != 0 && self.generation(interface) == delivery
    }
    fn facts(&self, slot: usize) -> InterfaceFacts {
        let Some(interface) = self.registry.at_slot(slot) else {
            return InterfaceFacts::EMPTY;
        };
        InterfaceFacts {
            generation: 1,
            bitrate_bps: interface.bitrate_bps.min(u64::from(u32::MAX)) as u32,
            clear_mtu: interface.clear_mtu() as u16,
            id: interface.id,
            mode: interface.mode,
            flags: 1
                | 4
                | if interface.online && interface.direction.outbound {
                    2
                } else {
                    0
                }
                | if interface.role == InterfaceRole::LocalClient {
                    8
                } else {
                    0
                },
        }
    }
    fn observe(&mut self, _meta: RxMeta, _config: &LiteConfig, _clear_mtu: usize) {}
    fn ifac(&self, id: InterfaceId, _config: &LiteConfig) -> Option<IfacConfig> {
        self.registry.get(id).and_then(|interface| interface.ifac)
    }
    fn online(&self, id: InterfaceId) -> bool {
        self.registry
            .get(id)
            .is_some_and(|interface| interface.online && interface.direction.outbound)
    }
    fn router(&self) -> Option<&Router> {
        Some(self)
    }
    fn router_mut(&mut self) -> Option<&mut Router> {
        Some(self)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::EMPTY
    }
}

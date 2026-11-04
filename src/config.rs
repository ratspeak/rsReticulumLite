use crate::announce_admission::AnnounceAdmissionConfig;
use crate::announce_cap::ANNOUNCE_CAP_PERMILLE;
use crate::constants::{LORA_SPLIT_FRAME_PAYLOAD_MAX, MDU, MTU};
use crate::identity::MAX_ANNOUNCE_APP_DATA;
use crate::ifac::{IFAC_KEY_LENGTH, IFAC_LORA_DEFAULT_SIZE};
use crate::tables::InterfaceId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceMode {
    Full,
    PointToPoint,
    Internal,
    AccessPoint,
    Gateway,
    Roaming,
    Boundary,
}

/// Transport-level purpose of an interface.
///
/// `Normal` and `LocalClient` are deliberately distinct. An accepted TCP-server peer is an
/// ordinary network interface, while a local client is a zero-hop peer sharing this Transport
/// instance. The wire framing may be identical, but their routing semantics are not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceRole {
    LoRa,
    Backbone,
    Normal,
    LocalClient,
}

/// Directional capabilities used before routing work is queued.
///
/// `repeat` is the explicit exception to reflection suppression. It is useful for a deliberately
/// configured same-medium repeater, but ordinary multi-interface routing leaves it disabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceDirection {
    pub inbound: bool,
    pub outbound: bool,
    pub forward: bool,
    pub repeat: bool,
}

impl InterfaceDirection {
    pub const BIDIRECTIONAL: Self = Self {
        inbound: true,
        outbound: true,
        forward: true,
        repeat: false,
    };

    pub const REPEATER: Self = Self {
        repeat: true,
        ..Self::BIDIRECTIONAL
    };

    pub const INBOUND_ONLY: Self = Self {
        inbound: true,
        outbound: false,
        forward: false,
        repeat: false,
    };

    pub const OUTBOUND_ONLY: Self = Self {
        inbound: false,
        outbound: true,
        forward: true,
        repeat: false,
    };

    const fn validate(self) -> Result<(), ConfigError> {
        if !self.inbound && !self.outbound {
            return Err(ConfigError::InterfaceHasNoDirection);
        }
        if (self.forward || self.repeat) && !self.outbound {
            return Err(ConfigError::InvalidInterfaceDirection);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableCaps {
    pub path_entries: usize,
    pub announce_entries: usize,
    pub reverse_entries: usize,
    pub link_entries: usize,
    pub packet_hashes: usize,
    pub recent_announces: usize,
    pub path_request_tags: usize,
    pub random_blobs_per_path: usize,
    pub queued_announces_per_interface: usize,
    pub tx_queue_depth: usize,
}

impl TableCaps {
    pub const ESP32_LORA_TRANSPORT_PSRAM: Self = Self {
        path_entries: 1024,
        announce_entries: 128,
        reverse_entries: 128,
        link_entries: 64,
        packet_hashes: 2048,
        recent_announces: 512,
        path_request_tags: 256,
        random_blobs_per_path: 32,
        queued_announces_per_interface: 64,
        tx_queue_depth: 8,
    };

    pub const ESP32_LORA_TRANSPORT_SMALL: Self = Self {
        path_entries: 256,
        announce_entries: 64,
        reverse_entries: 64,
        link_entries: 32,
        packet_hashes: 512,
        recent_announces: 128,
        path_request_tags: 64,
        random_blobs_per_path: 16,
        queued_announces_per_interface: 24,
        tx_queue_depth: 4,
    };

    /// Capacity preset paired with [`crate::MicroNode`]: 48 paths, 64 packet
    /// hashes, eight queued announces and path-request tags, and TX depth four.
    /// This does not measure a device's free memory. `recent_announces` and
    /// `random_blobs_per_path` are retained fields with no `LiteNode` consumer.
    pub const ESP32_LORA_TRANSPORT_MICRO: Self = Self {
        path_entries: 48,
        announce_entries: 8,
        reverse_entries: 8,
        link_entries: 4,
        packet_hashes: 64,
        recent_announces: 16,
        path_request_tags: 8,
        random_blobs_per_path: 8,
        queued_announces_per_interface: 8,
        tx_queue_depth: 4,
    };

    pub const fn validate(self) -> Result<(), ConfigError> {
        if self.path_entries == 0 {
            return Err(ConfigError::EmptyPathTable);
        }
        if self.packet_hashes == 0 {
            return Err(ConfigError::EmptyHashTable);
        }
        if self.tx_queue_depth == 0 {
            return Err(ConfigError::EmptyTxQueue);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IfacConfig {
    pub key: [u8; IFAC_KEY_LENGTH],
    pub size: u8,
}

impl core::fmt::Debug for IfacConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IfacConfig")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl IfacConfig {
    pub const fn lora_default(key: [u8; IFAC_KEY_LENGTH]) -> Self {
        Self {
            key,
            size: IFAC_LORA_DEFAULT_SIZE,
        }
    }

    pub const fn validate(self) -> Result<(), ConfigError> {
        if self.size == 0 || self.size as usize > 64 {
            return Err(ConfigError::InvalidIfacSize);
        }
        Ok(())
    }
}

/// Maximum number of independently owned router interfaces.
pub const MAX_INTERFACES: usize = 8;

/// Fixed-capacity description of one Reticulum interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceConfig {
    pub id: InterfaceId,
    pub role: InterfaceRole,
    pub mode: InterfaceMode,
    pub direction: InterfaceDirection,
    /// Plain Reticulum packet MTU, before any interface access-code bytes.
    pub mtu: usize,
    /// Nominal interface bitrate used for link proof timeout accounting.
    pub bitrate_bps: u64,
    pub ifac: Option<IfacConfig>,
    pub online: bool,
    /// Maximum number of frames this interface may occupy in the shared bounded TX queue.
    pub tx_queue_depth: usize,
    /// Target share for the announce release gate, in permille of estimated
    /// interface airtime. Zero is floored to 0.1%; this is not a duty-cycle measurement.
    pub announce_cap_permille: u16,
    /// Paths learned from unsolicited announces here are bulk: an uplink to a busy hub must not
    /// churn the paths LoRa and local peers depend on.
    pub bulk_paths: bool,
}

impl InterfaceConfig {
    pub const fn lora(id: InterfaceId, bitrate_bps: u64, tx_queue_depth: usize) -> Self {
        Self {
            id,
            role: InterfaceRole::LoRa,
            mode: InterfaceMode::Gateway,
            direction: InterfaceDirection::BIDIRECTIONAL,
            mtu: MTU,
            bitrate_bps,
            ifac: None,
            online: true,
            tx_queue_depth,
            announce_cap_permille: ANNOUNCE_CAP_PERMILLE,
            bulk_paths: false,
        }
    }

    /// One-medium relay profile. Unlike [`Self::lora`], this explicitly permits transmitting a
    /// forwarded frame back onto the receiving interface.
    pub const fn lora_repeater(id: InterfaceId, bitrate_bps: u64, tx_queue_depth: usize) -> Self {
        Self {
            direction: InterfaceDirection::REPEATER,
            ..Self::lora(id, bitrate_bps, tx_queue_depth)
        }
    }

    pub const fn backbone(id: InterfaceId, bitrate_bps: u64, tx_queue_depth: usize) -> Self {
        Self {
            id,
            role: InterfaceRole::Backbone,
            mode: InterfaceMode::Boundary,
            direction: InterfaceDirection::BIDIRECTIONAL,
            mtu: MTU,
            bitrate_bps,
            ifac: None,
            online: true,
            tx_queue_depth,
            announce_cap_permille: ANNOUNCE_CAP_PERMILLE,
            bulk_paths: true,
        }
    }

    pub const fn local_client(id: InterfaceId, bitrate_bps: u64, tx_queue_depth: usize) -> Self {
        Self {
            id,
            role: InterfaceRole::LocalClient,
            mode: InterfaceMode::Internal,
            direction: InterfaceDirection::BIDIRECTIONAL,
            mtu: MTU,
            bitrate_bps,
            ifac: None,
            online: true,
            tx_queue_depth,
            announce_cap_permille: ANNOUNCE_CAP_PERMILLE,
            bulk_paths: false,
        }
    }

    /// Network-facing peer accepted by a Reticulum TCP server. Access-point
    /// mode learns client paths and discovers unknown paths without granting
    /// the zero-hop/shared-instance privileges of a local client.
    pub const fn access_point(id: InterfaceId, bitrate_bps: u64, tx_queue_depth: usize) -> Self {
        Self {
            id,
            role: InterfaceRole::Normal,
            mode: InterfaceMode::AccessPoint,
            direction: InterfaceDirection::BIDIRECTIONAL,
            mtu: MTU,
            bitrate_bps,
            ifac: None,
            online: true,
            tx_queue_depth,
            announce_cap_permille: ANNOUNCE_CAP_PERMILLE,
            bulk_paths: false,
        }
    }

    /// Network-peer descriptor using Gateway mode. Its egress mode permits
    /// announces from other interface modes, subject to direction, availability,
    /// queue and admission limits. Like AccessPoint mode, it can discover unknown
    /// paths on a peer's behalf without local-client privileges.
    pub const fn network_peer(id: InterfaceId, bitrate_bps: u64, tx_queue_depth: usize) -> Self {
        Self {
            mode: InterfaceMode::Gateway,
            ..Self::access_point(id, bitrate_bps, tx_queue_depth)
        }
    }

    /// Effective clear-packet MTU after applying this interface's wire limit.
    ///
    /// This core uses a 500-byte protocol MTU. Its TCP framing can carry a full
    /// clear packet plus any supported IFAC tag. LoRa framing is limited to
    /// 508 wire bytes, so an IFAC tag larger than eight bytes reduces the clear
    /// limit. This helper does not validate the descriptor.
    pub const fn clear_mtu(self) -> usize {
        let physical_clear_mtu = match (self.role, self.ifac) {
            (InterfaceRole::LoRa, Some(ifac)) => {
                LORA_SPLIT_FRAME_PAYLOAD_MAX.saturating_sub(ifac.size as usize)
            }
            (InterfaceRole::LoRa, None) => LORA_SPLIT_FRAME_PAYLOAD_MAX,
            _ => self.mtu,
        };
        if self.mtu < physical_clear_mtu {
            self.mtu
        } else {
            physical_clear_mtu
        }
    }

    /// Whether the effective clear-packet capacity is at least 500 bytes.
    /// This is a size check, not an online-state or hardware qualification check.
    pub const fn supports_general_links(self) -> bool {
        self.clear_mtu() >= MTU
    }

    /// Maximum complete wire packet accepted by this interface, including an
    /// IFAC tag when configured.
    pub const fn wire_mtu(self) -> usize {
        self.clear_mtu().saturating_add(match self.ifac {
            Some(ifac) => ifac.size as usize,
            None => 0,
        })
    }

    #[allow(clippy::collapsible_if, clippy::question_mark)]
    pub const fn validate(&self, total_queue_depth: usize) -> Result<(), ConfigError> {
        if let Some(ifac) = self.ifac {
            if let Err(error) = ifac.validate() {
                return Err(error);
            }
        }
        if self.mtu < crate::constants::HEADER_MINSIZE || self.mtu > MTU {
            return Err(ConfigError::InvalidInterfaceMtu);
        }
        if self.tx_queue_depth == 0 || self.tx_queue_depth > total_queue_depth {
            return Err(ConfigError::InvalidInterfaceQueueDepth);
        }
        self.direction.validate()
    }
}

/// Small, allocation-free interface registry with stable caller-supplied IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceRegistry {
    entries: [Option<InterfaceConfig>; MAX_INTERFACES],
}

impl InterfaceRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_INTERFACES],
        }
    }

    /// Const-friendly constructor for firmware static configuration. Validation still happens in
    /// [`InterfaceRegistry::validate`] / `LiteNode::new_router`.
    pub const fn from_array(entries: [Option<InterfaceConfig>; MAX_INTERFACES]) -> Self {
        Self { entries }
    }

    pub const fn len(&self) -> usize {
        let mut count = 0;
        let mut idx = 0;
        while idx < MAX_INTERFACES {
            if self.entries[idx].is_some() {
                count += 1;
            }
            idx += 1;
        }
        count
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn slot(&self, id: InterfaceId) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|interface| interface.id == id))
    }

    pub fn get(&self, id: InterfaceId) -> Option<&InterfaceConfig> {
        self.entries
            .iter()
            .flatten()
            .find(|interface| interface.id == id)
    }

    pub fn get_mut(&mut self, id: InterfaceId) -> Option<&mut InterfaceConfig> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|interface| interface.id == id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &InterfaceConfig> {
        self.entries.iter().flatten()
    }

    pub(crate) fn at_slot(&self, slot: usize) -> Option<&InterfaceConfig> {
        self.entries.get(slot).and_then(Option::as_ref)
    }

    /// Insert a descriptor in the first free slot, rejecting duplicate IDs and
    /// a full registry. Existing entries stay in place. This does not validate
    /// the descriptor; use [`InterfaceRegistry::validate`] before applying the registry,
    /// or `LiteNode::register_interface` for a live node.
    pub fn register(&mut self, interface: InterfaceConfig) -> Result<(), ConfigError> {
        if self.get(interface.id).is_some() {
            return Err(ConfigError::DuplicateInterfaceId);
        }
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else {
            return Err(ConfigError::InterfaceRegistryFull);
        };
        *slot = Some(interface);
        Ok(())
    }

    pub fn set_online(&mut self, id: InterfaceId, online: bool) -> Result<(), ConfigError> {
        let Some(interface) = self.get_mut(id) else {
            return Err(ConfigError::UnknownInterface);
        };
        interface.online = online;
        Ok(())
    }

    pub fn unregister(&mut self, id: InterfaceId) -> Result<InterfaceConfig, ConfigError> {
        let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|interface| interface.id == id))
        else {
            return Err(ConfigError::UnknownInterface);
        };
        slot.take().ok_or(ConfigError::UnknownInterface)
    }

    #[allow(clippy::collapsible_if, clippy::question_mark)]
    pub const fn validate(&self, total_queue_depth: usize) -> Result<(), ConfigError> {
        let mut idx = 0;
        while idx < MAX_INTERFACES {
            if let Some(interface) = self.entries[idx] {
                if let Err(error) = interface.validate(total_queue_depth) {
                    return Err(error);
                }
                let mut other_idx = idx + 1;
                while other_idx < MAX_INTERFACES {
                    if let Some(other) = self.entries[other_idx] {
                        if other.id == interface.id {
                            return Err(ConfigError::DuplicateInterfaceId);
                        }
                    }
                    other_idx += 1;
                }
            }
            idx += 1;
        }
        Ok(())
    }
}

impl Default for InterfaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteConfig {
    pub mode: InterfaceMode,
    pub table_caps: TableCaps,
    pub mtu: usize,
    pub mdu: usize,
    pub max_announce_app_data: usize,
    pub transport_enabled: bool,
    pub probe_destination_enabled: bool,
    pub ifac: Option<IfacConfig>,
    pub announce_admission: AnnounceAdmissionConfig,
}

impl LiteConfig {
    pub const ESP32_LORA_TRANSPORT_PSRAM: Self = Self {
        mode: InterfaceMode::Gateway,
        table_caps: TableCaps::ESP32_LORA_TRANSPORT_PSRAM,
        mtu: MTU,
        mdu: MDU,
        // Accept the full single-packet announce app_data (wire max); Reticulum imposes no
        // smaller cap, so a tighter value would black-hole long-display-name announces.
        max_announce_app_data: MAX_ANNOUNCE_APP_DATA,
        transport_enabled: true,
        probe_destination_enabled: true,
        ifac: None,
        announce_admission: AnnounceAdmissionConfig::DISABLED,
    };

    pub const ESP32_LORA_TRANSPORT_SMALL: Self = Self {
        mode: InterfaceMode::Gateway,
        table_caps: TableCaps::ESP32_LORA_TRANSPORT_SMALL,
        mtu: MTU,
        mdu: MDU,
        max_announce_app_data: MAX_ANNOUNCE_APP_DATA,
        transport_enabled: true,
        probe_destination_enabled: true,
        ifac: None,
        announce_admission: AnnounceAdmissionConfig::DISABLED,
    };

    pub const ESP32_LORA_TRANSPORT_MICRO: Self = Self {
        mode: InterfaceMode::Gateway,
        table_caps: TableCaps::ESP32_LORA_TRANSPORT_MICRO,
        mtu: MTU,
        mdu: MDU,
        max_announce_app_data: MAX_ANNOUNCE_APP_DATA,
        transport_enabled: true,
        probe_destination_enabled: true,
        ifac: None,
        announce_admission: AnnounceAdmissionConfig::DISABLED,
    };

    pub const fn validate(self) -> Result<(), ConfigError> {
        if let Some(ifac) = self.ifac {
            if let Err(err) = ifac.validate() {
                return Err(err);
            }
        }
        if self.mtu != MTU {
            return Err(ConfigError::UnsupportedMtu);
        }
        if self.mdu > self.mtu {
            return Err(ConfigError::MduExceedsMtu);
        }
        self.table_caps.validate()
    }
}

impl Default for LiteConfig {
    fn default() -> Self {
        Self::ESP32_LORA_TRANSPORT_SMALL
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    EmptyPathTable,
    EmptyHashTable,
    EmptyTxQueue,
    UnsupportedMtu,
    MduExceedsMtu,
    InvalidIfacSize,
    DuplicateInterfaceId,
    InterfaceRegistryFull,
    UnknownInterface,
    InterfaceHasNoDirection,
    InvalidInterfaceDirection,
    InvalidInterfaceMtu,
    InvalidInterfaceQueueDepth,
    CannotRemoveLastInterface,
    InterfaceGenerationExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifac_config_accepts_valid_lora_default() {
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.ifac = Some(IfacConfig::lora_default([0x42; IFAC_KEY_LENGTH]));

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn ifac_config_rejects_invalid_size() {
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.ifac = Some(IfacConfig {
            key: [0x42; IFAC_KEY_LENGTH],
            size: 0,
        });

        assert_eq!(config.validate(), Err(ConfigError::InvalidIfacSize));
    }

    #[test]
    fn debug_output_never_shows_the_ifac_key() {
        let mut config = LiteConfig::ESP32_LORA_TRANSPORT_SMALL;
        config.ifac = Some(IfacConfig::lora_default([0x42; IFAC_KEY_LENGTH]));
        let text = std::format!("{config:?}");
        assert!(!text.contains("66, 66"), "{text}");
        assert!(text.contains("size: 8"), "{text}");
    }
}

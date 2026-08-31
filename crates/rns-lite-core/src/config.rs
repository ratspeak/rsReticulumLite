use crate::announce_admission::AnnounceAdmissionConfig;
use crate::constants::{MDU, MTU};
use crate::identity::MAX_ANNOUNCE_APP_DATA;
use crate::ifac::{IFAC_KEY_LENGTH, IFAC_LORA_DEFAULT_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceMode {
    Full,
    AccessPoint,
    Gateway,
    Roaming,
    Boundary,
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

    /// Cardputer-class endpoint profile (no PSRAM, ~55 KB free heap): caps mirror the donor
    /// cardputer micro config (KNOWN_DESTINATIONS 48, HASHLIST 32 -> 64 margin,
    /// QUEUED_ANNOUNCES 8, PR_TAGS 8, LoRa TX queue 4). Pairs with [`crate::MicroNode`]
    /// (whole node asserted <= 32 KB). `recent_announces`/`random_blobs_per_path` are
    /// vestigial for `LiteNode` (no const generic consumes them) — documentation values only.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfacConfig {
    pub key: [u8; IFAC_KEY_LENGTH],
    pub size: u8,
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
}

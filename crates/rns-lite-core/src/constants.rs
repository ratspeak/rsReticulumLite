pub const MTU: usize = 500;
pub const HEADER_MINSIZE: usize = 19;
pub const HEADER_MAXSIZE: usize = 35;
pub const MDU: usize = 464;

pub const DESTINATION_LENGTH: usize = 16;
pub const TRANSPORT_ID_LENGTH: usize = 16;
pub const TRUNCATED_HASH_LENGTH: usize = 16;
pub const PACKET_HASH_LENGTH: usize = 32;
pub const NAME_HASH_LENGTH: usize = 10;
pub const RANDOM_HASH_LENGTH: usize = 10;
pub const PUBLIC_KEY_LENGTH: usize = 64;
// Raw Reticulum private key: X25519 private (32) || Ed25519 seed (32). Endpoint role only.
pub const PRIVATE_KEY_LENGTH: usize = 64;
pub const SIGNATURE_LENGTH: usize = 64;

pub const LORA_FRAME_PAYLOAD_MAX: usize = 254;
pub const LORA_SPLIT_FRAME_PAYLOAD_MAX: usize = LORA_FRAME_PAYLOAD_MAX * 2;

// IFAC overhead rides ON TOP of the RNS MTU (upstream RNodeInterface.HW_MTU =
// 508 = 500 + default LoRa ifac size 8); wire buffers must fit the worst case.
pub const WIRE_MTU_MAX: usize = MTU + SIGNATURE_LENGTH;

pub const PATHFINDER_M: u8 = 128;
pub const PATHFINDER_E_SECS: u32 = 604_800;
pub const AP_PATH_TIME_SECS: u32 = 86_400;
pub const ROAMING_PATH_TIME_SECS: u32 = 21_600;
pub const REVERSE_TIMEOUT_SECS: u32 = 480;
pub const LINK_TIMEOUT_SECS: u32 = 900;
// Matches upstream ESTABLISHMENT_TIMEOUT_PER_HOP / DEFAULT_PER_HOP_TIMEOUT (6s).
// (The per-MTU extra_link_proof_timeout term is omitted as a deliberate simplification.)
pub const LINK_PROOF_TIMEOUT_PER_HOP_SECS: u32 = 6;
pub const PATH_REQUEST_TIMEOUT_SECS: u32 = 15;
pub const PATH_REQUEST_DUPLICATE_GATE_SECS: u32 = 120;
pub const QUEUED_ANNOUNCE_LIFE_SECS: u32 = 86_400;
pub const JOB_INTERVAL_MS: u32 = 250;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin protocol constants to their upstream rsReticulum / Python Reticulum values so an
    /// accidental change fails the tests (the audit caught a 10x LINK_PROOF timeout error here).
    #[test]
    fn constants_match_upstream() {
        // Timing
        assert_eq!(LINK_PROOF_TIMEOUT_PER_HOP_SECS, 6); // DEFAULT_PER_HOP_TIMEOUT
        assert_eq!(PATHFINDER_E_SECS, 604_800); // PATHFINDER_E (7d)
        assert_eq!(AP_PATH_TIME_SECS, 86_400); // AP_PATH_TIME (24h)
        assert_eq!(ROAMING_PATH_TIME_SECS, 21_600); // ROAMING_PATH_TIME (6h)
        // Wire lengths
        assert_eq!(MTU, 500);
        assert_eq!(DESTINATION_LENGTH, 16);
        assert_eq!(TRUNCATED_HASH_LENGTH, 16);
        assert_eq!(PACKET_HASH_LENGTH, 32);
        assert_eq!(NAME_HASH_LENGTH, 10);
        assert_eq!(RANDOM_HASH_LENGTH, 10);
        assert_eq!(PUBLIC_KEY_LENGTH, 64);
        assert_eq!(PRIVATE_KEY_LENGTH, 64);
        assert_eq!(SIGNATURE_LENGTH, 64);
    }
}

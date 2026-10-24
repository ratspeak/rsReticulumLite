//! Per-interface announce cap, from trusted rns-transport (`constants.rs` `ANNOUNCE_CAP`,
//! `actor/maintenance.rs` `process_announce_queues`).
//!
//! Releasing a rebroadcast closes its interface's gate for `tx_time / cap`. LoRa cost is the
//! modem airtime of the framed burst, the figure a host's duty limiter charges, instead of
//! trusted's `len * 8 / bitrate`. Hosts with an interface registry keep one [`AnnounceGate`]
//! per interface and release queued announces in [`release_precedes`] order.

use crate::constants::LORA_FRAME_PAYLOAD_MAX;
use crate::lora::LoraModemConfig;

/// Trusted `ANNOUNCE_CAP` (2 %), in permille.
pub const ANNOUNCE_CAP_PERMILLE: u16 = 20;

/// A zero cap is floored at 0.1 %, as trusted floors `announce_cap` at 0.001.
const fn cap_floor(cap_permille: u16) -> u64 {
    if cap_permille == 0 {
        1
    } else {
        cap_permille as u64
    }
}

/// Gate interval after releasing an announce that occupies its interface for `tx_ms`.
pub const fn spacing_ms(tx_ms: u32, cap_permille: u16) -> u64 {
    (tx_ms as u64 * 1000).div_ceil(cap_floor(cap_permille))
}

/// Trusted spacing on a bitrate interface, `len * 8 / bitrate / cap`, in whole milliseconds
/// rounded up. An interface without a bitrate is ungated.
pub const fn bitrate_spacing_ms(
    wire_len: usize,
    bitrate_bps: u64,
    cap_permille: u16,
) -> Option<u64> {
    if bitrate_bps == 0 {
        return None;
    }
    let scaled_bits = (wire_len as u64).saturating_mul(8_000_000);
    Some(scaled_bits.div_ceil(bitrate_bps.saturating_mul(cap_floor(cap_permille))))
}

/// LoRa spacing from the modem airtime of the framed burst.
pub fn lora_spacing_ms(wire_len: usize, modem: LoraModemConfig, cap_permille: u16) -> u64 {
    spacing_ms(lora_tx_ms(wire_len, modem), cap_permille)
}

/// Airtime of one packet as `LoraFramer` sends it: one frame up to 254 bytes, else two, each
/// with its one-byte header.
pub fn lora_tx_ms(wire_len: usize, modem: LoraModemConfig) -> u32 {
    if wire_len <= LORA_FRAME_PAYLOAD_MAX {
        modem.frame_airtime_ms(wire_len + 1)
    } else {
        modem
            .frame_airtime_ms(LORA_FRAME_PAYLOAD_MAX + 1)
            .saturating_add(modem.frame_airtime_ms(wire_len - LORA_FRAME_PAYLOAD_MAX + 1))
    }
}

/// Trusted release order: fewest hops first, then the longest queued.
pub const fn release_precedes(
    hops: u8,
    queued_ms: u64,
    other_hops: u8,
    other_queued_ms: u64,
) -> bool {
    hops < other_hops || (hops == other_hops && queued_ms < other_queued_ms)
}

/// One interface's announce gate, closed until `allowed_at_ms`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnnounceGate {
    pub allowed_at_ms: u64,
}

impl AnnounceGate {
    pub const OPEN: Self = Self { allowed_at_ms: 0 };

    pub const fn is_open(self, now_ms: u64) -> bool {
        now_ms >= self.allowed_at_ms
    }

    /// Close the gate for `spacing_ms` after a release.
    pub fn charge(&mut self, now_ms: u64, spacing_ms: u64) {
        self.allowed_at_ms = now_ms.saturating_add(spacing_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEDIUM_FAST: LoraModemConfig = LoraModemConfig {
        bandwidth_hz: 250_000,
        spreading_factor: 9,
        coding_rate_denominator: 5,
        preamble_symbols: 18,
        explicit_header: true,
        crc: true,
        low_data_rate_optimize: false,
    };

    #[test]
    fn spacing_is_trusted_tx_time_over_cap() {
        assert_eq!(spacing_ms(595, ANNOUNCE_CAP_PERMILLE), 29_750);
        assert_eq!(spacing_ms(1, ANNOUNCE_CAP_PERMILLE), 50);
        assert_eq!(spacing_ms(1, 1000), 1);
        assert_eq!(spacing_ms(7, 3), 2_334);
        assert_eq!(spacing_ms(1, 0), 1000);
        assert_eq!(spacing_ms(u32::MAX, 1), u32::MAX as u64 * 1000);
    }

    #[test]
    fn bitrate_spacing_is_trusted_len_over_bitrate_over_cap() {
        assert_eq!(bitrate_spacing_ms(231, 0, ANNOUNCE_CAP_PERMILLE), None);
        assert_eq!(
            bitrate_spacing_ms(231, 10_000_000, ANNOUNCE_CAP_PERMILLE),
            Some(10)
        );
        assert_eq!(
            bitrate_spacing_ms(231, 3_515, ANNOUNCE_CAP_PERMILLE),
            Some(26_288)
        );
        assert_eq!(bitrate_spacing_ms(250, 1_000, 1000), Some(2_000));
        assert_eq!(bitrate_spacing_ms(1, 1, 0), Some(8_000_000));
        assert_eq!(bitrate_spacing_ms(usize::MAX, 1, 1), Some(u64::MAX));
    }

    #[test]
    fn lora_cost_follows_the_framer_split() {
        let one = MEDIUM_FAST.frame_airtime_ms(232);
        assert_eq!(lora_tx_ms(231, MEDIUM_FAST), one);
        assert_eq!(one, 595);
        assert_eq!(
            lora_spacing_ms(231, MEDIUM_FAST, ANNOUNCE_CAP_PERMILLE),
            29_750
        );
        assert_eq!(
            lora_tx_ms(LORA_FRAME_PAYLOAD_MAX, MEDIUM_FAST),
            MEDIUM_FAST.frame_airtime_ms(LORA_FRAME_PAYLOAD_MAX + 1)
        );
        assert_eq!(
            lora_tx_ms(500, MEDIUM_FAST),
            MEDIUM_FAST.frame_airtime_ms(255) + MEDIUM_FAST.frame_airtime_ms(247)
        );
    }

    #[test]
    fn release_order_is_fewest_hops_then_oldest() {
        assert!(release_precedes(1, 900, 2, 100));
        assert!(release_precedes(2, 100, 2, 900));
        assert!(!release_precedes(2, 900, 2, 100));
        assert!(!release_precedes(2, 100, 2, 100));
        assert!(!release_precedes(3, 0, 2, 900));
    }

    #[test]
    fn gate_closes_for_the_spacing_after_a_release() {
        let mut gate = AnnounceGate::OPEN;
        assert!(gate.is_open(0));
        gate.charge(1_000, spacing_ms(595, ANNOUNCE_CAP_PERMILLE));
        assert!(!gate.is_open(30_749));
        assert!(gate.is_open(30_750));
        gate.charge(u64::MAX - 1, 29_750);
        assert_eq!(gate.allowed_at_ms, u64::MAX);
    }
}

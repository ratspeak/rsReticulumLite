use crate::constants::{LORA_FRAME_PAYLOAD_MAX, LORA_SPLIT_FRAME_PAYLOAD_MAX};
use crate::packet_buffer::{BufferError, PacketBuffer};

const LORA_FRAME_MAX: usize = LORA_FRAME_PAYLOAD_MAX + 1;
const SPLIT_FLAG: u8 = 0x01;
const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoraFrame {
    bytes: [u8; LORA_FRAME_MAX],
    len: usize,
}

impl LoraFrame {
    pub const fn new() -> Self {
        Self {
            bytes: [0; LORA_FRAME_MAX],
            len: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn set(&mut self, header: u8, payload: &[u8]) -> Result<(), LoraError> {
        if payload.len() > LORA_FRAME_PAYLOAD_MAX {
            return Err(LoraError::FrameTooLarge);
        }
        self.bytes[0] = header;
        self.bytes[1..1 + payload.len()].copy_from_slice(payload);
        self.len = payload.len() + 1;
        Ok(())
    }
}

impl Default for LoraFrame {
    fn default() -> Self {
        Self::new()
    }
}

/// Buffer for one reassembled RNode packet, up to 508 bytes: a 500-byte
/// Reticulum packet plus the default eight-byte IFAC tag. A packet over 254
/// bytes is carried in two physical LoRa frames, each with its own framing byte.
pub type LoraPacketBuffer = PacketBuffer<LORA_SPLIT_FRAME_PAYLOAD_MAX>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingSplit {
    sequence: u8,
    first: LoraPacketBuffer,
    expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoraFramer {
    pending: Option<PendingSplit>,
    split_timeout_ms: u64,
}

impl LoraFramer {
    pub const fn new(split_timeout_ms: u64) -> Self {
        Self {
            pending: None,
            split_timeout_ms,
        }
    }

    /// Split up to 508 packet bytes into one or two frames with at most 254
    /// payload bytes each. Uses the low four bits of `sequence_nibble` and returns
    /// the frame count; unused output entries are unchanged. The caller sends
    /// the frames in order and chooses sequence values for successive packets.
    pub fn encode(
        packet: &[u8],
        sequence_nibble: u8,
        out: &mut [LoraFrame; 2],
    ) -> Result<usize, LoraError> {
        if packet.len() > LORA_SPLIT_FRAME_PAYLOAD_MAX {
            return Err(LoraError::PacketTooLarge);
        }
        let sequence = (sequence_nibble & 0x0F) << 4;
        if packet.len() <= LORA_FRAME_PAYLOAD_MAX {
            out[0].set(sequence, packet)?;
            Ok(1)
        } else {
            out[0].set(sequence | SPLIT_FLAG, &packet[..LORA_FRAME_PAYLOAD_MAX])?;
            out[1].set(sequence | SPLIT_FLAG, &packet[LORA_FRAME_PAYLOAD_MAX..])?;
            Ok(2)
        }
    }

    /// Reassemble caller-supplied physical frames using one pending split slot.
    /// The caller checks physical frame size/CRC and supplies monotonic time.
    /// Two split frames with the same four-bit sequence are concatenated in arrival
    /// order; there is no first/second marker or duplicate check. A different split
    /// sequence replaces the pending half; an unsplit frame clears it. The helper
    /// only bounds the final 508-byte buffer, so validate the recovered packet.
    pub fn ingest_frame(
        &mut self,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Option<LoraPacketBuffer>, LoraError> {
        self.expire(now_ms);
        if frame.is_empty() {
            return Err(LoraError::FrameTooShort);
        }

        let header = frame[0];
        let sequence = header >> 4;
        let split = (header & SPLIT_FLAG) != 0;
        let payload = &frame[1..];

        if !split {
            self.pending = None;
            return LoraPacketBuffer::from_slice(payload)
                .map(Some)
                .map_err(LoraError::Buffer);
        }

        if let Some(pending) = self.pending.take() {
            if pending.sequence == sequence {
                let mut packet = pending.first;
                packet
                    .extend_from_slice(payload)
                    .map_err(LoraError::Buffer)?;
                return Ok(Some(packet));
            }
        }

        let first = LoraPacketBuffer::from_slice(payload).map_err(LoraError::Buffer)?;
        self.pending = Some(PendingSplit {
            sequence,
            first,
            expires_ms: now_ms.saturating_add(self.split_timeout_ms),
        });
        Ok(None)
    }

    pub fn expire(&mut self, now_ms: u64) {
        if self
            .pending
            .is_some_and(|pending| now_ms >= pending.expires_ms)
        {
            self.pending = None;
        }
    }
}

impl Default for LoraFramer {
    fn default() -> Self {
        Self::new(5000)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoraError {
    PacketTooLarge,
    FrameTooLarge,
    FrameTooShort,
    Buffer(BufferError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoraModemConfig {
    pub bandwidth_hz: u32,
    pub spreading_factor: u8,
    pub coding_rate_denominator: u8,
    pub preamble_symbols: u16,
    pub explicit_header: bool,
    pub crc: bool,
    pub low_data_rate_optimize: bool,
}

impl LoraModemConfig {
    pub const HELTEC_V3_LONG_FAST: Self = Self {
        bandwidth_hz: 250_000,
        spreading_factor: 11,
        coding_rate_denominator: 5,
        preamble_symbols: 18,
        explicit_header: true,
        crc: true,
        low_data_rate_optimize: false,
    };

    /// Estimate nominal bitrate as `sf * 4 * bandwidth / (cr * 2^sf)` using
    /// integer arithmetic. Zero inputs or an out-of-range shift return zero.
    /// This does not validate a radio profile or measure throughput.
    pub fn nominal_bitrate_bps(self) -> u64 {
        if self.bandwidth_hz == 0 || self.spreading_factor == 0 || self.coding_rate_denominator == 0
        {
            return 0;
        }
        let Some(chips_per_symbol) = 1u64.checked_shl(self.spreading_factor.into()) else {
            return 0;
        };
        u64::from(self.spreading_factor)
            .saturating_mul(4)
            .saturating_mul(u64::from(self.bandwidth_hz))
            / (u64::from(self.coding_rate_denominator).saturating_mul(chips_per_symbol))
    }

    /// Estimate one physical frame's airtime in milliseconds, rounding up.
    /// Supply valid radio settings and a frame length no greater than 255 bytes,
    /// including the framing byte. This helper does not validate the full radio
    /// parameter domain; zero bandwidth or an unusable symbol denominator returns
    /// zero. Sum both frame estimates for a split packet.
    pub fn frame_airtime_ms(self, frame_len: usize) -> u32 {
        if self.bandwidth_hz == 0 || self.spreading_factor == 0 {
            return 0;
        }

        let sf = self.spreading_factor as i32;
        let ldro = i32::from(self.low_data_rate_optimize);
        let denominator = 4 * (sf - 2 * ldro);
        if denominator <= 0 {
            return 0;
        }

        let symbol_us = ceil_div_u64(
            (1u64 << self.spreading_factor.min(31)) * 1_000_000,
            self.bandwidth_hz as u64,
        );
        let crc_bits = if self.crc { 16 } else { 0 };
        let implicit_header_bits = if self.explicit_header { 0 } else { 20 };
        let numerator = (8 * frame_len as i32) - (4 * sf) + 28 + crc_bits - implicit_header_bits;
        let coded_payload_symbols = if numerator <= 0 {
            0
        } else {
            let coding_rate = self.coding_rate_denominator.clamp(5, 8) as u64;
            ceil_div_u64(numerator as u64, denominator as u64) * coding_rate
        };
        let payload_symbols = 8 + coded_payload_symbols;
        let preamble_symbols_x100 = self.preamble_symbols as u64 * 100 + 425;
        let total_symbols_x100 = preamble_symbols_x100 + payload_symbols * 100;
        ceil_div_u64(total_symbols_x100 * symbol_us, 100_000) as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AirtimeLimiter {
    window_ms: u64,
    max_utilization_bps: u16,
    window_start_ms: u64,
    used_airtime_ms: u64,
}

impl AirtimeLimiter {
    /// Create a fixed-window airtime counter. Utilization is in basis points
    /// (10,000 means 100%); input is not clamped. An empty window may admit an
    /// over-budget frame; once charged, it blocks further positive reservations until reset.
    /// A zero-length window resets usage on every check. The caller supplies
    /// monotonic time, estimated airtime and the actual transmission schedule.
    pub const fn new(window_ms: u64, max_utilization_bps: u16) -> Self {
        Self {
            window_ms,
            max_utilization_bps,
            window_start_ms: 0,
            used_airtime_ms: 0,
        }
    }

    pub const fn window_ms(&self) -> u64 {
        self.window_ms
    }
    pub const fn max_utilization_bps(&self) -> u16 {
        self.max_utilization_bps
    }

    /// Check admission after refreshing the window; this does not charge airtime.
    /// Zero airtime always passes. Window expiry or a clock value before the
    /// current window start clears usage, so callers must provide a consistent clock.
    pub fn can_reserve(&mut self, airtime_ms: u32, now_ms: u64) -> bool {
        self.refresh(now_ms);
        let airtime_ms = airtime_ms as u64;
        if airtime_ms == 0 {
            return true;
        }
        let budget = self.budget_ms().max(1);
        self.used_airtime_ms.saturating_add(airtime_ms) <= budget
            || (self.used_airtime_ms == 0 && airtime_ms > budget)
    }

    /// Charge the supplied airtime if the current window admits it.
    /// Success updates local accounting only; it does not transmit or reserve the radio.
    pub fn reserve(&mut self, airtime_ms: u32, now_ms: u64) -> bool {
        if !self.can_reserve(airtime_ms, now_ms) {
            return false;
        }
        self.used_airtime_ms = self.used_airtime_ms.saturating_add(airtime_ms as u64);
        true
    }

    pub fn utilization_bps(&mut self, now_ms: u64) -> u16 {
        self.refresh(now_ms);
        if self.window_ms == 0 {
            return 0;
        }
        let value = self
            .used_airtime_ms
            .saturating_mul(BASIS_POINTS_DENOMINATOR)
            / self.window_ms;
        value.min(u16::MAX as u64) as u16
    }

    pub fn used_airtime_ms(&mut self, now_ms: u64) -> u64 {
        self.refresh(now_ms);
        self.used_airtime_ms
    }

    pub fn wait_ms(&mut self, airtime_ms: u32, now_ms: u64) -> u64 {
        if self.can_reserve(airtime_ms, now_ms) {
            return 0;
        }
        self.window_start_ms
            .saturating_add(self.window_ms)
            .saturating_sub(now_ms)
    }

    fn refresh(&mut self, now_ms: u64) {
        if self.window_ms == 0 || now_ms < self.window_start_ms {
            self.window_start_ms = now_ms;
            self.used_airtime_ms = 0;
            return;
        }
        if now_ms.saturating_sub(self.window_start_ms) >= self.window_ms {
            self.window_start_ms = now_ms;
            self.used_airtime_ms = 0;
        }
    }

    fn budget_ms(self) -> u64 {
        self.window_ms
            .saturating_mul(self.max_utilization_bps as u64)
            / BASIS_POINTS_DENOMINATOR
    }
}

fn ceil_div_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_add(denominator - 1) / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MTU;

    #[test]
    fn single_frame_roundtrip() {
        let packet = [0xA5; 32];
        let mut frames = [LoraFrame::new(), LoraFrame::new()];
        let count = LoraFramer::encode(&packet, 0x03, &mut frames).unwrap();
        assert_eq!(count, 1);

        let mut framer = LoraFramer::default();
        let decoded = framer
            .ingest_frame(frames[0].as_slice(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.as_slice(), packet);
    }

    #[test]
    fn split_frame_roundtrip_for_reticulum_mtu() {
        let packet = [0x5A; MTU];
        let mut frames = [LoraFrame::new(), LoraFrame::new()];
        let count = LoraFramer::encode(&packet, 0x0A, &mut frames).unwrap();
        assert_eq!(count, 2);

        let mut framer = LoraFramer::default();
        assert!(
            framer
                .ingest_frame(frames[0].as_slice(), 0)
                .unwrap()
                .is_none()
        );
        let decoded = framer
            .ingest_frame(frames[1].as_slice(), 10)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.as_slice(), packet);
    }

    #[test]
    fn split_timeout_discards_first_half() {
        let packet = [0x11; MTU];
        let mut frames = [LoraFrame::new(), LoraFrame::new()];
        LoraFramer::encode(&packet, 0x01, &mut frames).unwrap();

        let mut framer = LoraFramer::new(5);
        assert!(
            framer
                .ingest_frame(frames[0].as_slice(), 0)
                .unwrap()
                .is_none()
        );
        assert!(
            framer
                .ingest_frame(frames[1].as_slice(), 10)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn long_fast_airtime_matches_known_frame_sizes() {
        let modem = LoraModemConfig::HELTEC_V3_LONG_FAST;

        assert_eq!(modem.nominal_bitrate_bps(), 1_074);
        assert_eq!(modem.frame_airtime_ms(52), 658);
        assert_eq!(modem.frame_airtime_ms(84), 904);
        assert_eq!(modem.frame_airtime_ms(192), 1682);
        assert_eq!(modem.frame_airtime_ms(255), 2173);
    }

    #[test]
    fn airtime_limiter_blocks_until_window_resets() {
        let mut limiter = AirtimeLimiter::new(60_000, 2_500);

        assert!(limiter.reserve(10_000, 0));
        assert!(limiter.reserve(5_000, 1000));
        assert!(!limiter.reserve(1, 2000));
        assert_eq!(limiter.wait_ms(1, 2000), 58_000);
        assert_eq!(limiter.utilization_bps(2000), 2_500);

        assert!(limiter.reserve(1, 60_000));
        assert_eq!(limiter.used_airtime_ms(60_000), 1);
    }

    #[test]
    fn airtime_limiter_allows_oversized_frame_in_empty_window() {
        let mut limiter = AirtimeLimiter::new(1_000, 100);

        assert!(limiter.reserve(2_000, 0));
        assert!(!limiter.reserve(1, 1));
    }

    #[test]
    fn full_mtu_ifac_packet_roundtrips_over_lora_frames() {
        use crate::ifac::{IFAC_LORA_DEFAULT_SIZE, ifac_sign_into, ifac_verify_into};
        use crate::packet_buffer::WireBuffer;

        let mut clear = [0x5A; MTU];
        clear[0] = 0x00;
        clear[1] = 0x01;
        let key = [0x73; 64];
        let mut wrapped = WireBuffer::new();
        ifac_sign_into(&clear, &key, IFAC_LORA_DEFAULT_SIZE, &mut wrapped).unwrap();
        assert_eq!(wrapped.len(), LORA_SPLIT_FRAME_PAYLOAD_MAX);

        let mut frames = [LoraFrame::new(), LoraFrame::new()];
        assert_eq!(
            LoraFramer::encode(wrapped.as_slice(), 0x0A, &mut frames).unwrap(),
            2
        );

        let mut framer = LoraFramer::default();
        assert!(
            framer
                .ingest_frame(frames[0].as_slice(), 0)
                .unwrap()
                .is_none()
        );
        let decoded = framer
            .ingest_frame(frames[1].as_slice(), 10)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.as_slice(), wrapped.as_slice());

        let mut verified = PacketBuffer::new();
        ifac_verify_into(
            decoded.as_slice(),
            &key,
            IFAC_LORA_DEFAULT_SIZE,
            &mut verified,
        )
        .unwrap();
        assert_eq!(verified.as_slice(), clear);
    }
}

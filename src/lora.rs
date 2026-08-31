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

/// Complete bytes carried by one RNode LoRa transmission. This is deliberately
/// larger than the 500-byte clear Reticulum MTU: the default 8-byte IFAC tag
/// rides on top of a full-MTU packet, yielding the RNode `HW_MTU` of 508.
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
    pub const fn new(window_ms: u64, max_utilization_bps: u16) -> Self {
        Self {
            window_ms,
            max_utilization_bps,
            window_start_ms: 0,
            used_airtime_ms: 0,
        }
    }

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierSenseConfig {
    pub difs_ms: u32,
    pub slot_ms: u32,
    pub cw_min_slots: u8,
    pub cw_max_slots: u8,
}

impl CarrierSenseConfig {
    pub const HELTEC_V3_LONG_FAST: Self = Self {
        difs_ms: 48,
        slot_ms: 24,
        cw_min_slots: 0,
        cw_max_slots: 15,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediumObservation {
    Free,
    BusyRssi,
    BusyCad,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierSenseDeferReason {
    MediumRssi,
    MediumCad,
    Difs,
    Contention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierSenseDecision {
    Ready,
    Defer {
        reason: CarrierSenseDeferReason,
        wait_ms: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierSenseState {
    Idle,
    Difs { started_ms: u64 },
    Contention { started_ms: u64, wait_ms: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierSenseBackoff {
    config: CarrierSenseConfig,
    state: CarrierSenseState,
}

impl CarrierSenseBackoff {
    pub const fn new(config: CarrierSenseConfig) -> Self {
        Self {
            config,
            state: CarrierSenseState::Idle,
        }
    }

    pub const fn config(&self) -> CarrierSenseConfig {
        self.config
    }

    pub fn reset(&mut self) {
        self.state = CarrierSenseState::Idle;
    }

    pub fn poll(
        &mut self,
        now_ms: u64,
        observation: MediumObservation,
        random: u8,
    ) -> CarrierSenseDecision {
        match observation {
            MediumObservation::BusyRssi => {
                return self.defer_busy(CarrierSenseDeferReason::MediumRssi);
            }
            MediumObservation::BusyCad => {
                return self.defer_busy(CarrierSenseDeferReason::MediumCad);
            }
            MediumObservation::Free => {}
        }

        match self.state {
            CarrierSenseState::Idle => {
                self.state = CarrierSenseState::Difs { started_ms: now_ms };
                CarrierSenseDecision::Defer {
                    reason: CarrierSenseDeferReason::Difs,
                    wait_ms: self.config.difs_ms,
                }
            }
            CarrierSenseState::Difs { started_ms } => {
                let elapsed = elapsed_u32(now_ms, started_ms);
                if elapsed < self.config.difs_ms {
                    return CarrierSenseDecision::Defer {
                        reason: CarrierSenseDeferReason::Difs,
                        wait_ms: self.config.difs_ms - elapsed,
                    };
                }

                let wait_ms = self.contention_wait_ms(random);
                if wait_ms == 0 {
                    self.state = CarrierSenseState::Idle;
                    CarrierSenseDecision::Ready
                } else {
                    self.state = CarrierSenseState::Contention {
                        started_ms: now_ms,
                        wait_ms,
                    };
                    CarrierSenseDecision::Defer {
                        reason: CarrierSenseDeferReason::Contention,
                        wait_ms,
                    }
                }
            }
            CarrierSenseState::Contention {
                started_ms,
                wait_ms,
            } => {
                let elapsed = elapsed_u32(now_ms, started_ms);
                if elapsed < wait_ms {
                    CarrierSenseDecision::Defer {
                        reason: CarrierSenseDeferReason::Contention,
                        wait_ms: wait_ms - elapsed,
                    }
                } else {
                    self.state = CarrierSenseState::Idle;
                    CarrierSenseDecision::Ready
                }
            }
        }
    }

    fn defer_busy(&mut self, reason: CarrierSenseDeferReason) -> CarrierSenseDecision {
        self.state = CarrierSenseState::Idle;
        CarrierSenseDecision::Defer {
            reason,
            wait_ms: self.config.difs_ms,
        }
    }

    fn contention_wait_ms(self, random: u8) -> u32 {
        let min = self.config.cw_min_slots.min(self.config.cw_max_slots);
        let max = self.config.cw_min_slots.max(self.config.cw_max_slots);
        // u16: min==0 / max==255 must not wrap the span to 0 (mod-by-zero panics).
        let span = (max as u16 - min as u16) + 1;
        let slots = min as u16 + (random as u16 % span);
        slots as u32 * self.config.slot_ms
    }
}

fn elapsed_u32(now_ms: u64, started_ms: u64) -> u32 {
    now_ms.saturating_sub(started_ms).min(u32::MAX as u64) as u32
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
    fn carrier_sense_busy_resets_wait() {
        let mut backoff = CarrierSenseBackoff::new(CarrierSenseConfig::HELTEC_V3_LONG_FAST);

        assert_eq!(
            backoff.poll(0, MediumObservation::Free, 4),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::Difs,
                wait_ms: 48,
            }
        );
        assert_eq!(
            backoff.poll(24, MediumObservation::BusyRssi, 4),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::MediumRssi,
                wait_ms: 48,
            }
        );
        assert_eq!(
            backoff.poll(25, MediumObservation::Free, 4),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::Difs,
                wait_ms: 48,
            }
        );
    }

    #[test]
    fn carrier_sense_waits_difs_then_deterministic_contention() {
        let mut backoff = CarrierSenseBackoff::new(CarrierSenseConfig::HELTEC_V3_LONG_FAST);

        assert!(matches!(
            backoff.poll(100, MediumObservation::Free, 3),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::Difs,
                wait_ms: 48,
            }
        ));
        assert_eq!(
            backoff.poll(148, MediumObservation::Free, 3),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::Contention,
                wait_ms: 72,
            }
        );
        assert_eq!(
            backoff.poll(184, MediumObservation::Free, 99),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::Contention,
                wait_ms: 36,
            }
        );
        assert_eq!(
            backoff.poll(220, MediumObservation::Free, 99),
            CarrierSenseDecision::Ready
        );
    }

    #[test]
    fn carrier_sense_zero_contention_slot_can_send_after_difs() {
        let mut backoff = CarrierSenseBackoff::new(CarrierSenseConfig::HELTEC_V3_LONG_FAST);

        assert!(matches!(
            backoff.poll(0, MediumObservation::Free, 0),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::Difs,
                wait_ms: 48,
            }
        ));
        assert_eq!(
            backoff.poll(48, MediumObservation::Free, 0),
            CarrierSenseDecision::Ready
        );
    }

    #[test]
    fn carrier_sense_cad_busy_defers_medium() {
        let mut backoff = CarrierSenseBackoff::new(CarrierSenseConfig::HELTEC_V3_LONG_FAST);

        assert_eq!(
            backoff.poll(0, MediumObservation::BusyCad, 0),
            CarrierSenseDecision::Defer {
                reason: CarrierSenseDeferReason::MediumCad,
                wait_ms: 48,
            }
        );
    }

    #[test]
    fn carrier_sense_contention_simulation_staggers_two_nodes() {
        let mut a = CarrierSenseBackoff::new(CarrierSenseConfig::HELTEC_V3_LONG_FAST);
        let mut b = CarrierSenseBackoff::new(CarrierSenseConfig::HELTEC_V3_LONG_FAST);

        let mut ready_a = None;
        let mut ready_b = None;

        for now in (0..=500).step_by(24) {
            if ready_a.is_none()
                && a.poll(now, MediumObservation::Free, 2) == CarrierSenseDecision::Ready
            {
                ready_a = Some(now);
            }
            if ready_b.is_none()
                && b.poll(now, MediumObservation::Free, 7) == CarrierSenseDecision::Ready
            {
                ready_b = Some(now);
            }
        }

        assert_eq!(ready_a, Some(96));
        assert_eq!(ready_b, Some(216));
        assert_ne!(ready_a, ready_b);
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

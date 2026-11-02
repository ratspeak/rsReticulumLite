//! Durable ordering state for locally-created announces.
//!
//! Track the unsigned 40-bit ordering value carried in `random_hash[5..10]`.
//! The host supplies wall time or restores the logical value and owns durable
//! storage. Ratchet rotation and expiry are separate caller responsibilities.

/// Largest value representable by the announce wire field.
pub const ANNOUNCE_TIME_MAX: u64 = (1u64 << 40) - 1;

/// Exact serialized size of [`AnnounceWireState`]:
/// `version(1) | flags(1) | last_value(5 BE)`.
pub const ANNOUNCE_WIRE_STATE_BLOB_LEN: usize = 7;

const ANNOUNCE_WIRE_STATE_VERSION: u8 = 1;
const HAS_LAST_VALUE: u8 = 0x01;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnounceWireError {
    /// The stored bytes are malformed, truncated, or from another version.
    InvalidBlob,
    /// The caller's output buffer cannot hold the fixed-size state.
    OutputTooSmall,
    /// The requested wall value or logical increment exceeds the 40-bit range.
    Exhausted,
    /// The candidate has no value or does not advance the live ordering value.
    StaleCandidate,
}

/// Monotonically increasing announce ordering state for caller-owned storage.
///
/// A supplied wall value is used verbatim; same/backward values coalesce.
/// Without wall time, the first value is zero and later values increment by one.
/// Persist each prepared value before committing it or emitting its announce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnounceWireState {
    last_value: Option<u64>,
}

impl AnnounceWireState {
    pub const fn new() -> Self {
        Self { last_value: None }
    }

    pub const fn last_value(&self) -> Option<u64> {
        self.last_value
    }

    /// Plan the next wire value without mutating live state.
    ///
    /// `Some(_)` uses caller-supplied wall seconds. `None` selects the restored
    /// logical sequence. `Ok(None)` means the supplied wall value does not exceed
    /// the last value; the caller must coalesce or defer.
    pub fn prepare_next(&self, wall_secs: Option<u64>) -> Result<Option<Self>, AnnounceWireError> {
        let next = match wall_secs {
            Some(now) => {
                if now > ANNOUNCE_TIME_MAX {
                    return Err(AnnounceWireError::Exhausted);
                }
                if self.last_value.is_some_and(|last| now <= last) {
                    return Ok(None);
                }
                now
            }
            None => match self.last_value {
                Some(last) => last
                    .checked_add(1)
                    .filter(|value| *value <= ANNOUNCE_TIME_MAX)
                    .ok_or(AnnounceWireError::Exhausted)?,
                None => 0,
            },
        };

        Ok(Some(Self {
            last_value: Some(next),
        }))
    }

    /// Commit a candidate only after its serialized bytes have been durably
    /// stored by the host. This checks that the value advances; it cannot verify
    /// persistence or that the candidate was prepared from this instance.
    pub fn commit_prepared(&mut self, prepared: Self) -> Result<u64, AnnounceWireError> {
        let next = prepared
            .last_value
            .ok_or(AnnounceWireError::StaleCandidate)?;
        if self.last_value.is_some_and(|last| next <= last) {
            return Err(AnnounceWireError::StaleCandidate);
        }
        self.last_value = Some(next);
        Ok(next)
    }

    pub fn serialize_into(&self, out: &mut [u8]) -> Result<usize, AnnounceWireError> {
        if out.len() < ANNOUNCE_WIRE_STATE_BLOB_LEN {
            return Err(AnnounceWireError::OutputTooSmall);
        }
        out[0] = ANNOUNCE_WIRE_STATE_VERSION;
        out[1] = if self.last_value.is_some() {
            HAS_LAST_VALUE
        } else {
            0
        };
        let value = self.last_value.unwrap_or(0);
        if value > ANNOUNCE_TIME_MAX {
            return Err(AnnounceWireError::InvalidBlob);
        }
        out[2..7].copy_from_slice(&value.to_be_bytes()[3..]);
        Ok(ANNOUNCE_WIRE_STATE_BLOB_LEN)
    }

    pub fn deserialize(blob: &[u8]) -> Result<Self, AnnounceWireError> {
        if blob.len() != ANNOUNCE_WIRE_STATE_BLOB_LEN
            || blob[0] != ANNOUNCE_WIRE_STATE_VERSION
            || blob[1] & !HAS_LAST_VALUE != 0
        {
            return Err(AnnounceWireError::InvalidBlob);
        }
        let mut encoded = [0u8; 8];
        encoded[3..].copy_from_slice(&blob[2..7]);
        let value = u64::from_be_bytes(encoded);
        let last_value = if blob[1] & HAS_LAST_VALUE != 0 {
            Some(value)
        } else {
            if value != 0 {
                return Err(AnnounceWireError::InvalidBlob);
            }
            None
        };
        Ok(Self { last_value })
    }
}

impl Default for AnnounceWireState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clock_never_moves_wire_time_into_the_future() {
        let mut live = AnnounceWireState::new();
        let prepared = live.prepare_next(Some(100)).unwrap().unwrap();
        assert_eq!(live.last_value(), None, "preparation is non-mutating");
        assert_eq!(live.commit_prepared(prepared).unwrap(), 100);
        assert_eq!(live.prepare_next(Some(100)).unwrap(), None);
        assert_eq!(live.prepare_next(Some(99)).unwrap(), None);

        let prepared = live.prepare_next(Some(101)).unwrap().unwrap();
        assert_eq!(prepared.last_value(), Some(101));
    }

    #[test]
    fn clockless_fallback_is_durable_and_strictly_monotonic() {
        let live = AnnounceWireState::new();
        let first = live.prepare_next(None).unwrap().unwrap();
        assert_eq!(first.last_value(), Some(0));

        let mut blob = [0u8; ANNOUNCE_WIRE_STATE_BLOB_LEN];
        first.serialize_into(&mut blob).unwrap();
        let restored = AnnounceWireState::deserialize(&blob).unwrap();
        let second = restored.prepare_next(None).unwrap().unwrap();
        assert_eq!(second.last_value(), Some(1));

        // A stale persistence completion cannot roll live state back.
        let mut live = second;
        assert_eq!(
            live.commit_prepared(first),
            Err(AnnounceWireError::StaleCandidate)
        );
    }

    #[test]
    fn state_roundtrips_and_rejects_every_shape_error() {
        for state in [
            AnnounceWireState::new(),
            AnnounceWireState {
                last_value: Some(ANNOUNCE_TIME_MAX),
            },
        ] {
            let mut blob = [0u8; ANNOUNCE_WIRE_STATE_BLOB_LEN];
            state.serialize_into(&mut blob).unwrap();
            assert_eq!(AnnounceWireState::deserialize(&blob).unwrap(), state);
        }

        assert!(AnnounceWireState::deserialize(&[0; 6]).is_err());
        let mut bad = [0u8; ANNOUNCE_WIRE_STATE_BLOB_LEN];
        AnnounceWireState::new().serialize_into(&mut bad).unwrap();
        bad[0] = 0xff;
        assert!(AnnounceWireState::deserialize(&bad).is_err());
        bad[0] = ANNOUNCE_WIRE_STATE_VERSION;
        bad[1] = 0x80;
        assert!(AnnounceWireState::deserialize(&bad).is_err());
        bad[1] = 0;
        bad[6] = 1;
        assert!(AnnounceWireState::deserialize(&bad).is_err());
    }

    #[test]
    fn forty_bit_exhaustion_fails_closed() {
        let state = AnnounceWireState {
            last_value: Some(ANNOUNCE_TIME_MAX),
        };
        assert_eq!(state.prepare_next(None), Err(AnnounceWireError::Exhausted));
        assert_eq!(
            state.prepare_next(Some(ANNOUNCE_TIME_MAX + 1)),
            Err(AnnounceWireError::Exhausted)
        );
    }
}

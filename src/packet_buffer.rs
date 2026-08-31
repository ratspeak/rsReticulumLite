use crate::constants::{MTU, WIRE_MTU_MAX};

/// Fixed-capacity packet storage. The default capacity is the RNS MTU (plain
/// packets); [`WireBuffer`] fits IFAC-wrapped frames (MTU + max tag).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketBuffer<const CAP: usize = MTU> {
    bytes: [u8; CAP],
    len: usize,
}

pub type WireBuffer = PacketBuffer<WIRE_MTU_MAX>;

impl<const CAP: usize> PacketBuffer<CAP> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAP],
            len: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, BufferError> {
        let mut out = Self::new();
        out.extend_from_slice(data)?;
        Ok(out)
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    pub fn push(&mut self, byte: u8) -> Result<(), BufferError> {
        if self.len == CAP {
            return Err(BufferError::InsufficientCapacity);
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), BufferError> {
        if self.len + data.len() > CAP {
            return Err(BufferError::InsufficientCapacity);
        }
        self.bytes[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    pub fn set_len(&mut self, len: usize) -> Result<(), BufferError> {
        if len > CAP {
            return Err(BufferError::InsufficientCapacity);
        }
        self.len = len;
        Ok(())
    }

    pub fn copy_with_hops(&self, hops: u8) -> Self {
        let mut out = *self;
        if out.len > 1 {
            out.bytes[1] = hops;
        }
        out
    }
}

impl<const CAP: usize> Default for PacketBuffer<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferError {
    InsufficientCapacity,
}

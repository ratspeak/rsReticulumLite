use sha2::{Digest, Sha256};

use crate::constants::{
    HEADER_MAXSIZE, HEADER_MINSIZE, MTU, PACKET_HASH_LENGTH, TRANSPORT_ID_LENGTH,
};
use crate::packet_buffer::{BufferError, PacketBuffer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    Data = 0x00,
    Announce = 0x01,
    LinkRequest = 0x02,
    Proof = 0x03,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DestinationType {
    Single = 0x00,
    Group = 0x01,
    Plain = 0x02,
    Link = 0x03,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HeaderType {
    Header1 = 0x00,
    Header2 = 0x01,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportType {
    Broadcast = 0x00,
    Transport = 0x01,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketFlags {
    pub header_type: HeaderType,
    pub context_flag: bool,
    pub transport_type: TransportType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
}

impl PacketFlags {
    pub const fn pack(self) -> u8 {
        ((self.header_type as u8) << 6)
            | ((self.context_flag as u8) << 5)
            | ((self.transport_type as u8) << 4)
            | ((self.destination_type as u8) << 2)
            | (self.packet_type as u8)
    }

    pub const fn unpack(byte: u8) -> Self {
        let header_type = if (byte & 0b0100_0000) == 0 {
            HeaderType::Header1
        } else {
            HeaderType::Header2
        };
        let transport_type = if (byte & 0b0001_0000) == 0 {
            TransportType::Broadcast
        } else {
            TransportType::Transport
        };
        let destination_type = match (byte & 0b0000_1100) >> 2 {
            0 => DestinationType::Single,
            1 => DestinationType::Group,
            2 => DestinationType::Plain,
            _ => DestinationType::Link,
        };
        let packet_type = match byte & 0b0000_0011 {
            0 => PacketType::Data,
            1 => PacketType::Announce,
            2 => PacketType::LinkRequest,
            _ => PacketType::Proof,
        };
        Self {
            header_type,
            context_flag: (byte & 0b0010_0000) != 0,
            transport_type,
            destination_type,
            packet_type,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketContext {
    None,
    Resource,
    ResourceAdv,
    ResourceReq,
    ResourceHmu,
    ResourcePrf,
    ResourceIcl,
    ResourceRcl,
    CacheRequest,
    Request,
    Response,
    PathResponse,
    Command,
    CommandStatus,
    Channel,
    Keepalive,
    LinkIdentify,
    LinkClose,
    LinkProof,
    Lrrtt,
    Lrproof,
    Unknown(u8),
}

impl PacketContext {
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::None,
            0x01 => Self::Resource,
            0x02 => Self::ResourceAdv,
            0x03 => Self::ResourceReq,
            0x04 => Self::ResourceHmu,
            0x05 => Self::ResourcePrf,
            0x06 => Self::ResourceIcl,
            0x07 => Self::ResourceRcl,
            0x08 => Self::CacheRequest,
            0x09 => Self::Request,
            0x0A => Self::Response,
            0x0B => Self::PathResponse,
            0x0C => Self::Command,
            0x0D => Self::CommandStatus,
            0x0E => Self::Channel,
            0xFA => Self::Keepalive,
            0xFB => Self::LinkIdentify,
            0xFC => Self::LinkClose,
            0xFD => Self::LinkProof,
            0xFE => Self::Lrrtt,
            0xFF => Self::Lrproof,
            other => Self::Unknown(other),
        }
    }

    pub const fn to_byte(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Resource => 0x01,
            Self::ResourceAdv => 0x02,
            Self::ResourceReq => 0x03,
            Self::ResourceHmu => 0x04,
            Self::ResourcePrf => 0x05,
            Self::ResourceIcl => 0x06,
            Self::ResourceRcl => 0x07,
            Self::CacheRequest => 0x08,
            Self::Request => 0x09,
            Self::Response => 0x0A,
            Self::PathResponse => 0x0B,
            Self::Command => 0x0C,
            Self::CommandStatus => 0x0D,
            Self::Channel => 0x0E,
            Self::Keepalive => 0xFA,
            Self::LinkIdentify => 0xFB,
            Self::LinkClose => 0xFC,
            Self::LinkProof => 0xFD,
            Self::Lrrtt => 0xFE,
            Self::Lrproof => 0xFF,
            Self::Unknown(byte) => byte,
        }
    }

    pub const fn skip_hashlist(self) -> bool {
        matches!(
            self,
            Self::Resource
                | Self::ResourceReq
                | Self::ResourcePrf
                | Self::CacheRequest
                | Self::Channel
                | Self::Keepalive
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    pub flags: PacketFlags,
    pub hops: u8,
    pub transport_id: Option<[u8; TRANSPORT_ID_LENGTH]>,
    pub destination_hash: [u8; TRANSPORT_ID_LENGTH],
    pub context: PacketContext,
}

impl PacketHeader {
    pub const fn size(self) -> usize {
        match self.flags.header_type {
            HeaderType::Header1 => HEADER_MINSIZE,
            HeaderType::Header2 => HEADER_MAXSIZE,
        }
    }

    pub fn parse(raw: &[u8]) -> Result<(Self, usize), WireError> {
        if raw.len() < HEADER_MINSIZE {
            return Err(WireError::TooShort);
        }
        if raw.len() > MTU {
            return Err(WireError::ExceedsMtu);
        }

        let flags = PacketFlags::unpack(raw[0]);
        let hops = raw[1];
        match flags.header_type {
            HeaderType::Header1 => {
                let mut destination_hash = [0u8; TRANSPORT_ID_LENGTH];
                destination_hash.copy_from_slice(&raw[2..18]);
                Ok((
                    Self {
                        flags,
                        hops,
                        transport_id: None,
                        destination_hash,
                        context: PacketContext::from_byte(raw[18]),
                    },
                    HEADER_MINSIZE,
                ))
            }
            HeaderType::Header2 => {
                if raw.len() < HEADER_MAXSIZE {
                    return Err(WireError::TooShort);
                }
                let mut transport_id = [0u8; TRANSPORT_ID_LENGTH];
                transport_id.copy_from_slice(&raw[2..18]);
                let mut destination_hash = [0u8; TRANSPORT_ID_LENGTH];
                destination_hash.copy_from_slice(&raw[18..34]);
                Ok((
                    Self {
                        flags,
                        hops,
                        transport_id: Some(transport_id),
                        destination_hash,
                        context: PacketContext::from_byte(raw[34]),
                    },
                    HEADER_MAXSIZE,
                ))
            }
        }
    }

    pub fn write_into(self, out: &mut PacketBuffer) -> Result<(), BufferError> {
        out.push(self.flags.pack())?;
        out.push(self.hops)?;
        if let Some(transport_id) = self.transport_id {
            out.extend_from_slice(&transport_id)?;
        }
        out.extend_from_slice(&self.destination_hash)?;
        out.push(self.context.to_byte())?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketView<'a> {
    pub header: PacketHeader,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
    pub payload_offset: usize,
}

impl<'a> PacketView<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, WireError> {
        let (header, payload_offset) = PacketHeader::parse(raw)?;
        Ok(Self {
            header,
            payload: &raw[payload_offset..],
            raw,
            payload_offset,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    TooShort,
    ExceedsMtu,
    Buffer(BufferError),
}

impl From<BufferError> for WireError {
    fn from(value: BufferError) -> Self {
        Self::Buffer(value)
    }
}

pub fn sha256(data: &[u8]) -> [u8; PACKET_HASH_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn truncated_hash(data: &[u8]) -> [u8; TRANSPORT_ID_LENGTH] {
    let full = sha256(data);
    let mut out = [0u8; TRANSPORT_ID_LENGTH];
    out.copy_from_slice(&full[..TRANSPORT_ID_LENGTH]);
    out
}

pub fn packet_hash(raw: &[u8], header_type: HeaderType) -> [u8; PACKET_HASH_LENGTH] {
    // Guard the only indexed byte: firmware callers must never be able to
    // panic this pub API on an empty buffer.
    if raw.is_empty() {
        return [0u8; PACKET_HASH_LENGTH];
    }
    let mut hasher = Sha256::new();
    hasher.update([raw[0] & 0x0F]);
    let skip = match header_type {
        HeaderType::Header1 => 2,
        HeaderType::Header2 => 2 + TRANSPORT_ID_LENGTH,
    };
    if raw.len() > skip {
        hasher.update(&raw[skip..]);
    }
    hasher.finalize().into()
}

pub fn truncated_packet_hash(raw: &[u8], header_type: HeaderType) -> [u8; TRANSPORT_ID_LENGTH] {
    let full = packet_hash(raw, header_type);
    let mut out = [0u8; TRANSPORT_ID_LENGTH];
    out.copy_from_slice(&full[..TRANSPORT_ID_LENGTH]);
    out
}

pub fn link_id_from_raw(raw: &[u8], header_type: HeaderType) -> [u8; TRANSPORT_ID_LENGTH] {
    const LINK_REQUEST_KEY_BYTES: usize = 64;
    if raw.is_empty() {
        return [0u8; TRANSPORT_ID_LENGTH];
    }
    let mut hasher = Sha256::new();
    hasher.update([raw[0] & 0x0F]);

    match header_type {
        HeaderType::Header1 => {
            if raw.len() > 2 {
                let header_end = HEADER_MINSIZE.min(raw.len());
                hasher.update(&raw[2..header_end]);
                let payload = &raw[header_end..raw.len()];
                hasher.update(&payload[..payload.len().min(LINK_REQUEST_KEY_BYTES)]);
            }
        }
        HeaderType::Header2 => {
            if raw.len() > 2 + TRANSPORT_ID_LENGTH {
                let dest_start = 2 + TRANSPORT_ID_LENGTH;
                let header_end = HEADER_MAXSIZE.min(raw.len());
                hasher.update(&raw[dest_start..header_end]);
                let payload = &raw[header_end..raw.len()];
                hasher.update(&payload[..payload.len().min(LINK_REQUEST_KEY_BYTES)]);
            }
        }
    }

    let full: [u8; PACKET_HASH_LENGTH] = hasher.finalize().into();
    let mut out = [0u8; TRANSPORT_ID_LENGTH];
    out.copy_from_slice(&full[..TRANSPORT_ID_LENGTH]);
    out
}

pub fn build_packet(header: PacketHeader, payload: &[u8]) -> Result<PacketBuffer, WireError> {
    let mut out = PacketBuffer::new();
    header.write_into(&mut out)?;
    out.extend_from_slice(payload)?;
    Ok(out)
}

pub fn rewrite_with_header(
    raw: &[u8],
    old_header: PacketHeader,
    new_header: PacketHeader,
) -> Result<PacketBuffer, WireError> {
    let payload_offset = old_header.size();
    if raw.len() < payload_offset {
        return Err(WireError::TooShort);
    }
    build_packet(new_header, &raw[payload_offset..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header1() -> PacketHeader {
        PacketHeader {
            flags: PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xAA; 16],
            context: PacketContext::None,
        }
    }

    #[test]
    fn flags_match_reticulum_examples() {
        let announce = PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        };
        assert_eq!(announce.pack(), 0x01);

        let transport = PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        };
        assert_eq!(transport.pack(), 0x50);
    }

    #[test]
    fn header1_roundtrip() {
        let raw = build_packet(header1(), &[1, 2, 3]).unwrap();
        let view = PacketView::parse(raw.as_slice()).unwrap();
        assert_eq!(view.header, header1());
        assert_eq!(view.payload, &[1, 2, 3]);
    }

    #[test]
    fn packet_hash_ignores_hops() {
        let raw = build_packet(header1(), &[1, 2, 3]).unwrap();
        let mut raw2 = raw;
        raw2.as_mut_slice()[1] = 7;
        assert_eq!(
            packet_hash(raw.as_slice(), HeaderType::Header1),
            packet_hash(raw2.as_slice(), HeaderType::Header1)
        );
    }
}

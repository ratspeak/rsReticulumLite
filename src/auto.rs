use core::fmt::{self, Write};
use core::net::Ipv6Addr;

use sha2::{Digest, Sha256};

/// Longest RFC 5952 IPv6 text form, excluding a trailing NUL.
pub const IPV6_TEXT_MAX: usize = 39;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoError {
    OutputTooSmall,
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Write for SliceWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let dst = self.out.get_mut(self.len..end).ok_or(fmt::Error)?;
        dst.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Write the canonical lowercase IPv6 text form used by AutoInterface beacon hashing.
pub fn format_ipv6(address: &[u8; 16], out: &mut [u8]) -> Result<usize, AutoError> {
    let mut writer = SliceWriter { out, len: 0 };
    write!(&mut writer, "{}", Ipv6Addr::from(*address)).map_err(|_| AutoError::OutputTooSmall)?;
    Ok(writer.len)
}

/// Derive Python AutoInterface's default Temporary + Link multicast group.
pub fn multicast_group_for(group_id: &[u8]) -> [u8; 16] {
    let hash: [u8; 32] = Sha256::digest(group_id).into();
    let mut out = [0u8; 16];
    out[0] = 0xff;
    out[1] = 0x12;
    out[4..].copy_from_slice(&hash[2..14]);
    out
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.update(value.as_bytes());
        Ok(())
    }
}

/// Build the AutoInterface beacon token: SHA-256(group_id || canonical IPv6 text).
pub fn beacon_token(group_id: &[u8], address: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(group_id);
    write!(HashWriter(&mut hasher), "{}", Ipv6Addr::from(*address))
        .expect("hash writer is infallible");
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn ipv6_text_matches_trusted_std_formatter() {
        let cases = [
            [0u8; 16],
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1],
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0xaa, 0xff, 0xfe, 0x9a, 0x4c, 0x01, 0x02,
            ],
            [0xff; 16],
        ];

        for address in cases {
            let expected = std::net::Ipv6Addr::from(address).to_string();
            let mut out = [0u8; IPV6_TEXT_MAX];
            let len = format_ipv6(&address, &mut out).unwrap();
            assert_eq!(&out[..len], expected.as_bytes());
        }
    }

    #[test]
    fn ipv6_text_reports_capacity() {
        let address = [0xff; 16];
        assert_eq!(
            format_ipv6(&address, &mut [0u8; IPV6_TEXT_MAX - 1]),
            Err(AutoError::OutputTooSmall)
        );
    }

    #[test]
    fn multicast_and_beacon_match_trusted_auto_construction() {
        let group_id = b"reticulum";
        let group = multicast_group_for(group_id);
        assert_eq!(
            group,
            [
                0xff, 0x12, 0, 0, 0xd7, 0x0b, 0xfb, 0x1c, 0x16, 0xe4, 0x5e, 0x39, 0x48, 0x5e, 0x31,
                0xe1,
            ]
        );

        let address = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut input = group_id.to_vec();
        input.extend_from_slice(std::net::Ipv6Addr::from(address).to_string().as_bytes());
        assert_eq!(
            beacon_token(group_id, &address),
            rns_crypto::sha::sha256(&input)
        );
    }
}

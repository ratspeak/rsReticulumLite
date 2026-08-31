//! Reticulum Interface Access Control (IFAC) for no-std transports.
//!
//! IFAC wraps packets as `[flags|0x80, hops, tag, masked payload...]`. The tag
//! is the trailing bytes of an Ed25519 signature over the original packet, and
//! the mask is HKDF-SHA256 keyed by the tag and full 64-byte IFAC key.

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::constants::{MTU, SIGNATURE_LENGTH, WIRE_MTU_MAX};
use crate::packet_buffer::{BufferError, PacketBuffer, WireBuffer};

pub const IFAC_FLAG: u8 = 0x80;
pub const IFAC_KEY_LENGTH: usize = 64;
pub const IFAC_LORA_DEFAULT_SIZE: u8 = 8;

const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IfacError {
    InvalidSize,
    TooShort,
    MissingFlag,
    ExceedsMtu,
    AuthenticationFailed,
    Hkdf,
    Buffer(BufferError),
}

impl From<BufferError> for IfacError {
    fn from(value: BufferError) -> Self {
        Self::Buffer(value)
    }
}

pub fn derive_ifac_key(
    network_name: Option<&str>,
    passphrase: Option<&str>,
) -> Result<[u8; IFAC_KEY_LENGTH], IfacError> {
    let mut origin = [0u8; 64];
    let mut origin_len = 0;

    if let Some(name) = network_name {
        origin[origin_len..origin_len + 32].copy_from_slice(&sha256(name.as_bytes()));
        origin_len += 32;
    }
    if let Some(passphrase) = passphrase {
        origin[origin_len..origin_len + 32].copy_from_slice(&sha256(passphrase.as_bytes()));
        origin_len += 32;
    }

    let origin_hash = sha256(&origin[..origin_len]);
    let hkdf = Hkdf::<Sha256>::new(Some(&IFAC_SALT), &origin_hash);
    let mut key = [0u8; IFAC_KEY_LENGTH];
    hkdf.expand(&[], &mut key).map_err(|_| IfacError::Hkdf)?;
    Ok(key)
}

pub fn ifac_sign_into(
    packet: &[u8],
    ifac_key: &[u8; IFAC_KEY_LENGTH],
    ifac_size: u8,
    out: &mut WireBuffer,
) -> Result<(), IfacError> {
    let ifac_size = validate_size(ifac_size)?;
    if packet.len() < 2 {
        return Err(IfacError::TooShort);
    }
    // Upstream sizes the wrapped frame at MTU + ifac_size (RNodeInterface
    // HW_MTU 508): the tag rides on top of a full-MTU packet, it does not
    // shrink the usable MTU.
    if packet.len() > MTU {
        return Err(IfacError::ExceedsMtu);
    }
    let wrapped_len = packet.len() + ifac_size;

    let signature = sign_packet(packet, ifac_key);
    let tag = &signature[SIGNATURE_LENGTH - ifac_size..];
    let mut mask = [0u8; WIRE_MTU_MAX];
    derive_mask(tag, ifac_key, &mut mask[..wrapped_len])?;

    out.clear();
    out.push(packet[0] | IFAC_FLAG)?;
    out.push(packet[1])?;
    out.extend_from_slice(tag)?;
    out.extend_from_slice(&packet[2..])?;

    for (i, byte) in out.as_mut_slice().iter_mut().enumerate() {
        if i == 0 {
            *byte = (*byte ^ mask[i]) | IFAC_FLAG;
        } else if i == 1 || i > ifac_size + 1 {
            *byte ^= mask[i];
        }
    }

    Ok(())
}

pub fn ifac_verify_into(
    raw: &[u8],
    ifac_key: &[u8; IFAC_KEY_LENGTH],
    ifac_size: u8,
    out: &mut PacketBuffer,
) -> Result<(), IfacError> {
    let ifac_size = validate_size(ifac_size)?;
    if raw.len() > MTU + ifac_size {
        return Err(IfacError::ExceedsMtu);
    }
    if raw.len() <= 2 + ifac_size {
        return Err(IfacError::TooShort);
    }
    if raw[0] & IFAC_FLAG == 0 {
        return Err(IfacError::MissingFlag);
    }

    let tag = &raw[2..2 + ifac_size];
    let mut mask = [0u8; WIRE_MTU_MAX];
    derive_mask(tag, ifac_key, &mut mask[..raw.len()])?;

    out.clear();
    out.set_len(raw.len() - ifac_size)?;
    let plain = out.as_mut_slice();
    plain[0] = (raw[0] ^ mask[0]) & !IFAC_FLAG;
    plain[1] = raw[1] ^ mask[1];
    for raw_i in 2 + ifac_size..raw.len() {
        plain[raw_i - ifac_size] = raw[raw_i] ^ mask[raw_i];
    }

    let expected = sign_packet(out.as_slice(), ifac_key);
    let expected_tag = &expected[SIGNATURE_LENGTH - ifac_size..];
    if tag.ct_eq(expected_tag).into() {
        Ok(())
    } else {
        Err(IfacError::AuthenticationFailed)
    }
}

pub const fn has_ifac_flag(raw: &[u8]) -> bool {
    !raw.is_empty() && raw[0] & IFAC_FLAG != 0
}

fn validate_size(ifac_size: u8) -> Result<usize, IfacError> {
    if ifac_size == 0 || ifac_size as usize > SIGNATURE_LENGTH {
        return Err(IfacError::InvalidSize);
    }
    Ok(ifac_size as usize)
}

fn sign_packet(packet: &[u8], ifac_key: &[u8; IFAC_KEY_LENGTH]) -> [u8; SIGNATURE_LENGTH] {
    let mut signing_seed = [0u8; 32];
    signing_seed.copy_from_slice(&ifac_key[32..64]);
    SigningKey::from_bytes(&signing_seed)
        .sign(packet)
        .to_bytes()
}

fn derive_mask(
    tag: &[u8],
    ifac_key: &[u8; IFAC_KEY_LENGTH],
    out: &mut [u8],
) -> Result<(), IfacError> {
    let hkdf = Hkdf::<Sha256>::new(Some(ifac_key), tag);
    hkdf.expand(&[], out).map_err(|_| IfacError::Hkdf)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut out = [0u8; N];
        for (idx, byte) in out.iter_mut().enumerate() {
            let pos = idx * 2;
            *byte = u8::from_str_radix(&hex[pos..pos + 2], 16).unwrap();
        }
        out
    }

    fn test_key() -> [u8; IFAC_KEY_LENGTH] {
        derive_ifac_key(Some("testnet"), Some("password")).unwrap()
    }

    #[test]
    fn derivation_matches_reticulum_vectors() {
        let cases = [
            (
                Some("testnet"),
                Some("password"),
                "6bf05e0b5e2593e6ccae7edfc669df9082b910a7ed5a1f0728e63ba2a27f8201d4407628c6ce33b01bdeb0a5896327b24e762377195e36c25285b49ce1c31541",
            ),
            (
                None,
                None,
                "03cc109cb110647125576b5a387042cf8ef6f8dc6f90633946728b074e74d823b68e3fae06e83e486fbde0f2d26d8dc690e40fe6d499c57a7b30fd7aa9635300",
            ),
            (
                Some("mynetwork"),
                Some("mysecret"),
                "bbf482e7ca83cfe317e47ac5b8fd060152c4abbeb9d20c6f81dde8eb933063963cd0c986e9b89de1e9b0814b3f166bb70da033f83ec741b23f97ec0b1afa5499",
            ),
            (
                Some("reticulum"),
                None,
                "72d150219ab6dced2295432fadfee27a358593b1b058c4b8737a96366b6c93de16280a774866e555eac9a973117f237245d5e6d6493f3e2058ab2192976045df",
            ),
            (
                None,
                Some("passphrase"),
                "2bfb451b666555ce988e89e0e7268a6b086d76329410e6c5d8f824067dc09c071252276ae8206efeceeaa198bdf9b4009dcbb559c085c597d62eb66e6dc61d3e",
            ),
        ];

        for (network, passphrase, expected) in cases {
            assert_eq!(
                derive_ifac_key(network, passphrase).unwrap(),
                decode_hex::<64>(expected)
            );
        }
    }

    #[test]
    fn none_and_empty_string_are_distinct() {
        let none = derive_ifac_key(None, None).unwrap();
        let empty = derive_ifac_key(Some(""), Some("")).unwrap();
        assert_ne!(none, empty);
    }

    #[test]
    fn sign_verify_roundtrips_different_sizes() {
        let key = test_key();
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x01, 0x03]);
        packet.extend_from_slice(&[0xAA; 32]);

        for size in [1, 2, 4, 8, 16, 32, 64] {
            let mut signed = WireBuffer::new();
            ifac_sign_into(&packet, &key, size, &mut signed).unwrap();
            assert_eq!(signed.len(), packet.len() + size as usize);
            assert!(has_ifac_flag(signed.as_slice()));

            let mut verified = PacketBuffer::new();
            ifac_verify_into(signed.as_slice(), &key, size, &mut verified).unwrap();
            assert_eq!(verified.as_slice(), packet.as_slice());
        }
    }

    #[test]
    fn full_mtu_packet_roundtrips_through_ifac() {
        // A full 500-byte RNS packet must survive IFAC wrapping (508 bytes on
        // the wire with the LoRa default tag) — upstream HW_MTU semantics.
        let key = test_key();
        let mut packet = [0xA5u8; MTU];
        packet[0] = 0x01;
        packet[1] = 0x00;

        let mut signed = WireBuffer::new();
        ifac_sign_into(&packet, &key, IFAC_LORA_DEFAULT_SIZE, &mut signed).unwrap();
        assert_eq!(signed.len(), MTU + IFAC_LORA_DEFAULT_SIZE as usize);

        let mut verified = PacketBuffer::new();
        ifac_verify_into(
            signed.as_slice(),
            &key,
            IFAC_LORA_DEFAULT_SIZE,
            &mut verified,
        )
        .unwrap();
        assert_eq!(verified.as_slice(), packet.as_slice());

        // But an over-MTU plain packet still refuses to wrap.
        let oversize = [0x01u8; MTU + 1];
        assert_eq!(
            ifac_sign_into(&oversize, &key, IFAC_LORA_DEFAULT_SIZE, &mut signed),
            Err(IfacError::ExceedsMtu)
        );
    }

    #[test]
    fn verify_rejects_wrong_key_and_tamper() {
        let key = test_key();
        let wrong = derive_ifac_key(Some("wrong"), Some("key")).unwrap();
        let packet = [0x01, 0x03, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut signed = WireBuffer::new();
        ifac_sign_into(&packet, &key, 8, &mut signed).unwrap();

        let mut verified = PacketBuffer::new();
        assert_eq!(
            ifac_verify_into(signed.as_slice(), &wrong, 8, &mut verified),
            Err(IfacError::AuthenticationFailed)
        );

        let last = signed.len() - 1;
        signed.as_mut_slice()[last] ^= 0x01;
        assert_eq!(
            ifac_verify_into(signed.as_slice(), &key, 8, &mut verified),
            Err(IfacError::AuthenticationFailed)
        );
    }

    #[test]
    fn verify_rejects_missing_flag_and_header_only_packet() {
        let key = test_key();
        let packet = [0x01, 0x03, 0xAA, 0xBB];
        let mut verified = PacketBuffer::new();
        assert_eq!(
            ifac_verify_into(&packet, &key, 1, &mut verified),
            Err(IfacError::MissingFlag)
        );

        let mut signed = WireBuffer::new();
        ifac_sign_into(&[0x01, 0x03], &key, 1, &mut signed).unwrap();
        assert_eq!(
            ifac_verify_into(signed.as_slice(), &key, 1, &mut verified),
            Err(IfacError::TooShort)
        );
    }

    #[test]
    fn masking_changes_payload_but_preserves_flags_after_verify() {
        let key = test_key();
        let packet = [0x55, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut signed = WireBuffer::new();
        ifac_sign_into(&packet, &key, 8, &mut signed).unwrap();
        assert_ne!(&signed.as_slice()[10..], &packet[2..]);

        let mut verified = PacketBuffer::new();
        ifac_verify_into(signed.as_slice(), &key, 8, &mut verified).unwrap();
        assert_eq!(verified.as_slice(), packet.as_slice());
    }
}

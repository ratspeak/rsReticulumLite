//! Build a signed PLAIN tunnel-synthesis packet for a client interface.
//! Adapted from `rns-transport::tunnel`. The caller supplies entropy and sends
//! the packet on the intended connection; the hub owns validation, tunnel
//! rebinding and restoration of any retained paths.

use crate::constants::{HEADER_MINSIZE, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::identity::{LocalIdentity, destination_hash_from_name};
use crate::wire::{
    DestinationType, HeaderType, PacketContext, PacketFlags, PacketType, TransportType, sha256,
};

/// Length of `public_key(64) || interface_hash(32) || random_hash(16) || signature(64)`.
/// This is the synthesis payload, excluding the packet header.
pub const TUNNEL_SYNTHESIS_LEN: usize = PUBLIC_KEY_LENGTH + 32 + 16 + SIGNATURE_LENGTH;
/// The HEADER_1 packet that carries one synthesis.
pub const TUNNEL_SYNTHESIS_PACKET_LEN: usize = HEADER_MINSIZE + TUNNEL_SYNTHESIS_LEN;

const SIGNED_LEN: usize = TUNNEL_SYNTHESIS_LEN - SIGNATURE_LENGTH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelError {
    /// `out` is shorter than [`TUNNEL_SYNTHESIS_PACKET_LEN`].
    OutputTooSmall,
}

/// SHA-256 of a caller-supplied interface identifier's UTF-8 bytes.
/// Pass the same stable full identifier on reconnect, such as
/// `TCPInterface[name/host:port]`; this helper does not format addresses.
pub fn interface_hash(name: &str) -> [u8; 32] {
    sha256(name.as_bytes())
}

/// Write a synthesis packet into `out` and return its length; this does not send it.
/// Use fresh cryptographic `random_hash` bytes for each connection so duplicate
/// suppression at the hub does not mistake a reconnect for a repeated packet.
// Out of line so the signing scratch never joins a caller's stack frame.
#[inline(never)]
pub fn build_tunnel_synthesis_packet(
    identity: &LocalIdentity,
    interface_hash: &[u8; 32],
    random_hash: &[u8; 16],
    out: &mut [u8],
) -> Result<usize, TunnelError> {
    let out = out
        .get_mut(..TUNNEL_SYNTHESIS_PACKET_LEN)
        .ok_or(TunnelError::OutputTooSmall)?;
    let (header, synthesis) = out.split_at_mut(HEADER_MINSIZE);
    header[0] = PacketFlags {
        header_type: HeaderType::Header1,
        context_flag: false,
        transport_type: TransportType::Broadcast,
        destination_type: DestinationType::Plain,
        packet_type: PacketType::Data,
    }
    .pack();
    header[1] = 0;
    header[2..HEADER_MINSIZE - 1].copy_from_slice(&destination_hash_from_name(
        "rnstransport.tunnel.synthesize",
        None,
    ));
    header[HEADER_MINSIZE - 1] = PacketContext::None.to_byte();

    let (signed, signature) = synthesis.split_at_mut(SIGNED_LEN);
    signed[..PUBLIC_KEY_LENGTH].copy_from_slice(identity.public_key());
    signed[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + 32].copy_from_slice(interface_hash);
    signed[PUBLIC_KEY_LENGTH + 32..].copy_from_slice(random_hash);
    signature.copy_from_slice(&identity.sign(signed));
    Ok(TUNNEL_SYNTHESIS_PACKET_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::PacketView;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const NAME: &str = "TCPInterface[Uplink/127.0.0.1:4242]";

    fn build(identity: &LocalIdentity, random_hash: [u8; 16]) -> [u8; TUNNEL_SYNTHESIS_PACKET_LEN] {
        let mut out = [0u8; TUNNEL_SYNTHESIS_PACKET_LEN];
        let len =
            build_tunnel_synthesis_packet(identity, &interface_hash(NAME), &random_hash, &mut out)
                .unwrap();
        assert_eq!(len, TUNNEL_SYNTHESIS_PACKET_LEN);
        out
    }

    #[test]
    fn synthesis_is_a_signed_176_byte_plain_packet() {
        let identity = LocalIdentity::from_private_key(&[0x21; 64]);
        let packet = build(&identity, [0xA5; 16]);
        let view = PacketView::parse(&packet).unwrap();
        assert_eq!(TUNNEL_SYNTHESIS_LEN, 176);
        assert_eq!(view.payload.len(), TUNNEL_SYNTHESIS_LEN);
        assert_eq!(
            view.header.flags,
            PacketFlags {
                header_type: HeaderType::Header1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
            }
        );
        assert_eq!(view.header.hops, 0);
        assert_eq!(view.header.context, PacketContext::None);
        assert_eq!(
            view.header.destination_hash,
            destination_hash_from_name("rnstransport.tunnel.synthesize", None)
        );
        assert_eq!(&view.payload[..64], identity.public_key());
        assert_eq!(view.payload[64..96], interface_hash(NAME));
        assert_eq!(view.payload[96..112], [0xA5; 16]);

        let key =
            VerifyingKey::from_bytes(identity.public_key()[32..].try_into().unwrap()).unwrap();
        let signature = Signature::from_bytes(view.payload[112..].try_into().unwrap());
        assert!(key.verify(&view.payload[..112], &signature).is_ok());
    }

    #[test]
    fn each_connection_gets_a_distinct_packet() {
        let identity = LocalIdentity::from_private_key(&[0x22; 64]);
        assert_eq!(build(&identity, [1; 16]), build(&identity, [1; 16]));
        assert_ne!(
            crate::wire::packet_hash(&build(&identity, [1; 16]), HeaderType::Header1),
            crate::wire::packet_hash(&build(&identity, [2; 16]), HeaderType::Header1)
        );
    }

    #[test]
    fn a_short_buffer_is_refused_untouched() {
        let identity = LocalIdentity::from_private_key(&[0x23; 64]);
        let mut out = [0x5A; TUNNEL_SYNTHESIS_PACKET_LEN - 1];
        assert_eq!(
            build_tunnel_synthesis_packet(&identity, &[0; 32], &[0; 16], &mut out),
            Err(TunnelError::OutputTooSmall)
        );
        assert!(out.iter().all(|&byte| byte == 0x5A));

        let mut larger = [0x5A; TUNNEL_SYNTHESIS_PACKET_LEN + 8];
        assert_eq!(
            build_tunnel_synthesis_packet(&identity, &[0; 32], &[0; 16], &mut larger),
            Ok(TUNNEL_SYNTHESIS_PACKET_LEN)
        );
        assert!(
            larger[TUNNEL_SYNTHESIS_PACKET_LEN..]
                .iter()
                .all(|&byte| byte == 0x5A)
        );
    }
}

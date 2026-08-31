use rns_lite_core::config::LiteConfig;
use rns_lite_core::packet_buffer::{PacketBuffer, WireBuffer};
use rns_lite_core::transport::{IngestAction, OutboundReason, RxMeta, SmallNode};
use rns_lite_core::wire::{
    DestinationType, HeaderType, PacketContext, PacketFlags, PacketHeader, PacketType, PacketView,
    TransportType, build_packet, link_id_from_raw, truncated_packet_hash,
};

const HELTEC_TRANSPORT_ID: [u8; 16] = *b"rslite-heltec-v3";
const LORA_IFACE: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endpoint {
    Injector,
    Receiver,
}

struct VirtualRelayTopology {
    relay: SmallNode,
    injector_observed: Vec<WireBuffer>,
    receiver_observed: Vec<WireBuffer>,
    now_ms: u64,
}

impl VirtualRelayTopology {
    fn new() -> Self {
        Self {
            relay: SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, HELTEC_TRANSPORT_ID)
                .unwrap(),
            injector_observed: Vec::new(),
            receiver_observed: Vec::new(),
            now_ms: 1_000,
        }
    }

    fn tx_endpoint_to_relay(&mut self, endpoint: Endpoint, packet: &PacketBuffer) -> IngestAction {
        let injector_before = self.injector_observed.len();
        let receiver_before = self.receiver_observed.len();
        let action = self
            .relay
            .ingest(packet.as_slice(), RxMeta::new(LORA_IFACE), self.now_ms)
            .unwrap();
        self.now_ms += 100;

        match endpoint {
            Endpoint::Injector => {
                assert_eq!(
                    self.receiver_observed.len(),
                    receiver_before,
                    "virtual topology leaked injector traffic directly to receiver"
                );
            }
            Endpoint::Receiver => {
                assert_eq!(
                    self.injector_observed.len(),
                    injector_before,
                    "virtual topology leaked receiver traffic directly to injector"
                );
            }
        }

        action
    }

    fn tick(&mut self) {
        self.relay.tick(self.now_ms);
        self.now_ms += 100;
    }

    fn pump_relay_broadcast(&mut self) -> Vec<OutboundReason> {
        let mut reasons = Vec::new();
        while let Some(outbound) = self.relay.poll_tx() {
            assert_eq!(outbound.interface_id, LORA_IFACE);
            reasons.push(outbound.reason);
            let packet = outbound.packet;
            self.injector_observed.push(packet);
            self.receiver_observed.push(packet);
        }
        reasons
    }

    fn pump_until_relay_broadcast(&mut self) -> Vec<OutboundReason> {
        for _ in 0..20 {
            let reasons = self.pump_relay_broadcast();
            if !reasons.is_empty() {
                return reasons;
            }
            self.tick();
        }
        self.pump_relay_broadcast()
    }

    fn clear_observed(&mut self) {
        self.injector_observed.clear();
        self.receiver_observed.clear();
    }
}

fn receiver_announce() -> ([u8; 16], PacketBuffer) {
    let identity = rns_identity::identity::Identity::from_private_key(&[0x71; 64]).unwrap();
    let announce =
        rns_identity::announce::AnnounceData::create(&identity, "lxmf.delivery", Some(b"rx"), None)
            .unwrap();
    let payload = announce.pack();
    let destination_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        "lxmf.delivery",
        Some(&identity.hash),
    );

    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: PacketContext::None,
    };
    (destination_hash, build_packet(header, &payload).unwrap())
}

fn h2_to_heltec(
    packet_type: PacketType,
    destination_hash: [u8; 16],
    payload: &[u8],
) -> rns_lite_core::packet_buffer::PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type,
        },
        hops: 0,
        transport_id: Some(HELTEC_TRANSPORT_ID),
        destination_hash,
        context: PacketContext::None,
    };
    build_packet(header, payload).unwrap()
}

fn link_data(
    link_id: [u8; 16],
    context: PacketContext,
) -> rns_lite_core::packet_buffer::PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    build_packet(header, b"isolated link payload").unwrap()
}

fn h1_proof(destination_hash: [u8; 16]) -> PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Proof,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: PacketContext::None,
    };
    build_packet(header, &[0x55; 64]).unwrap()
}

fn link_proof(link_id: [u8; 16]) -> PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context: PacketContext::LinkProof,
    };
    build_packet(header, &[0x7A; 64]).unwrap()
}

#[test]
fn isolated_three_device_relay_does_not_require_direct_ratdeck_rf() {
    let (receiver_hash, announce) = receiver_announce();
    let mut topology = VirtualRelayTopology::new();

    assert_eq!(
        topology.tx_endpoint_to_relay(Endpoint::Receiver, &announce),
        IngestAction::ScheduledAnnounce
    );
    let reasons = topology.pump_until_relay_broadcast();
    assert_eq!(reasons, [OutboundReason::AnnounceRebroadcast]);
    topology.clear_observed();

    let data = h2_to_heltec(PacketType::Data, receiver_hash, b"opportunistic lxmf bytes");
    assert_eq!(
        topology.tx_endpoint_to_relay(Endpoint::Injector, &data),
        IngestAction::ForwardedTransport
    );
    assert!(topology.receiver_observed.is_empty());
    let reasons = topology.pump_relay_broadcast();
    assert_eq!(reasons, [OutboundReason::TransportForward]);
    assert_eq!(topology.receiver_observed.len(), 1);

    let data_view = PacketView::parse(topology.receiver_observed[0].as_slice()).unwrap();
    assert_eq!(data_view.header.flags.header_type, HeaderType::Header1);
    assert_eq!(data_view.header.destination_hash, receiver_hash);
    assert_eq!(data_view.payload, b"opportunistic lxmf bytes");
    topology.clear_observed();

    let data_proof_hash = truncated_packet_hash(data.as_slice(), HeaderType::Header2);
    let proof = h1_proof(data_proof_hash);
    assert_eq!(
        topology.tx_endpoint_to_relay(Endpoint::Receiver, &proof),
        IngestAction::ForwardedProof
    );
    assert!(topology.injector_observed.is_empty());
    let reasons = topology.pump_relay_broadcast();
    assert_eq!(reasons, [OutboundReason::ProofReturn]);
    assert_eq!(topology.injector_observed.len(), 1);
    topology.clear_observed();

    let link_request_payload: [u8; 64] = core::array::from_fn(|i| 0xA5u8.wrapping_add(i as u8));
    let link_request = h2_to_heltec(
        PacketType::LinkRequest,
        receiver_hash,
        &link_request_payload,
    );
    let link_id = link_id_from_raw(link_request.as_slice(), HeaderType::Header2);
    assert_eq!(
        topology.tx_endpoint_to_relay(Endpoint::Injector, &link_request),
        IngestAction::ForwardedTransport
    );
    assert!(topology.receiver_observed.is_empty());
    let reasons = topology.pump_relay_broadcast();
    assert_eq!(reasons, [OutboundReason::TransportForward]);
    assert_eq!(topology.receiver_observed.len(), 1);
    topology.clear_observed();

    for (offset, context) in [
        PacketContext::Channel,
        PacketContext::Resource,
        PacketContext::ResourceReq,
        PacketContext::ResourceReq,
    ]
    .into_iter()
    .enumerate()
    {
        let raw = link_data(link_id, context);
        assert_eq!(
            topology.tx_endpoint_to_relay(Endpoint::Injector, &raw),
            IngestAction::ForwardedTransport
        );
        assert!(topology.receiver_observed.is_empty());
        let reasons = topology.pump_relay_broadcast();
        assert_eq!(reasons, [OutboundReason::TransportForward]);
        assert_eq!(topology.receiver_observed.len(), 1, "offset {offset}");
        let view = PacketView::parse(topology.receiver_observed[0].as_slice()).unwrap();
        assert_eq!(view.header.destination_hash, link_id);
        assert_eq!(view.header.context, context);
        topology.clear_observed();
    }

    let proof = link_proof(link_id);
    assert_eq!(
        topology.tx_endpoint_to_relay(Endpoint::Receiver, &proof),
        IngestAction::ForwardedProof
    );
    assert!(topology.injector_observed.is_empty());
    let reasons = topology.pump_relay_broadcast();
    assert_eq!(reasons, [OutboundReason::ProofReturn]);
    assert_eq!(topology.injector_observed.len(), 1);

    assert_eq!(topology.relay.stats().dropped, 0);
    assert_eq!(topology.relay.stats().duplicates, 0);
}

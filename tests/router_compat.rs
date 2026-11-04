//! Router-model regression coverage carried from the frozen rsNode transport.
//! Shared packet/link/proof cases remain in transport's unit suite; these cases
//! exercise the per-interface router policy through its public consumption API.
use ed25519_dalek::{Signer, SigningKey};
use rns_lite_core::config::{
    ConfigError, IfacConfig, InterfaceConfig, InterfaceDirection, InterfaceMode, InterfaceRegistry,
    InterfaceRole, LiteConfig, TableCaps,
};
use rns_lite_core::identity::{destination_hash_from_parts, identity_hash, name_hash};
use rns_lite_core::ifac::{has_ifac_flag, ifac_sign_into, ifac_verify_into};
use rns_lite_core::lora::LoraModemConfig;
use rns_lite_core::model::Router;
use rns_lite_core::packet_buffer::{PacketBuffer, WireBuffer};
use rns_lite_core::tables::InterfaceId;
use rns_lite_core::transport::{
    IngestAction, LOCAL_LINKS_MAX, LiteNode, OutboundReason, RouterOutboundFrame, RxMeta,
    TransportError, path_request_destination,
};
use rns_lite_core::wire::{
    DestinationType, HeaderType, PacketContext, PacketFlags, PacketHeader, PacketType, PacketView,
    TransportType, build_packet,
};

const TRANSPORT_ID: [u8; 16] = [0x42; 16];
const IFACE: InterfaceId = 1;
const LORA: InterfaceId = 1;
const UPLINK: InterfaceId = 2;
const PEER: InterfaceId = 3;
type TestRouter = LiteNode<16, 64, 16, 8, 4, 16, 8, 0, 4, Router>;
type TinyRouter = LiteNode<4, 64, 4, 8, 4, 16, 8, 0, 4, Router>;
type RouterConfig = (LiteConfig, InterfaceRegistry, Option<LoraModemConfig>);

fn multi_config(interfaces: &[InterfaceConfig], total_queue_depth: usize) -> RouterConfig {
    let mut registry = InterfaceRegistry::new();
    for interface in interfaces {
        registry.register(*interface).unwrap();
    }
    let mut config = LiteConfig::ESP32_LORA_TRANSPORT_MICRO;
    config.table_caps = TableCaps {
        path_entries: 16,
        announce_entries: 16,
        reverse_entries: 8,
        link_entries: 4,
        packet_hashes: 64,
        path_request_tags: 16,
        queued_announces_per_interface: 4,
        tx_queue_depth: total_queue_depth,
        ..config.table_caps
    };
    (config, registry, None)
}
fn make_router(config: RouterConfig, id: [u8; 16]) -> Result<TestRouter, TransportError> {
    TestRouter::new_router(config.0, id, config.1, config.2)
}
fn make_tiny(config: RouterConfig, id: [u8; 16]) -> Result<TinyRouter, TransportError> {
    TinyRouter::new_router(config.0, id, config.1, config.2)
}
fn node() -> TestRouter {
    make_router(
        multi_config(&[InterfaceConfig::lora_repeater(IFACE, 1074, 8)], 8),
        TRANSPORT_ID,
    )
    .unwrap()
}
struct SignedAnnounce {
    destination_hash: [u8; 16],
    raw: PacketBuffer,
}

const MEDIUM_FAST: rns_lite_core::lora::LoraModemConfig = rns_lite_core::lora::LoraModemConfig {
    bandwidth_hz: 250_000,
    spreading_factor: 9,
    coding_rate_denominator: 5,
    preamble_symbols: 18,
    explicit_header: true,
    crc: true,
    low_data_rate_optimize: false,
};

fn signed_announce(seed: [u8; 32], app_name: &str, app_data: &[u8]) -> SignedAnnounce {
    signed_announce_rh(seed, app_name, app_data, [0xBC; 10])
}

fn signed_announce_rh(
    seed: [u8; 32],
    app_name: &str,
    app_data: &[u8],
    random_hash: [u8; 10],
) -> SignedAnnounce {
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying = signing_key.verifying_key();

    let mut public_key = [0u8; 64];
    public_key[..32].copy_from_slice(&[0xA7; 32]);
    public_key[32..].copy_from_slice(verifying.as_bytes());

    let identity_hash = identity_hash(&public_key);
    let name_hash = name_hash(app_name);
    let destination_hash = destination_hash_from_parts(&name_hash, Some(&identity_hash));

    let mut signed = Vec::new();
    signed.extend_from_slice(&destination_hash);
    signed.extend_from_slice(&public_key);
    signed.extend_from_slice(&name_hash);
    signed.extend_from_slice(&random_hash);
    signed.extend_from_slice(app_data);
    let signature = signing_key.sign(&signed).to_bytes();

    let mut payload = Vec::new();
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

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
    SignedAnnounce {
        destination_hash,
        raw: build_packet(header, &payload).unwrap(),
    }
}

fn path_request(destination_hash: [u8; 16], tag: [u8; 16]) -> PacketBuffer {
    let mut payload = Vec::new();
    payload.extend_from_slice(&destination_hash);
    payload.extend_from_slice(&tag);
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: path_request_destination(),
        context: PacketContext::None,
    };
    build_packet(header, &payload).unwrap()
}

fn h2_data(destination_hash: [u8; 16], payload: &[u8]) -> PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: Some(TRANSPORT_ID),
        destination_hash,
        context: PacketContext::None,
    };
    build_packet(header, payload).unwrap()
}

fn link_request(destination_hash: [u8; 16], hops: u8) -> PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        },
        hops,
        transport_id: Some(TRANSPORT_ID),
        destination_hash,
        context: PacketContext::None,
    };
    build_packet(header, &[0xA5; 64]).unwrap()
}

fn link_packet(link_id: [u8; 16], hops: u8, context: PacketContext) -> PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
        },
        hops,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    build_packet(header, b"link payload").unwrap()
}

fn plain_broadcast(payload: &[u8]) -> PacketBuffer {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0xD5; 16],
        context: PacketContext::None,
    };
    build_packet(header, payload).unwrap()
}

fn endpoint_ingest(node: &mut TestRouter, raw: &[u8], now_ms: u64) -> (IngestAction, PacketBuffer) {
    let mut endpoint = PacketBuffer::new();
    let action = node
        .ingest_endpoint(raw, RxMeta::new(IFACE), now_ms, &mut endpoint)
        .unwrap();
    (action, endpoint)
}

#[test]
fn link_requests_and_own_link_packets_reach_the_endpoint() {
    let own = [0x6D; 16];
    let mut node = node();
    node.set_own_destination(Some(own));
    assert_eq!(node.own_destination(), Some(own));

    let mut header = PacketView::parse(link_request(own, 0).as_slice())
        .unwrap()
        .header;
    header.flags.header_type = HeaderType::Header1;
    header.flags.transport_type = TransportType::Broadcast;
    header.transport_id = None;
    let direct = build_packet(header, &[0xA5; 64]).unwrap();
    for request in [direct, link_request(own, 0)] {
        let (action, endpoint) = endpoint_ingest(&mut node, request.as_slice(), 1_000);
        assert_eq!(action, IngestAction::LocalEndpoint);
        let mut expected = request;
        expected.as_mut_slice()[1] = 1;
        assert_eq!(endpoint.as_slice(), expected.as_slice());
    }
    // Nothing routed: no transit Link, nothing queued. A host without a buffer drops it.
    let link_id = rns_lite_core::link::compute_link_id(&own, &[0xA5; 64]);
    assert!(node.links.get(&link_id, 1_000).is_none());
    assert_eq!(node.outbound_len(), 0);
    assert_eq!(
        node.ingest(link_request(own, 0).as_slice(), RxMeta::new(IFACE), 1_100)
            .unwrap(),
        IngestAction::Dropped
    );
    // Addressed through another relay: next-hop admission drops it first.
    let mut elsewhere = link_request(own, 0);
    elsewhere.as_mut_slice()[2..18].copy_from_slice(&[0x99; 16]);
    assert_eq!(
        endpoint_ingest(&mut node, elsewhere.as_slice(), 1_200).0,
        IngestAction::Dropped
    );

    // Only registered Links are the endpoint's, and their repeats skip the hashlist.
    let link_id = [0x4C; 16];
    let keepalive = link_packet(link_id, 0, PacketContext::Keepalive);
    assert_ne!(
        endpoint_ingest(&mut node, keepalive.as_slice(), 2_000).0,
        IngestAction::LocalEndpoint
    );
    assert!(node.register_local_link(link_id));
    assert!(node.register_local_link(link_id));
    for now_ms in [3_000, 3_001] {
        let (action, endpoint) = endpoint_ingest(&mut node, keepalive.as_slice(), now_ms);
        assert_eq!(action, IngestAction::LocalEndpoint);
        assert_eq!(endpoint.as_slice()[1], 1);
    }
    let data = link_packet(link_id, 0, PacketContext::None);
    assert_eq!(
        endpoint_ingest(&mut node, data.as_slice(), 3_002).0,
        IngestAction::LocalEndpoint
    );
    assert_eq!(node.stats().duplicates, 0);
    node.unregister_local_link(&link_id);
    assert_ne!(
        endpoint_ingest(&mut node, data.as_slice(), 3_003).0,
        IngestAction::LocalEndpoint
    );

    for index in 0..LOCAL_LINKS_MAX as u8 {
        assert!(node.register_local_link([index; 16]));
    }
    assert!(!node.register_local_link([0xEE; 16]));
    node.set_own_destination(None);
    assert_eq!(
        endpoint_ingest(&mut node, link_request(own, 0).as_slice(), 4_000).0,
        IngestAction::Dropped
    );
}

#[test]
fn own_path_requests_reach_the_endpoint_after_tag_dedup() {
    let own = [0x6D; 16];
    let tag = [0x7E; 16];
    let mut node = node();
    node.set_own_destination(Some(own));

    let request = path_request(own, tag);
    let (action, endpoint) = endpoint_ingest(&mut node, request.as_slice(), 1_000);
    assert_eq!(action, IngestAction::LocalEndpoint);
    assert_eq!(endpoint.as_slice()[1], 1);
    assert_eq!(&endpoint.as_slice()[19..35], &own);
    assert_eq!(node.outbound_len(), 0);
    assert_eq!(
        endpoint_ingest(&mut node, request.as_slice(), 1_100).0,
        IngestAction::Duplicate
    );
    // The same tag behind a requestor transport id is new bytes but the same request.
    let mut payload = Vec::new();
    payload.extend_from_slice(&own);
    payload.extend_from_slice(&[0x31; 16]);
    payload.extend_from_slice(&tag);
    let header = PacketView::parse(request.as_slice()).unwrap().header;
    let relayed = build_packet(header, &payload).unwrap();
    assert_eq!(
        endpoint_ingest(&mut node, relayed.as_slice(), 1_200).0,
        IngestAction::Duplicate
    );
    // Other destinations are still discovered for the mesh.
    assert_eq!(
        endpoint_ingest(&mut node, path_request([0x12; 16], tag).as_slice(), 1_300).0,
        IngestAction::ForwardedPathRequest
    );
}

#[test]
fn mixed_ifac_domains_verify_ingress_and_wrap_each_egress_independently() {
    let lora_key = [0x11; 64];
    let local_key = [0x22; 64];
    let mut lora = InterfaceConfig::lora(1, 1_074, 2);
    lora.ifac = Some(IfacConfig {
        key: lora_key,
        size: 8,
    });
    let backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    let mut local = InterfaceConfig::local_client(3, 10_000_000, 2);
    local.ifac = Some(IfacConfig {
        key: local_key,
        size: 4,
    });
    let config = multi_config(&[lora, backbone, local], 6);
    let announce = signed_announce([0x81; 32], "lxmf.delivery", b"mixed-ifac");
    let mut wrapped = WireBuffer::new();
    ifac_sign_into(announce.raw.as_slice(), &lora_key, 8, &mut wrapped).unwrap();

    let mut node = make_router(config, TRANSPORT_ID).unwrap();
    assert_eq!(
        node.ingest(wrapped.as_slice(), RxMeta::new(1), 1_000)
            .unwrap(),
        IngestAction::ScheduledAnnounce
    );
    node.tick(2_000);

    let frames = [
        node.poll_tx_for_interface(2).unwrap(),
        node.poll_tx_for_interface(3).unwrap(),
    ];
    assert!(node.poll_tx_for_interface(1).is_none());
    assert_eq!(frames.map(|frame| frame.interface_id), [2, 3]);
    assert!(!has_ifac_flag(frames[0].packet.as_slice()));
    PacketView::parse(frames[0].packet.as_slice()).unwrap();
    assert!(has_ifac_flag(frames[1].packet.as_slice()));
    let mut local_plain = PacketBuffer::new();
    ifac_verify_into(frames[1].packet.as_slice(), &local_key, 4, &mut local_plain).unwrap();
    PacketView::parse(local_plain.as_slice()).unwrap();

    // The LoRa domain requires its own IFAC; a clear packet cannot contaminate its path state.
    let clear = signed_announce([0x82; 32], "lxmf.delivery", b"clear");
    assert_eq!(
        node.ingest(clear.raw.as_slice(), RxMeta::new(1), 3_000)
            .unwrap(),
        IngestAction::Dropped
    );
    assert!(!node.has_path(&clear.destination_hash, 3_000));
}

#[test]
fn routed_packets_use_the_destination_interfaces_ifac_domain() {
    let backbone_key = [0x23; 64];
    let lora = InterfaceConfig::lora(1, 1_074, 2);
    let mut backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    backbone.ifac = Some(IfacConfig {
        key: backbone_key,
        size: 8,
    });
    let mut node = make_router(multi_config(&[lora, backbone], 4), TRANSPORT_ID).unwrap();

    let announce = signed_announce([0x88; 32], "lxmf.delivery", b"backbone-path");
    let mut wrapped = WireBuffer::new();
    ifac_sign_into(announce.raw.as_slice(), &backbone_key, 8, &mut wrapped).unwrap();
    node.ingest(wrapped.as_slice(), RxMeta::new(2), 1_000)
        .unwrap();
    node.tick(2_000);
    assert_eq!(node.poll_tx_for_interface(1).unwrap().interface_id, 1);

    assert_eq!(
        node.ingest(
            h2_data(announce.destination_hash, b"cross-domain").as_slice(),
            RxMeta::new(1),
            3_000,
        )
        .unwrap(),
        IngestAction::ForwardedTransport
    );
    let frame = node.poll_tx_for_interface(2).unwrap();
    assert_eq!(frame.interface_id, 2);
    assert!(has_ifac_flag(frame.packet.as_slice()));
    let mut plain = PacketBuffer::new();
    ifac_verify_into(frame.packet.as_slice(), &backbone_key, 8, &mut plain).unwrap();
    let view = PacketView::parse(plain.as_slice()).unwrap();
    assert_eq!(view.payload, b"cross-domain");
    assert!(node.poll_tx_for_interface(2).is_none());
}

#[test]
fn boundary_and_local_client_announce_policy_matches_trusted_transport() {
    let mut roaming = InterfaceConfig::lora(1, 1_074, 2);
    roaming.mode = InterfaceMode::Roaming;
    let boundary = InterfaceConfig::backbone(2, 10_000_000, 2);
    let local = InterfaceConfig::local_client(3, 10_000_000, 2);
    let announce = signed_announce([0x83; 32], "lxmf.delivery", b"roaming-origin");

    let mut node = make_router(multi_config(&[roaming, boundary, local], 6), TRANSPORT_ID).unwrap();
    node.ingest(announce.raw.as_slice(), RxMeta::new(1), 1_000)
        .unwrap();
    node.tick(2_000);
    let frame = node.poll_tx_for_interface(3).unwrap();
    assert_eq!(
        frame.interface_id, 3,
        "local peer still receives the announce"
    );
    assert!(
        node.poll_tx_for_interface(2).is_none(),
        "roaming must not flood boundary egress"
    );

    let gateway = InterfaceConfig::lora(1, 1_074, 2);
    let announce = signed_announce([0x84; 32], "lxmf.delivery", b"gateway-origin");
    let mut node = make_router(multi_config(&[gateway, boundary, local], 6), TRANSPORT_ID).unwrap();
    node.ingest(announce.raw.as_slice(), RxMeta::new(1), 1_000)
        .unwrap();
    node.tick(2_000);
    assert_eq!(node.poll_tx_for_interface(2).unwrap().interface_id, 2);
    assert_eq!(node.poll_tx_for_interface(3).unwrap().interface_id, 3);
    assert!(node.poll_tx_for_interface(1).is_none());
}

#[test]
fn explicit_interfaces_suppress_reflection_unless_repeater_is_opted_in() {
    let announce = signed_announce([0x85; 32], "lxmf.delivery", b"no-reflection");
    let lora = InterfaceConfig::lora(7, 1_074, 2);
    let mut node = make_router(multi_config(&[lora], 2), TRANSPORT_ID).unwrap();
    node.ingest(announce.raw.as_slice(), RxMeta::new(7), 1_000)
        .unwrap();
    node.tick(2_000);
    assert!(node.poll_tx_for_interface(7).is_none());

    let repeat = InterfaceConfig::lora_repeater(7, 1_074, 2);
    let mut node = make_router(multi_config(&[repeat], 2), TRANSPORT_ID).unwrap();
    node.ingest(announce.raw.as_slice(), RxMeta::new(7), 1_000)
        .unwrap();
    node.tick(2_000);
    assert_eq!(node.poll_tx_for_interface(7).unwrap().interface_id, 7);
}

#[test]
fn interface_mtu_is_enforced_on_ingress_and_egress() {
    let mut tiny = InterfaceConfig::lora_repeater(1, 1_074, 2);
    tiny.mtu = 64;
    let announce = signed_announce([0x86; 32], "lxmf.delivery", b"too-large");
    let mut node = make_router(multi_config(&[tiny], 2), TRANSPORT_ID).unwrap();
    assert_eq!(
        node.ingest(announce.raw.as_slice(), RxMeta::new(1), 1_000)
            .unwrap(),
        IngestAction::Dropped
    );
    assert_eq!(node.router_stats().mtu_dropped, 1);

    assert_eq!(
        node.request_path(&[0x55; 16], &[0x66; 16], 1, 2_000),
        Err(TransportError::MtuExceeded)
    );
    assert!(node.poll_tx_for_interface(1).is_none());
    assert_eq!(node.router_stats().mtu_dropped, 2);
}

#[test]
fn every_lora_ifac_size_rejects_untransmittable_clear_egress_before_queueing() {
    use rns_lite_core::constants::{HEADER_MINSIZE, LORA_SPLIT_FRAME_PAYLOAD_MAX, MTU};

    let payload = [0xA6; MTU - HEADER_MINSIZE];
    for size in 1..=rns_lite_core::ifac::IFAC_KEY_LENGTH as u8 {
        let mut lora = InterfaceConfig::lora_repeater(1, 1_074, 2);
        lora.ifac = Some(IfacConfig {
            key: [size; rns_lite_core::ifac::IFAC_KEY_LENGTH],
            size,
        });
        let clear_mtu = MTU.min(LORA_SPLIT_FRAME_PAYLOAD_MAX - usize::from(size));
        assert_eq!(lora.clear_mtu(), clear_mtu);

        let exact = plain_broadcast(&payload[..clear_mtu - HEADER_MINSIZE]);
        assert_eq!(exact.len(), clear_mtu);
        let mut node = make_router(multi_config(&[lora], 2), TRANSPORT_ID).unwrap();
        assert!(node.send_local(1, exact));
        let queued = node.poll_tx_for_interface(1).unwrap();
        assert_eq!(queued.packet.len(), clear_mtu + usize::from(size));
        assert!(queued.packet.len() <= LORA_SPLIT_FRAME_PAYLOAD_MAX);
        assert_eq!(node.router_stats().mtu_dropped, 0);

        let mut receiver = make_router(multi_config(&[lora], 2), [0x43; 16]).unwrap();
        receiver
            .ingest(queued.packet.as_slice(), RxMeta::new(1), 1_000)
            .unwrap();
        assert_eq!(receiver.stats().accepted, 1);
        assert_eq!(receiver.router_stats().mtu_dropped, 0);

        if clear_mtu < MTU {
            let oversized = plain_broadcast(&payload[..clear_mtu + 1 - HEADER_MINSIZE]);
            assert_eq!(oversized.len(), clear_mtu + 1);
            assert!(!node.send_local(1, oversized));
            assert!(node.poll_tx_for_interface(1).is_none());
            assert_eq!(node.router_stats().mtu_dropped, 1);
            assert_eq!(node.stats().outbound_dropped, 1);
            assert_eq!(node.stats().dropped, 1);

            let ifac = lora.ifac.unwrap();
            let mut oversized_wire = WireBuffer::new();
            ifac_sign_into(
                oversized.as_slice(),
                &ifac.key,
                ifac.size,
                &mut oversized_wire,
            )
            .unwrap();
            assert_eq!(oversized_wire.len(), LORA_SPLIT_FRAME_PAYLOAD_MAX + 1);
            let mut receiver = make_router(multi_config(&[lora], 2), [0x44; 16]).unwrap();
            assert_eq!(
                receiver
                    .ingest(oversized_wire.as_slice(), RxMeta::new(1), 2_000)
                    .unwrap(),
                IngestAction::Dropped
            );
            assert_eq!(receiver.stats().accepted, 0);
            assert_eq!(receiver.router_stats().mtu_dropped, 1);
        }
    }
}

#[test]
fn maximum_ifac_keeps_full_clear_mtu_on_tcp_interfaces() {
    use rns_lite_core::constants::{HEADER_MINSIZE, MTU, WIRE_MTU_MAX};

    let mut backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    backbone.ifac = Some(IfacConfig {
        key: [0x64; rns_lite_core::ifac::IFAC_KEY_LENGTH],
        size: rns_lite_core::ifac::IFAC_KEY_LENGTH as u8,
    });
    let payload = [0xB7; MTU - HEADER_MINSIZE];
    let packet = plain_broadcast(&payload);
    assert_eq!(packet.len(), MTU);

    let mut node = make_router(multi_config(&[backbone], 2), TRANSPORT_ID).unwrap();
    assert!(node.send_local(2, packet));
    let queued = node.poll_tx_for_interface(2).unwrap();
    assert_eq!(queued.packet.len(), WIRE_MTU_MAX);
    assert_eq!(node.router_stats().mtu_dropped, 0);
}

#[test]
fn local_plain_packets_bridge_outward_and_external_packets_only_reach_local_clients() {
    let lora = InterfaceConfig::lora(1, 1_074, 2);
    let backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    let local = InterfaceConfig::local_client(3, 10_000_000, 2);
    let config = multi_config(&[lora, backbone, local], 6);
    let mut node = make_router(config, TRANSPORT_ID).unwrap();

    assert_eq!(
        node.ingest(
            plain_broadcast(b"from-local").as_slice(),
            RxMeta::new(3),
            1_000,
        )
        .unwrap(),
        IngestAction::ForwardedTransport
    );
    let lora_frame = node.poll_tx_for_interface(1).unwrap();
    let backbone_frame = node.poll_tx_for_interface(2).unwrap();
    assert_eq!(lora_frame.interface_id, 1);
    assert_eq!(backbone_frame.interface_id, 2);
    assert_eq!(
        PacketView::parse(lora_frame.packet.as_slice())
            .unwrap()
            .header
            .hops,
        0
    );
    assert_eq!(
        PacketView::parse(backbone_frame.packet.as_slice())
            .unwrap()
            .header
            .hops,
        0
    );
    assert!(node.poll_tx_for_interface(3).is_none());

    assert_eq!(
        node.ingest(
            plain_broadcast(b"from-network").as_slice(),
            RxMeta::new(1),
            2_000,
        )
        .unwrap(),
        IngestAction::ForwardedTransport
    );
    let local_frame = node.poll_tx_for_interface(3).unwrap();
    assert_eq!(local_frame.interface_id, 3);
    assert_eq!(
        PacketView::parse(local_frame.packet.as_slice())
            .unwrap()
            .header
            .hops,
        1
    );
    assert!(node.poll_tx_for_interface(1).is_none());
}

#[test]
fn tcp_access_point_announce_is_a_real_hop_and_rebroadcasts_to_lora() {
    let lora = InterfaceConfig::lora(1, 1_074, 4);
    let server = InterfaceConfig::access_point(3, 10_000_000, 4);
    let mut node = make_router(multi_config(&[lora, server], 8), TRANSPORT_ID).unwrap();
    let announce = signed_announce([0xD5; 32], "lxmf.delivery", b"tcp-client");

    assert_eq!(
        node.ingest(announce.raw.as_slice(), RxMeta::new(3), 1_000)
            .unwrap(),
        IngestAction::ScheduledAnnounce
    );
    assert!(node.has_path(&announce.destination_hash, 1_000));
    node.tick(2_000);

    let frame = node.poll_tx_for_interface(1).unwrap();
    assert_eq!(frame.reason, OutboundReason::AnnounceRebroadcast);
    let view = PacketView::parse(frame.packet.as_slice()).unwrap();
    assert_eq!(view.header.flags.header_type, HeaderType::Header2);
    assert_eq!(
        view.header.hops, 1,
        "TCP server peers consume a network hop"
    );
    assert_eq!(view.header.transport_id, Some(TRANSPORT_ID));
    assert!(node.poll_tx_for_interface(3).is_none());
}

#[test]
fn lora_and_tcp_access_point_exchange_path_discovery_without_local_privileges() {
    let lora = InterfaceConfig::lora(1, 1_074, 4);
    let server = InterfaceConfig::access_point(3, 10_000_000, 4);

    let mut from_lora = make_router(multi_config(&[lora, server], 8), TRANSPORT_ID).unwrap();
    let request = path_request([0xD6; 16], [0xD7; 16]);
    assert_eq!(
        from_lora
            .ingest(request.as_slice(), RxMeta::new(1), 1_000)
            .unwrap(),
        IngestAction::ForwardedPathRequest
    );
    let tcp_frame = from_lora.poll_tx_for_interface(3).unwrap();
    assert_eq!(tcp_frame.reason, OutboundReason::PathRequestForward);
    assert_eq!(
        PacketView::parse(tcp_frame.packet.as_slice())
            .unwrap()
            .header
            .hops,
        0
    );
    assert!(from_lora.poll_tx_for_interface(1).is_none());

    let mut from_tcp = make_router(multi_config(&[lora, server], 8), TRANSPORT_ID).unwrap();
    let request = path_request([0xD8; 16], [0xD9; 16]);
    assert_eq!(
        from_tcp
            .ingest(request.as_slice(), RxMeta::new(3), 2_000)
            .unwrap(),
        IngestAction::ForwardedPathRequest
    );
    let lora_frame = from_tcp.poll_tx_for_interface(1).unwrap();
    assert_eq!(lora_frame.reason, OutboundReason::PathRequestForward);
    assert!(from_tcp.poll_tx_for_interface(3).is_none());

    // AP mode intentionally does not flood unrelated network announces
    // down to clients; they resolve paths through the request exchange.
    let announce = signed_announce([0xDA; 32], "lxmf.delivery", b"radio-node");
    let mut announce_from_lora =
        make_router(multi_config(&[lora, server], 8), TRANSPORT_ID).unwrap();
    announce_from_lora
        .ingest(announce.raw.as_slice(), RxMeta::new(1), 3_000)
        .unwrap();
    announce_from_lora.tick(4_000);
    assert!(announce_from_lora.poll_tx_for_interface(3).is_none());
}

#[test]
fn boundary_unknown_path_request_falls_back_to_local_clients_only() {
    let lora = InterfaceConfig::lora(1, 1_074, 2);
    let boundary = InterfaceConfig::backbone(2, 10_000_000, 2);
    let local = InterfaceConfig::local_client(3, 10_000_000, 2);
    let mut node = make_router(multi_config(&[lora, boundary, local], 6), TRANSPORT_ID).unwrap();
    let request = path_request([0xD1; 16], [0xD2; 16]);

    assert_eq!(
        node.ingest(request.as_slice(), RxMeta::new(2), 1_000)
            .unwrap(),
        IngestAction::ForwardedPathRequest
    );
    assert_eq!(node.poll_tx_for_interface(3).unwrap().interface_id, 3);
    assert!(node.poll_tx_for_interface(1).is_none());
}

#[test]
fn local_client_unknown_path_request_searches_external_interfaces() {
    let lora = InterfaceConfig::lora(1, 1_074, 2);
    let boundary = InterfaceConfig::backbone(2, 10_000_000, 2);
    let local = InterfaceConfig::local_client(3, 10_000_000, 2);
    let mut node = make_router(multi_config(&[lora, boundary, local], 6), TRANSPORT_ID).unwrap();
    let requested = [0xD3; 16];
    let request = path_request(requested, [0xD4; 16]);

    assert_eq!(
        node.ingest(request.as_slice(), RxMeta::new(3), 1_000)
            .unwrap(),
        IngestAction::ForwardedPathRequest
    );
    let first = node.poll_tx_for_interface(1).unwrap();
    let second = node.poll_tx_for_interface(2).unwrap();
    assert_eq!([first.interface_id, second.interface_id], [1, 2]);
    for frame in [first, second] {
        assert_eq!(frame.reason, OutboundReason::PathRequestForward);
        let view = PacketView::parse(frame.packet.as_slice()).unwrap();
        assert_eq!(view.header.destination_hash, path_request_destination());
        assert_eq!(&view.payload[..16], &requested);
        assert_eq!(&view.payload[16..32], &TRANSPORT_ID);
    }
    assert!(
        node.poll_tx_for_interface(3).is_none(),
        "request must not reflect to its TCP peer"
    );
}

#[test]
fn unknown_offline_and_directionally_invalid_interfaces_fail_closed() {
    let mut lora = InterfaceConfig::lora(1, 1_074, 2);
    lora.direction = InterfaceDirection::INBOUND_ONLY;
    let backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    let config = multi_config(&[lora, backbone], 4);
    let mut node = make_router(config, TRANSPORT_ID).unwrap();
    let announce = signed_announce([0x87; 32], "lxmf.delivery", b"closed");

    assert_eq!(
        node.ingest(announce.raw.as_slice(), RxMeta::new(99), 1_000),
        Err(TransportError::UnknownInterface)
    );
    assert_eq!(
        node.request_path(&[0x11; 16], &[0x22; 16], 1, 1_000),
        Err(TransportError::InterfaceNotOutbound)
    );
    node.set_interface_online(2, false).unwrap();
    assert_eq!(
        node.ingest(announce.raw.as_slice(), RxMeta::new(2), 1_000),
        Err(TransportError::InterfaceOffline)
    );
}

#[test]
fn dynamic_local_client_lifecycle_is_bounded_and_culls_volatile_routes() {
    let lora = InterfaceConfig::lora(1, 1_074, 2);
    let backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    let mut node = make_router(multi_config(&[lora, backbone], 4), TRANSPORT_ID).unwrap();
    let local = InterfaceConfig::local_client(9, 10_000_000, 1);
    node.register_interface(local).unwrap();
    assert_eq!(node.interface(9), Some(local));
    assert_eq!(
        node.register_interface(local),
        Err(ConfigError::DuplicateInterfaceId)
    );

    let announce = signed_announce([0x89; 32], "lxmf.delivery", b"ephemeral-local");
    node.ingest(announce.raw.as_slice(), RxMeta::new(9), 1_000)
        .unwrap();
    assert!(node.has_path(&announce.destination_hash, 1_000));
    node.request_path(&[0x31; 16], &[0x32; 16], 9, 1_100)
        .unwrap();
    assert_eq!(node.outbound_len_for_interface(9), 1);

    assert_eq!(node.unregister_interface(9).unwrap(), local);
    assert!(node.interface(9).is_none());
    assert!(!node.has_path(&announce.destination_hash, 1_100));
    assert_eq!(node.outbound_len_for_interface(9), 0);

    node.unregister_interface(2).unwrap();
    assert_eq!(
        node.unregister_interface(1),
        Err(ConfigError::CannotRemoveLastInterface)
    );
}

#[test]
fn replacing_dynamic_access_point_at_same_id_culls_previous_peer_routes() {
    let lora = InterfaceConfig::lora(1, 1_074, 2);
    let backbone = InterfaceConfig::backbone(2, 10_000_000, 2);
    let mut node = make_router(multi_config(&[lora, backbone], 4), TRANSPORT_ID).unwrap();
    let peer = InterfaceConfig::access_point(9, 10_000_000, 1);
    node.register_interface(peer).unwrap();

    let old_announce = signed_announce([0x8a; 32], "lxmf.delivery", b"old-tcp-peer");
    node.ingest(old_announce.raw.as_slice(), RxMeta::new(9), 1_000)
        .unwrap();
    assert!(node.has_path(&old_announce.destination_hash, 1_000));

    // A socket generation change drives exactly this unregister/register
    // boundary even if two main-loop samples both report the ID online.
    assert_eq!(node.unregister_interface(9).unwrap(), peer);
    node.register_interface(peer).unwrap();
    assert!(!node.has_path(&old_announce.destination_hash, 1_001));

    let new_announce = signed_announce([0x8b; 32], "lxmf.delivery", b"new-tcp-peer");
    node.ingest(new_announce.raw.as_slice(), RxMeta::new(9), 1_002)
        .unwrap();
    assert!(node.has_path(&new_announce.destination_hash, 1_002));
}

#[test]
fn offline_backbone_keeps_descriptor_but_invalidates_cached_reachability_and_held_response() {
    let config = multi_config(
        &[
            InterfaceConfig::lora_repeater(1, 1074, 4),
            InterfaceConfig::backbone(2, 1_000_000, 4),
        ],
        4,
    );
    let mut node = make_router(config, TRANSPORT_ID).unwrap();
    let announce = signed_announce([0x78; 32], "lxmf.delivery", b"backbone");
    node.ingest(announce.raw.as_slice(), RxMeta::new(2), 1000)
        .unwrap();
    let request = path_request(announce.destination_hash, [0x79; 16]);
    assert_eq!(
        node.ingest(request.as_slice(), RxMeta::new(1), 1100)
            .unwrap(),
        IngestAction::AnsweredPathRequest
    );
    let held = node.poll_tx_for_interface(1).unwrap();
    node.set_interface_online(2, false).unwrap();
    assert_eq!(node.interface(2).unwrap().role, InterfaceRole::Backbone);
    assert!(!node.interface(2).unwrap().online);
    assert!(!node.has_path(&announce.destination_hash, 1200));
    assert!(
        node.announce_cache
            .get(&announce.destination_hash, 1200)
            .is_none()
    );
    assert!(!node.router_outbound_is_live(1, held.lifetime, held.target_generation, 1200));
    node.set_interface_online(2, true).unwrap();
    assert!(!node.has_path(&announce.destination_hash, 1200));
    assert!(!node.router_outbound_is_live(1, held.lifetime, held.target_generation, 1200));
}

fn gateway_config(lora_cap_permille: u16) -> RouterConfig {
    let mut config = multi_config(
        &[
            InterfaceConfig {
                announce_cap_permille: lora_cap_permille,
                ..InterfaceConfig::lora_repeater(LORA, 3_515, 6)
            },
            InterfaceConfig::backbone(UPLINK, 10_000_000, 2),
        ],
        8,
    );
    config.2 = Some(MEDIUM_FAST);
    config
}

fn tiny_config() -> RouterConfig {
    let mut config = gateway_config(20);
    config.0.table_caps.path_entries = 4;
    config.0.table_caps.announce_entries = 4;
    config.0.table_caps.reverse_entries = 8;
    config.0.table_caps.link_entries = 4;
    config.0.table_caps.packet_hashes = 64;
    config.0.table_caps.path_request_tags = 16;
    config.0.table_caps.queued_announces_per_interface = 4;
    config
}

fn announce_with_hops(index: u8, wire_hops: u8) -> SignedAnnounce {
    let mut announce = signed_announce([index.wrapping_add(0x30); 32], "lxmf.delivery", b"x");
    let mut raw = announce.raw.as_slice().to_vec();
    raw[1] = wire_hops;
    announce.raw = PacketBuffer::from_slice(&raw).unwrap();
    announce
}

fn heard<const P: usize, const A: usize, const O: usize, const S: usize>(
    node: &mut LiteNode<P, 64, A, 8, 4, 16, O, 0, S, Router>,
    announce: &SignedAnnounce,
    interface: InterfaceId,
    now_ms: u64,
) -> IngestAction {
    node.ingest(announce.raw.as_slice(), RxMeta::new(interface), now_ms)
        .unwrap()
}

fn rebroadcast_destination(frame: RouterOutboundFrame) -> [u8; 16] {
    assert_eq!(frame.reason, OutboundReason::AnnounceRebroadcast);
    PacketView::parse(frame.packet.as_slice())
        .unwrap()
        .header
        .destination_hash
}

fn gateway_node(lora_cap_permille: u16) -> TestRouter {
    make_router(gateway_config(lora_cap_permille), TRANSPORT_ID).unwrap()
}

fn small_heard(node: &mut TestRouter, announce: &SignedAnnounce, iface: InterfaceId, now: u64) {
    assert_eq!(
        node.ingest(announce.raw.as_slice(), RxMeta::new(iface), now)
            .unwrap(),
        IngestAction::ScheduledAnnounce
    );
}

#[test]
fn lora_rebroadcasts_are_spaced_by_their_airtime_over_the_cap() {
    let mut node = gateway_node(20);
    let first = announce_with_hops(1, 0);
    let second = announce_with_hops(2, 0);
    small_heard(&mut node, &first, UPLINK, 1_000);
    small_heard(&mut node, &second, UPLINK, 1_000);
    node.tick(2_000);
    let frame = node.poll_tx_for_interface(LORA).unwrap();
    assert_eq!(rebroadcast_destination(frame), first.destination_hash);
    let spacing = rns_lite_core::announce_cap::lora_spacing_ms(frame.packet.len(), MEDIUM_FAST, 20);
    assert!((20_000..40_000).contains(&spacing), "{spacing}");

    node.tick(2_000 + spacing - 1);
    assert!(node.outbound_peek_for_interface(LORA).is_none());
    node.tick(2_000 + spacing);
    let frame = node.poll_tx_for_interface(LORA).unwrap();
    // The first announce's retry was queued afresh after its first copy went out.
    assert_eq!(rebroadcast_destination(frame), second.destination_hash);
    // An uplink announce has one target here: LoRa.
    assert_eq!(node.router_stats().announces_released, 2);
}

#[test]
fn tcp_gate_spacing_is_milliseconds() {
    let mut node = gateway_node(20);
    let first = announce_with_hops(1, 0);
    let second = announce_with_hops(2, 0);
    small_heard(&mut node, &first, LORA, 1_000);
    small_heard(&mut node, &second, LORA, 1_000);
    node.tick(2_000);
    let frame = node.poll_tx_for_interface(UPLINK).unwrap();
    assert_eq!(rebroadcast_destination(frame), first.destination_hash);
    let spacing =
        rns_lite_core::announce_cap::bitrate_spacing_ms(frame.packet.len(), 10_000_000, 20)
            .unwrap();
    assert!(spacing <= 10, "{spacing}");
    node.tick(2_000 + spacing);
    let frame = node.poll_tx_for_interface(UPLINK).unwrap();
    assert_eq!(rebroadcast_destination(frame), second.destination_hash);
}

#[test]
fn pending_rebroadcasts_release_fewest_hops_first_one_at_a_time() {
    let mut node = gateway_node(1000);
    let far = announce_with_hops(1, 3);
    let near = announce_with_hops(2, 0);
    let middle = announce_with_hops(3, 1);
    for announce in [&far, &near, &middle] {
        small_heard(&mut node, announce, UPLINK, 1_000);
    }
    node.tick(2_000);
    let mut now = 2_000;
    let mut order = Vec::new();
    for _ in 0..3 {
        // One rebroadcast waits in the queue per interface, even with its gate open.
        node.tick(now + 4_000);
        assert_eq!(node.outbound_len_for_interface(LORA), 1);
        let frame = node.poll_tx_for_interface(LORA).unwrap();
        order.push(rebroadcast_destination(frame));
        now += 1_000;
        node.tick(now);
    }
    assert_eq!(
        order,
        [
            near.destination_hash,
            middle.destination_hash,
            far.destination_hash
        ]
    );
}

#[test]
fn uplink_paths_are_bulk_and_never_displace_lora_paths() {
    let mut node = make_tiny(tiny_config(), TRANSPORT_ID).unwrap();
    let lora: Vec<_> = (0..4).map(|i| announce_with_hops(i, 0)).collect();
    for (offset, announce) in lora.iter().enumerate() {
        heard(&mut node, announce, LORA, 1_000 + offset as u64);
    }
    let uplink = announce_with_hops(10, 0);
    assert_eq!(
        heard(&mut node, &uplink, UPLINK, 2_000),
        IngestAction::AnnounceIgnored
    );
    assert!(
        lora.iter()
            .all(|a| node.has_path(&a.destination_hash, 2_000))
    );
    assert!(!node.has_path(&uplink.destination_hash, 2_000));
    assert_eq!(node.router_stats().bulk_paths_refused, 1);

    // A LoRa path displaces a bulk path before an older LoRa path.
    let mut node = make_tiny(tiny_config(), TRANSPORT_ID).unwrap();
    for (offset, announce) in lora.iter().take(3).enumerate() {
        heard(&mut node, announce, LORA, 1_000 + offset as u64);
    }
    heard(&mut node, &uplink, UPLINK, 1_500);
    assert_eq!(node.router_stats().bulk_paths_learned, 1);
    heard(&mut node, &lora[3], LORA, 2_000);
    assert!(!node.has_path(&uplink.destination_hash, 2_000));
    assert!(
        lora.iter()
            .all(|a| node.has_path(&a.destination_hash, 2_000))
    );
}

#[test]
fn a_requested_path_answered_over_the_uplink_is_protected() {
    let mut node = make_tiny(tiny_config(), TRANSPORT_ID).unwrap();
    let wanted = announce_with_hops(20, 0);
    let request = path_request(wanted.destination_hash, [0x5A; 16]);
    assert_eq!(
        node.ingest(request.as_slice(), RxMeta::new(LORA), 1_000)
            .unwrap(),
        IngestAction::ForwardedPathRequest
    );
    for interface in [LORA, UPLINK] {
        while node.poll_tx_for_interface(interface).is_some() {}
    }
    heard(&mut node, &wanted, UPLINK, 1_100);
    assert!(!node.paths.get(&wanted.destination_hash).unwrap().bulk);
    assert_eq!(node.router_stats().bulk_paths_learned, 0);
}

#[test]
fn network_peers_receive_announces_from_every_source() {
    let mut config = gateway_config(1000);
    config
        .1
        .register(InterfaceConfig::network_peer(PEER, 10_000_000, 2))
        .unwrap();
    let mut node = make_router(config, TRANSPORT_ID).unwrap();
    let from_lora = announce_with_hops(1, 0);
    let from_uplink = announce_with_hops(2, 0);
    small_heard(&mut node, &from_lora, LORA, 1_000);
    small_heard(&mut node, &from_uplink, UPLINK, 1_000);
    node.tick(2_000);
    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(rebroadcast_destination(
            node.poll_tx_for_interface(PEER).unwrap(),
        ));
        node.tick(2_100);
    }
    seen.sort();
    let mut expected = [from_lora.destination_hash, from_uplink.destination_hash];
    expected.sort();
    assert_eq!(seen, expected);

    let mut config = gateway_config(1000);
    config
        .1
        .register(InterfaceConfig::access_point(PEER, 10_000_000, 2))
        .unwrap();
    let mut node = make_router(config, TRANSPORT_ID).unwrap();
    small_heard(&mut node, &from_lora, LORA, 1_000);
    node.tick(2_000);
    assert!(node.outbound_peek_for_interface(PEER).is_none());
}

#[test]
fn an_offline_interface_forgets_its_waiting_rebroadcasts() {
    let mut node = gateway_node(20);
    let first = announce_with_hops(1, 0);
    let second = announce_with_hops(2, 0);
    small_heard(&mut node, &first, UPLINK, 1_000);
    small_heard(&mut node, &second, UPLINK, 1_000);
    node.tick(2_000);
    node.set_interface_online(LORA, false).unwrap();
    node.set_interface_online(LORA, true).unwrap();
    node.tick(2_100);
    assert!(node.outbound_peek_for_interface(LORA).is_none());
}

#[test]
fn a_neighbour_relay_cancels_a_waiting_rebroadcast() {
    let mut node = gateway_node(20);
    let first = announce_with_hops(1, 0);
    let second = announce_with_hops(2, 0);
    small_heard(&mut node, &first, UPLINK, 1_000);
    small_heard(&mut node, &second, UPLINK, 1_000);
    node.tick(2_000);
    assert_eq!(
        rebroadcast_destination(node.poll_tx_for_interface(LORA).unwrap()),
        first.destination_hash
    );
    // A neighbour already carried `second` one hop further on LoRa.
    let relayed = announce_with_hops(2, 2);
    node.ingest(relayed.raw.as_slice(), RxMeta::new(LORA), 2_500)
        .unwrap();
    node.tick(200_000);
    while let Some(frame) = node.poll_tx_for_interface(LORA) {
        assert_ne!(rebroadcast_destination(frame), second.destination_hash);
    }
}

#[test]
fn a_waiting_rebroadcast_whose_path_moved_on_is_dropped_at_release() {
    let mut node = gateway_node(20);
    let first = announce_with_hops(1, 0);
    let second = announce_with_hops(2, 0);
    small_heard(&mut node, &first, UPLINK, 1_000);
    small_heard(&mut node, &second, UPLINK, 1_000);
    node.tick(2_000);
    node.poll_tx_for_interface(LORA).unwrap();
    // Both retries run; `second` now waits only on LoRa's closed gate.
    node.tick(7_600);
    assert!(node.outbound_peek_for_interface(LORA).is_none());
    // A fresher announce for `second`, answering a path request, replaces its path without
    // scheduling a rebroadcast.
    let mut fresher = signed_announce_rh(
        [2u8.wrapping_add(0x30); 32],
        "lxmf.delivery",
        b"x",
        [0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    );
    let mut raw = fresher.raw.as_slice().to_vec();
    raw[18] = PacketContext::PathResponse.to_byte();
    fresher.raw = PacketBuffer::from_slice(&raw).unwrap();
    assert_eq!(
        node.ingest(fresher.raw.as_slice(), RxMeta::new(LORA), 8_000)
            .unwrap(),
        IngestAction::LearnedAnnounce
    );
    node.tick(200_000);
    let frame = node.poll_tx_for_interface(LORA).unwrap();
    assert_eq!(rebroadcast_destination(frame), first.destination_hash);
    assert!(
        node.announce_schedule
            .get_mut(&second.destination_hash)
            .is_none()
    );
}

#[test]
fn announce_mode_matrix_matches_trusted_rsreticulum() {
    // Expected policy is the frozen Router corpus; exercise scheduling and egress
    // rather than calling the internal predicate that implements that policy.
    let modes = [
        InterfaceMode::Full,
        InterfaceMode::PointToPoint,
        InterfaceMode::AccessPoint,
        InterfaceMode::Roaming,
        InterfaceMode::Boundary,
        InterfaceMode::Gateway,
        InterfaceMode::Internal,
    ];
    let announce = signed_announce([0xE1; 32], "lxmf.delivery", b"mode matrix");
    for source_mode in modes {
        for target_mode in modes {
            let source = InterfaceConfig {
                mode: source_mode,
                ..InterfaceConfig::lora(1, 1074, 2)
            };
            let target = InterfaceConfig {
                mode: target_mode,
                ..InterfaceConfig::backbone(2, 10_000_000, 2)
            };
            let expected = match target_mode {
                InterfaceMode::AccessPoint => false,
                InterfaceMode::Internal => source_mode != InterfaceMode::Boundary,
                InterfaceMode::Roaming => !matches!(
                    source_mode,
                    InterfaceMode::Roaming | InterfaceMode::Boundary
                ),
                InterfaceMode::Boundary => source_mode != InterfaceMode::Roaming,
                InterfaceMode::Full | InterfaceMode::PointToPoint | InterfaceMode::Gateway => true,
            };
            let mut node = make_router(multi_config(&[source, target], 4), TRANSPORT_ID).unwrap();
            node.ingest(announce.raw.as_slice(), RxMeta::new(1), 1000)
                .unwrap();
            node.tick(2000);
            assert_eq!(
                node.poll_tx_for_interface(2).is_some(),
                expected,
                "{source_mode:?} -> {target_mode:?}"
            );
            assert!(node.poll_tx_for_interface(1).is_none());
        }
    }
}

#[test]
fn interface_quotas_and_global_capacity_preserve_other_interfaces() {
    let interfaces = [
        InterfaceConfig::lora(1, 1074, 2),
        InterfaceConfig::backbone(2, 10_000_000, 2),
        InterfaceConfig::local_client(3, 10_000_000, 2),
        InterfaceConfig::local_client(4, 10_000_000, 2),
    ];
    let mut node = make_router(multi_config(&interfaces, 6), TRANSPORT_ID).unwrap();
    for byte in [0x10, 0x11, 0x12] {
        assert!(node.send_local(1, plain_broadcast(&[byte])));
    }
    for (interface, bytes) in [(2, [0x20, 0x21]), (3, [0x30, 0x31])] {
        for byte in bytes {
            assert!(node.send_local(interface, plain_broadcast(&[byte])));
        }
    }
    assert!(!node.send_local(4, plain_broadcast(&[0x40])));
    assert_eq!(node.stats().outbound_dropped, 2);
    for id in [1, 2, 3] {
        assert_eq!(node.outbound_len_for_interface(id), 2);
    }
    assert_eq!(node.outbound_len_for_interface(4), 0);
    // C2 removes the old test-only round robin contract. Drivers select their
    // own interface; a busy radio cannot block the TCP peer's two frames.
    for byte in [0x20, 0x21] {
        let frame = node.poll_tx_for_interface(2).unwrap();
        assert_eq!(
            PacketView::parse(frame.packet.as_slice()).unwrap().payload,
            &[byte]
        );
    }
    assert!(node.poll_tx_for_interface(2).is_none());
    assert_eq!(node.outbound_len_for_interface(1), 2);
    let expected_len = plain_broadcast(&[0x11]).len();
    assert_eq!(
        node.outbound_peek_for_interface(1),
        Some((expected_len, OutboundReason::Local))
    );
    for byte in [0x11, 0x12] {
        let frame = node.poll_tx_for_interface(1).unwrap();
        assert_eq!(
            PacketView::parse(frame.packet.as_slice()).unwrap().payload,
            &[byte]
        );
    }
    assert_eq!(node.outbound_len_for_interface(3), 2);
}

#[test]
fn scheduled_rebroadcast_yields_to_local_traffic_and_cannot_evict_it() {
    let mut node = make_router(
        multi_config(
            &[
                InterfaceConfig::lora_repeater(1, 1074, 2),
                InterfaceConfig::backbone(2, 10_000_000, 2),
            ],
            4,
        ),
        TRANSPORT_ID,
    )
    .unwrap();
    let announce = signed_announce([0xE2; 32], "lxmf.delivery", b"priority");
    node.ingest(announce.raw.as_slice(), RxMeta::new(2), 1000)
        .unwrap();
    node.tick(2000);
    assert_eq!(
        node.outbound_peek_for_interface(1).unwrap().1,
        OutboundReason::AnnounceRebroadcast
    );
    assert!(node.send_local(1, plain_broadcast(b"first")));
    assert_eq!(
        node.outbound_peek_for_interface(1).unwrap().1,
        OutboundReason::Local
    );
    assert_eq!(
        node.poll_tx_for_interface(1).unwrap().reason,
        OutboundReason::Local
    );
    assert!(node.send_local(1, plain_broadcast(b"kept")));
    assert!(node.send_local(1, plain_broadcast(b"last")));
    assert_eq!(node.outbound_len_for_interface(1), 2);
    // Retry release occurs while the share contains only class-A work.
    node.tick(8000);
    for expected in [b"kept".as_slice(), b"last".as_slice()] {
        let frame = node.poll_tx_for_interface(1).unwrap();
        assert_eq!(frame.reason, OutboundReason::Local);
        assert_eq!(
            PacketView::parse(frame.packet.as_slice()).unwrap().payload,
            expected
        );
    }
    assert!(node.poll_tx_for_interface(1).is_none());
}

#[test]
fn local_plain_sink_applies_only_after_ingress_admission_and_keeps_full_payload() {
    let sink = [0xF1; 16];
    let payload = [0x5A; 100];
    let mut header = PacketView::parse(plain_broadcast(&payload).as_slice())
        .unwrap()
        .header;
    header.destination_hash = sink;
    let packet = build_packet(header, &payload).unwrap();
    let mut node = make_router(
        multi_config(
            &[
                InterfaceConfig::lora_repeater(1, 1074, 4),
                InterfaceConfig::local_client(3, 10_000_000, 4),
            ],
            8,
        ),
        TRANSPORT_ID,
    )
    .unwrap();
    node.set_local_plain_sink(Some(sink));
    let mut capture = PacketBuffer::new();
    for id in [1, 3] {
        assert_eq!(
            node.ingest_endpoint(packet.as_slice(), RxMeta::new(id), 1000, &mut capture),
            Ok(IngestAction::LocalPlain)
        );
        // C4 removed the old 64-byte retained slot: the supplied buffer receives
        // the complete payload, with no unread/newest-replaces-old state.
        assert_eq!(capture.as_slice(), &payload);
    }
    assert_eq!(node.stats().accepted, 0);
    assert_eq!(node.outbound_len(), 0);
    header.hops = 1;
    let relayed = build_packet(header, &payload).unwrap();
    assert_eq!(
        node.ingest_endpoint(relayed.as_slice(), RxMeta::new(1), 1100, &mut capture),
        Ok(IngestAction::Dropped)
    );
    node.set_interface_online(1, false).unwrap();
    assert_eq!(
        node.ingest_endpoint(packet.as_slice(), RxMeta::new(1), 1200, &mut capture),
        Err(TransportError::InterfaceOffline)
    );
    node.set_local_plain_sink(None);
    assert_ne!(
        node.ingest_endpoint(packet.as_slice(), RxMeta::new(3), 1300, &mut capture),
        Ok(IngestAction::LocalPlain)
    );
}

#[test]
fn originated_requests_keep_ordinary_residence_and_forwarded_requests_keep_discovery_deadline() {
    let mut node = node();
    node.request_path(&[0x21; 16], &[0x31; 16], IFACE, 1000)
        .unwrap();
    let originated = node.poll_tx_for_interface(IFACE).unwrap();
    assert_eq!(originated.lifetime.expires_ms, 121_000);
    assert!(node.router_outbound_is_live(
        IFACE,
        originated.lifetime,
        originated.target_generation,
        120_999
    ));
    assert!(!node.router_outbound_is_live(
        IFACE,
        originated.lifetime,
        originated.target_generation,
        121_000
    ));
    node.ingest(
        path_request([0x22; 16], [0x32; 16]).as_slice(),
        RxMeta::new(IFACE),
        1000,
    )
    .unwrap();
    let forwarded = node.poll_tx_for_interface(IFACE).unwrap();
    assert_eq!(forwarded.lifetime.expires_ms, 16_000);
    assert!(!node.router_outbound_is_live(
        IFACE,
        forwarded.lifetime,
        forwarded.target_generation,
        16_000
    ));
}

#[path = "support/router_isolated.rs"]
mod isolated;

#[test]
fn full_mtu_announce_survives_ifac_wrapping_end_to_end() {
    let key = [0x73; 64];
    let radio = InterfaceConfig {
        ifac: Some(IfacConfig { key, size: 8 }),
        ..InterfaceConfig::lora_repeater(IFACE, 1074, 8)
    };
    let config = multi_config(&[radio], 8);
    let announce = signed_announce([0x45; 32], "lxmf.delivery", &[0x5A; 317]);
    let mut sender = make_router(config, TRANSPORT_ID).unwrap();
    let mut wire = WireBuffer::new();
    ifac_sign_into(announce.raw.as_slice(), &key, 8, &mut wire).unwrap();
    assert_eq!(
        sender.ingest(wire.as_slice(), RxMeta::new(IFACE), 1000),
        Ok(IngestAction::ScheduledAnnounce)
    );
    sender.tick(3000);
    let forwarded = sender.poll_tx_for_interface(IFACE).unwrap();
    assert_eq!(forwarded.packet.len(), rns_lite_core::constants::MTU + 8);
    assert!(has_ifac_flag(forwarded.packet.as_slice()));
    let mut receiver = make_router(config, [0x77; 16]).unwrap();
    assert_eq!(
        receiver.ingest(forwarded.packet.as_slice(), RxMeta::new(IFACE), 1000),
        Ok(IngestAction::ScheduledAnnounce)
    );
    assert!(receiver.has_path(&announce.destination_hash, 1000));
}

#[test]
fn local_packets_are_class_a_and_take_the_interface_ifac() {
    let key = [0x73; 64];
    let radio = InterfaceConfig {
        ifac: Some(IfacConfig { key, size: 8 }),
        ..InterfaceConfig::lora_repeater(IFACE, 1074, 8)
    };
    let mut node = make_router(multi_config(&[radio], 8), TRANSPORT_ID).unwrap();
    let packet = link_packet([0x4C; 16], 0, PacketContext::Keepalive);
    assert!(node.send_local(IFACE, packet));
    let frame = node.poll_tx_for_interface(IFACE).unwrap();
    assert_eq!(frame.reason, OutboundReason::Local);
    assert!(!frame.reason.gated());
    let mut clear = PacketBuffer::new();
    ifac_verify_into(frame.packet.as_slice(), &key, 8, &mut clear).unwrap();
    assert_eq!(clear, packet);
}

#[test]
fn in_place_reset_retires_traffic_state_and_rejects_bad_config_atomically() {
    let config = multi_config(
        &[
            InterfaceConfig::lora_repeater(IFACE, 1074, 4),
            InterfaceConfig::backbone(2, 10_000_000, 4),
        ],
        8,
    );
    let mut node = make_router(config, TRANSPORT_ID).unwrap();
    let announce = signed_announce([0x52; 32], "lxmf.delivery", b"before reset");
    node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1000)
        .unwrap();
    node.ingest(
        h2_data(announce.destination_hash, b"pending proof").as_slice(),
        RxMeta::new(2),
        1100,
    )
    .unwrap();
    node.ingest(
        link_request(announce.destination_hash, 0).as_slice(),
        RxMeta::new(2),
        1200,
    )
    .unwrap();
    let held = node.poll_tx_for_interface(IFACE).unwrap();
    node.request_path(&[0x91; 16], &[0x92; 16], IFACE, 1300)
        .unwrap();
    node.set_local_plain_sink(Some([0x53; 16]));
    node.register_local_destination([0x54; 16]);
    node.register_local_link([0x55; 16]);
    let before = format!("{node:?}");
    let mut invalid = config.0;
    invalid.table_caps.path_entries = 17;
    assert_eq!(
        node.reset_router_in_place(invalid, [0x99; 16], config.1, None),
        Err(TransportError::CapacityTooSmall)
    );
    assert_eq!(format!("{node:?}"), before);
    let mut invalid_registry = config.1;
    invalid_registry
        .register(InterfaceConfig::access_point(3, 1000, 9))
        .unwrap();
    assert_eq!(
        node.reset_router_in_place(config.0, [0x99; 16], invalid_registry, None),
        Err(TransportError::InvalidConfig)
    );
    assert_eq!(format!("{node:?}"), before);
    node.reset_router_in_place(config.0, [0x99; 16], config.1, None)
        .unwrap();
    assert_eq!(node.transport_id(), [0x99; 16]);
    assert_eq!(node.outbound_len(), 0);
    assert_eq!(node.path_count(1300), 0);
    assert_eq!(node.local_plain_sink(), None);
    assert_eq!(node.own_destination(), None);
    assert!(!node.router_outbound_is_live(IFACE, held.lifetime, held.target_generation, 1400));
    // C9 keeps counters monotonic: reset state intentionally differs from a
    // freshly constructed node, and identical relearning cannot revive a token.
    node.ingest(announce.raw.as_slice(), RxMeta::new(IFACE), 1400)
        .unwrap();
    assert!(!node.router_outbound_is_live(IFACE, held.lifetime, held.target_generation, 1500));
    assert!(node.send_local(IFACE, plain_broadcast(b"new epoch")));
    let fresh = node.poll_tx_for_interface(IFACE).unwrap();
    assert_ne!(fresh.target_generation, held.target_generation);
}

#[test]
fn link_request_route_retention_samples_registered_bitrate_once() {
    for bitrate in [1074, 10_000_000] {
        let mut node = make_router(
            multi_config(
                &[
                    InterfaceConfig::lora_repeater(1, bitrate, 4),
                    InterfaceConfig::backbone(2, 10_000_000, 4),
                ],
                8,
            ),
            TRANSPORT_ID,
        )
        .unwrap();
        let announce = signed_announce([0x2A; 32], "lxmf.delivery", b"node");
        node.ingest(announce.raw.as_slice(), RxMeta::new(1), 1000)
            .unwrap();
        let request = link_request(announce.destination_hash, 0);
        let id = rns_lite_core::wire::link_id_from_raw(request.as_slice(), HeaderType::Header2);
        node.ingest(request.as_slice(), RxMeta::new(2), 1100)
            .unwrap();
        let deadline = 1100 + 6000 + 8_000_000u64.div_ceil(bitrate);
        assert_eq!(node.links.get(&id, 1100).unwrap().expires_ms, deadline);
        let held = node.poll_tx_for_interface(1).unwrap();
        assert_eq!(held.lifetime.expires_ms, deadline);
        // Re-announcing the same route keeps its incarnation without renewing
        // this pending Link's sampled establishment deadline.
        let renewed = signed_announce_rh([0x2A; 32], "lxmf.delivery", b"node", [0xBD; 10]);
        node.ingest(renewed.raw.as_slice(), RxMeta::new(1), 1200)
            .unwrap();
        assert_eq!(node.links.get(&id, 1200).unwrap().expires_ms, deadline);
        assert!(node.router_outbound_is_live(
            1,
            held.lifetime,
            held.target_generation,
            deadline - 1
        ));
        assert!(!node.router_outbound_is_live(1, held.lifetime, held.target_generation, deadline));
    }
}

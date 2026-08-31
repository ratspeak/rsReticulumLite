use rns_lite_core::config::LiteConfig;
use rns_lite_core::identity::{
    LocalIdentity, destination_hash_from_name, identity_hash, name_hash,
};
use rns_lite_core::packet_buffer::PacketBuffer;
use rns_lite_core::transport::{IngestAction, RxMeta, SmallNode};
use rns_lite_core::wire::{
    DestinationType, HeaderType, PacketContext, PacketFlags, PacketHeader, PacketType,
    TransportType, build_packet, packet_hash,
};

#[test]
fn header_encoding_matches_rsreticulum_wire() {
    let lite_header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: true,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        },
        hops: 7,
        transport_id: Some([0x11; 16]),
        destination_hash: [0x22; 16],
        context: PacketContext::PathResponse,
    };
    let lite = build_packet(lite_header, &[0xAA, 0xBB]).unwrap();

    let rns_header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header2,
            context_flag: true,
            transport_type: rns_wire::flags::TransportType::Transport,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        },
        hops: 7,
        transport_id: Some([0x11; 16]),
        destination_hash: [0x22; 16],
        context: rns_wire::context::PacketContext::PathResponse,
    };
    let mut rns = rns_header.pack();
    rns.extend_from_slice(&[0xAA, 0xBB]);

    assert_eq!(lite.as_slice(), rns.as_slice());
}

#[test]
fn packet_hash_matches_rsreticulum_wire() {
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 3,
        transport_id: Some([0x33; 16]),
        destination_hash: [0x44; 16],
        context: PacketContext::None,
    };
    let raw = build_packet(header, b"payload").unwrap();

    let lite_hash = packet_hash(raw.as_slice(), HeaderType::Header2);
    let rns_hash =
        rns_wire::hash::packet_hash(raw.as_slice(), rns_wire::flags::HeaderType::Header2);

    assert_eq!(lite_hash, rns_hash);
}

#[test]
fn destination_hash_matches_rsreticulum_identity() {
    let identity = rns_identity::identity::Identity::from_private_key(&[0x51; 64]).unwrap();
    let public_key = identity.get_public_key();
    let lite_identity_hash = identity_hash(&public_key);
    assert_eq!(lite_identity_hash, identity.hash);

    let app_name = "lxmf.delivery";
    let lite_dest = destination_hash_from_name(app_name, Some(&lite_identity_hash));
    let rns_dest = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    assert_eq!(lite_dest, rns_dest);
}

#[test]
fn lite_accepts_rsreticulum_signed_announce() {
    let identity = rns_identity::identity::Identity::from_private_key(&[0x61; 64]).unwrap();
    let app_name = "lxmf.delivery";
    let announce =
        rns_identity::announce::AnnounceData::create(&identity, app_name, Some(b"hello"), None)
            .unwrap();
    let payload = announce.pack();
    let destination_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
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
    let raw = build_packet(header, &payload).unwrap();

    let mut node = SmallNode::new(LiteConfig::ESP32_LORA_TRANSPORT_SMALL, [0xAA; 16]).unwrap();
    let action = node.ingest(raw.as_slice(), RxMeta::new(1), 1000).unwrap();
    assert_eq!(action, IngestAction::ScheduledAnnounce);
    assert!(node.has_path(&destination_hash, 1000));
}

// Reverse of `lite_accepts_rsreticulum_signed_announce`: the trusted upstream
// `rns-identity` must accept and validate an announce CREATED by the lite endpoint.
#[test]
fn rsreticulum_validates_lite_signed_announce() {
    let prv = [0x62u8; 64];
    let lite_id = LocalIdentity::from_private_key(&prv);
    let app_name = "lxmf.delivery";
    let random_hash = [0xCDu8; 10];

    let mut out = [0u8; rns_lite_core::constants::MTU];
    let n = lite_id
        .create_announce_named(app_name, &random_hash, None, b"world", &mut out)
        .unwrap();

    let ad = rns_identity::announce::AnnounceData::unpack(&out[..n], false).unwrap();
    let dest = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(lite_id.identity_hash()),
    );
    let validated = ad.validate(&dest).unwrap();
    assert_eq!(&validated.hash, lite_id.identity_hash());
}

// Byte-for-byte: the lite endpoint produces exactly the bytes the trusted upstream would,
// for the same key + fixed random_hash (Ed25519 is deterministic, RFC 8032).
#[test]
fn lite_announce_bytes_match_rsreticulum() {
    for (ratchet, app_data) in [
        (None, &b"hello"[..]),
        (Some([0x42u8; 32]), &b""[..]),
        (Some([0x42u8; 32]), &b"\x93\xc4\x03Rat\xc0\x90"[..]),
    ] {
        let prv = [0x61u8; 64];
        let lite_id = LocalIdentity::from_private_key(&prv);
        let trusted = rns_identity::identity::Identity::from_private_key(&prv).unwrap();
        let app_name = "lxmf.delivery";
        let random_hash = [0xABu8; 10];

        let mut out = [0u8; rns_lite_core::constants::MTU];
        let n = lite_id
            .create_announce_named(app_name, &random_hash, ratchet.as_ref(), app_data, &mut out)
            .unwrap();

        // Rebuild the same announce through the trusted impl: same signed_data, same key,
        // deterministic Ed25519 -> identical signature -> identical packed bytes.
        let nh = name_hash(app_name);
        let dest = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&trusted.hash),
        );
        let mut signed = Vec::new();
        signed.extend_from_slice(&dest);
        signed.extend_from_slice(&trusted.get_public_key());
        signed.extend_from_slice(&nh);
        signed.extend_from_slice(&random_hash);
        if let Some(ref r) = ratchet {
            signed.extend_from_slice(r);
        }
        signed.extend_from_slice(app_data);
        let sig = trusted.sign(&signed).unwrap();
        let trusted_ad = rns_identity::announce::AnnounceData {
            public_key: trusted.get_public_key(),
            name_hash: nh,
            random_hash,
            ratchet,
            signature: sig,
            app_data: if app_data.is_empty() {
                None
            } else {
                Some(app_data.to_vec())
            },
        };
        assert_eq!(&out[..n], trusted_ad.pack().as_slice());
    }
}

// A packet PROOF (delivery receipt) must be byte-exact with the trusted rsReticulum
// Identity::prove, and the lite validator must accept a proof the trusted impl built.
#[test]
fn lite_proof_matches_rsreticulum_identity() {
    let prv = [0x51u8; 64];
    let lite = LocalIdentity::from_private_key(&prv);
    let trusted = rns_identity::identity::Identity::from_private_key(&prv).unwrap();
    let packet_hash = [0x7au8; 32];
    for implicit in [true, false] {
        let mut out = [0u8; 96];
        let n = rns_lite_core::proof::build_proof(&lite, &packet_hash, implicit, &mut out).unwrap();
        assert_eq!(
            &out[..n],
            trusted.prove(&packet_hash, implicit).unwrap().as_slice()
        );
        // lite validates a proof CREATED by the trusted impl.
        let trusted_proof = trusted.prove(&packet_hash, implicit).unwrap();
        assert!(rns_lite_core::proof::validate_proof(
            &trusted.get_public_key(),
            &packet_hash,
            &trusted_proof
        ));
    }
}

// The well-known path-request destination must match Python RNS 1.4.2 and rsReticulum, or the
// endpoint's path requests would target a destination no peer answers.
#[test]
fn path_request_destination_matches_python_and_rsreticulum() {
    // Python RNS 1.4.2: Destination.hash(None, "rnstransport", "path", "request").
    let want_python: [u8; 16] = [
        0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27,
        0x61,
    ];
    let lite = rns_lite_core::path_request_destination();
    assert_eq!(lite, want_python);

    let rns = rns_identity::destination::Destination::hash_from_name_and_identity(
        "rnstransport.path.request",
        None,
    );
    assert_eq!(lite, rns);
}

// The SINGLE-destination ECIES must interop byte-for-byte with the trusted rsReticulum
// Identity::encrypt/decrypt in BOTH directions, or opportunistic LXMF can't be exchanged.
#[test]
fn lite_ecies_interops_with_rsreticulum_identity() {
    let prv = [0x51u8; 64];
    let recipient = rns_identity::identity::Identity::from_private_key(&prv).unwrap();
    let pub64 = recipient.get_public_key();
    let mut x_pub = [0u8; 32];
    x_pub.copy_from_slice(&pub64[..32]);
    let id_hash = recipient.hash;
    let mut x_priv = [0u8; 32];
    x_priv.copy_from_slice(&prv[..32]);

    let plaintext = b"opportunistic lxmf single-frame payload";

    // lite encrypts -> rsReticulum (trusted) decrypts.
    let mut ct = [0u8; 600];
    let n = rns_lite_core::crypto::ecies_encrypt(
        plaintext,
        &x_pub,
        &id_hash,
        &[0x33; 32],
        &[0x44; 16],
        &mut ct,
    )
    .unwrap();
    let recovered = recipient.decrypt(&ct[..n], None, false).unwrap();
    assert_eq!(&recovered, plaintext);

    // rsReticulum (trusted) encrypts -> lite decrypts.
    let rns_ct = recipient.encrypt(plaintext, None).unwrap();
    let mut pt = [0u8; 600];
    let m = rns_lite_core::crypto::ecies_decrypt(&rns_ct, &x_priv, &id_hash, &mut pt).unwrap();
    assert_eq!(&pt[..m], plaintext);
}

// Ratchet ECIES must interop with the trusted impl in BOTH directions: trusted encrypts to
// our announced ratchet (current AND stale) and the lite ring decrypts newest-first with
// base-key fallback; lite encrypts to a peer ratchet and trusted Identity::decrypt with
// retained ratchets recovers it. No enforce mode on either side (EMB ADR 2026-07-18).
#[test]
fn lite_ratchet_ecies_interops_with_rsreticulum_identity() {
    let prv = [0x71u8; 64];
    let me = rns_identity::identity::Identity::from_private_key(&prv).unwrap();
    let id_hash = me.hash;
    let mut x_priv = [0u8; 32];
    x_priv.copy_from_slice(&prv[..32]);

    let mut ring = rns_lite_core::ratchet::RatchetRing::new();
    let mut ring_blob = [0u8; rns_lite_core::ratchet::RATCHET_RING_BLOB_MAX];
    let old_priv = [0x72u8; 32];
    let prepared = ring
        .prepare_rotation_into(
            old_priv,
            rns_lite_core::ratchet::RatchetClock::new(Some(1_000), 0),
            &mut ring_blob,
        )
        .unwrap();
    let old_len = prepared.blob_len().unwrap();
    ring.commit_prepared_blob(&ring_blob[..old_len]).unwrap();
    let prepared = ring
        .prepare_rotation_into(
            [0x73; 32],
            rns_lite_core::ratchet::RatchetClock::new(
                Some(1_000 + rns_lite_core::ratchet::RATCHET_INTERVAL_SECS),
                0,
            ),
            &mut ring_blob,
        )
        .unwrap();
    let rns_lite_core::ratchet::RatchetPreparation::Rotated {
        blob_len,
        public_key: current_pub,
    } = prepared
    else {
        panic!("second ratchet rotation was not prepared");
    };
    ring.commit_prepared_blob(&ring_blob[..blob_len]).unwrap();
    assert_eq!(ring.current_public_key(), Some(current_pub));

    let plaintext = b"ratcheted opportunistic payload";
    let mut pt = [0u8; 600];

    // Trusted encrypts to our CURRENT announced ratchet -> lite decrypts at ring index 0.
    let rns_ct = me.encrypt(plaintext, Some(&current_pub)).unwrap();
    let (m, which) = rns_lite_core::crypto::ecies_decrypt_with_ratchets(
        &rns_ct,
        ring.private_keys(),
        &x_priv,
        &id_hash,
        &mut pt,
    )
    .unwrap();
    assert_eq!((&pt[..m], which), (&plaintext[..], Some(0)));

    // Trusted encrypts to the PREVIOUS ratchet (stale peer knowledge) -> ring index 1.
    let old_pub = rns_lite_core::ratchet::ratchet_public_bytes(&old_priv);
    let rns_ct = me.encrypt(plaintext, Some(&old_pub)).unwrap();
    let (m, which) = rns_lite_core::crypto::ecies_decrypt_with_ratchets(
        &rns_ct,
        ring.private_keys(),
        &x_priv,
        &id_hash,
        &mut pt,
    )
    .unwrap();
    assert_eq!((&pt[..m], which), (&plaintext[..], Some(1)));

    // Trusted encrypts base-key (no ratchet known) -> fallback still decrypts, None.
    let rns_ct = me.encrypt(plaintext, None).unwrap();
    let (m, which) = rns_lite_core::crypto::ecies_decrypt_with_ratchets(
        &rns_ct,
        ring.private_keys(),
        &x_priv,
        &id_hash,
        &mut pt,
    )
    .unwrap();
    assert_eq!((&pt[..m], which), (&plaintext[..], None));

    // lite encrypts to a peer's announced ratchet -> trusted decrypts via retained ratchets.
    let peer_ratchet_priv = [0x74u8; 32];
    let peer_ratchet_pub = rns_lite_core::ratchet::ratchet_public_bytes(&peer_ratchet_priv);
    let mut ct = [0u8; 600];
    let n = rns_lite_core::crypto::ecies_encrypt(
        plaintext,
        &peer_ratchet_pub,
        &id_hash,
        &[0x75; 32],
        &[0x76; 16],
        &mut ct,
    )
    .unwrap();
    let recovered = me
        .decrypt(&ct[..n], Some(&[&peer_ratchet_priv]), false)
        .unwrap();
    assert_eq!(&recovered, plaintext);
}

// IFAC key derivation and wire wrap must be byte-exact with the trusted rsReticulum
// implementations (rns-identity derive, rns-transport sign/verify). Ed25519 signing and
// the HKDF mask are deterministic, so identical inputs must yield identical masked bytes;
// unwrap is cross-checked in both directions.
#[test]
fn lite_ifac_interops_with_rsreticulum() {
    for (network, passphrase) in [
        (Some("testnet"), Some("password")),
        (None, None),
        (Some("reticulum"), None),
        (None, Some("passphrase")),
        // Some("") is hashed as present by both impls — distinct from None. Any
        // string-accepting config surface must map "" to None to match Python peers.
        (Some(""), Some("")),
        (Some(""), None),
    ] {
        let lite_key = rns_lite_core::derive_ifac_key(network, passphrase).unwrap();
        let trusted_key = rns_identity::ifac::derive_ifac_key(network, passphrase).unwrap();
        assert_eq!(lite_key, trusted_key);
    }

    let key = rns_lite_core::derive_ifac_key(Some("testnet"), Some("password")).unwrap();
    let header = PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header2,
            context_flag: false,
            transport_type: TransportType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 2,
        transport_id: Some([0x55; 16]),
        destination_hash: [0x66; 16],
        context: PacketContext::None,
    };
    let packet = build_packet(header, b"ifac interop payload").unwrap();

    for size in [1usize, 8, 16, 64] {
        // lite wraps -> byte-exact vs trusted, and trusted unwraps it.
        let mut lite_wrapped = PacketBuffer::new();
        rns_lite_core::ifac_sign_into(packet.as_slice(), &key, size as u8, &mut lite_wrapped)
            .unwrap();
        let trusted_wrapped = rns_transport::ifac::ifac_sign(packet.as_slice(), &key, size);
        assert_eq!(lite_wrapped.as_slice(), trusted_wrapped.as_slice());
        let trusted_plain =
            rns_transport::ifac::ifac_verify(lite_wrapped.as_slice(), &key, size).unwrap();
        assert_eq!(trusted_plain.as_slice(), packet.as_slice());

        // trusted wraps -> lite unwraps.
        let mut lite_plain = PacketBuffer::new();
        rns_lite_core::ifac_verify_into(&trusted_wrapped, &key, size as u8, &mut lite_plain)
            .unwrap();
        assert_eq!(lite_plain.as_slice(), packet.as_slice());

        // Wrong key rejected by both. Skipped for size 1: a 1-byte tag collides with
        // probability 1/256 and this fixed input happens to hit one — protocol reality,
        // not a bug (Reticulum's minimum useful ifac_size is larger).
        if size >= 8 {
            let wrong = rns_lite_core::derive_ifac_key(Some("wrong"), Some("key")).unwrap();
            assert!(
                rns_transport::ifac::ifac_verify(lite_wrapped.as_slice(), &wrong, size).is_none()
            );
            let mut rejected = PacketBuffer::new();
            assert!(
                rns_lite_core::ifac_verify_into(
                    &trusted_wrapped,
                    &wrong,
                    size as u8,
                    &mut rejected
                )
                .is_err()
            );
        }
    }
}

#[test]
fn lite_packet_buffer_enforces_reticulum_mtu() {
    let too_large = [0u8; rns_lite_core::constants::MTU + 1];
    let buf: Result<PacketBuffer, _> = PacketBuffer::from_slice(&too_large);
    assert!(buf.is_err());
}

// Link establishment and session encryption parity against rns-link.
//
// The lite link handshake must be byte-identical to rsReticulum's audited rns-link: same link_id,
// same proof signature, same derived session key, and an interoperable Token frame. These cross
// the embedded port against the full implementation directly (Ed25519 is deterministic, so the
// proof bytes are reproducible), as in the ECIES interoperability tests.

#[test]
fn lite_link_id_matches_rsreticulum() {
    // A LINKREQUEST payload (x25519_pub || ed25519_pub || signalling).
    let init_x = rns_crypto::x25519::X25519PrivateKey::from_bytes(&[0x33; 32]);
    let init_ed = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&[0x44; 32]);
    let signalling = rns_lite_core::link::SignallingData::new(1, 500);
    let mut request = [0u8; rns_lite_core::link::LINK_REQUEST_LEN];
    let n =
        rns_lite_core::link::build_link_request(&[0x33; 32], &[0x44; 32], signalling, &mut request)
            .unwrap();
    // Sanity: the lite-derived pubs match rns-crypto's.
    assert_eq!(&request[..32], init_x.public_key().to_bytes());
    assert_eq!(&request[32..64], &init_ed.public_key().to_bytes());

    let dest_hash = [0xAB; 16];
    let lite_id = rns_lite_core::link::compute_link_id(&dest_hash, &request[..n]);
    let trusted_id = rns_link::handshake::compute_link_id(&dest_hash, &request[..n]);
    assert_eq!(lite_id, trusted_id);
}

#[test]
fn lite_link_proof_byte_exact_and_cross_validates() {
    let prv = [0x71u8; 64];
    let lite_id_holder = LocalIdentity::from_private_key(&prv);
    let seed: [u8; 32] = prv[32..].try_into().unwrap();
    let trusted_sig_key = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&seed);
    let identity_ed_pub: [u8; 32] = lite_id_holder.public_key()[32..].try_into().unwrap();

    let resp_x_priv = [0x55u8; 32];
    let resp_x_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&resp_x_priv)
        .public_key()
        .to_bytes();
    let link_id = [0xCD; 16];

    let lite_sig = rns_lite_core::link::SignallingData::new(1, 500);
    let trusted_sig = rns_link::mtu_discovery::SignallingData::new(1, 500);

    // lite builds the proof.
    let mut lite_proof = [0u8; rns_lite_core::link::LINK_PROOF_LEN];
    let n = rns_lite_core::link::build_link_proof(
        &lite_id_holder,
        &resp_x_priv,
        &link_id,
        lite_sig,
        &mut lite_proof,
    )
    .unwrap();

    // trusted builds the proof from the same inputs.
    let trusted_proof = rns_link::handshake::LinkProofData::create(
        &trusted_sig_key,
        &resp_x_pub,
        &identity_ed_pub,
        &link_id,
        trusted_sig,
    )
    .pack();

    // Deterministic Ed25519 -> byte-identical proof.
    assert_eq!(&lite_proof[..n], trusted_proof.as_slice());

    // trusted validates the lite-built proof.
    let trusted_view = rns_link::handshake::LinkProofData::unpack(&lite_proof[..n]).unwrap();
    let trusted_verify_key =
        rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&identity_ed_pub).unwrap();
    assert!(trusted_view.validate(&trusted_verify_key, &link_id, &identity_ed_pub));

    // lite validates the trusted-built proof.
    let lite_view = rns_lite_core::link::LinkProofView::parse(&trusted_proof).unwrap();
    assert!(lite_view.validate(lite_id_holder.public_key(), &link_id));
    // Wrong link id rejected.
    assert!(!lite_view.validate(lite_id_holder.public_key(), &[0x00; 16]));
}

#[test]
fn lite_link_keys_match_rsreticulum() {
    let init_x = [0x33u8; 32];
    let resp_x = [0x55u8; 32];
    let link_id = [0xCD; 16];

    let init_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&init_x)
        .public_key()
        .to_bytes();
    let resp_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&resp_x)
        .public_key()
        .to_bytes();

    let lite_init = rns_lite_core::link::LinkKeys::derive(&init_x, &resp_pub, &link_id);

    let trusted_init = rns_link::key_derivation::LinkKeys::derive(
        &rns_crypto::x25519::X25519PrivateKey::from_bytes(&init_x),
        &rns_crypto::x25519::X25519PublicKey::from_bytes(&resp_pub),
        &link_id,
        rns_link::constants::MODE_AES256_CBC,
    )
    .unwrap();

    // trusted splits as signing || encryption; lite combined() is the same 64-byte concat.
    let mut trusted_combined = [0u8; 64];
    trusted_combined[..32].copy_from_slice(&trusted_init.signing_key);
    trusted_combined[32..].copy_from_slice(&trusted_init.encryption_key);
    assert_eq!(lite_init.combined(), &trusted_combined);
    assert_eq!(lite_init.signing_key(), trusted_init.signing_key.as_slice());
    assert_eq!(
        lite_init.encryption_key(),
        trusted_init.encryption_key.as_slice()
    );

    // The responder end also matches (closes the handshake loop with the trusted impl).
    let lite_resp = rns_lite_core::link::LinkKeys::derive(&resp_x, &init_pub, &link_id);
    assert_eq!(lite_resp.combined(), lite_init.combined());
}

// Resource transfer parity against rns-protocol.
//
// The lite single-resource machinery must be byte-identical to rsReticulum's audited rns-protocol:
// same advertisement msgpack, same map hashes over the same ciphertext chunks, same request wire
// and the same proof-over-data-hash. Cross-checked in BOTH directions with a full transfer loop.

fn resource_test_keys() -> (
    rns_lite_core::link::LinkKeys,
    rns_link::key_derivation::LinkKeys,
) {
    let init_x = [0x33u8; 32];
    let resp_x = [0x55u8; 32];
    let link_id = [0xCD; 16];
    let init_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&init_x)
        .public_key()
        .to_bytes();
    let resp_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&resp_x)
        .public_key()
        .to_bytes();
    let lite = rns_lite_core::link::LinkKeys::derive(&init_x, &resp_pub, &link_id);
    let trusted = rns_link::key_derivation::LinkKeys::derive(
        &rns_crypto::x25519::X25519PrivateKey::from_bytes(&resp_x),
        &rns_crypto::x25519::X25519PublicKey::from_bytes(&init_pub),
        &link_id,
        rns_link::constants::MODE_AES256_CBC,
    )
    .unwrap();
    (lite, trusted)
}

fn resource_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn lite_link_mdu_and_resource_constants_match_rsreticulum() {
    // The negotiated link plaintext MDU — NOT the LINK_PADDED_MAX receive cap — sizes ADV frames.
    assert_eq!(rns_lite_core::link::LINK_MDU, 431);
    assert_eq!(rns_lite_core::link::LINK_MDU, rns_wire::constants::LINK_MDU);
    assert_eq!(rns_lite_core::link::link_mdu(500), 431);
    // Part SDU is the raw packet budget (parts are pre-encrypted ciphertext chunks).
    assert_eq!(rns_lite_core::resource::SDU, rns_protocol::resource::SDU);
    assert_eq!(rns_lite_core::resource::SDU, rns_wire::constants::MDU);
    // ADV hashmap capacity parity across MDUs.
    for mdu in [415usize, 431, 200, 134, 64] {
        assert_eq!(
            rns_lite_core::resource::hashmap_max_len(mdu),
            rns_protocol::resource_adv::hashmap_max_len(mdu)
        );
    }
    assert_eq!(
        rns_lite_core::resource::MAPHASH_LEN,
        rns_protocol::resource::MAPHASH_LEN
    );
    assert_eq!(
        rns_lite_core::resource::RANDOM_HASH_SIZE,
        rns_protocol::resource::RANDOM_HASH_SIZE
    );
}

#[test]
fn lite_adv_watchdog_matches_trusted_check_timeout() {
    use rns_lite_core::resource::{AdvWatchdog, AdvWatchdogAction, MAX_ADV_RETRIES};
    use rns_protocol::resource::{OutboundTransfer, ResourceState, TransferAction};
    use std::time::{Duration, Instant};

    // Policy constants pin (trusted d986749: deadline = rtt * 6.0 + 1.0 s, 4 retries).
    assert_eq!(MAX_ADV_RETRIES, rns_protocol::resource::MAX_ADV_RETRIES);
    assert_eq!(
        rns_lite_core::resource::ADV_PROCESSING_GRACE_MS as f64 / 1000.0,
        rns_protocol::resource::PROCESSING_GRACE
    );
    assert_eq!(
        rns_lite_core::resource::TRAFFIC_TIMEOUT_FACTOR as f64,
        rns_link::constants::TRAFFIC_TIMEOUT_FACTOR
    );

    // Behavior lockstep: identical action sequence against the trusted state machine.
    let rtt_ms = 1u64;
    let mut trusted =
        OutboundTransfer::new(b"watchdog parity".to_vec(), false, Duration::from_millis(1))
            .unwrap();
    assert!(matches!(
        trusted.tick(),
        TransferAction::SendAdvertisement(_)
    ));
    let mut lite = AdvWatchdog::new(0);
    let mut now_ms = 0u64;

    for round in 1..=MAX_ADV_RETRIES {
        // Not yet expired on either side.
        assert!(matches!(trusted.check_timeout(), TransferAction::None));
        assert_eq!(lite.poll(now_ms, rtt_ms), AdvWatchdogAction::Wait);
        // Force both past the deadline.
        trusted.started_at = Instant::now() - Duration::from_secs(60);
        now_ms += 60_000;
        assert!(matches!(
            trusted.check_timeout(),
            TransferAction::SendAdvertisement(_)
        ));
        assert_eq!(lite.poll(now_ms, rtt_ms), AdvWatchdogAction::Resend);
        assert_eq!(lite.retries(), trusted.retries);
        assert_eq!(trusted.retries, round);
    }

    trusted.started_at = Instant::now() - Duration::from_secs(60);
    now_ms += 60_000;
    assert!(matches!(trusted.check_timeout(), TransferAction::Failed(_)));
    assert_eq!(lite.poll(now_ms, rtt_ms), AdvWatchdogAction::Failed);
    assert_eq!(trusted.resource.state, ResourceState::Failed);

    // Terminal on both sides.
    trusted.started_at = Instant::now() - Duration::from_secs(60);
    now_ms += 60_000;
    assert!(matches!(trusted.check_timeout(), TransferAction::None));
    assert_eq!(lite.poll(now_ms, rtt_ms), AdvWatchdogAction::Wait);
}

#[test]
fn lite_resource_hashes_match_rns_protocol() {
    let part = resource_payload(464);
    let rh = [0xA1u8, 0xB2, 0xC3, 0xD4];
    assert_eq!(
        rns_lite_core::resource::get_map_hash(&part, &rh),
        rns_protocol::resource::get_map_hash(&part, &rh)
    );
    let data = resource_payload(1200);
    let hash = rns_lite_core::resource::compute_resource_hash(&data, &rh);
    assert_eq!(
        hash,
        rns_protocol::resource::compute_resource_hash(&data, &rh)
    );
    assert_eq!(
        rns_lite_core::resource::compute_expected_proof(&data, &hash),
        rns_protocol::resource::compute_expected_proof(&data, &hash)
    );
}

// The advertisement msgpack must be byte-identical for the same field values, in both request-id
// variants, and each side must decode the other's bytes.
#[test]
fn lite_resource_adv_bytes_match_rns_protocol() {
    let (lite_keys, _) = resource_test_keys();
    let data = resource_payload(2000);
    let lite_out = rns_lite_core::resource::OutboundResource::build(
        &data,
        &lite_keys,
        &[0xAB; 4],
        &[0x11; 16],
    )
    .unwrap();
    let lite_adv = lite_out.advertisement();
    let mut lite_bytes = [0u8; rns_lite_core::resource::ADV_PACKED_MAX];
    let n = lite_adv.pack(&mut lite_bytes).unwrap();

    let map_hashes: Vec<[u8; 4]> = lite_adv.hashmap[..lite_adv.hashmap_len]
        .chunks_exact(4)
        .map(|c| c.try_into().unwrap())
        .collect();
    let mut trusted_adv = rns_protocol::resource_adv::ResourceAdvertisement::new(
        lite_adv.transfer_size as usize,
        lite_adv.data_size as usize,
        lite_adv.num_parts as usize,
        lite_adv.resource_hash,
        lite_adv.random_hash.to_vec(),
        rns_protocol::resource::ResourceFlags {
            encrypted: true,
            ..Default::default()
        },
        &map_hashes,
        rns_wire::constants::LINK_MDU,
    );
    assert_eq!(&lite_bytes[..n], trusted_adv.pack().as_slice());

    // trusted decodes lite bytes; lite decodes trusted bytes.
    let unpacked =
        rns_protocol::resource_adv::ResourceAdvertisement::unpack(&lite_bytes[..n]).unwrap();
    assert_eq!(unpacked.transfer_size, lite_out.transfer_size());
    assert_eq!(unpacked.num_parts, lite_out.num_parts());
    assert_eq!(unpacked.resource_hash, *lite_out.resource_hash());
    assert_eq!(unpacked.flags.to_byte(), 0x01);
    let reparsed = rns_lite_core::resource::ResourceAdv::parse(&trusted_adv.pack()).unwrap();
    assert_eq!(reparsed, lite_adv);

    // With a request id (q = Binary instead of Nil).
    trusted_adv.request_id = Some(vec![0x42; 16]);
    let mut lite_q = lite_adv;
    lite_q.request_id_len = 16;
    lite_q.request_id[..16].copy_from_slice(&[0x42; 16]);
    let qn = lite_q.pack(&mut lite_bytes).unwrap();
    assert_eq!(&lite_bytes[..qn], trusted_adv.pack().as_slice());
}

// Full transfer, lite SENDER -> trusted rns-protocol RECEIVER: the trusted InboundTransfer parses
// the lite ADV, slots the lite ciphertext parts by map hash, drives its own RESOURCE_REQs (parsed
// and served by the lite sender), reassembles through the trusted link decrypt, and its proof
// validates against the lite sender.
#[test]
fn rns_protocol_receives_lite_resource_and_lite_validates_proof() {
    use rns_protocol::resource::TransferAction;

    let (lite_keys, trusted_keys) = resource_test_keys();
    let data = resource_payload(2000);
    let lite_out = rns_lite_core::resource::OutboundResource::build(
        &data,
        &lite_keys,
        &[0xAB; 4],
        &[0x11; 16],
    )
    .unwrap();
    assert_eq!(lite_out.num_parts(), 5);

    let mut adv_bytes = [0u8; rns_lite_core::resource::ADV_PACKED_MAX];
    let n = lite_out.advertisement().pack(&mut adv_bytes).unwrap();
    let adv = rns_protocol::resource_adv::ResourceAdvertisement::unpack(&adv_bytes[..n]).unwrap();

    let mut random_hash = [0u8; 4];
    random_hash.copy_from_slice(&adv.random_hash[..4]);
    let mut inbound = rns_protocol::resource::InboundTransfer::from_advertisement(
        adv.num_parts,
        adv.transfer_size,
        adv.data_size,
        random_hash,
        adv.resource_hash,
        adv.flags,
        adv.get_map_hashes(),
        std::time::Duration::from_millis(10),
    )
    .unwrap();

    // Feed the first part; the trusted receiver answers with a RESOURCE_REQ that the lite sender
    // must parse and serve. Loop until the receiver reports completion.
    let mut pending: Vec<usize> = vec![0];
    let mut complete = false;
    let mut guard = 0;
    while let Some(idx) = pending.pop() {
        guard += 1;
        assert!(guard < 64, "transfer did not converge");
        match inbound.receive_part(lite_out.part(idx).unwrap().to_vec()) {
            TransferAction::Complete => {
                complete = true;
                break;
            }
            TransferAction::SendRequest(req) => {
                let view = rns_lite_core::resource::PartRequestView::parse(&req).unwrap();
                assert!(!view.wants_more_hashmap);
                assert_eq!(view.resource_hash, *lite_out.resource_hash());
                let (idxs, cnt) = lite_out.requested_parts(&view);
                assert!(cnt > 0);
                // Serve in reverse so pop() emits wire order.
                for &i in idxs[..cnt].iter().rev() {
                    pending.push(i);
                }
            }
            TransferAction::None => {}
            other => panic!("unexpected action: {other:?}"),
        }
    }
    assert!(complete);

    let decrypt = |ct: &[u8]| {
        rns_link::encryption::link_decrypt(&trusted_keys, ct)
            .map_err(|_| rns_protocol::resource::ResourceError::DecryptFailed)
    };
    let assembled = inbound.resource.assemble(Some(&decrypt)).unwrap();
    assert_eq!(assembled, data);

    let proof = inbound.resource.generate_proof(&assembled);
    assert!(lite_out.validate_proof(&proof));
    let mut tampered = proof.clone();
    tampered[40] ^= 0x01;
    assert!(!lite_out.validate_proof(&tampered));
}

// Full transfer, trusted rns-protocol SENDER -> lite RECEIVER: lite parses the trusted ADV,
// accepts the trusted parts, emits a RESOURCE_REQ the trusted sender serves, reassembles with the
// lite in-place Token decrypt, and the lite proof completes the trusted sender.
#[test]
fn lite_receives_rns_protocol_resource_and_rns_protocol_validates_proof() {
    use rns_protocol::resource::TransferAction;

    let (lite_keys, trusted_keys) = resource_test_keys();
    let data = resource_payload(2000);
    let mut outbound = rns_protocol::resource::OutboundTransfer::new_encrypted(
        data.clone(),
        false, // auto_compress off: the wire flag must be plain uncompressed
        std::time::Duration::from_millis(10),
        trusted_keys,
    )
    .unwrap();

    let mut lite_inb: Option<rns_lite_core::resource::InboundResource> = None;
    let mut guard = 0;
    loop {
        guard += 1;
        assert!(guard < 64, "transfer did not converge");
        match outbound.tick() {
            TransferAction::SendAdvertisement(bytes) => {
                let adv = rns_lite_core::resource::ResourceAdv::parse(&bytes).unwrap();
                assert_eq!(adv.num_parts, 5);
                assert!(adv.flags.encrypted && !adv.flags.compressed);
                lite_inb = Some(
                    rns_lite_core::resource::InboundResource::from_advertisement(&adv).unwrap(),
                );
            }
            TransferAction::SendPart(_, part) => {
                assert!(lite_inb.as_mut().unwrap().receive_part(&part));
            }
            TransferAction::None => {
                let inb = lite_inb.as_mut().unwrap();
                if inb.is_complete() {
                    break;
                }
                // Sender window drained: lite requests the missing parts.
                assert!(outbound.awaiting_hmu);
                let mut req = [0u8; rns_lite_core::resource::REQUEST_MAX];
                let rn = inb.build_part_request(&mut req).unwrap();
                for action in outbound.handle_request(&req[..rn]) {
                    if let TransferAction::SendPart(_, part) = action {
                        assert!(inb.receive_part(&part));
                    }
                }
            }
            other => panic!("unexpected action: {other:?}"),
        }
        if lite_inb.as_ref().is_some_and(|i| i.is_complete()) {
            break;
        }
    }

    let mut inb = lite_inb.unwrap();
    let len = inb.assemble(&lite_keys).unwrap();
    assert_eq!(inb.data().unwrap(), &data[..]);
    assert_eq!(len, data.len());

    let mut proof = [0u8; rns_lite_core::resource::PROOF_LEN];
    inb.build_proof(&mut proof).unwrap();
    assert!(outbound.handle_proof(&proof));
    assert!(matches!(outbound.tick(), TransferAction::Complete));
}

// Fail-closed parity: a compressed ADV from the full stack is parsed but cleanly refused by the
// lite receiver (the fleet ships without bz2), and an rns-protocol RESOURCE_REQ in the exhausted
// form is still parseable by the lite sender.
#[test]
fn lite_rejects_compressed_rns_protocol_adv() {
    let hashes: Vec<[u8; 4]> = (0..2).map(|i| [i as u8; 4]).collect();
    let adv = rns_protocol::resource_adv::ResourceAdvertisement::new(
        1056,
        1000,
        2,
        [0xAA; 32],
        vec![0xBB; 4],
        rns_protocol::resource::ResourceFlags {
            encrypted: true,
            compressed: true,
            ..Default::default()
        },
        &hashes,
        rns_wire::constants::LINK_MDU,
    );
    let parsed = rns_lite_core::resource::ResourceAdv::parse(&adv.pack()).unwrap();
    assert_eq!(
        rns_lite_core::resource::InboundResource::from_advertisement(&parsed).unwrap_err(),
        rns_lite_core::resource::ResourceError::CompressedUnsupported
    );
}

#[test]
fn lite_link_encryption_interops_with_rsreticulum() {
    let init_x = [0x33u8; 32];
    let resp_x = [0x55u8; 32];
    let link_id = [0xCD; 16];
    let init_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&init_x)
        .public_key()
        .to_bytes();
    let resp_pub = rns_crypto::x25519::X25519PrivateKey::from_bytes(&resp_x)
        .public_key()
        .to_bytes();

    let lite_keys = rns_lite_core::link::LinkKeys::derive(&init_x, &resp_pub, &link_id);
    let trusted_keys = rns_link::key_derivation::LinkKeys::derive(
        &rns_crypto::x25519::X25519PrivateKey::from_bytes(&resp_x),
        &rns_crypto::x25519::X25519PublicKey::from_bytes(&init_pub),
        &link_id,
        rns_link::constants::MODE_AES256_CBC,
    )
    .unwrap();

    let plaintext = b"reticulum link session data frame";

    // lite encrypts (fixed IV) -> trusted decrypts.
    let mut ct = [0u8; 256];
    let cn =
        rns_lite_core::link::link_encrypt(&lite_keys, plaintext, &[0x66; 16], &mut ct).unwrap();
    let recovered = rns_link::encryption::link_decrypt(&trusted_keys, &ct[..cn]).unwrap();
    assert_eq!(&recovered, plaintext);

    // trusted encrypts (random IV) -> lite decrypts.
    let trusted_ct = rns_link::encryption::link_encrypt(&trusted_keys, plaintext).unwrap();
    let mut pt = [0u8; 256];
    let pn = rns_lite_core::link::link_decrypt(&lite_keys, &trusted_ct, &mut pt).unwrap();
    assert_eq!(&pt[..pn], plaintext);
}

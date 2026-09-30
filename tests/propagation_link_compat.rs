use rns_crypto::{
    ed25519::Ed25519PrivateKey,
    x25519::{X25519PrivateKey, X25519PublicKey},
};
use rns_link::link::Link;
use rns_lite_core::{
    identity::LocalIdentity,
    link::{LinkError, LinkKeys, build_identification},
    resource::{InboundResource, OutboundResource, REQUEST_MAX, ResourceAdv, ResourceError},
};
use rns_protocol::resource::{OutboundTransfer, TransferAction};
use std::time::Duration;

#[test]
fn identification_is_accepted_by_trusted_link_and_bound_to_its_id() {
    let destination = [0x31; 16];
    let signer = Ed25519PrivateKey::generate();
    let public = signer.public_key();
    let (mut initiator, request) = Link::new_initiator(destination, 1);
    let (mut responder, proof) = Link::new_responder(&request, &signer, destination, 1).unwrap();
    let rtt = initiator
        .validate_proof(&proof, &public, &public.to_bytes())
        .unwrap();
    responder.receive_rtt_packet(&rtt).unwrap();
    let local = LocalIdentity::from_private_key(&[0x62; 64]);
    let mut bytes = [0x55; 128];
    assert_eq!(
        build_identification(&local, &initiator.link_id, &mut bytes[..127]),
        Err(LinkError::OutputTooSmall)
    );
    assert_eq!(bytes, [0x55; 128]);
    build_identification(&local, &[0xFF; 16], &mut bytes).unwrap();
    assert!(
        responder
            .handle_identification(&initiator.encrypt(&bytes).unwrap())
            .is_err()
    );
    assert_eq!(
        build_identification(&local, &initiator.link_id, &mut bytes),
        Ok(128)
    );
    let trusted = initiator
        .identify_with(local.public_key(), |data| local.sign(data))
        .unwrap();
    assert_eq!(responder.decrypt(&trusted).unwrap(), bytes);
    assert_eq!(
        responder
            .handle_identification(&initiator.encrypt(&bytes).unwrap())
            .unwrap(),
        *local.public_key()
    );
}

#[test]
fn matched_response_resource_interoperates_without_relaxing_plain_admission() {
    let a = X25519PrivateKey::from_bytes(&[0x33; 32]);
    let b = X25519PrivateKey::from_bytes(&[0x55; 32]);
    let link_id = [0xCD; 16];
    let keys = LinkKeys::derive(&[0x33; 32], &b.public_key().to_bytes(), &link_id);
    let trusted = rns_link::key_derivation::LinkKeys::derive(
        &b,
        &X25519PublicKey::from_bytes(&a.public_key().to_bytes()),
        &link_id,
        rns_link::constants::MODE_AES256_CBC,
    )
    .unwrap();
    let data: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
    let mut sender =
        OutboundTransfer::new_encrypted(data.clone(), false, Duration::from_millis(10), trusted)
            .unwrap();
    let request_id = [0xA7; 16];
    sender.resource.flags.is_response = true;
    sender.resource.request_id = Some(request_id.to_vec());
    let TransferAction::SendAdvertisement(raw) = sender.tick() else {
        panic!("missing ADV")
    };
    let adv = ResourceAdv::parse(&raw).unwrap();
    assert_eq!(
        InboundResource::from_advertisement(&adv).unwrap_err(),
        ResourceError::RequestResponseUnsupported
    );
    let seed = OutboundResource::build(b"existing", &keys, &[3; 4], &[4; 16]).unwrap();
    let mut receiver = InboundResource::from_advertisement(&seed.advertisement()).unwrap();
    let old_hash = *receiver.resource_hash();
    for variant in 0..7 {
        let mut invalid = adv;
        match variant {
            0 => invalid.request_id[0] ^= 1,
            1 => invalid.request_id_len = 0,
            2 => invalid.request_id_len = 32,
            3 => invalid.flags.is_response = false,
            4 => invalid.flags.is_request = true,
            5 => invalid.flags.compressed = true,
            _ => invalid.flags.split = true,
        }
        assert!(receiver.from_response_into(&invalid, &request_id).is_err());
        assert_eq!(
            *receiver.resource_hash(),
            old_hash,
            "refusal must preserve accepted transfer"
        );
    }
    receiver.from_response_into(&adv, &request_id).unwrap();
    for _ in 0..8 {
        if receiver.is_complete() {
            break;
        }
        let mut req = [0; REQUEST_MAX];
        let n = receiver.build_part_request(&mut req).unwrap();
        for action in sender.handle_request(&req[..n]) {
            if let TransferAction::SendPart(_, part) = action {
                assert!(receiver.receive_part(&part));
            }
        }
    }
    assert!(receiver.is_complete());
    assert_eq!(receiver.assemble(&keys).unwrap(), data.len());
    assert_eq!(receiver.data().unwrap(), data);
    let mut proof = [0; 64];
    receiver.build_proof(&mut proof).unwrap();
    assert!(sender.handle_proof(&proof));
}

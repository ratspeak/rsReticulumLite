use rns_identity::identity::Identity;
use rns_lite_core::crypto::{
    CryptoError, ECIES_PLAINTEXT_OFFSET, MAX_ECIES_PLAINTEXT, ecies_ciphertext_len,
    ecies_decrypt_in_place, ecies_encrypt, ecies_encrypt_in_place,
};

#[test]
fn large_ecies_interoperates_with_trusted_identity_both_directions() {
    let recipient = Identity::from_private_key(&[0x51; 64]).unwrap();
    let public: [u8; 32] = recipient.get_public_key()[..32].try_into().unwrap();
    for size in [0, 1, 15, 16, 31, 32, 383, 384, 431, 1024, 3500, 4096] {
        let plaintext: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
        let total = ecies_ciphertext_len(size).unwrap();
        let mut buf = vec![0; total];
        buf[ECIES_PLAINTEXT_OFFSET..ECIES_PLAINTEXT_OFFSET + size].copy_from_slice(&plaintext);
        let n =
            ecies_encrypt_in_place(&public, &recipient.hash, &[9; 32], &[7; 16], &mut buf, size)
                .unwrap();
        assert_eq!(n, total);
        assert_eq!(recipient.decrypt(&buf, None, false).unwrap(), plaintext);
        if size <= MAX_ECIES_PLAINTEXT {
            let mut packet = vec![0; total];
            assert_eq!(
                ecies_encrypt(
                    &plaintext,
                    &public,
                    &recipient.hash,
                    &[9; 32],
                    &[7; 16],
                    &mut packet
                ),
                Ok(total)
            );
            assert_eq!(buf, packet);
        }
        let mut from_trusted = recipient.encrypt(&plaintext, None).unwrap();
        assert_eq!(
            ecies_decrypt_in_place(&[0x51; 32], &recipient.hash, &mut from_trusted),
            Ok(size)
        );
        assert_eq!(
            &from_trusted[ECIES_PLAINTEXT_OFFSET..ECIES_PLAINTEXT_OFFSET + size],
            plaintext
        );
    }
}

#[test]
fn bounds_do_not_modify_input_or_relax_packet_admission() {
    let recipient = Identity::from_private_key(&[0x51; 64]).unwrap();
    let public: [u8; 32] = recipient.get_public_key()[..32].try_into().unwrap();
    let mut buf = [0x55; 512];
    for (size, expected) in [
        (500, CryptoError::OutputTooSmall),
        (usize::MAX, CryptoError::PlaintextTooLong),
    ] {
        assert_eq!(
            ecies_encrypt_in_place(&public, &recipient.hash, &[9; 32], &[7; 16], &mut buf, size),
            Err(expected)
        );
        assert_eq!(buf, [0x55; 512]);
    }
    assert_eq!(
        ecies_encrypt(
            &[0; 384],
            &public,
            &recipient.hash,
            &[9; 32],
            &[7; 16],
            &mut buf
        ),
        Err(CryptoError::PlaintextTooLong)
    );
}

#[test]
fn authentication_failures_preserve_ciphertext_for_retained_key_attempts() {
    let recipient = Identity::from_private_key(&[0x51; 64]).unwrap();
    let original = recipient.encrypt(&[0x73; 2048], None).unwrap();
    let mut data = original.clone();
    assert_eq!(
        ecies_decrypt_in_place(&[0x52; 32], &recipient.hash, &mut data),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(data, original);
    assert_eq!(
        ecies_decrypt_in_place(&[0x51; 32], &recipient.hash, &mut data),
        Ok(2048)
    );
    for offset in [0, 32, 48, original.len() - 1] {
        let mut corrupt = original.clone();
        corrupt[offset] ^= 1;
        let saved = corrupt.clone();
        assert_eq!(
            ecies_decrypt_in_place(&[0x51; 32], &recipient.hash, &mut corrupt),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(corrupt, saved);
    }
    for length in [0, 31, 32, 80, 95, 97, original.len() - 1] {
        let mut truncated = original[..length].to_vec();
        assert_eq!(
            ecies_decrypt_in_place(&[0x51; 32], &recipient.hash, &mut truncated),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

#[test]
fn large_retained_ratchet_uses_original_identity_salt() {
    let recipient = Identity::from_private_key(&[0x51; 64]).unwrap();
    let ratchet = x25519_dalek::StaticSecret::from([0x62; 32]);
    let public = x25519_dalek::PublicKey::from(&ratchet);
    let mut data = recipient
        .encrypt(&[0x73; 2000], Some(public.as_bytes()))
        .unwrap();
    assert_eq!(
        ecies_decrypt_in_place(&[0x51; 32], &recipient.hash, &mut data),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        ecies_decrypt_in_place(&[0x62; 32], &recipient.hash, &mut data),
        Ok(2000)
    );
    assert_eq!(&data[48..2048], &[0x73; 2000]);
}

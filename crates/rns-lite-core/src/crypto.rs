//! RNS SINGLE-destination encryption (ECIES) — `no_std`, no-alloc, fixed-buffer.
//!
//! Faithful port of rsReticulum `rns-crypto` (`token` + `Identity::encrypt`/`decrypt`). The
//! embedded port has no RNG/clock, so the ephemeral X25519 key and the AES IV are CALLER-supplied
//! (platform entropy on-device; fixed values for deterministic vectors). Output layout, byte-exact
//! with Python Reticulum `Identity.encrypt`:
//!
//! ```text
//! ephemeral_X25519_pub(32) || IV(16) || AES-256-CBC(PKCS7(plaintext)) || HMAC-SHA256(IV || ct)(32)
//! ```
//!
//! Token key = `HKDF-SHA256(ikm = ECDH(ephemeral, target_x25519_pub), salt = recipient_identity_hash,
//! info = "")` → 64 bytes. Per rns-crypto `Token::split_key`, the HMAC (signing) key is the FIRST
//! 32 bytes and the AES-256 key is the LAST 32 bytes. AES-256 only (rsDeck never negotiates the
//! legacy AES-128 Token).

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Raw Token overhead: IV(16) + HMAC-SHA256(32). The full token is this plus the PKCS7-padded
/// ciphertext (≥ one 16-byte block). Matches rns-wire `TOKEN_OVERHEAD` / Python `Identity.TOKEN_OVERHEAD`.
pub const TOKEN_OVERHEAD: usize = 16 + 32;

/// Non-plaintext ECIES bytes: ephemeral_pub(32) + Token overhead.
pub const ECIES_FIXED_OVERHEAD: usize = 32 + TOKEN_OVERHEAD;

/// Largest plaintext the SINGLE-dest ECIES token can wrap and still fit the Reticulum MDU — the
/// FORWARDABLE per-packet budget (MDU already reserves HEADER_MAXSIZE + IFAC so a relayed Header2
/// packet fits MTU). Matches Python `RNS.Packet.ENCRYPTED_MDU`:
/// `floor((MDU - ECIES_FIXED_OVERHEAD)/16)*16 - 1` = `floor((464-80)/16)*16 - 1` = 383. The `-1`
/// keeps the PKCS7-padded ciphertext at exactly one block budget (383 → 384), so the blob
/// (80 + 384 = 464) never exceeds the MDU. Building a larger message returns `PlaintextTooLong`
/// (the caller falls back to link delivery, mirroring Python's OPPORTUNISTIC→DIRECT downgrade).
pub const MAX_ECIES_PLAINTEXT: usize = (crate::constants::MDU - ECIES_FIXED_OVERHEAD) / 16 * 16 - 1;
const _: () = assert!(MAX_ECIES_PLAINTEXT == 383);
/// PKCS7-padded ciphertext budget: one full block past the max plaintext (383 pads to 384).
const PADDED_MAX: usize = MAX_ECIES_PLAINTEXT + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Plaintext exceeds [`MAX_ECIES_PLAINTEXT`].
    PlaintextTooLong,
    /// Caller's output buffer is too small for the result.
    OutputTooSmall,
    /// Ciphertext is malformed (too short / not block-aligned) or the HMAC/padding did not validate.
    /// All decrypt failures collapse here (padding-oracle defence).
    AuthenticationFailed,
}

/// PKCS7-pad `plaintext` into `out` (16-byte block). Block-aligned input gets a full 0x10 block,
/// per RFC 5652. Returns the padded length.
fn pkcs7_pad(plaintext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
    let pad = 16 - (plaintext.len() % 16); // 1..=16
    let total = plaintext.len() + pad;
    if out.len() < total {
        return Err(CryptoError::OutputTooSmall);
    }
    out[..plaintext.len()].copy_from_slice(plaintext);
    for b in &mut out[plaintext.len()..total] {
        *b = pad as u8;
    }
    Ok(total)
}

/// Strip + validate PKCS7 padding. Returns the unpadded slice.
fn pkcs7_unpad(data: &[u8]) -> Result<&[u8], CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::AuthenticationFailed);
    }
    let pad = data[data.len() - 1] as usize;
    if pad == 0 || pad > 16 || pad > data.len() {
        return Err(CryptoError::AuthenticationFailed);
    }
    let start = data.len() - pad;
    for &b in &data[start..] {
        if b as usize != pad {
            return Err(CryptoError::AuthenticationFailed);
        }
    }
    Ok(&data[..start])
}

/// HKDF-SHA256(ikm = shared, salt = identity_hash, info = "") → 64 bytes.
/// Matches rsReticulum `rns-crypto::hkdf::derive_key_64`.
fn derive_token_key(shared: &[u8; 32], salt: &[u8; 16]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = [0u8; 64];
    // 64 <= 255*32, so expand never fails.
    let _ = hk.expand(b"", &mut okm);
    okm
}

/// The raw RNS Token (Fernet-like) primitive — `IV(16) || AES-256-CBC(PKCS7(pt)) || HMAC-SHA256(32)`
/// over a 64-byte combined key (`signing(32) || encryption(32)`). This is the shared inner layer of
/// both SINGLE-destination ECIES (which prepends an ephemeral key) and link session encryption
/// (which derives the key from the handshake). Byte-exact with rsReticulum `rns-crypto::token`.
///
/// Per `Token::split_key`, the HMAC (signing) key is the FIRST 32 bytes and the AES-256 key is the
/// LAST 32. `PAD` bounds the PKCS7-padded plaintext (and, on decrypt, the accepted ciphertext) —
/// each caller pins its own protocol budget so an oversized frame is rejected, not buffered.
///
/// `iv` is caller-supplied entropy (`no_std`: no RNG) and MUST be fresh per frame for real traffic;
/// fixed only for deterministic test vectors.
pub fn token_encrypt<const PAD: usize>(
    plaintext: &[u8],
    key: &[u8; 64],
    iv: &[u8; 16],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let mut padded = [0u8; PAD];
    let plen = match pkcs7_pad(plaintext, &mut padded) {
        Ok(n) => n,
        // Buffer too small for the padded plaintext == plaintext exceeds this caller's budget.
        Err(_) => return Err(CryptoError::PlaintextTooLong),
    };
    let total = 16 + plen + 32;
    if out.len() < total {
        padded.zeroize();
        return Err(CryptoError::OutputTooSmall);
    }

    out[..16].copy_from_slice(iv);
    out[16..16 + plen].copy_from_slice(&padded[..plen]);
    padded.zeroize();

    // AES-256-CBC (key = key[32..]) in place over the ct region.
    let enc = Encryptor::<Aes256>::new_from_slices(&key[32..], iv)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    enc.encrypt_padded_mut::<NoPadding>(&mut out[16..16 + plen], plen)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    // HMAC-SHA256 (key = key[..32]) over IV || ct (= out[..16+plen]).
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32])
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    mac.update(&out[..16 + plen]);
    let tag = mac.finalize().into_bytes();
    out[16 + plen..total].copy_from_slice(&tag);
    Ok(total)
}

/// Inverse of [`token_encrypt`]. Constant-time HMAC verify, then AES-CBC decrypt + PKCS7 unpad.
/// Every malformed/forged input collapses to [`CryptoError::AuthenticationFailed`] (padding-oracle
/// defence). `PAD` bounds the accepted ciphertext length.
pub fn token_decrypt<const PAD: usize>(
    data: &[u8],
    key: &[u8; 64],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    // IV(16) + >=1 ct block(16) + HMAC(32).
    if data.len() < 16 + 16 + 32 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let split = data.len() - 32;
    let signed_parts = &data[..split]; // IV || ct
    let received = &data[split..];

    let mut mac = match Hmac::<Sha256>::new_from_slice(&key[..32]) {
        Ok(m) => m,
        Err(_) => return Err(CryptoError::AuthenticationFailed),
    };
    mac.update(signed_parts);
    let computed = mac.finalize().into_bytes();
    if computed.ct_eq(received).unwrap_u8() != 1 {
        return Err(CryptoError::AuthenticationFailed);
    }

    let iv = &signed_parts[..16];
    let ciphertext = &signed_parts[16..];
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 || ciphertext.len() > PAD {
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut buf = [0u8; PAD];
    buf[..ciphertext.len()].copy_from_slice(ciphertext);
    let dec = match Decryptor::<Aes256>::new_from_slices(&key[32..], iv) {
        Ok(d) => d,
        Err(_) => return Err(CryptoError::AuthenticationFailed),
    };
    let padded = match dec.decrypt_padded_mut::<NoPadding>(&mut buf[..ciphertext.len()]) {
        Ok(p) => p,
        Err(_) => {
            buf.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }
    };
    let plaintext = match pkcs7_unpad(padded) {
        Ok(p) => p,
        Err(e) => {
            buf.zeroize();
            return Err(e);
        }
    };
    if out.len() < plaintext.len() {
        buf.zeroize();
        return Err(CryptoError::OutputTooSmall);
    }
    let n = plaintext.len();
    out[..n].copy_from_slice(plaintext);
    buf.zeroize();
    Ok(n)
}

/// In-place variant of [`token_encrypt`] for frames too large for a PAD-sized stack copy (resource
/// blobs). Caller layout on entry: plaintext at `buf[16..16 + pt_len]`. Writes the IV, PKCS7-pads
/// and AES-256-CBC-encrypts in place, then appends the HMAC; returns the total token length
/// `16 + padded + 32`. The caller's fixed-size `buf` is the anti-DoS bound. Byte-identical output
/// to [`token_encrypt`] for the same key/iv/plaintext.
pub fn token_encrypt_in_place(
    key: &[u8; 64],
    iv: &[u8; 16],
    buf: &mut [u8],
    pt_len: usize,
) -> Result<usize, CryptoError> {
    let pad = 16 - (pt_len % 16); // 1..=16
    let padded = pt_len
        .checked_add(pad)
        .ok_or(CryptoError::PlaintextTooLong)?;
    let total = padded
        .checked_add(TOKEN_OVERHEAD)
        .ok_or(CryptoError::PlaintextTooLong)?;
    if buf.len() < total {
        return Err(CryptoError::OutputTooSmall);
    }

    buf[..16].copy_from_slice(iv);
    for b in &mut buf[16 + pt_len..16 + padded] {
        *b = pad as u8;
    }

    let enc = Encryptor::<Aes256>::new_from_slices(&key[32..], iv)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    enc.encrypt_padded_mut::<NoPadding>(&mut buf[16..16 + padded], padded)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32])
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    mac.update(&buf[..16 + padded]);
    let tag = mac.finalize().into_bytes();
    buf[16 + padded..total].copy_from_slice(&tag);
    Ok(total)
}

/// In-place inverse of [`token_encrypt_in_place`]: `buf` holds one full token
/// (`IV || ct || HMAC`). Constant-time HMAC verify, then decrypt + unpad in place. On success the
/// plaintext sits at `buf[16..16 + n]` and `n` is returned. Every malformed/forged input collapses
/// to [`CryptoError::AuthenticationFailed`].
pub fn token_decrypt_in_place(key: &[u8; 64], buf: &mut [u8]) -> Result<usize, CryptoError> {
    // IV(16) + >=1 ct block(16) + HMAC(32).
    if buf.len() < 16 + 16 + 32 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let split = buf.len() - 32;

    let mut mac = match Hmac::<Sha256>::new_from_slice(&key[..32]) {
        Ok(m) => m,
        Err(_) => return Err(CryptoError::AuthenticationFailed),
    };
    mac.update(&buf[..split]);
    let computed = mac.finalize().into_bytes();
    if computed.ct_eq(&buf[split..]).unwrap_u8() != 1 {
        return Err(CryptoError::AuthenticationFailed);
    }

    let ct_len = split - 16;
    if ct_len % 16 != 0 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&buf[..16]);
    let dec = match Decryptor::<Aes256>::new_from_slices(&key[32..], &iv) {
        Ok(d) => d,
        Err(_) => return Err(CryptoError::AuthenticationFailed),
    };
    if dec
        .decrypt_padded_mut::<NoPadding>(&mut buf[16..split])
        .is_err()
    {
        buf[16..split].zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }
    match pkcs7_unpad(&buf[16..split]) {
        Ok(pt) => Ok(pt.len()),
        Err(e) => {
            buf[16..split].zeroize();
            Err(e)
        }
    }
}

/// ECIES-encrypt `plaintext` to a recipient identity, writing
/// `ephemeral_pub(32) || IV(16) || ct || HMAC(32)` into `out`; returns the byte length.
///
/// `target_x25519_pub` is the recipient's X25519 public key (the first 32 bytes of their 64-byte
/// public key, or a ratchet public). `recipient_identity_hash` is the HKDF salt.
///
/// SECURITY: `ephemeral_priv` and `iv` are caller-supplied entropy (`no_std`: no RNG). On-device they
/// MUST be freshly random PER MESSAGE — reusing an `(ephemeral_priv, iv)` pair across two different
/// plaintexts leaks the AES-CBC key-stream relationship and breaks confidentiality. Fixed values are
/// ONLY for deterministic test vectors, never for real traffic.
pub fn ecies_encrypt(
    plaintext: &[u8],
    target_x25519_pub: &[u8; 32],
    recipient_identity_hash: &[u8; 16],
    ephemeral_priv: &[u8; 32],
    iv: &[u8; 16],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    if plaintext.len() > MAX_ECIES_PLAINTEXT {
        return Err(CryptoError::PlaintextTooLong);
    }

    let secret = StaticSecret::from(*ephemeral_priv);
    let ephemeral_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*target_x25519_pub));
    let mut token_key = derive_token_key(shared.as_bytes(), recipient_identity_hash);

    // ephemeral_pub(32) || token(IV || ct || HMAC). The token reuses the shared inner layer.
    if out.is_empty() || out.len() < 32 {
        token_key.zeroize();
        return Err(CryptoError::OutputTooSmall);
    }
    out[..32].copy_from_slice(ephemeral_pub.as_bytes());
    let token_len = match token_encrypt::<PADDED_MAX>(plaintext, &token_key, iv, &mut out[32..]) {
        Ok(n) => n,
        Err(e) => {
            token_key.zeroize();
            return Err(e);
        }
    };
    token_key.zeroize();
    Ok(32 + token_len)
}

/// ECIES-decrypt a payload addressed to us into `out`; returns the plaintext length.
///
/// `my_x25519_priv` is the first 32 bytes of our raw 64-byte private key; `my_identity_hash` is the
/// HKDF salt. Every malformed/forged input returns [`CryptoError::AuthenticationFailed`].
pub fn ecies_decrypt(
    data: &[u8],
    my_x25519_priv: &[u8; 32],
    my_identity_hash: &[u8; 16],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    // ephemeral_pub(32) + IV(16) + >=1 ct block(16) + HMAC(32).
    if data.len() < 32 + 16 + 16 + 32 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&data[..32]);
    let token = &data[32..];

    let secret = StaticSecret::from(*my_x25519_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_pub));
    let mut token_key = derive_token_key(shared.as_bytes(), my_identity_hash);

    let result = token_decrypt::<PADDED_MAX>(token, &token_key, out);
    token_key.zeroize();
    result
}

/// ECIES-decrypt trying retained ratchet private keys newest-first, then the base identity key
/// (upstream `Identity.decrypt` with ratchets; the base-key fallback is never disabled — no
/// enforce mode, EMB ADR 2026-07-18). Returns the plaintext length and which ratchet index
/// decrypted it (`None` = base key).
pub fn ecies_decrypt_with_ratchets(
    data: &[u8],
    ratchet_privs: &[[u8; 32]],
    my_x25519_priv: &[u8; 32],
    my_identity_hash: &[u8; 16],
    out: &mut [u8],
) -> Result<(usize, Option<usize>), CryptoError> {
    for (index, ratchet_priv) in ratchet_privs.iter().enumerate() {
        if let Ok(len) = ecies_decrypt(data, ratchet_priv, my_identity_hash, out) {
            return Ok((len, Some(index)));
        }
    }
    ecies_decrypt(data, my_x25519_priv, my_identity_hash, out).map(|len| (len, None))
}

/// ECIES-decrypt with the exact key selected by an earlier authenticated parse.
///
/// This is the bounded second-pass counterpart to [`ecies_decrypt_with_ratchets`]:
/// `Some(index)` selects exactly one retained ratchet and `None` selects exactly
/// the base identity key. An out-of-range index fails closed. It prevents a
/// peek-then-parse LXMF pipeline from scanning all 64 retained keys twice.
pub fn ecies_decrypt_with_ratchet_hint(
    data: &[u8],
    ratchet_privs: &[[u8; 32]],
    my_x25519_priv: &[u8; 32],
    my_identity_hash: &[u8; 16],
    ratchet_index: Option<usize>,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    match ratchet_index {
        Some(index) => {
            let ratchet = ratchet_privs
                .get(index)
                .ok_or(CryptoError::AuthenticationFailed)?;
            ecies_decrypt(data, ratchet, my_identity_hash, out)
        }
        None => ecies_decrypt(data, my_x25519_priv, my_identity_hash, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // X25519 keypair derived from a fixed scalar (StaticSecret clamps internally).
    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let priv_bytes = [seed; 32];
        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(&secret);
        (priv_bytes, *public.as_bytes())
    }

    #[test]
    fn ecies_decrypt_with_ratchets_tries_ring_then_base_key() {
        let (base_priv, base_pub) = keypair(0x51);
        let (old_ratchet_priv, _) = keypair(0x52);
        let (cur_ratchet_priv, cur_ratchet_pub) = keypair(0x53);
        let ring = [cur_ratchet_priv, old_ratchet_priv];
        let id_hash = [0x54u8; 16];
        let plaintext = b"ratcheted opportunistic frame";
        let mut ct = [0u8; 600];
        let mut pt = [0u8; 600];

        // Encrypted to the current ratchet: found at ring index 0.
        let n = ecies_encrypt(
            plaintext,
            &cur_ratchet_pub,
            &id_hash,
            &[0x55; 32],
            &[0x56; 16],
            &mut ct,
        )
        .unwrap();
        let (len, which) =
            ecies_decrypt_with_ratchets(&ct[..n], &ring, &base_priv, &id_hash, &mut pt).unwrap();
        assert_eq!((&pt[..len], which), (&plaintext[..], Some(0)));

        // Encrypted to the base identity key: ring misses, fallback decrypts (never enforced).
        let n = ecies_encrypt(
            plaintext,
            &base_pub,
            &id_hash,
            &[0x57; 32],
            &[0x58; 16],
            &mut ct,
        )
        .unwrap();
        let (len, which) =
            ecies_decrypt_with_ratchets(&ct[..n], &ring, &base_priv, &id_hash, &mut pt).unwrap();
        assert_eq!((&pt[..len], which), (&plaintext[..], None));

        // Encrypted to an unknown ratchet: every key fails closed.
        let (_, unknown_pub) = keypair(0x59);
        let n = ecies_encrypt(
            plaintext,
            &unknown_pub,
            &id_hash,
            &[0x5A; 32],
            &[0x5B; 16],
            &mut ct,
        )
        .unwrap();
        assert_eq!(
            ecies_decrypt_with_ratchets(&ct[..n], &ring, &base_priv, &id_hash, &mut pt),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn ratchet_hint_uses_exact_key_and_rejects_untrusted_index() {
        let (base_priv, _) = keypair(0x61);
        let (newest_priv, _) = keypair(0x62);
        let (old_priv, old_pub) = keypair(0x63);
        let ring = [newest_priv, old_priv];
        let id_hash = [0x64; 16];
        let mut ct = [0u8; 600];
        let mut pt = [0u8; 600];
        let plaintext = b"single hinted decrypt attempt";
        let n = ecies_encrypt(
            plaintext,
            &old_pub,
            &id_hash,
            &[0x65; 32],
            &[0x66; 16],
            &mut ct,
        )
        .unwrap();

        let len = ecies_decrypt_with_ratchet_hint(
            &ct[..n],
            &ring,
            &base_priv,
            &id_hash,
            Some(1),
            &mut pt,
        )
        .unwrap();
        assert_eq!(&pt[..len], plaintext);
        assert_eq!(
            ecies_decrypt_with_ratchet_hint(
                &ct[..n],
                &ring,
                &base_priv,
                &id_hash,
                Some(ring.len()),
                &mut pt,
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            ecies_decrypt_with_ratchet_hint(&ct[..n], &ring, &base_priv, &id_hash, None, &mut pt,),
            Err(CryptoError::AuthenticationFailed),
            "base hint must not silently rescan the ring"
        );
    }

    #[test]
    fn ecies_roundtrip() {
        let (recip_priv, recip_pub) = keypair(0x11);
        let id_hash = [0x22u8; 16];
        let ephemeral = [0x33u8; 32];
        let iv = [0x44u8; 16];
        let plaintext = b"opportunistic lxmf single frame";

        let mut ct = [0u8; 600];
        let n = ecies_encrypt(plaintext, &recip_pub, &id_hash, &ephemeral, &iv, &mut ct).unwrap();
        // ephemeral(32) + IV(16) + ct(32, two blocks for 31 bytes) + HMAC(32) = 112.
        assert_eq!(n, 32 + 16 + 32 + 32);

        let mut pt = [0u8; 600];
        let m = ecies_decrypt(&ct[..n], &recip_priv, &id_hash, &mut pt).unwrap();
        assert_eq!(&pt[..m], plaintext);
    }

    #[test]
    fn ecies_deterministic_for_fixed_ephemeral_and_iv() {
        let (_, recip_pub) = keypair(0x55);
        let id_hash = [0x66u8; 16];
        let ephemeral = [0x77u8; 32];
        let iv = [0x88u8; 16];
        let mut a = [0u8; 300];
        let mut b = [0u8; 300];
        let na = ecies_encrypt(b"hi", &recip_pub, &id_hash, &ephemeral, &iv, &mut a).unwrap();
        let nb = ecies_encrypt(b"hi", &recip_pub, &id_hash, &ephemeral, &iv, &mut b).unwrap();
        assert_eq!(a[..na], b[..nb]);
    }

    #[test]
    fn ecies_tampered_hmac_fails() {
        let (recip_priv, recip_pub) = keypair(0x11);
        let id_hash = [0x22u8; 16];
        let mut ct = [0u8; 300];
        let n = ecies_encrypt(
            b"secret",
            &recip_pub,
            &id_hash,
            &[0x33; 32],
            &[0x44; 16],
            &mut ct,
        )
        .unwrap();
        ct[n - 1] ^= 0xFF;
        let mut pt = [0u8; 300];
        assert_eq!(
            ecies_decrypt(&ct[..n], &recip_priv, &id_hash, &mut pt),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn ecies_wrong_recipient_fails() {
        let (_, recip_pub) = keypair(0x11);
        let (wrong_priv, _) = keypair(0x99);
        let id_hash = [0x22u8; 16];
        let mut ct = [0u8; 300];
        let n = ecies_encrypt(
            b"secret",
            &recip_pub,
            &id_hash,
            &[0x33; 32],
            &[0x44; 16],
            &mut ct,
        )
        .unwrap();
        let mut pt = [0u8; 300];
        assert_eq!(
            ecies_decrypt(&ct[..n], &wrong_priv, &id_hash, &mut pt),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn token_in_place_matches_stack_variant() {
        let key = [0x5Au8; 64];
        let iv = [0x77u8; 16];
        for len in [0usize, 1, 15, 16, 17, 100, 464] {
            let pt = [0xC3u8; 464];
            let mut stack_ct = [0u8; 600];
            let n = token_encrypt::<480>(&pt[..len], &key, &iv, &mut stack_ct).unwrap();

            let mut buf = [0u8; 600];
            buf[16..16 + len].copy_from_slice(&pt[..len]);
            let m = token_encrypt_in_place(&key, &iv, &mut buf, len).unwrap();
            assert_eq!(&buf[..m], &stack_ct[..n]);

            let k = token_decrypt_in_place(&key, &mut buf[..m]).unwrap();
            assert_eq!(&buf[16..16 + k], &pt[..len]);
        }
    }

    #[test]
    fn token_in_place_rejects_tamper_and_bounds() {
        let key = [0x5Au8; 64];
        let mut buf = [0u8; 128];
        buf[16..24].copy_from_slice(b"resource");
        let n = token_encrypt_in_place(&key, &[0x01; 16], &mut buf, 8).unwrap();
        // Tampered ciphertext fails the HMAC.
        let mut bad = buf;
        bad[20] ^= 0xFF;
        assert_eq!(
            token_decrypt_in_place(&key, &mut bad[..n]),
            Err(CryptoError::AuthenticationFailed)
        );
        // Too-short input and non-block-aligned ct collapse to the same error.
        assert_eq!(
            token_decrypt_in_place(&key, &mut buf[..48]),
            Err(CryptoError::AuthenticationFailed)
        );
        // Output buffer too small for padded plaintext + overhead.
        let mut tiny = [0u8; 60];
        assert_eq!(
            token_encrypt_in_place(&key, &[0x01; 16], &mut tiny, 8),
            Err(CryptoError::OutputTooSmall)
        );
    }

    #[test]
    fn pkcs7_roundtrip_all_lengths() {
        for len in 0..64usize {
            let data = [0xABu8; 64];
            let mut buf = [0u8; 96];
            let n = pkcs7_pad(&data[..len], &mut buf).unwrap();
            assert_eq!(n % 16, 0);
            assert!(n > len);
            assert_eq!(pkcs7_unpad(&buf[..n]).unwrap(), &data[..len]);
        }
    }
}

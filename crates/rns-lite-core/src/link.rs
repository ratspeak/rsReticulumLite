//! Reticulum LINK establishment + session encryption — `no_std`, no-alloc, fixed-buffer.
//!
//! Faithful port of rsReticulum `rns-link` (`handshake`, `key_derivation`, `encryption`,
//! `mtu_discovery`), byte-exact with Python RNS 1.4.2 `RNS.Link`. This module provides
//! cryptographic and wire primitives for initiators and responders; the caller owns
//! the link state machine, timers and packet I/O.
//!
//! Handshake (two packets):
//! ```text
//! 1. LINKREQUEST  (initiator -> dest):  x25519_pub(32) || ed25519_pub(32) || signalling(3)
//!    link_id = truncated_hash( 0x02 || dest_hash(16) || 0x00 || x25519_pub || ed25519_pub )
//!    (the signalling trailer is EXCLUDED from the link_id so both sides agree pre-negotiation)
//! 2. LRPROOF      (dest -> initiator):  signature(64) || responder_x25519_pub(32) || signalling(3)
//!    signature = identity.sign( link_id || responder_x25519_pub || identity_ed25519_pub || signalling )
//! ```
//! Both sides then derive the session key `HKDF-SHA256(64, ikm = ECDH, salt = link_id, info = "")`
//! → `signing(32) || encryption(32)`, and frames are encrypted with the shared [`crate::crypto`]
//! Token layer (`IV(16) || AES-256-CBC(PKCS7(pt)) || HMAC-SHA256(32)`). Only AES-256-CBC
//! is supported; the legacy AES-128 link mode is rejected.
//!
//! Packet proofs ON an established link are role-strict (trusted `f7ae027`): the INITIATOR proves
//! with the LINKREQUEST transient Ed25519 key (so it must retain that seed for the link's life),
//! the RESPONDER proves with the destination identity; on-link proofs are always the explicit
//! 96-byte form. The signer choice is the host owner's — [`crate::proof::build_proof`] takes an
//! explicit signer and never falls back to the identity key.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::constants::{DESTINATION_LENGTH, MDU, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::crypto::{CryptoError, token_decrypt, token_encrypt};
use crate::identity::LocalIdentity;
use crate::wire::truncated_hash;

/// X25519 / Ed25519 public key size.
pub const KEYSIZE: usize = 32;
/// Combined ephemeral public block: X25519(32) || Ed25519(32).
pub const ECPUBSIZE: usize = 64;
/// MTU/mode signalling trailer size.
pub const LINK_MTU_SIZE: usize = 3;

/// Legacy LINKREQUEST payload (keys only) / modern (keys + signalling).
pub const LINK_REQUEST_LEGACY_LEN: usize = ECPUBSIZE;
pub const LINK_REQUEST_LEN: usize = ECPUBSIZE + LINK_MTU_SIZE;
/// Legacy LRPROOF payload (sig + key) / modern (sig + key + signalling).
pub const LINK_PROOF_LEGACY_LEN: usize = SIGNATURE_LENGTH + KEYSIZE;
pub const LINK_PROOF_LEN: usize = SIGNATURE_LENGTH + KEYSIZE + LINK_MTU_SIZE;

/// AES-256-CBC link mode (the only mode rsDeck enables).
pub const MODE_AES256_CBC: u8 = 0x01;
pub const DEFAULT_MODE: u8 = MODE_AES256_CBC;
/// AES-256 derived key length: cipher(32) || HMAC(32).
pub const LINK_KEY_LENGTH: usize = 64;

const MTU_BYTEMASK: u32 = 0x001F_FFFF;
const MODE_BYTEMASK: u32 = 0x00E0;

/// PKCS7-padded plaintext budget for one link frame. A generous bound at the Reticulum MDU (a clean
/// 29 AES blocks); the link/resource layer is responsible for sizing each frame's plaintext to fit
/// the negotiated MTU — this is only the fixed-buffer / anti-DoS cap on what [`link_decrypt`] will
/// buffer. Larger ciphertext is rejected, never allocated. NOTE: this is the receive-buffer ceiling,
/// NOT the negotiated link plaintext MDU — use [`link_mdu`] / [`LINK_MDU`] for frame plaintext sizing.
pub const LINK_PADDED_MAX: usize = MDU;
const _: () = assert!(LINK_PADDED_MAX % 16 == 0);

/// Negotiated link plaintext MDU for a given MTU: the largest plaintext whose Token frame still
/// fits one relayed packet, `floor((mtu - IFAC_MIN(1) - HEADER_MINSIZE - TOKEN_OVERHEAD)/16)*16 - 1`
/// (the trailing `-1` reserves the PKCS7 worst case). Byte-exact with Python RNS 1.4.2 `Link.mdu` /
/// rsReticulum `rns-link::Link::update_mdu`. Returns 0 when the MTU cannot carry one AES block.
pub const fn link_mdu(mtu: usize) -> usize {
    let overhead = 1 + crate::constants::HEADER_MINSIZE + crate::crypto::TOKEN_OVERHEAD;
    if mtu <= overhead {
        return 0;
    }
    let blocks = (mtu - overhead) / 16;
    if blocks == 0 { 0 } else { blocks * 16 - 1 }
}

/// Link plaintext MDU at the default Reticulum MTU (500) — Python `RNS.Link.MDU` = 431.
pub const LINK_MDU: usize = link_mdu(crate::constants::MTU);
const _: () = assert!(LINK_MDU == 431);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkError {
    /// Output buffer too small for the requested artefact.
    OutputTooSmall,
    /// Payload length is not a valid LINKREQUEST / LRPROOF size.
    InvalidLength,
    /// Requested encryption mode is not enabled (rsDeck enables AES-256-CBC only). Mirrors Python
    /// `Link.signalling_bytes` raising for a mode outside `ENABLED_MODES`.
    UnsupportedMode,
}

/// MTU + encryption-mode signalling, packed into 3 big-endian bytes:
/// `[23:21] mode (0..=7)`, `[20:0] mtu`. Port of rsReticulum `SignallingData` / Python
/// `Link.signalling_bytes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignallingData {
    pub mode: u8,
    pub mtu: u32,
}

impl SignallingData {
    pub fn new(mode: u8, mtu: u32) -> Self {
        Self {
            mode: mode & 0x07,
            mtu: mtu & MTU_BYTEMASK,
        }
    }

    /// The default AES-256 / MTU=500 signalling used when a peer sends a legacy (key-only) payload.
    pub fn default_signalling() -> Self {
        Self::new(DEFAULT_MODE, crate::constants::MTU as u32)
    }

    pub fn pack(&self) -> [u8; 3] {
        let value = (self.mtu & MTU_BYTEMASK) | ((((self.mode as u32) << 5) & MODE_BYTEMASK) << 16);
        let bytes = value.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    pub fn unpack(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        Some(Self {
            mode: ((value >> 21) & 0x07) as u8,
            mtu: value & MTU_BYTEMASK,
        })
    }
}

/// Compute the 16-byte link id from the destination hash and the LINKREQUEST payload.
///
/// `link_id = truncated_hash( 0x02 || dest_hash || 0x00 || request[..64] )` — the low flag nibble
/// of a LINKREQUEST/Single packet (`0x02`), the destination hash, the `None` context byte, and the
/// two ephemeral public keys. The signalling trailer is EXCLUDED (only the first 64 request bytes
/// are hashed) so both peers agree on the same id regardless of MTU/mode negotiation.
pub fn compute_link_id(
    destination_hash: &[u8; DESTINATION_LENGTH],
    request_data: &[u8],
) -> [u8; DESTINATION_LENGTH] {
    let key_len = request_data.len().min(ECPUBSIZE);
    let mut hashable = [0u8; 1 + DESTINATION_LENGTH + 1 + ECPUBSIZE];
    hashable[0] = 0x02; // LinkRequest(0x02) | Single(0x00)
    hashable[1..1 + DESTINATION_LENGTH].copy_from_slice(destination_hash);
    hashable[1 + DESTINATION_LENGTH] = 0x00; // context None
    let body = 2 + DESTINATION_LENGTH;
    hashable[body..body + key_len].copy_from_slice(&request_data[..key_len]);
    truncated_hash(&hashable[..body + key_len])
}

/// Build a LINKREQUEST payload (initiator → destination) into `out`, returning its length (67).
///
/// `x25519_priv` and `ed25519_seed` are the initiator's per-link EPHEMERAL key material (caller-
/// supplied entropy; `no_std` has no RNG). The initiator MUST retain `x25519_priv` to derive the
/// session keys once the proof arrives. The two public keys are derived here and written as
/// `x25519_pub(32) || ed25519_pub(32) || signalling(3)`.
pub fn build_link_request(
    x25519_priv: &[u8; KEYSIZE],
    ed25519_seed: &[u8; KEYSIZE],
    signalling: SignallingData,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    if signalling.mode != MODE_AES256_CBC {
        return Err(LinkError::UnsupportedMode);
    }
    if out.len() < LINK_REQUEST_LEN {
        return Err(LinkError::OutputTooSmall);
    }
    let x_pub = PublicKey::from(&StaticSecret::from(*x25519_priv));
    let ed_pub = ed25519_dalek::SigningKey::from_bytes(ed25519_seed).verifying_key();

    out[..KEYSIZE].copy_from_slice(x_pub.as_bytes());
    out[KEYSIZE..ECPUBSIZE].copy_from_slice(ed_pub.as_bytes());
    out[ECPUBSIZE..LINK_REQUEST_LEN].copy_from_slice(&signalling.pack());
    Ok(LINK_REQUEST_LEN)
}

/// A parsed LINKREQUEST payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkRequestView {
    pub peer_x25519_pub: [u8; KEYSIZE],
    pub peer_ed25519_pub: [u8; KEYSIZE],
    pub signalling: SignallingData,
}

impl LinkRequestView {
    /// Parse a LINKREQUEST payload. Accepts exactly the legacy 64-byte or modern 67-byte form
    /// (matching Python `Link.validate_request`); any other length is rejected.
    pub fn parse(data: &[u8]) -> Result<Self, LinkError> {
        if data.len() != LINK_REQUEST_LEGACY_LEN && data.len() != LINK_REQUEST_LEN {
            return Err(LinkError::InvalidLength);
        }
        let mut peer_x25519_pub = [0u8; KEYSIZE];
        let mut peer_ed25519_pub = [0u8; KEYSIZE];
        peer_x25519_pub.copy_from_slice(&data[..KEYSIZE]);
        peer_ed25519_pub.copy_from_slice(&data[KEYSIZE..ECPUBSIZE]);
        let signalling = if data.len() == LINK_REQUEST_LEN {
            SignallingData::unpack(&data[ECPUBSIZE..LINK_REQUEST_LEN])
                .unwrap_or_else(SignallingData::default_signalling)
        } else {
            SignallingData::default_signalling()
        };
        Ok(Self {
            peer_x25519_pub,
            peer_ed25519_pub,
            signalling,
        })
    }
}

/// Build an LRPROOF payload (destination → initiator) into `out`, returning its length (99).
///
/// `identity` is the destination's LONG-TERM identity (its Ed25519 key authenticates the link).
/// `responder_x25519_priv` is the responder's per-link EPHEMERAL X25519 key (caller-supplied; the
/// responder retains it to derive the session keys). The signature binds
/// `link_id || responder_x25519_pub || identity_ed25519_pub || signalling`. Layout:
/// `signature(64) || responder_x25519_pub(32) || signalling(3)`.
pub fn build_link_proof(
    identity: &LocalIdentity,
    responder_x25519_priv: &[u8; KEYSIZE],
    link_id: &[u8; DESTINATION_LENGTH],
    signalling: SignallingData,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    if signalling.mode != MODE_AES256_CBC {
        return Err(LinkError::UnsupportedMode);
    }
    if out.len() < LINK_PROOF_LEN {
        return Err(LinkError::OutputTooSmall);
    }
    let responder_x25519_pub =
        *PublicKey::from(&StaticSecret::from(*responder_x25519_priv)).as_bytes();
    let identity_ed25519_pub = &identity.public_key()[KEYSIZE..PUBLIC_KEY_LENGTH];

    // signed_data = link_id || responder_x25519_pub || identity_ed25519_pub || signalling
    let sig_bytes = signalling.pack();
    let mut signed = [0u8; DESTINATION_LENGTH + KEYSIZE + KEYSIZE + LINK_MTU_SIZE];
    let mut s = 0;
    signed[s..s + DESTINATION_LENGTH].copy_from_slice(link_id);
    s += DESTINATION_LENGTH;
    signed[s..s + KEYSIZE].copy_from_slice(&responder_x25519_pub);
    s += KEYSIZE;
    signed[s..s + KEYSIZE].copy_from_slice(identity_ed25519_pub);
    s += KEYSIZE;
    signed[s..s + LINK_MTU_SIZE].copy_from_slice(&sig_bytes);
    s += LINK_MTU_SIZE;
    let signature = identity.sign(&signed[..s]);

    out[..SIGNATURE_LENGTH].copy_from_slice(&signature);
    out[SIGNATURE_LENGTH..SIGNATURE_LENGTH + KEYSIZE].copy_from_slice(&responder_x25519_pub);
    out[SIGNATURE_LENGTH + KEYSIZE..LINK_PROOF_LEN].copy_from_slice(&sig_bytes);
    Ok(LINK_PROOF_LEN)
}

/// A parsed LRPROOF payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkProofView {
    pub signature: [u8; SIGNATURE_LENGTH],
    pub responder_x25519_pub: [u8; KEYSIZE],
    pub signalling: SignallingData,
}

impl LinkProofView {
    /// Parse an LRPROOF payload. Accepts exactly the legacy 96-byte or modern 99-byte form.
    pub fn parse(data: &[u8]) -> Result<Self, LinkError> {
        if data.len() != LINK_PROOF_LEGACY_LEN && data.len() != LINK_PROOF_LEN {
            return Err(LinkError::InvalidLength);
        }
        let mut signature = [0u8; SIGNATURE_LENGTH];
        let mut responder_x25519_pub = [0u8; KEYSIZE];
        signature.copy_from_slice(&data[..SIGNATURE_LENGTH]);
        responder_x25519_pub.copy_from_slice(&data[SIGNATURE_LENGTH..SIGNATURE_LENGTH + KEYSIZE]);
        let signalling = if data.len() == LINK_PROOF_LEN {
            SignallingData::unpack(&data[SIGNATURE_LENGTH + KEYSIZE..LINK_PROOF_LEN])
                .unwrap_or_else(SignallingData::default_signalling)
        } else {
            SignallingData::default_signalling()
        };
        Ok(Self {
            signature,
            responder_x25519_pub,
            signalling,
        })
    }

    /// Verify this proof against the destination identity's 64-byte public key and the link id.
    /// Reconstructs `link_id || responder_x25519_pub || identity_ed25519_pub || signalling` and
    /// checks the Ed25519 signature (permissive `verify`, matching pyca / the network).
    ///
    /// Rejects any proof whose advertised mode is not AES-256-CBC — rsDeck's only enabled link mode.
    /// This mirrors Python `Link.validate_proof` raising on `mode != self.mode` (the initiator's mode
    /// is always AES-256), so a peer that down-/cross-negotiates to AES-128 or GCM fails visibly here
    /// instead of silently agreeing on an AES-256 key the peer isn't using.
    pub fn validate(
        &self,
        identity_public_key: &[u8; PUBLIC_KEY_LENGTH],
        link_id: &[u8; DESTINATION_LENGTH],
    ) -> bool {
        if self.signalling.mode != MODE_AES256_CBC {
            return false;
        }
        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&identity_public_key[KEYSIZE..PUBLIC_KEY_LENGTH]);
        let key = match VerifyingKey::from_bytes(&ed_pub) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig_bytes = self.signalling.pack();
        let mut signed = [0u8; DESTINATION_LENGTH + KEYSIZE + KEYSIZE + LINK_MTU_SIZE];
        let mut s = 0;
        signed[s..s + DESTINATION_LENGTH].copy_from_slice(link_id);
        s += DESTINATION_LENGTH;
        signed[s..s + KEYSIZE].copy_from_slice(&self.responder_x25519_pub);
        s += KEYSIZE;
        signed[s..s + KEYSIZE].copy_from_slice(&ed_pub);
        s += KEYSIZE;
        signed[s..s + LINK_MTU_SIZE].copy_from_slice(&sig_bytes);
        s += LINK_MTU_SIZE;
        let signature = Signature::from_bytes(&self.signature);
        key.verify(&signed[..s], &signature).is_ok()
    }
}

/// Derived link session key: `signing(32) || encryption(32)`. Zeroized on drop. Both peers compute
/// the identical key from the ECDH of their ephemeral X25519 keys salted by the shared link id.
pub struct LinkKeys {
    key: [u8; LINK_KEY_LENGTH],
}

impl LinkKeys {
    /// `HKDF-SHA256(64, ikm = ECDH(my_x25519_priv, peer_x25519_pub), salt = link_id, info = "")`.
    /// Byte-exact with Python `Link.handshake` (`derived_key_length = 64`, `salt = link_id`,
    /// `context = None`).
    pub fn derive(
        my_x25519_priv: &[u8; KEYSIZE],
        peer_x25519_pub: &[u8; KEYSIZE],
        link_id: &[u8; DESTINATION_LENGTH],
    ) -> Self {
        let secret = StaticSecret::from(*my_x25519_priv);
        let shared = secret.diffie_hellman(&PublicKey::from(*peer_x25519_pub));
        let hk = Hkdf::<Sha256>::new(Some(link_id), shared.as_bytes());
        let mut key = [0u8; LINK_KEY_LENGTH];
        // 64 <= 255*32, so expand never fails.
        let _ = hk.expand(b"", &mut key);
        Self { key }
    }

    /// Reconstruct from a previously-derived combined key (`signing(32) || encryption(32)`). For the
    /// firmware seam, where the C++ link owner holds the 64-byte session key for the link's lifetime
    /// and passes it back per frame — the key never re-derives, so the per-frame call is stateless.
    /// The caller MUST zeroize its copy when the link closes.
    pub fn from_combined(key: &[u8; LINK_KEY_LENGTH]) -> Self {
        Self { key: *key }
    }

    /// The HMAC (signing) half — first 32 bytes.
    pub fn signing_key(&self) -> &[u8] {
        &self.key[..32]
    }
    /// The AES-256 (encryption) half — last 32 bytes.
    pub fn encryption_key(&self) -> &[u8] {
        &self.key[32..]
    }
    /// The full 64-byte combined key (for [`crate::crypto::token_encrypt`]).
    pub fn combined(&self) -> &[u8; LINK_KEY_LENGTH] {
        &self.key
    }
}

impl Drop for LinkKeys {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Encrypt a link frame with the session key. `iv` is caller-supplied entropy and MUST be fresh per
/// frame (reusing an IV across two plaintexts under one key leaks the CBC key-stream relationship).
/// Output: `IV(16) || AES-256-CBC(PKCS7(pt)) || HMAC-SHA256(32)`.
pub fn link_encrypt(
    keys: &LinkKeys,
    plaintext: &[u8],
    iv: &[u8; 16],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    token_encrypt::<LINK_PADDED_MAX>(plaintext, keys.combined(), iv, out)
}

/// Decrypt a link frame with the session key. Every malformed/forged input collapses to
/// [`CryptoError::AuthenticationFailed`].
pub fn link_decrypt(
    keys: &LinkKeys,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    token_decrypt::<LINK_PADDED_MAX>(ciphertext, keys.combined(), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const M: usize>(s: &str) -> [u8; M] {
        let b = s.as_bytes();
        let mut o = [0u8; M];
        let mut i = 0;
        while i < M {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            o[i] = (hi << 4) | lo;
            i += 1;
        }
        o
    }

    const INCREMENTING: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    #[test]
    fn signalling_roundtrip() {
        for (mode, mtu) in [(1u8, 500u32), (0, 500), (7, MTU_BYTEMASK), (1, 1500)] {
            let sd = SignallingData::new(mode, mtu);
            let packed = sd.pack();
            let back = SignallingData::unpack(&packed).unwrap();
            assert_eq!(back, sd);
        }
    }

    #[test]
    fn link_id_excludes_signalling_includes_dest() {
        let xpub = [0x11u8; 32];
        let edpub = [0x22u8; 32];
        let dest = [0xAAu8; 16];
        let mut req1 = [0u8; LINK_REQUEST_LEN];
        let mut req2 = [0u8; LINK_REQUEST_LEN];
        req1[..32].copy_from_slice(&xpub);
        req1[32..64].copy_from_slice(&edpub);
        req1[64..].copy_from_slice(&SignallingData::new(1, 500).pack());
        req2.copy_from_slice(&req1);
        req2[64..].copy_from_slice(&SignallingData::new(1, 1500).pack());
        // Different signalling, same keys -> same link_id.
        assert_eq!(compute_link_id(&dest, &req1), compute_link_id(&dest, &req2));
        // Different dest -> different link_id.
        assert_ne!(
            compute_link_id(&dest, &req1),
            compute_link_id(&[0xBB; 16], &req1)
        );
        // Legacy (64-byte) form hashes identically to the modern form's key prefix.
        assert_eq!(
            compute_link_id(&dest, &req1),
            compute_link_id(&dest, &req1[..64])
        );
    }

    #[test]
    fn full_handshake_key_agreement_and_proof() {
        // Destination long-term identity.
        let identity = LocalIdentity::from_private_key(&unhex::<64>(INCREMENTING));
        let dest_hash = identity.lxmf_delivery_hash();

        // Initiator ephemeral.
        let init_x = [0x33u8; 32];
        let init_ed = [0x44u8; 32];
        let mut request = [0u8; LINK_REQUEST_LEN];
        let n = build_link_request(&init_x, &init_ed, SignallingData::new(1, 500), &mut request)
            .unwrap();
        assert_eq!(n, LINK_REQUEST_LEN);
        let req = LinkRequestView::parse(&request).unwrap();

        let link_id = compute_link_id(&dest_hash, &request);

        // Responder ephemeral + proof.
        let resp_x = [0x55u8; 32];
        let mut proof = [0u8; LINK_PROOF_LEN];
        let pn =
            build_link_proof(&identity, &resp_x, &link_id, req.signalling, &mut proof).unwrap();
        assert_eq!(pn, LINK_PROOF_LEN);
        let proof_view = LinkProofView::parse(&proof).unwrap();

        // Initiator validates the proof with the destination identity's public key.
        assert!(proof_view.validate(identity.public_key(), &link_id));
        // Wrong link id -> invalid.
        assert!(!proof_view.validate(identity.public_key(), &[0x00; 16]));
        // Tampered signature -> invalid.
        let mut bad = proof;
        bad[0] ^= 0xFF;
        assert!(
            !LinkProofView::parse(&bad)
                .unwrap()
                .validate(identity.public_key(), &link_id)
        );

        // Both sides derive the same session key.
        let init_keys = LinkKeys::derive(&init_x, &proof_view.responder_x25519_pub, &link_id);
        let resp_keys = LinkKeys::derive(&resp_x, &req.peer_x25519_pub, &link_id);
        assert_eq!(init_keys.combined(), resp_keys.combined());

        // Encrypt one way, decrypt the other.
        let msg = b"reticulum link data frame";
        let mut ct = [0u8; 128];
        let cn = link_encrypt(&init_keys, msg, &[0x66; 16], &mut ct).unwrap();
        let mut pt = [0u8; 128];
        let pn2 = link_decrypt(&resp_keys, &ct[..cn], &mut pt).unwrap();
        assert_eq!(&pt[..pn2], msg);
    }

    #[test]
    fn rejects_bad_lengths() {
        assert_eq!(
            LinkRequestView::parse(&[0u8; 63]),
            Err(LinkError::InvalidLength)
        );
        assert_eq!(
            LinkRequestView::parse(&[0u8; 65]),
            Err(LinkError::InvalidLength)
        );
        assert_eq!(
            LinkProofView::parse(&[0u8; 95]),
            Err(LinkError::InvalidLength)
        );
        assert_eq!(
            LinkProofView::parse(&[0u8; 100]),
            Err(LinkError::InvalidLength)
        );
        // Legacy lengths are accepted.
        assert!(LinkRequestView::parse(&[0u8; LINK_REQUEST_LEGACY_LEN]).is_ok());
        assert!(LinkProofView::parse(&[0u8; LINK_PROOF_LEGACY_LEN]).is_ok());
    }

    #[test]
    fn rejects_unsupported_mode() {
        let identity = LocalIdentity::from_private_key(&unhex::<64>(INCREMENTING));
        let mut buf = [0u8; LINK_PROOF_LEN];
        // Build with a non-AES-256 mode (0 = AES-128, 2 = GCM) is refused.
        for mode in [0u8, 2, 3] {
            assert_eq!(
                build_link_request(
                    &[0x33; 32],
                    &[0x44; 32],
                    SignallingData::new(mode, 500),
                    &mut buf
                ),
                Err(LinkError::UnsupportedMode)
            );
            assert_eq!(
                build_link_proof(
                    &identity,
                    &[0x55; 32],
                    &[0xCD; 16],
                    SignallingData::new(mode, 500),
                    &mut buf
                ),
                Err(LinkError::UnsupportedMode)
            );
        }
        // A structurally valid, correctly-SIGNED proof that advertises a non-AES-256 mode must still
        // be rejected by validate (mirrors Python's mode-mismatch refusal). Forge the signed_data so
        // the signature itself is valid for mode=0, then confirm validate rejects on the mode gate.
        let link_id = [0xCDu8; 16];
        let resp_x_pub =
            *x25519_dalek::PublicKey::from(&StaticSecret::from([0x55u8; 32])).as_bytes();
        let sig = SignallingData::new(0, 500); // AES-128 — not enabled
        let ed_pub: [u8; 32] = identity.public_key()[32..].try_into().unwrap();
        let mut signed = [0u8; 16 + 32 + 32 + 3];
        signed[..16].copy_from_slice(&link_id);
        signed[16..48].copy_from_slice(&resp_x_pub);
        signed[48..80].copy_from_slice(&ed_pub);
        signed[80..83].copy_from_slice(&sig.pack());
        let signature = identity.sign(&signed);
        let mut proof = [0u8; LINK_PROOF_LEN];
        proof[..64].copy_from_slice(&signature);
        proof[64..96].copy_from_slice(&resp_x_pub);
        proof[96..99].copy_from_slice(&sig.pack());
        let view = LinkProofView::parse(&proof).unwrap();
        assert_eq!(view.signalling.mode, 0);
        assert!(!view.validate(identity.public_key(), &link_id)); // rejected on the mode gate
    }
}

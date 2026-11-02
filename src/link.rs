//! Reticulum Link handshake and encryption primitives with fixed buffers.
//!
//! These helpers use the full Rust stack's wire layout and AES-256 Token format.
//! The caller owns state, timers, entropy and packet I/O. Builders and proof
//! validation enforce AES-256-CBC with an effective MTU of 500; structural
//! parsers accept a wider signalling domain for callers to inspect.
//!
//! ```text
//! LINKREQUEST: x25519_pub(32) || ed25519_pub(32) || signalling(3)
//! LRPROOF:     signature(64) || responder_x25519_pub(32) || signalling(3)
//! ```
//!
//! The link ID hashes the request's key block with its destination and packet
//! type/context; signalling is excluded. The proof signs the link ID, responder
//! X25519 key, destination Ed25519 key and optional signalling trailer. Legacy
//! request/proof forms omit that trailer. Derivation uses X25519 and HKDF-SHA256
//! with the link ID as salt, yielding `HMAC key(32) || AES key(32)`.
//!
//! On-link packet receipts use explicit 96-byte proofs. Initiators sign with the
//! request's retained ephemeral Ed25519 seed via
//! [`crate::proof::build_initiator_proof`]; responders use their destination
//! identity via [`crate::proof::build_proof`]. The host enforces role and state.

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

/// AES-256-CBC link mode, the only mode enabled by these endpoint helpers.
pub const MODE_AES256_CBC: u8 = 0x01;
pub const DEFAULT_MODE: u8 = MODE_AES256_CBC;
/// AES-256 derived key length: HMAC key(32) followed by AES key(32).
pub const LINK_KEY_LENGTH: usize = 64;

/// Build the plaintext for LINKIDENTIFY, adapted from `rns-link::Link::identify`.
/// The host must use this only on an ACTIVE initiator Link, encrypt it with that
/// Link's session key and send with context 0xFB. This does not authenticate the
/// receiver; the normal Link proof must already have done that.
pub fn build_identification(
    identity: &LocalIdentity,
    link_id: &[u8; DESTINATION_LENGTH],
    out: &mut [u8],
) -> Result<usize, LinkError> {
    if out.len() < 128 {
        return Err(LinkError::OutputTooSmall);
    }
    let mut signed = [0u8; 80];
    signed[..16].copy_from_slice(link_id);
    signed[16..].copy_from_slice(identity.public_key());
    out[..64].copy_from_slice(identity.public_key());
    out[64..128].copy_from_slice(&identity.sign(&signed));
    Ok(128)
}

/// Verify exactly one decrypted LINKIDENTIFY public-key/signature payload.
/// Adapted from the pinned trusted `rns-link::Link::handle_identification`.
///
/// The owner must first authenticate/decrypt on the exact responder Link, from the
/// handshake on (an initiator may identify before its RTT packet arrives), and then
/// enforce first-identity-wins. A later valid identification must never replace
/// an already recorded peer or trigger a second identity callback. This stateless
/// primitive does not activate a Link, admit a caller, or mutate peer state.
pub fn verify_identification(
    link_id: &[u8; DESTINATION_LENGTH],
    plaintext: &[u8],
) -> Option<[u8; PUBLIC_KEY_LENGTH]> {
    if plaintext.len() != PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH {
        return None;
    }
    let mut public_key = [0; PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(&plaintext[..PUBLIC_KEY_LENGTH]);
    let mut ed_public = [0; KEYSIZE];
    ed_public.copy_from_slice(&public_key[KEYSIZE..]);
    let key = VerifyingKey::from_bytes(&ed_public).ok()?;
    let mut signed = [0; DESTINATION_LENGTH + PUBLIC_KEY_LENGTH];
    signed[..DESTINATION_LENGTH].copy_from_slice(link_id);
    signed[DESTINATION_LENGTH..].copy_from_slice(&public_key);
    let mut signature = [0; SIGNATURE_LENGTH];
    signature.copy_from_slice(&plaintext[PUBLIC_KEY_LENGTH..]);
    key.verify(&signed, &Signature::from_bytes(&signature))
        .ok()?;
    Some(public_key)
}

const MTU_BYTEMASK: u32 = 0x001F_FFFF;
const MODE_BYTEMASK: u32 = 0x00E0;

/// Fixed 464-byte padded-ciphertext/stack budget for link Token operations.
/// This is larger than the padded budget of an ordinary 500-byte packet. The
/// caller must enforce [`link_mdu`] / [`LINK_MDU`] before framing or sending;
/// [`link_encrypt`] and [`link_decrypt`] enforce only this buffer ceiling.
pub const LINK_PADDED_MAX: usize = MDU;
const _: () = assert!(LINK_PADDED_MAX.is_multiple_of(16));

/// Compute the plaintext budget for an MTU using the Reticulum link formula:
/// `floor((mtu - 1 - HEADER_MINSIZE - TOKEN_OVERHEAD) / 16) * 16 - 1`.
/// Returns zero when no padded AES block fits. This arithmetic helper does not
/// validate signalling or change the endpoint's fixed 500-byte admission limit.
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
    /// Encryption mode is outside the wire domain or unsupported by the operation.
    /// Endpoint builders and proof validation enable only AES-256-CBC.
    UnsupportedMode,
    /// MTU is outside the checked protocol domain or fixed 500-byte endpoint budget.
    InvalidMtu,
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
    /// Mask mode to three bits and MTU to 21 bits without validating either.
    /// Use [`Self::try_new`] for domain checks; endpoint builders apply stricter
    /// AES-256/MTU-500 admission checks.
    pub fn new(mode: u8, mtu: u32) -> Self {
        Self {
            mode: mode & 0x07,
            mtu: mtu & MTU_BYTEMASK,
        }
    }

    /// Check the wire domain: mode 0..=7 and MTU zero or 500..=0x1F_FFFF.
    /// Zero becomes 500. This accepts modes and MTUs the fixed endpoint does not
    /// support; it does not mask out-of-range input.
    pub fn try_new(mode: u8, mtu: u32) -> Result<Self, LinkError> {
        if mode > 7 {
            return Err(LinkError::UnsupportedMode);
        }
        let checked = Self { mode, mtu };
        Ok(Self {
            mode,
            mtu: checked.effective_mtu()?,
        })
    }

    /// Return 500 for MTU zero, otherwise require 500..=0x1F_FFFF.
    /// Does not check mode or mutate the stored trailer used for signatures.
    pub fn effective_mtu(self) -> Result<u32, LinkError> {
        match self.mtu {
            0 => Ok(crate::constants::MTU as u32),
            500..=MTU_BYTEMASK => Ok(self.mtu),
            _ => Err(LinkError::InvalidMtu),
        }
    }

    fn fixed_endpoint(self) -> Result<Self, LinkError> {
        if self.mode != MODE_AES256_CBC {
            return Err(LinkError::UnsupportedMode);
        }
        let checked = Self::try_new(self.mode, self.mtu)?;
        if checked.mtu != crate::constants::MTU as u32 {
            return Err(LinkError::InvalidMtu);
        }
        Ok(checked)
    }

    /// The default AES-256 / MTU=500 signalling used when a peer sends a legacy (key-only) payload.
    pub fn default_signalling() -> Self {
        Self::new(DEFAULT_MODE, crate::constants::MTU as u32)
    }

    /// Pack the low three mode bits and low 21 MTU bits without validation.
    /// Construct validated signalling first when masking would hide invalid input.
    pub fn pack(&self) -> [u8; 3] {
        let value = (self.mtu & MTU_BYTEMASK) | ((((self.mode as u32) << 5) & MODE_BYTEMASK) << 16);
        let bytes = value.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    /// Decode the first three bytes without domain or endpoint checks.
    /// Returns `None` for shorter input and ignores any trailing bytes.
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

/// Hash `0x02 || destination_hash || 0x00 || request_data[..64]` to a 16-byte
/// link ID, excluding the signalling trailer.
///
/// This helper does not validate request shape: shorter input is hashed as-is
/// and bytes beyond the key block are ignored. Parse the request before using
/// the result as a session identifier.
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

/// Build a 67-byte LINKREQUEST: `x25519_pub(32) || ed25519_pub(32) || signalling(3)`.
/// Only AES-256 with effective MTU 500 is accepted; zero MTU becomes 500.
///
/// Supply fresh cryptographically random per-link private keys. Retain X25519
/// material for session-key derivation and the Ed25519 seed for initiator
/// packet proofs, then wipe caller copies when no longer needed. This helper
/// derives public keys but does not transmit or retain the request.
pub fn build_link_request(
    x25519_priv: &[u8; KEYSIZE],
    ed25519_seed: &[u8; KEYSIZE],
    signalling: SignallingData,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    let signalling = signalling.fixed_endpoint()?;
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
    /// Parse exactly 64 bytes (legacy) or 67 bytes (with signalling).
    /// Legacy input uses AES-256/MTU-500 defaults. Checks the MTU wire domain but
    /// does not restrict the mode, authenticate the keys or enforce endpoint MTU.
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
        signalling.effective_mtu()?;
        Ok(Self {
            peer_x25519_pub,
            peer_ed25519_pub,
            signalling,
        })
    }
}

/// Build a 99-byte LRPROOF using the destination's long-term signing identity
/// and a fresh caller-supplied ephemeral X25519 private key. Only AES-256 with
/// effective MTU 500 is accepted; zero MTU becomes 500.
///
/// The signature covers `link_id || responder_x25519_pub || identity_ed25519_pub || signalling`.
/// Output is `signature(64) || responder_x25519_pub(32) || signalling(3)`.
/// The caller binds the identity and link ID to the accepted request and keeps
/// the ephemeral private key long enough to derive session keys.
pub fn build_link_proof(
    identity: &LocalIdentity,
    responder_x25519_priv: &[u8; KEYSIZE],
    link_id: &[u8; DESTINATION_LENGTH],
    signalling: SignallingData,
    out: &mut [u8],
) -> Result<usize, LinkError> {
    let signalling = signalling.fixed_endpoint()?;
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
    /// Legacy proofs omit the trailer from the signed bytes.
    pub signalling_present: bool,
}

impl LinkProofView {
    /// Parse exactly 96 bytes (legacy) or 99 bytes (with signalling).
    /// Checks the MTU wire domain; use [`Self::validate`] to verify the signature
    /// and fixed endpoint's mode/MTU restrictions. Parsing alone authenticates nothing.
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
        signalling.effective_mtu()?;
        Ok(Self {
            signature,
            responder_x25519_pub,
            signalling,
            signalling_present: data.len() == LINK_PROOF_LEN,
        })
    }

    /// Verify the proof with the expected destination identity's Ed25519 key
    /// and original link ID. Requires AES-256 with effective MTU 500.
    ///
    /// The signed fields include the raw signalling trailer when present; legacy
    /// proofs omit it. The caller must authenticate the destination-key binding
    /// and supply the link ID of its pending request. This does not activate a
    /// session or identify the initiator.
    pub fn validate(
        &self,
        identity_public_key: &[u8; PUBLIC_KEY_LENGTH],
        link_id: &[u8; DESTINATION_LENGTH],
    ) -> bool {
        if self.signalling.fixed_endpoint().is_err() {
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
        if self.signalling_present {
            signed[s..s + LINK_MTU_SIZE].copy_from_slice(&sig_bytes);
            s += LINK_MTU_SIZE;
        }
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
    /// Derive `HMAC key(32) || AES key(32)` with HKDF-SHA256 over the X25519
    /// shared secret, using `link_id` as salt and empty info. This does not
    /// authenticate the handshake, validate key provenance or reject an all-zero
    /// shared secret. The caller must complete the role's handshake checks.
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

    /// Copy a previously derived `HMAC key(32) || AES key(32)`.
    /// The new value wipes its own key on drop; the caller must also wipe the
    /// original copy when the link closes.
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

/// Encrypt with the link's session key and a fresh, unpredictable IV.
/// Output is `IV(16) || AES-256-CBC(PKCS7(pt)) || HMAC-SHA256(IV || ct)(32)`.
/// The caller enforces the packet plaintext limit; this helper checks only
/// [`LINK_PADDED_MAX`] and output capacity, and does not transmit the frame.
pub fn link_encrypt(
    keys: &LinkKeys,
    plaintext: &[u8],
    iv: &[u8; 16],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    token_encrypt::<LINK_PADDED_MAX>(plaintext, keys.combined(), iv, out)
}

/// Verify and decrypt a link Token. Shape, HMAC and padding failures return
/// [`CryptoError::AuthenticationFailed`]; insufficient output capacity returns
/// [`CryptoError::OutputTooSmall`]. Output is unchanged on error. The caller
/// checks packet framing, session state and application/replay policy.
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
    #[test]
    fn checked_signalling_domain_and_builders_do_not_mask() {
        for mtu in 1..500 {
            assert_eq!(SignallingData::try_new(1, mtu), Err(LinkError::InvalidMtu));
            let mut request = [0u8; LINK_REQUEST_LEN];
            request[64..].copy_from_slice(&SignallingData::new(1, mtu).pack());
            assert_eq!(LinkRequestView::parse(&request), Err(LinkError::InvalidMtu));
            let mut proof = [0u8; LINK_PROOF_LEN];
            proof[96..].copy_from_slice(&request[64..]);
            assert_eq!(LinkProofView::parse(&proof), Err(LinkError::InvalidMtu));
        }
        for mtu in [0, 500, 501, MTU_BYTEMASK] {
            assert!(SignallingData::try_new(1, mtu).is_ok());
        }
        for mtu in [MTU_BYTEMASK + 1, u32::MAX] {
            assert!(SignallingData::try_new(1, mtu).is_err());
        }
        assert!(SignallingData::try_new(8, 500).is_err());
        let identity = LocalIdentity::from_private_key(&[7; 64]);
        for signalling in [
            SignallingData { mode: 1, mtu: 499 },
            SignallingData { mode: 1, mtu: 501 },
            SignallingData {
                mode: 1,
                mtu: u32::MAX,
            },
            SignallingData { mode: 9, mtu: 500 },
        ] {
            let mut out = [0xAB; LINK_PROOF_LEN];
            assert!(build_link_request(&[1; 32], &[2; 32], signalling, &mut out).is_err());
            assert_eq!(out, [0xAB; LINK_PROOF_LEN]);
            assert!(build_link_proof(&identity, &[3; 32], &[4; 16], signalling, &mut out).is_err());
            assert_eq!(out, [0xAB; LINK_PROOF_LEN]);
        }
    }

    #[test]
    fn signed_legacy_zero_and_base_proof_shapes_are_authenticated_exactly() {
        let identity = LocalIdentity::from_private_key(&[7; 64]);
        let id = [8; 16];
        for mtu in [None, Some(0), Some(500), Some(501)] {
            let mut signed = [0u8; 83];
            signed[..16].copy_from_slice(&id);
            signed[16..48].copy_from_slice(&[9; 32]);
            signed[48..80].copy_from_slice(&identity.public_key()[32..]);
            let n = if let Some(mtu) = mtu {
                signed[80..].copy_from_slice(&SignallingData::new(1, mtu).pack());
                83
            } else {
                80
            };
            let mut proof = [0u8; 99];
            proof[..64].copy_from_slice(&identity.sign(&signed[..n]));
            proof[64..96].copy_from_slice(&[9; 32]);
            proof[96..].copy_from_slice(&signed[80..]);
            let n = if mtu.is_some() { 99 } else { 96 };
            let parsed = LinkProofView::parse(&proof[..n]).unwrap();
            assert_eq!(
                parsed.validate(identity.public_key(), &id),
                mtu != Some(501)
            );
            proof[0] ^= 1;
            assert!(
                !LinkProofView::parse(&proof[..n])
                    .unwrap()
                    .validate(identity.public_key(), &id)
            );
        }
        for len in [0, 63, 65, 66, 68, 95, 97, 98, 100] {
            assert!(LinkRequestView::parse(&[0u8; 100][..len]).is_err());
            assert!(LinkProofView::parse(&[0u8; 100][..len]).is_err());
        }
    }
}

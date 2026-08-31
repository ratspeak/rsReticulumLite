use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

use crate::constants::{
    DESTINATION_LENGTH, HEADER_MINSIZE, MTU, NAME_HASH_LENGTH, PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, RANDOM_HASH_LENGTH, SIGNATURE_LENGTH,
};
use crate::wire::truncated_hash;

const ANNOUNCE_BASE_SIZE: usize =
    PUBLIC_KEY_LENGTH + NAME_HASH_LENGTH + RANDOM_HASH_LENGTH + SIGNATURE_LENGTH;

pub const RATCHET_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnounceView<'a> {
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    pub name_hash: [u8; NAME_HASH_LENGTH],
    pub random_hash: [u8; RANDOM_HASH_LENGTH],
    pub ratchet: Option<[u8; RATCHET_SIZE]>,
    pub signature: [u8; SIGNATURE_LENGTH],
    pub app_data: &'a [u8],
}

impl<'a> AnnounceView<'a> {
    pub fn parse(
        payload: &'a [u8],
        has_ratchet: bool,
        max_app_data: usize,
    ) -> Result<Self, AnnounceError> {
        let min_size = ANNOUNCE_BASE_SIZE + if has_ratchet { RATCHET_SIZE } else { 0 };
        if payload.len() < min_size {
            return Err(AnnounceError::TooShort);
        }

        let app_data_len = payload.len() - min_size;
        if app_data_len > max_app_data {
            return Err(AnnounceError::AppDataTooLong);
        }

        let mut pos = 0;
        let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
        public_key.copy_from_slice(&payload[pos..pos + PUBLIC_KEY_LENGTH]);
        pos += PUBLIC_KEY_LENGTH;

        let mut name_hash = [0u8; NAME_HASH_LENGTH];
        name_hash.copy_from_slice(&payload[pos..pos + NAME_HASH_LENGTH]);
        pos += NAME_HASH_LENGTH;

        let mut random_hash = [0u8; RANDOM_HASH_LENGTH];
        random_hash.copy_from_slice(&payload[pos..pos + RANDOM_HASH_LENGTH]);
        pos += RANDOM_HASH_LENGTH;

        let ratchet = if has_ratchet {
            let mut ratchet = [0u8; RATCHET_SIZE];
            ratchet.copy_from_slice(&payload[pos..pos + RATCHET_SIZE]);
            pos += RATCHET_SIZE;
            Some(ratchet)
        } else {
            None
        };

        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(&payload[pos..pos + SIGNATURE_LENGTH]);
        pos += SIGNATURE_LENGTH;

        Ok(Self {
            public_key,
            name_hash,
            random_hash,
            ratchet,
            signature,
            app_data: &payload[pos..],
        })
    }

    pub fn identity_hash(&self) -> [u8; DESTINATION_LENGTH] {
        identity_hash(&self.public_key)
    }

    pub fn validate(
        &self,
        destination_hash: &[u8; DESTINATION_LENGTH],
        known_public_key: Option<&[u8; PUBLIC_KEY_LENGTH]>,
        scratch: &mut [u8],
    ) -> Result<[u8; DESTINATION_LENGTH], AnnounceError> {
        let identity_hash = self.identity_hash();
        let expected_dest = destination_hash_from_parts(&self.name_hash, Some(&identity_hash));
        if &expected_dest != destination_hash {
            return Err(AnnounceError::DestinationHashMismatch);
        }
        // Spine file: nested (not let-chained) so the byte-identical rsNode copy still
        // compiles at this crate's MSRV 1.85; newer clippy would collapse it.
        #[allow(clippy::collapsible_if)]
        if let Some(known) = known_public_key {
            if known != &self.public_key {
                return Err(AnnounceError::PublicKeyChanged);
            }
        }
        self.verify_signature(destination_hash, scratch)?;
        Ok(identity_hash)
    }

    pub fn verify_signature(
        &self,
        destination_hash: &[u8; DESTINATION_LENGTH],
        scratch: &mut [u8],
    ) -> Result<(), AnnounceError> {
        let signed_len = DESTINATION_LENGTH
            + PUBLIC_KEY_LENGTH
            + NAME_HASH_LENGTH
            + RANDOM_HASH_LENGTH
            + self.ratchet.map_or(0, |_| RATCHET_SIZE)
            + self.app_data.len();

        if scratch.len() < signed_len {
            return Err(AnnounceError::ScratchTooSmall);
        }

        let mut pos = 0;
        scratch[pos..pos + DESTINATION_LENGTH].copy_from_slice(destination_hash);
        pos += DESTINATION_LENGTH;
        scratch[pos..pos + PUBLIC_KEY_LENGTH].copy_from_slice(&self.public_key);
        pos += PUBLIC_KEY_LENGTH;
        scratch[pos..pos + NAME_HASH_LENGTH].copy_from_slice(&self.name_hash);
        pos += NAME_HASH_LENGTH;
        scratch[pos..pos + RANDOM_HASH_LENGTH].copy_from_slice(&self.random_hash);
        pos += RANDOM_HASH_LENGTH;
        if let Some(ratchet) = self.ratchet {
            scratch[pos..pos + RATCHET_SIZE].copy_from_slice(&ratchet);
            pos += RATCHET_SIZE;
        }
        scratch[pos..pos + self.app_data.len()].copy_from_slice(self.app_data);
        pos += self.app_data.len();

        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&self.public_key[32..]);
        let key = VerifyingKey::from_bytes(&ed_pub).map_err(|_| AnnounceError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        // Permissive verify() to match rsReticulum (rns-crypto Ed25519PublicKey::verify) and the
        // Python reference (pyca Ed25519PublicKey.verify). A relay must accept exactly what the
        // network's source-of-truth verifier accepts; verify_strict() would reject some
        // network-valid edge-case (low-order/non-canonical) signatures and black-hole them.
        key.verify(&scratch[..pos], &signature)
            .map_err(|_| AnnounceError::SignatureInvalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnounceError {
    TooShort,
    AppDataTooLong,
    ScratchTooSmall,
    /// Caller's `out` buffer is too small to hold the produced `announce_data`.
    OutputTooSmall,
    InvalidPublicKey,
    SignatureInvalid,
    DestinationHashMismatch,
    PublicKeyChanged,
}

pub fn identity_hash(public_key: &[u8; PUBLIC_KEY_LENGTH]) -> [u8; DESTINATION_LENGTH] {
    truncated_hash(public_key)
}

pub fn name_hash(name: &str) -> [u8; NAME_HASH_LENGTH] {
    let full = crate::wire::sha256(name.as_bytes());
    let mut out = [0u8; NAME_HASH_LENGTH];
    out.copy_from_slice(&full[..NAME_HASH_LENGTH]);
    out
}

pub fn destination_hash_from_parts(
    name_hash: &[u8; NAME_HASH_LENGTH],
    identity_hash: Option<&[u8; DESTINATION_LENGTH]>,
) -> [u8; DESTINATION_LENGTH] {
    match identity_hash {
        Some(identity_hash) => {
            let mut material = [0u8; NAME_HASH_LENGTH + DESTINATION_LENGTH];
            material[..NAME_HASH_LENGTH].copy_from_slice(name_hash);
            material[NAME_HASH_LENGTH..].copy_from_slice(identity_hash);
            truncated_hash(&material)
        }
        None => truncated_hash(name_hash),
    }
}

pub fn destination_hash_from_name(
    name: &str,
    identity_hash: Option<&[u8; DESTINATION_LENGTH]>,
) -> [u8; DESTINATION_LENGTH] {
    let name_hash = name_hash(name);
    destination_hash_from_parts(&name_hash, identity_hash)
}

// ---- Endpoint identity (announce CREATE) ----
//
// The relay role only verifies announces (`AnnounceView`). An endpoint such as rsDeck
// additionally creates and signs its own announces, which needs the private key, the
// derived X25519 public key, and Ed25519 signing. This section adds exactly that, reusing
// the wire/hash primitives above. Byte-for-byte with rsReticulum `rns-identity`
// (`Identity::from_private_key` / `AnnounceData::create`) and Python `Destination.announce`.

/// The fully-expanded LXMF delivery destination name (app "lxmf", aspect "delivery").
pub const LXMF_DELIVERY_NAME: &str = "lxmf.delivery";

/// Fixed (non-app_data) announce_data fields for a no-ratchet announce — the layout with the
/// LARGEST possible app_data (a ratchet only shrinks the room left for app_data).
const ANNOUNCE_FIXED_NO_RATCHET: usize =
    PUBLIC_KEY_LENGTH + NAME_HASH_LENGTH + RANDOM_HASH_LENGTH + SIGNATURE_LENGTH;

/// Max `app_data` a single-packet announce can carry on the wire, sized to the LARGEST packet that
/// can arrive: a HEADER_1 (directly-received) announce spends only `HEADER_MINSIZE`, so the ceiling
/// is `MTU - HEADER_MINSIZE - announce_fixed`. NOT an arbitrary cap, and NOT the MDU-derived value
/// (`MTU - HEADER_MAXSIZE - IFAC`) — that under-counts by the forwarding-header + IFAC bytes and
/// would black-hole a long-display-name announce the rest of the network accepts (validate_announce
/// imposes no app_data limit). rsDeck's own emitted announces are tiny (~8 B), but ingest must
/// accept any network-valid single-packet announce. (Forwardability is bounded separately, at the
/// rebroadcast step, which skips an announce too large to re-frame as HEADER_2 rather than dropping
/// the learned path.)
pub const MAX_ANNOUNCE_APP_DATA: usize = MTU - HEADER_MINSIZE - ANNOUNCE_FIXED_NO_RATCHET;

// Pin the wire bound (MTU 500 - HEADER_MINSIZE 19 - fixed 148 = 333). A regression that lowers it
// would re-introduce the long-display-name black-hole; raising MTU should bump this in lockstep.
const _: () = assert!(MAX_ANNOUNCE_APP_DATA == 333);

/// signed_data = dest_hash || pub || name_hash || random_hash || \[ratchet\] || app_data.
/// Public so consumers (the FFI) can size their scratch identically and never drift.
pub const SIGNED_DATA_MAX: usize = DESTINATION_LENGTH
    + PUBLIC_KEY_LENGTH
    + NAME_HASH_LENGTH
    + RANDOM_HASH_LENGTH
    + RATCHET_SIZE
    + MAX_ANNOUNCE_APP_DATA;

/// Compose an announce `random_hash` in the canonical Reticulum layout: `rng(5) || unix_secs_be(5)`.
///
/// The low 5 bytes ARE the announce emission time (big-endian Unix seconds), matching Python
/// `Destination.announce` (`get_random_hash()[0:5] + int(time).to_bytes(5,"big")`) and rsReticulum
/// `AnnounceData::create`. This is load-bearing, not cosmetic: the relay freshness / anti-replay
/// gate ([`crate::tables`] `announce_emitted`) parses bytes `[5..10]` big-endian to order and reject
/// stale/replayed announces. A `random_hash` that is fully random, wrong-endian, or carries a
/// non-Unix tick still passes signature validation everywhere (nobody validates its structure) but
/// is mis-ordered or dropped by freshness-aware relays. Compose it through this helper (no_std has
/// no clock/RNG, so the caller supplies the 5 entropy bytes + the Unix time) so the create seam
/// cannot produce a freshness-hostile announce.
pub fn compose_random_hash(rng: &[u8; 5], unix_secs: u64) -> [u8; RANDOM_HASH_LENGTH] {
    let mut out = [0u8; RANDOM_HASH_LENGTH];
    out[..5].copy_from_slice(rng);
    out[5..].copy_from_slice(&unix_secs.to_be_bytes()[3..8]);
    out
}

/// An endpoint identity: owns the raw 64-byte private key (X25519 priv || Ed25519 seed),
/// the derived 64-byte public key, and the 16-byte identity hash. Can create + sign announces.
///
/// Not `Clone` (avoids silent secret-key copies). The raw private key is zeroized on drop;
/// the public key and identity hash are not secret.
pub struct LocalIdentity {
    private_key: [u8; PRIVATE_KEY_LENGTH],
    public_key: [u8; PUBLIC_KEY_LENGTH],
    identity_hash: [u8; DESTINATION_LENGTH],
}

impl Drop for LocalIdentity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl LocalIdentity {
    /// Load a raw 64-byte private key and derive the public key + identity hash.
    pub fn from_private_key(private_key: &[u8; PRIVATE_KEY_LENGTH]) -> Self {
        let public_key = derive_public_key(private_key);
        let identity_hash = identity_hash(&public_key);
        Self {
            private_key: *private_key,
            public_key,
            identity_hash,
        }
    }

    /// The raw 64-byte private key (the canonical Reticulum export form).
    pub fn private_key(&self) -> &[u8; PRIVATE_KEY_LENGTH] {
        &self.private_key
    }
    /// The 64-byte public key (X25519 pub || Ed25519 pub).
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key
    }
    /// The 16-byte identity hash.
    pub fn identity_hash(&self) -> &[u8; DESTINATION_LENGTH] {
        &self.identity_hash
    }

    /// Destination hash for a fully-expanded `name` (e.g. `"lxmf.delivery"`).
    pub fn destination_hash(&self, name: &str) -> [u8; DESTINATION_LENGTH] {
        destination_hash_from_name(name, Some(&self.identity_hash))
    }

    /// The `lxmf.delivery` destination hash for this identity.
    pub fn lxmf_delivery_hash(&self) -> [u8; DESTINATION_LENGTH] {
        self.destination_hash(LXMF_DELIVERY_NAME)
    }

    /// Ed25519-sign `message` with the seed half of the private key.
    /// Plain Ed25519 (RFC 8032), matching pyca `Ed25519PrivateKey.sign` and rsReticulum.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(&self.private_key[32..]);
        let signing = SigningKey::from_bytes(&ed_seed);
        ed_seed.zeroize();
        signing.sign(message).to_bytes()
    }

    /// Build a signed `announce_data` payload for the `lxmf.delivery` destination.
    /// See [`Self::create_announce_named`] for the full contract.
    pub fn create_lxmf_announce(
        &self,
        random_hash: &[u8; RANDOM_HASH_LENGTH],
        ratchet: Option<&[u8; RATCHET_SIZE]>,
        app_data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AnnounceError> {
        self.create_announce_named(LXMF_DELIVERY_NAME, random_hash, ratchet, app_data, out)
    }

    /// Build a signed `announce_data` payload for destination `name`, writing it into `out`
    /// and returning the byte length. `no_std`: the caller supplies `random_hash`
    /// (`random(5) || unix_seconds_be(5)`) and the optional `ratchet` public bytes — this
    /// crate has no RNG or clock.
    ///
    /// On-wire layout (identical to Python `Destination.announce`):
    /// `announce_data = pub(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || sig(64) || app_data`
    /// signed over `dest_hash(16) || pub(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || app_data`.
    ///
    /// The packet header (flags/hops/dest_hash/context byte) is built separately; the
    /// announce's `context_flag` MUST be set iff `ratchet` is `Some` (Python parses on it).
    pub fn create_announce_named(
        &self,
        name: &str,
        random_hash: &[u8; RANDOM_HASH_LENGTH],
        ratchet: Option<&[u8; RATCHET_SIZE]>,
        app_data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AnnounceError> {
        let name_hash = name_hash(name);
        self.create_announce_with_name_hash(&name_hash, random_hash, ratchet, app_data, out)
    }

    /// As [`Self::create_announce_named`], but takes a precomputed `name_hash` (avoids re-hashing
    /// the destination name on the hot path).
    pub fn create_announce_with_name_hash(
        &self,
        name_hash: &[u8; NAME_HASH_LENGTH],
        random_hash: &[u8; RANDOM_HASH_LENGTH],
        ratchet: Option<&[u8; RATCHET_SIZE]>,
        app_data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AnnounceError> {
        if app_data.len() > MAX_ANNOUNCE_APP_DATA {
            return Err(AnnounceError::AppDataTooLong);
        }
        let ratchet_len = ratchet.map_or(0, |_| RATCHET_SIZE);
        let announce_len = PUBLIC_KEY_LENGTH
            + NAME_HASH_LENGTH
            + RANDOM_HASH_LENGTH
            + ratchet_len
            + SIGNATURE_LENGTH
            + app_data.len();
        if out.len() < announce_len {
            return Err(AnnounceError::OutputTooSmall);
        }

        let dest_hash = destination_hash_from_parts(name_hash, Some(&self.identity_hash));

        // signed_data = dest_hash || pub || name_hash || random_hash || [ratchet] || app_data
        let mut signed = [0u8; SIGNED_DATA_MAX];
        let mut s = 0;
        signed[s..s + DESTINATION_LENGTH].copy_from_slice(&dest_hash);
        s += DESTINATION_LENGTH;
        signed[s..s + PUBLIC_KEY_LENGTH].copy_from_slice(&self.public_key);
        s += PUBLIC_KEY_LENGTH;
        signed[s..s + NAME_HASH_LENGTH].copy_from_slice(name_hash);
        s += NAME_HASH_LENGTH;
        signed[s..s + RANDOM_HASH_LENGTH].copy_from_slice(random_hash);
        s += RANDOM_HASH_LENGTH;
        if let Some(r) = ratchet {
            signed[s..s + RATCHET_SIZE].copy_from_slice(r);
            s += RATCHET_SIZE;
        }
        signed[s..s + app_data.len()].copy_from_slice(app_data);
        s += app_data.len();
        let signature = self.sign(&signed[..s]);

        // announce_data = pub || name_hash || random_hash || [ratchet] || signature || app_data
        let mut w = 0;
        out[w..w + PUBLIC_KEY_LENGTH].copy_from_slice(&self.public_key);
        w += PUBLIC_KEY_LENGTH;
        out[w..w + NAME_HASH_LENGTH].copy_from_slice(name_hash);
        w += NAME_HASH_LENGTH;
        out[w..w + RANDOM_HASH_LENGTH].copy_from_slice(random_hash);
        w += RANDOM_HASH_LENGTH;
        if let Some(r) = ratchet {
            out[w..w + RATCHET_SIZE].copy_from_slice(r);
            w += RATCHET_SIZE;
        }
        out[w..w + SIGNATURE_LENGTH].copy_from_slice(&signature);
        w += SIGNATURE_LENGTH;
        out[w..w + app_data.len()].copy_from_slice(app_data);
        w += app_data.len();
        debug_assert_eq!(w, announce_len);
        Ok(w)
    }
}

/// Derive the 64-byte public key (X25519 public 32 || Ed25519 public 32) from a raw 64-byte
/// private key, matching Reticulum's `Identity.load_private_key`.
pub fn derive_public_key(private_key: &[u8; PRIVATE_KEY_LENGTH]) -> [u8; PUBLIC_KEY_LENGTH] {
    let mut x_priv = [0u8; 32];
    x_priv.copy_from_slice(&private_key[..32]);
    let mut ed_seed = [0u8; 32];
    ed_seed.copy_from_slice(&private_key[32..]);

    // X25519: clamped scalar * basepoint (RFC 7748), as the `cryptography` lib does.
    let x_secret = x25519_dalek::StaticSecret::from(x_priv);
    let x_public = x25519_dalek::PublicKey::from(&x_secret);

    // Ed25519: public from the 32-byte seed (RFC 8032).
    let ed_signing = SigningKey::from_bytes(&ed_seed);
    let ed_public = ed_signing.verifying_key();

    let mut out = [0u8; PUBLIC_KEY_LENGTH];
    out[..32].copy_from_slice(x_public.as_bytes());
    out[32..].copy_from_slice(ed_public.as_bytes());
    x_priv.zeroize();
    ed_seed.zeroize();
    out
}

#[cfg(test)]
mod create_tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let b = s.as_bytes();
        assert_eq!(b.len(), 2 * N, "hex len");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            let hi = (b[2 * i] as char).to_digit(16).expect("hex") as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex") as u8;
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    // "incrementing" key (bytes 0..64); identity/dest hashes pinned against the RNS wire format (validated vs rsReticulum at the RNS 1.3.8 parity baseline).
    const INCREMENTING: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    #[test]
    fn local_identity_hash_parity() {
        let id = LocalIdentity::from_private_key(&unhex::<PRIVATE_KEY_LENGTH>(INCREMENTING));
        assert_eq!(
            id.identity_hash(),
            &unhex::<DESTINATION_LENGTH>("aca31af0441d81dbec71e82da0b4b5f5")
        );
        assert_eq!(
            id.lxmf_delivery_hash(),
            unhex::<DESTINATION_LENGTH>("fae321c442e3c9bdcd7a3e79d850e03c")
        );
    }

    #[test]
    fn create_announce_roundtrips_through_validate() {
        let id = LocalIdentity::from_private_key(&unhex::<PRIVATE_KEY_LENGTH>(INCREMENTING));
        let random_hash = [0xABu8; RANDOM_HASH_LENGTH];
        let app_data = unhex::<8>("93c403526174c090"); // device "Rat" app_data
        let mut out = [0u8; 512];
        let n = id
            .create_lxmf_announce(&random_hash, None, &app_data, &mut out)
            .unwrap();

        let view = AnnounceView::parse(&out[..n], false, MAX_ANNOUNCE_APP_DATA).unwrap();
        let dest = id.lxmf_delivery_hash();
        let mut scratch = [0u8; 512];
        let returned = view.validate(&dest, None, &mut scratch).unwrap();
        assert_eq!(&returned, id.identity_hash());
        assert_eq!(view.public_key, *id.public_key());
        assert_eq!(view.app_data, &app_data[..]);
        assert!(view.ratchet.is_none());
    }

    #[test]
    fn create_announce_with_ratchet_roundtrips() {
        let id = LocalIdentity::from_private_key(&unhex::<PRIVATE_KEY_LENGTH>(INCREMENTING));
        let random_hash = [0x11u8; RANDOM_HASH_LENGTH];
        let ratchet = [0x42u8; RATCHET_SIZE];
        let mut out = [0u8; 512];
        let n = id
            .create_lxmf_announce(&random_hash, Some(&ratchet), b"", &mut out)
            .unwrap();

        // has_ratchet must match the packet context flag the caller will set.
        let view = AnnounceView::parse(&out[..n], true, MAX_ANNOUNCE_APP_DATA).unwrap();
        let dest = id.lxmf_delivery_hash();
        let mut scratch = [0u8; 512];
        view.validate(&dest, None, &mut scratch).unwrap();
        assert_eq!(view.ratchet, Some(ratchet));
        assert!(view.app_data.is_empty());
    }

    #[test]
    fn create_announce_rejects_oversize_app_data() {
        let id = LocalIdentity::from_private_key(&[0u8; PRIVATE_KEY_LENGTH]);
        let big = [0u8; MAX_ANNOUNCE_APP_DATA + 1];
        let mut out = [0u8; 1024];
        assert_eq!(
            id.create_lxmf_announce(&[0u8; RANDOM_HASH_LENGTH], None, &big, &mut out),
            Err(AnnounceError::AppDataTooLong)
        );
    }

    #[test]
    fn create_announce_rejects_small_out() {
        let id = LocalIdentity::from_private_key(&[0u8; PRIVATE_KEY_LENGTH]);
        let mut out = [0u8; 10];
        assert_eq!(
            id.create_lxmf_announce(&[0u8; RANDOM_HASH_LENGTH], None, b"x", &mut out),
            Err(AnnounceError::OutputTooSmall)
        );
    }

    #[test]
    fn tampered_app_data_breaks_signature() {
        let id = LocalIdentity::from_private_key(&[0x9u8; PRIVATE_KEY_LENGTH]);
        let mut out = [0u8; 512];
        let n = id
            .create_lxmf_announce(&[0x7u8; RANDOM_HASH_LENGTH], None, b"abc", &mut out)
            .unwrap();
        out[n - 1] ^= 0xFF; // flip a trailing app_data byte
        let view = AnnounceView::parse(&out[..n], false, MAX_ANNOUNCE_APP_DATA).unwrap();
        let dest = id.lxmf_delivery_hash();
        let mut scratch = [0u8; 512];
        assert_eq!(
            view.validate(&dest, None, &mut scratch),
            Err(AnnounceError::SignatureInvalid)
        );
    }

    #[test]
    fn create_announce_accepts_full_single_packet_app_data() {
        // A no-ratchet announce can carry MAX_ANNOUNCE_APP_DATA (= MDU - fixed) bytes and still
        // round-trips through parse+validate. Guards the receive-path parity bound (>256).
        let id = LocalIdentity::from_private_key(&unhex::<PRIVATE_KEY_LENGTH>(INCREMENTING));
        let app = [0x5au8; MAX_ANNOUNCE_APP_DATA];
        let mut out = [0u8; 600];
        let n = id
            .create_lxmf_announce(&[0x11u8; RANDOM_HASH_LENGTH], None, &app, &mut out)
            .unwrap();
        let view = AnnounceView::parse(&out[..n], false, MAX_ANNOUNCE_APP_DATA).unwrap();
        let dest = id.lxmf_delivery_hash();
        let mut scratch = [0u8; SIGNED_DATA_MAX];
        view.validate(&dest, None, &mut scratch).unwrap();
        assert_eq!(view.app_data.len(), MAX_ANNOUNCE_APP_DATA);
    }

    #[test]
    fn compose_random_hash_matches_reference_layout() {
        // rng(5) || unix_secs_be(5); 1234567890 -> 00 49 96 02 d2 (matches the pinned vector).
        let rh = compose_random_hash(&[0xa1, 0xa2, 0xa3, 0xa4, 0xa5], 1234567890);
        assert_eq!(rh, unhex::<RANDOM_HASH_LENGTH>("a1a2a3a4a500499602d2"));
    }
}

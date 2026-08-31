//! Reticulum packet PROOF (delivery receipt) create/validate + bounded inbound-message dedup.
//!
//! A proof of receipt is the receiver's Ed25519 signature over the proven packet's FULL 32-byte
//! packet hash. Matches Python RNS `Identity.prove` / rsReticulum `rns-identity::Identity::prove`:
//!
//! ```text
//! implicit (default): signature(64)
//! explicit:           packet_hash(32) || signature(64)
//! ```
//!
//! Validation verifies the signature over the original packet hash with the prover's identity
//! Ed25519 public key (and, for an explicit proof, checks the prepended hash). The sender maps a
//! valid proof → DELIVERED. `no_std`, no-alloc.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::constants::{PACKET_HASH_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::identity::LocalIdentity;

/// Implicit proof: the 64-byte signature alone (Reticulum's default).
pub const PROOF_IMPLICIT_LEN: usize = SIGNATURE_LENGTH;
/// Explicit proof: `packet_hash(32) || signature(64)`.
pub const PROOF_EXPLICIT_LEN: usize = PACKET_HASH_LENGTH + SIGNATURE_LENGTH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// Caller's `out` buffer is too small for the requested proof form.
    OutputTooSmall,
}

/// Build a proof of receipt for a packet whose full 32-byte hash is `packet_hash`, signed by
/// `identity` (the receiver). `implicit` → `signature(64)`; otherwise `packet_hash(32) ||
/// signature(64)`. Returns the byte length written to `out`. Byte-exact with Python RNS
/// `Identity.prove` (Ed25519 is deterministic).
pub fn build_proof(
    identity: &LocalIdentity,
    packet_hash: &[u8; PACKET_HASH_LENGTH],
    implicit: bool,
    out: &mut [u8],
) -> Result<usize, ProofError> {
    let signature = identity.sign(packet_hash);
    if implicit {
        if out.len() < PROOF_IMPLICIT_LEN {
            return Err(ProofError::OutputTooSmall);
        }
        out[..SIGNATURE_LENGTH].copy_from_slice(&signature);
        Ok(PROOF_IMPLICIT_LEN)
    } else {
        if out.len() < PROOF_EXPLICIT_LEN {
            return Err(ProofError::OutputTooSmall);
        }
        out[..PACKET_HASH_LENGTH].copy_from_slice(packet_hash);
        out[PACKET_HASH_LENGTH..PROOF_EXPLICIT_LEN].copy_from_slice(&signature);
        Ok(PROOF_EXPLICIT_LEN)
    }
}

/// Validate a proof of receipt for `packet_hash`, signed by the identity whose 64-byte public key is
/// `prover_public_key`. Accepts an implicit (64-byte) or explicit (96-byte, hash-prefixed) proof; any
/// other length, a hash-prefix mismatch, or a bad signature returns `false`. Permissive Ed25519
/// `verify` (matches pyca / the network).
///
/// BINDING CONTRACT (the caller is responsible for this — it is NOT enforced here): this only proves
/// "`prover_public_key` signed `packet_hash`". It does NOT identify which of the caller's pending
/// messages the proof is for, nor that `prover_public_key` is the right prover. To map a proof →
/// DELIVERED safely (mirroring Python `Transport`'s receipt iteration):
/// - pass `packet_hash` = the ORIGINAL sent packet's own 32-byte hash, and `prover_public_key` = the
///   public key of THAT message's recipient identity (the destination it was sent to);
/// - for an IMPLICIT (64-byte) proof there is no embedded hash, so iterate each outstanding sent
///   packet's `(hash, recipient_key)` and accept DELIVERED only on the first that validates;
/// - an EXPLICIT (96-byte) proof carries its own hash, so match it to the receipt whose hash equals
///   the prefix before validating. Never accept a proof for an arbitrary pending message.
pub fn validate_proof(
    prover_public_key: &[u8; PUBLIC_KEY_LENGTH],
    packet_hash: &[u8; PACKET_HASH_LENGTH],
    proof: &[u8],
) -> bool {
    let mut signature_bytes = [0u8; SIGNATURE_LENGTH];
    match proof.len() {
        PROOF_IMPLICIT_LEN => signature_bytes.copy_from_slice(proof),
        PROOF_EXPLICIT_LEN => {
            if &proof[..PACKET_HASH_LENGTH] != packet_hash {
                return false;
            }
            signature_bytes.copy_from_slice(&proof[PACKET_HASH_LENGTH..PROOF_EXPLICIT_LEN]);
        }
        _ => return false,
    }
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&prover_public_key[32..]);
    let key = match VerifyingKey::from_bytes(&ed_pub) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(packet_hash, &signature).is_ok()
}

/// Bounded, FIFO set of recently-seen 32-byte message ids — inbound-duplicate suppression so a
/// re-delivered message isn't double-stored. rsDeck uses `MAX_SEEN_IDS = 100` ([`SeenMessages100`]).
/// `no_std`, no-alloc; membership is a linear scan (N is small).
///
/// IN-MEMORY ONLY: this set is empty after construction and does NOT persist. The production dedup
/// contract holds across a reboot only because the owner (the C++ MessageStore) seeds its set from
/// storage at boot (`loadRecentMessageIds(MAX_SEEN_IDS)`). To make THIS set the dedup owner, the
/// caller MUST replay the recently-stored ids via [`SeenMessages::insert_if_new`] after init —
/// otherwise a post-reboot retry of an already-stored message is seen as NEW and double-stored.
#[derive(Clone, Debug)]
pub struct SeenMessages<const N: usize> {
    ids: [[u8; 32]; N],
    head: usize,
    len: usize,
}

/// rsDeck's seen-id capacity (`MAX_SEEN_IDS = 100`).
pub type SeenMessages100 = SeenMessages<100>;

impl<const N: usize> SeenMessages<N> {
    pub const fn new() -> Self {
        Self {
            ids: [[0u8; 32]; N],
            head: 0,
            len: 0,
        }
    }

    /// Check membership without changing the FIFO. Storage owners can persist a new
    /// message before inserting its id, so a failed write remains retryable.
    pub fn contains(&self, id: &[u8; 32]) -> bool {
        (0..self.len).any(|i| &self.ids[(self.head + i) % N] == id)
    }

    /// Record `id`. Returns `true` if it was NEW (process the message), `false` if already seen
    /// (a duplicate — drop it). On overflow the OLDEST id is evicted (FIFO).
    pub fn insert_if_new(&mut self, id: &[u8; 32]) -> bool {
        if self.contains(id) {
            return false;
        }
        if N == 0 {
            return true;
        }
        if self.len == N {
            self.ids[self.head] = *id;
            self.head = (self.head + 1) % N;
        } else {
            let idx = (self.head + self.len) % N;
            self.ids[idx] = *id;
            self.len += 1;
        }
        true
    }

    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for SeenMessages<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_does_not_reserve_or_evict() {
        let mut seen = SeenMessages::<2>::new();
        assert!(!seen.contains(&[1; 32]));
        assert!(!seen.contains(&[1; 32]));
        assert!(seen.is_empty());
        assert!(seen.insert_if_new(&[1; 32]));
        assert!(seen.insert_if_new(&[2; 32]));
        assert!(seen.contains(&[1; 32]));
        assert!(seen.insert_if_new(&[3; 32]));
        assert!(!seen.contains(&[1; 32]));
        assert!(seen.contains(&[2; 32]));
        assert!(!SeenMessages::<0>::new().contains(&[1; 32]));
    }

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
    fn proof_roundtrip_implicit_and_explicit() {
        let id = LocalIdentity::from_private_key(&unhex::<64>(INCREMENTING));
        let packet_hash = [0x5au8; PACKET_HASH_LENGTH];
        for implicit in [true, false] {
            let mut out = [0u8; PROOF_EXPLICIT_LEN];
            let n = build_proof(&id, &packet_hash, implicit, &mut out).unwrap();
            assert_eq!(
                n,
                if implicit {
                    PROOF_IMPLICIT_LEN
                } else {
                    PROOF_EXPLICIT_LEN
                }
            );
            assert!(validate_proof(id.public_key(), &packet_hash, &out[..n]));
            // Wrong packet hash -> invalid.
            assert!(!validate_proof(id.public_key(), &[0x00; 32], &out[..n]));
            // Tampered signature -> invalid.
            let mut bad = out;
            bad[n - 1] ^= 0xFF;
            assert!(!validate_proof(id.public_key(), &packet_hash, &bad[..n]));
        }
    }

    #[test]
    fn proof_rejects_wrong_prover_and_bad_length() {
        let id = LocalIdentity::from_private_key(&unhex::<64>(INCREMENTING));
        let other = LocalIdentity::from_private_key(&[0x99u8; 64]);
        let packet_hash = [0x11u8; PACKET_HASH_LENGTH];
        let mut out = [0u8; PROOF_IMPLICIT_LEN];
        let n = build_proof(&id, &packet_hash, true, &mut out).unwrap();
        assert!(!validate_proof(other.public_key(), &packet_hash, &out[..n]));
        assert!(!validate_proof(
            id.public_key(),
            &packet_hash,
            &out[..n - 1]
        )); // 63 bytes
        assert!(!validate_proof(id.public_key(), &packet_hash, &[])); // empty
    }

    #[test]
    fn seen_messages_dedup_and_fifo() {
        let mut seen = SeenMessages::<4>::new();
        let id = |b: u8| [b; 32];
        assert!(seen.insert_if_new(&id(1)));
        assert!(!seen.insert_if_new(&id(1))); // duplicate
        assert!(seen.insert_if_new(&id(2)));
        assert!(seen.insert_if_new(&id(3)));
        assert!(seen.insert_if_new(&id(4))); // full (1,2,3,4)
        assert!(seen.insert_if_new(&id(5))); // evicts 1
        assert!(seen.insert_if_new(&id(1))); // 1 was evicted -> new again
        assert!(!seen.insert_if_new(&id(5))); // still present
    }
}

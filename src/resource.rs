//! Reticulum RESOURCE transfer (staged: single resource, single segment) — `no_std`, no-alloc,
//! fixed-buffer.
//!
//! Faithful adaptation of rsReticulum `rns-protocol` (`resource.rs` / `resource_adv.rs`), byte-exact
//! with Python RNS 1.4.2 `RNS.Resource`. The lite endpoint provides the resource MECHANISM
//! (advertisement codec, part hashing, part request/response, delivery proof, bounded reassembly);
//! the transfer state machine and persistence stay with the host owner (mirroring the link.rs
//! split); retry/window timing is host-driven too, with [`AdvWatchdog`] encoding the trusted ADV
//! retry policy against a caller-supplied clock. Entropy (`random_hash`, IV) is caller-supplied.
//!
//! Wire formats (all byte-exact with rns-protocol / Python):
//! ```text
//! blob      = Token( random_hash(4) || data )          — ONE link-session Token over the whole
//!             payload (IV(16) || AES-256-CBC(PKCS7) || HMAC(32)); parts are raw SDU-sized chunks
//!             of this ciphertext (packet context RESOURCE, sent without re-encryption).
//! ADV       = msgpack fixmap, keys in order: t(transfer_size) d(data_size) n(num_parts)
//!             h(resource_hash,32) r(random_hash,4) o(original_hash,32) i(segment_index)
//!             l(total_segments) q(request_id | nil) f(flags byte) m(hashmap, 4B/part)
//!             — sent link-encrypted (context RESOURCE_ADV).
//! map_hash  = SHA-256(part_ciphertext || random_hash)[..4]
//! hash      = SHA-256(data || random_hash)              (over PLAINTEXT data)
//! REQ       = exhausted_flag(1) || [last_map_hash(4) when 0xFF] || resource_hash(32)
//!             || wanted_map_hashes(4N)                  (context RESOURCE_REQ, link-encrypted)
//! PROOF     = resource_hash(32) || SHA-256(data || resource_hash)(32)   (context RESOURCE_PRF)
//! flags f   = bit0 encrypted, 1 compressed, 2 split, 3 is_request, 4 is_response, 5 has_metadata
//! ```
//!
//! Honest-subset bounds (fail-closed, documented divergences from the full stack):
//! - MCU caps: [`MAX_PARTS`] parts / [`TRANSFER_MAX`] ciphertext / [`DATA_MAX`] payload per
//!   resource. Larger advertisements return [`ResourceError::TooLarge`]. The host must send an
//!   encrypted RESOURCE_RCL containing [`ResourceAdv::rejection_hash`] to notify the sender.
//! - UNCOMPRESSED only: the fleet ships bz2 disabled (micro fork) and lite targets MCU, so
//!   compressed ADVs are rejected at accept time ([`ResourceError::CompressedUnsupported`]) — the
//!   honest no-bz2 behaviour (a bz2-less peer would fail the transfer at assembly; lite fails it
//!   up front instead of accepting parts it can never decode). The sender never sets the flag.
//! - Single segment only (`split`/multi-segment and metadata-prefixed resources rejected), plain
//!   transfers only (request/response resources rejected), encrypted-only (Python link resources
//!   always set `encrypted`; a plaintext ADV is refused).
//! - `random_hash` and the Token IV are caller-supplied entropy. On a map-hash collision the
//!   builder returns [`ResourceError::MapHashCollision`]; the caller retries with fresh
//!   `random_hash` (rns-protocol/Python loop internally on their own RNG).
//! - With ≤ [`MAX_PARTS`] parts the FULL hashmap always fits one ADV (capacity 74 at MTU 500), so
//!   the receiver never exhausts its hashmap and HMU segments are not needed.
//!
//! [`OutboundResource`]/[`InboundResource`] embed a [`TRANSFER_MAX`]-byte buffer (~3.7 KiB); place
//! them in static storage on MCU targets rather than the stack.

use sha2::{Digest, Sha256};

use crate::constants::{HEADER_MAXSIZE, MTU};
use crate::crypto::{CryptoError, TOKEN_OVERHEAD, token_decrypt_in_place, token_encrypt_in_place};
use crate::link::{LINK_MDU, LinkKeys};

/// Truncated part-hash length in the hashmap / request wire.
pub const MAPHASH_LEN: usize = 4;
/// Random tag bytes shipped in the ADV `r` field and mixed into every hash.
pub const RANDOM_HASH_SIZE: usize = 4;
pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;
/// Advertisement overhead reserved for the non-hashmap fields (Python
/// `ResourceAdvertisement.OVERHEAD`).
pub const ADV_OVERHEAD: usize = 134;
/// Delivery proof length: `resource_hash(32) || proof(32)`.
pub const PROOF_LEN: usize = 64;
/// Cap on a parsed ADV `q` (request id) field. Request/response resources are rejected anyway;
/// this only bounds the parse buffer.
pub const REQUEST_ID_MAX: usize = 32;

// Flow-control window constants (Python Resource.*, rns-protocol resource.rs — parity values).
pub const WINDOW_INITIAL: usize = 4;
pub const WINDOW_MIN: usize = 2;
pub const WINDOW_MAX_SLOW: usize = 10;
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
pub const WINDOW_MAX_FAST: usize = 75;
pub const FAST_RATE_THRESHOLD: usize = 4;
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
/// bytes/sec — rate above which the window ceiling is promoted to the fast tier.
pub const RATE_FAST: usize = 6250;
/// bytes/sec — rate below which the window ceiling is demoted to the very-slow tier.
pub const RATE_VERY_SLOW: usize = 250;
pub const WINDOW_FLEXIBILITY: usize = 4;

/// Resource part payload size: `mtu - HEADER_MAXSIZE - IFAC_MIN(1)`. Parts are chunks of the
/// pre-encrypted blob, so they use the RAW packet budget, not the link plaintext MDU (Python
/// `Resource.sdu` when `link.mtu` is set; rns-protocol `SDU`).
pub const fn resource_sdu(mtu: usize) -> usize {
    mtu.saturating_sub(HEADER_MAXSIZE + 1)
}

/// Part size at the default Reticulum MTU (500) = 464.
pub const SDU: usize = resource_sdu(MTU);
const _: () = assert!(SDU == 464);

/// Map-hash entries that fit alongside [`ADV_OVERHEAD`] in one link-MDU advertisement
/// (Python `ResourceAdvertisement.HASHMAP_MAX_LEN`, rns-protocol `resource_adv::hashmap_max_len`).
pub const fn hashmap_max_len(mdu: usize) -> usize {
    if mdu > ADV_OVERHEAD {
        (mdu - ADV_OVERHEAD) / MAPHASH_LEN
    } else {
        0
    }
}
const _: () = assert!(hashmap_max_len(LINK_MDU) == 74);

/// MCU bound: parts per resource. 8 × 464 B keeps each endpoint buffer under 4 KiB while still
/// carrying a full LXMF message with attachments headroom; the full hashmap always fits one ADV.
pub const MAX_PARTS: usize = 8;
const _: () = assert!(MAX_PARTS <= hashmap_max_len(LINK_MDU));

/// Largest acceptable transfer (encrypted blob) size: `MAX_PARTS * SDU` = 3712.
pub const TRANSFER_MAX: usize = MAX_PARTS * SDU;
const _: () = assert!(TRANSFER_MAX % 16 == 0);

/// Largest payload the encrypted blob can carry: padded budget minus the PKCS7 reserve byte and
/// the embedded random hash = 3659.
pub const DATA_MAX: usize = (TRANSFER_MAX - TOKEN_OVERHEAD) - 1 - RANDOM_HASH_SIZE;
const _: () = assert!(DATA_MAX == 3659);

/// Worst-case packed ADV size at lite bounds (u32 ints, 32-byte request id, full hashmap).
pub const ADV_PACKED_MAX: usize = 192;
/// Worst-case lite part request: flag + resource_hash + MAX_PARTS wanted hashes.
pub const REQUEST_MAX: usize = 1 + 32 + MAX_PARTS * MAPHASH_LEN;

/// Token length for `pt_len` bytes of plaintext: IV + PKCS7-padded body + HMAC.
const fn token_len(pt_len: usize) -> usize {
    16 + (pt_len / 16 + 1) * 16 + 32
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    /// Resource exceeds the lite MCU bounds ([`MAX_PARTS`]/[`TRANSFER_MAX`]/[`DATA_MAX`]).
    TooLarge,
    /// Malformed or internally inconsistent advertisement.
    InvalidAdvertisement,
    /// ADV carries the bz2 `compressed` flag — lite ships without bz2 (fail-closed).
    CompressedUnsupported,
    /// Multi-segment (`split`) resource — lite is single-segment only.
    SplitUnsupported,
    /// Metadata-prefixed resource — outside the staged lite scope.
    MetadataUnsupported,
    /// Request/response resource (`q`/`is_request`/`is_response`) — outside the lite scope.
    RequestResponseUnsupported,
    /// ADV without the `encrypted` flag; link resources are always Token-encrypted.
    EncryptionRequired,
    /// Two parts share a truncated map hash; retry with fresh `random_hash` entropy.
    MapHashCollision,
    /// Malformed part request wire.
    InvalidRequest,
    /// Reassembly attempted before every part arrived.
    Incomplete,
    /// Reassembled data does not hash to the advertised resource hash.
    HashMismatch,
    /// Decrypted blob shorter than the embedded random hash.
    Corrupt,
    /// Operation is invalid in the current transfer state.
    InvalidState,
    /// Caller-supplied output buffer too small.
    OutputTooSmall,
    /// Blob encryption/decryption failure (bad session keys or forged ciphertext).
    Crypto(CryptoError),
}

/// Bitfield in the ADV `f` field. Bit layout identical to rns-protocol `ResourceFlags` /
/// Python's inline shifts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
}

impl ResourceFlags {
    pub fn to_byte(self) -> u8 {
        (self.encrypted as u8)
            | ((self.compressed as u8) << 1)
            | ((self.split as u8) << 2)
            | ((self.is_request as u8) << 3)
            | ((self.is_response as u8) << 4)
            | ((self.has_metadata as u8) << 5)
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            encrypted: b & 0x01 != 0,
            compressed: b & 0x02 != 0,
            split: b & 0x04 != 0,
            is_request: b & 0x08 != 0,
            is_response: b & 0x10 != 0,
            has_metadata: b & 0x20 != 0,
        }
    }
}

fn hash_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// `SHA-256(part || random_hash)[..4]` — identifies a part slot in the hashmap.
pub fn get_map_hash(part: &[u8], random_hash: &[u8; RANDOM_HASH_SIZE]) -> [u8; MAPHASH_LEN] {
    let full = hash_pair(part, random_hash);
    let mut mh = [0u8; MAPHASH_LEN];
    mh.copy_from_slice(&full[..MAPHASH_LEN]);
    mh
}

/// `SHA-256(data || random_hash)` — the advertised resource identifier (over plaintext data).
pub fn compute_resource_hash(data: &[u8], random_hash: &[u8; RANDOM_HASH_SIZE]) -> [u8; 32] {
    hash_pair(data, random_hash)
}

/// `SHA-256(data || resource_hash)` — the value a valid delivery proof must reproduce.
pub fn compute_expected_proof(data: &[u8], resource_hash: &[u8; 32]) -> [u8; 32] {
    hash_pair(data, resource_hash)
}

// === msgpack mini-codec ==========================================================================
// Only what the ADV needs (fixmap/fixstr-1/uint/bin/nil), minimal encodings — byte-exact with
// Python umsgpack and rmpv for these shapes. The parser is TOTAL: every length is bounds-checked
// with checked arithmetic before use (32-bit usize targets; attacker-controlled input).

struct MpWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl MpWriter<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), ResourceError> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(ResourceError::OutputTooSmall)?;
        if end > self.out.len() {
            return Err(ResourceError::OutputTooSmall);
        }
        self.out[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn key(&mut self, k: u8) -> Result<(), ResourceError> {
        self.put(&[0xA1, k])
    }

    fn uint(&mut self, v: u32) -> Result<(), ResourceError> {
        if v < 0x80 {
            self.put(&[v as u8])
        } else if v <= 0xFF {
            self.put(&[0xCC, v as u8])
        } else if v <= 0xFFFF {
            let b = (v as u16).to_be_bytes();
            self.put(&[0xCD, b[0], b[1]])
        } else {
            let b = v.to_be_bytes();
            self.put(&[0xCE, b[0], b[1], b[2], b[3]])
        }
    }

    fn bin(&mut self, data: &[u8]) -> Result<(), ResourceError> {
        if data.len() <= 0xFF {
            self.put(&[0xC4, data.len() as u8])?;
        } else if data.len() <= 0xFFFF {
            let b = (data.len() as u16).to_be_bytes();
            self.put(&[0xC5, b[0], b[1]])?;
        } else {
            return Err(ResourceError::TooLarge);
        }
        self.put(data)
    }

    fn nil(&mut self) -> Result<(), ResourceError> {
        self.put(&[0xC0])
    }
}

struct MpReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MpReader<'a> {
    fn byte(&mut self) -> Result<u8, ResourceError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(ResourceError::InvalidAdvertisement)?;
        self.pos += 1;
        Ok(b)
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ResourceError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ResourceError::InvalidAdvertisement)?;
        if end > self.data.len() {
            return Err(ResourceError::InvalidAdvertisement);
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn uint(&mut self) -> Result<u32, ResourceError> {
        match self.byte()? {
            b @ 0x00..=0x7F => Ok(b as u32),
            0xCC => Ok(self.byte()? as u32),
            0xCD => {
                let s = self.take(2)?;
                Ok(u16::from_be_bytes([s[0], s[1]]) as u32)
            }
            0xCE => {
                let s = self.take(4)?;
                Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
            }
            0xCF => {
                let s = self.take(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(s);
                u32::try_from(u64::from_be_bytes(b)).map_err(|_| ResourceError::TooLarge)
            }
            _ => Err(ResourceError::InvalidAdvertisement),
        }
    }

    fn bin(&mut self) -> Result<&'a [u8], ResourceError> {
        match self.byte()? {
            0xC4 => {
                let n = self.byte()? as usize;
                self.take(n)
            }
            0xC5 => {
                let s = self.take(2)?;
                let n = u16::from_be_bytes([s[0], s[1]]) as usize;
                self.take(n)
            }
            _ => Err(ResourceError::InvalidAdvertisement),
        }
    }
}

/// Decoded/encodable resource advertisement (the msgpack map documented in the module header).
/// Fixed buffers; `hashmap_len`/`request_id_len` are byte counts into their arrays.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceAdv {
    pub transfer_size: u32,
    pub data_size: u32,
    pub num_parts: u32,
    pub resource_hash: [u8; 32],
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    pub original_hash: [u8; 32],
    pub segment_index: u32,
    pub total_segments: u32,
    /// 0 = wire `nil` (no request id).
    pub request_id_len: usize,
    pub request_id: [u8; REQUEST_ID_MAX],
    pub flags: ResourceFlags,
    pub hashmap_len: usize,
    pub hashmap: [u8; MAX_PARTS * MAPHASH_LEN],
}

impl ResourceAdv {
    /// Encode as msgpack, byte-exact with rns-protocol `ResourceAdvertisement::pack` / Python
    /// `ResourceAdvertisement.pack`. Returns the packed length (≤ [`ADV_PACKED_MAX`]).
    pub fn pack(&self, out: &mut [u8]) -> Result<usize, ResourceError> {
        if self.hashmap_len > self.hashmap.len() || self.request_id_len > self.request_id.len() {
            return Err(ResourceError::InvalidAdvertisement);
        }
        let mut w = MpWriter { out, pos: 0 };
        w.put(&[0x8B])?; // fixmap, 11 entries
        w.key(b't')?;
        w.uint(self.transfer_size)?;
        w.key(b'd')?;
        w.uint(self.data_size)?;
        w.key(b'n')?;
        w.uint(self.num_parts)?;
        w.key(b'h')?;
        w.bin(&self.resource_hash)?;
        w.key(b'r')?;
        w.bin(&self.random_hash)?;
        w.key(b'o')?;
        w.bin(&self.original_hash)?;
        w.key(b'i')?;
        w.uint(self.segment_index)?;
        w.key(b'l')?;
        w.uint(self.total_segments)?;
        w.key(b'q')?;
        if self.request_id_len == 0 {
            w.nil()?;
        } else {
            w.bin(&self.request_id[..self.request_id_len])?;
        }
        w.key(b'f')?;
        w.uint(self.flags.to_byte() as u32)?;
        w.key(b'm')?;
        w.bin(&self.hashmap[..self.hashmap_len])?;
        Ok(w.pos)
    }

    /// Decode an advertisement produced by [`Self::pack`], rns-protocol, or Python. Total parser:
    /// requires the canonical 11-key map (any key order, no duplicates), exact hash/random-tag
    /// lengths, integers ≤ `u32::MAX`, and a whole-entry hashmap that fits the lite part cap
    /// (larger resources return [`ResourceError::TooLarge`]). Trailing bytes after the map are
    /// ignored (both references decode a single object).
    pub fn parse(data: &[u8]) -> Result<Self, ResourceError> {
        let adv = Self::parse_bounded(data)?;
        if adv.hashmap_len > MAX_PARTS * MAPHASH_LEN {
            return Err(ResourceError::TooLarge);
        }
        Ok(adv)
    }

    /// Identify a syntactically valid advertisement even when its hashmap exceeds our endpoint
    /// capacity. The host can refuse it with RESOURCE_RCL without allocating a transfer or
    /// accepting its data. As in the trusted runtime, cancellation names the segment hash `h`,
    /// not the original multi-segment hash `o`. Malformed maps never yield a cancellation target.
    pub fn rejection_hash(data: &[u8]) -> Result<[u8; 32], ResourceError> {
        Ok(Self::parse_bounded(data)?.resource_hash)
    }

    // Parse the entire map before exposing its hash. Large hashmaps are validated as slices,
    // not copied; this private intermediate must not be passed to the transfer implementation.
    fn parse_bounded(data: &[u8]) -> Result<Self, ResourceError> {
        let mut r = MpReader { data, pos: 0 };
        let head = r.byte()?;
        if !(0x80..=0x8F).contains(&head) || head & 0x0F != 11 {
            return Err(ResourceError::InvalidAdvertisement);
        }

        let mut adv = Self::default();
        let mut seen: u16 = 0;
        for _ in 0..11 {
            if r.byte()? != 0xA1 {
                return Err(ResourceError::InvalidAdvertisement);
            }
            let k = r.byte()?;
            let bit: u16 = match k {
                b't' => 0x001,
                b'd' => 0x002,
                b'n' => 0x004,
                b'h' => 0x008,
                b'r' => 0x010,
                b'o' => 0x020,
                b'i' => 0x040,
                b'l' => 0x080,
                b'q' => 0x100,
                b'f' => 0x200,
                b'm' => 0x400,
                _ => return Err(ResourceError::InvalidAdvertisement),
            };
            if seen & bit != 0 {
                return Err(ResourceError::InvalidAdvertisement);
            }
            seen |= bit;
            match k {
                b't' => adv.transfer_size = r.uint()?,
                b'd' => adv.data_size = r.uint()?,
                b'n' => adv.num_parts = r.uint()?,
                b'h' => {
                    let s = r.bin()?;
                    if s.len() != 32 {
                        return Err(ResourceError::InvalidAdvertisement);
                    }
                    adv.resource_hash.copy_from_slice(s);
                }
                b'r' => {
                    let s = r.bin()?;
                    if s.len() != RANDOM_HASH_SIZE {
                        return Err(ResourceError::InvalidAdvertisement);
                    }
                    adv.random_hash.copy_from_slice(s);
                }
                b'o' => {
                    let s = r.bin()?;
                    if s.len() != 32 {
                        return Err(ResourceError::InvalidAdvertisement);
                    }
                    adv.original_hash.copy_from_slice(s);
                }
                b'i' => adv.segment_index = r.uint()?,
                b'l' => adv.total_segments = r.uint()?,
                b'q' => {
                    if r.peek() == Some(0xC0) {
                        let _ = r.byte();
                    } else {
                        let s = r.bin()?;
                        if s.len() > REQUEST_ID_MAX {
                            return Err(ResourceError::InvalidAdvertisement);
                        }
                        adv.request_id[..s.len()].copy_from_slice(s);
                        adv.request_id_len = s.len();
                    }
                }
                b'f' => {
                    let f = r.uint()?;
                    if f > 0xFF {
                        return Err(ResourceError::InvalidAdvertisement);
                    }
                    adv.flags = ResourceFlags::from_byte(f as u8);
                }
                b'm' => {
                    let s = r.bin()?;
                    if s.len() % MAPHASH_LEN != 0 {
                        return Err(ResourceError::InvalidAdvertisement);
                    }
                    if s.len() <= MAX_PARTS * MAPHASH_LEN {
                        adv.hashmap[..s.len()].copy_from_slice(s);
                    }
                    adv.hashmap_len = s.len();
                }
                _ => unreachable!(),
            }
        }
        Ok(adv)
    }
}

/// Parsed RESOURCE_REQ (receiver → sender). See the module header for the wire layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartRequestView<'a> {
    /// `exhausted_flag == 0xFF`: the receiver ran out of map hashes (never emitted by lite
    /// receivers — the full hashmap ships in the ADV — but parsed for peer compatibility).
    pub wants_more_hashmap: bool,
    /// Present only when `wants_more_hashmap`.
    pub last_map_hash: Option<[u8; MAPHASH_LEN]>,
    pub resource_hash: [u8; 32],
    requested: &'a [u8],
}

impl<'a> PartRequestView<'a> {
    /// Total parser for a request payload. Trailing bytes that do not fill a whole map hash are
    /// ignored (mirrors rns-protocol's `chunks_exact`).
    pub fn parse(data: &'a [u8]) -> Result<Self, ResourceError> {
        let flag = *data.first().ok_or(ResourceError::InvalidRequest)?;
        let wants_more_hashmap = flag == HASHMAP_IS_EXHAUSTED;
        let offset = if wants_more_hashmap {
            1 + MAPHASH_LEN
        } else {
            1
        };
        let hash_end = offset + 32;
        if data.len() < hash_end {
            return Err(ResourceError::InvalidRequest);
        }
        let last_map_hash = if wants_more_hashmap {
            let mut mh = [0u8; MAPHASH_LEN];
            mh.copy_from_slice(&data[1..1 + MAPHASH_LEN]);
            Some(mh)
        } else {
            None
        };
        let mut resource_hash = [0u8; 32];
        resource_hash.copy_from_slice(&data[offset..hash_end]);
        Ok(Self {
            wants_more_hashmap,
            last_map_hash,
            resource_hash,
            requested: &data[hash_end..],
        })
    }

    /// Map hashes of the parts the receiver still wants.
    pub fn requested_hashes(&self) -> impl Iterator<Item = [u8; MAPHASH_LEN]> + '_ {
        self.requested.chunks_exact(MAPHASH_LEN).map(|c| {
            let mut mh = [0u8; MAPHASH_LEN];
            mh.copy_from_slice(c);
            mh
        })
    }

    pub fn requested_count(&self) -> usize {
        self.requested.len() / MAPHASH_LEN
    }
}

/// Receiver flow-control window (Python `Resource` window fields; rns-protocol `WindowState`).
/// The lite core exposes it; the host owner decides WHEN to grow (batch completed) or shrink
/// (timeout), since the core has no clock.
#[derive(Clone, Copy, Debug)]
pub struct WindowState {
    pub window: usize,
    pub window_min: usize,
    pub window_max: usize,
    pub fast_rate_rounds: usize,
    pub very_slow_rate_rounds: usize,
}

impl WindowState {
    pub fn new() -> Self {
        Self {
            window: WINDOW_INITIAL,
            window_min: WINDOW_MIN,
            window_max: WINDOW_MAX_SLOW,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
        }
    }

    /// Grow after a completed batch; `rate` is the observed transfer rate in bytes/sec, or 0 when
    /// the host has no estimate (0 is NEUTRAL: Python only feeds measured rates into the tier
    /// counters, so an unknown rate must not count as a very-slow round). A run of fast/very-slow
    /// rounds promotes/demotes the ceiling.
    pub fn grow(&mut self, rate: usize) {
        if self.window < self.window_max {
            self.window += 1;
            // saturating: a very-slow demotion can clamp `window` below `window_min` (Python's
            // signed comparison is false there; a plain sub underflows).
            if self.window.saturating_sub(self.window_min) > (WINDOW_FLEXIBILITY - 1) {
                self.window_min += 1;
            }
        }
        if rate == 0 {
            // Unknown rate: tier counters untouched.
        } else if rate > RATE_FAST {
            self.fast_rate_rounds += 1;
            self.very_slow_rate_rounds = 0;
            if self.fast_rate_rounds >= FAST_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_FAST;
            }
        } else if rate < RATE_VERY_SLOW {
            self.very_slow_rate_rounds += 1;
            self.fast_rate_rounds = 0;
            if self.very_slow_rate_rounds >= VERY_SLOW_RATE_THRESHOLD {
                self.window_max = WINDOW_MAX_VERY_SLOW;
                if self.window > self.window_max {
                    self.window = self.window_max;
                }
            }
        } else {
            self.fast_rate_rounds = 0;
            self.very_slow_rate_rounds = 0;
        }
    }

    /// Shrink after a timeout, keeping the flexibility band.
    pub fn shrink(&mut self) {
        if self.window > self.window_min {
            self.window -= 1;
        }
        if self.window_max > self.window_min {
            self.window_max -= 1;
        }
        if self.window_max.saturating_sub(self.window) > WINDOW_FLEXIBILITY - 1 {
            self.window_max -= 1;
        }
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}

// Duplicate map-hash scan (rns-protocol collision guard, sized for MAX_PARTS).
fn has_map_hash_collision(map_hashes: &[[u8; MAPHASH_LEN]]) -> bool {
    for (i, a) in map_hashes.iter().enumerate() {
        if map_hashes[..i].contains(a) {
            return true;
        }
    }
    false
}

/// Sender side of a single-segment resource: the Token-encrypted blob plus everything the wire
/// needs (ADV fields, map hashes, expected proof). ~3.7 KiB — statically place on MCU.
pub struct OutboundResource {
    buf: [u8; TRANSFER_MAX],
    total_size: u32,
    data_size: u32,
    num_parts: usize,
    resource_hash: [u8; 32],
    expected_proof: [u8; 32],
    random_hash: [u8; RANDOM_HASH_SIZE],
    map_hashes: [[u8; MAPHASH_LEN]; MAX_PARTS],
}

impl core::fmt::Debug for OutboundResource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboundResource")
            .field("total_size", &self.total_size)
            .field("data_size", &self.data_size)
            .field("num_parts", &self.num_parts)
            .field("resource_hash", &self.resource_hash)
            .finish_non_exhaustive()
    }
}

impl OutboundResource {
    /// All-zero resource (valid: every field is a zeroable POD). Used to obtain a
    /// destination for [`Self::build_into`] without a large by-value temporary.
    pub const fn zeroed() -> Self {
        Self {
            buf: [0u8; TRANSFER_MAX],
            total_size: 0,
            data_size: 0,
            num_parts: 0,
            resource_hash: [0u8; 32],
            expected_proof: [0u8; 32],
            random_hash: [0u8; RANDOM_HASH_SIZE],
            map_hashes: [[0u8; MAPHASH_LEN]; MAX_PARTS],
        }
    }

    /// Build a resource IN PLACE into `self`: hash the plaintext, Token-encrypt
    /// `random_hash || data` with the link session keys, chunk into SDU parts and
    /// derive the map hashes. `self` is typically heap-resident (the
    /// [`TRANSFER_MAX`]-byte `buf` is ~3.7 KiB), so this avoids the ~7.7 KiB stack
    /// frame a by-value [`Self::build`] costs — which overflows small MCU task stacks
    /// (loopTask).
    ///
    /// `random_hash` and `iv` are caller-supplied entropy and MUST be fresh per
    /// resource for real traffic (fixed only for deterministic vectors). On
    /// [`ResourceError::MapHashCollision`] retry with a fresh `random_hash`.
    /// On any error `self` is left invalidated (`num_parts == 0`), never a mix of
    /// old metadata over new ciphertext.
    pub fn build_into(
        &mut self,
        data: &[u8],
        keys: &LinkKeys,
        random_hash: &[u8; RANDOM_HASH_SIZE],
        iv: &[u8; 16],
    ) -> Result<(), ResourceError> {
        if data.len() > DATA_MAX {
            return Err(ResourceError::TooLarge);
        }

        let resource_hash = compute_resource_hash(data, random_hash);
        let expected_proof = compute_expected_proof(data, &resource_hash);

        self.buf.fill(0);
        // Invalidate previous contents before the fallible steps: an error below must
        // not leave stale metadata describing the old resource over the new ciphertext.
        self.total_size = 0;
        self.data_size = 0;
        self.num_parts = 0;
        self.buf[16..16 + RANDOM_HASH_SIZE].copy_from_slice(random_hash);
        self.buf[16 + RANDOM_HASH_SIZE..16 + RANDOM_HASH_SIZE + data.len()].copy_from_slice(data);
        let total = token_encrypt_in_place(
            keys.combined(),
            iv,
            &mut self.buf,
            RANDOM_HASH_SIZE + data.len(),
        )
        .map_err(ResourceError::Crypto)?;

        let num_parts = total.div_ceil(SDU);
        let mut map_hashes = [[0u8; MAPHASH_LEN]; MAX_PARTS];
        for (i, mh) in map_hashes.iter_mut().take(num_parts).enumerate() {
            let end = ((i + 1) * SDU).min(total);
            *mh = get_map_hash(&self.buf[i * SDU..end], random_hash);
        }
        if has_map_hash_collision(&map_hashes[..num_parts]) {
            return Err(ResourceError::MapHashCollision);
        }

        self.total_size = total as u32;
        self.data_size = data.len() as u32;
        self.num_parts = num_parts;
        self.resource_hash = resource_hash;
        self.expected_proof = expected_proof;
        self.random_hash = *random_hash;
        self.map_hashes = map_hashes;
        Ok(())
    }

    pub fn build(
        data: &[u8],
        keys: &LinkKeys,
        random_hash: &[u8; RANDOM_HASH_SIZE],
        iv: &[u8; 16],
    ) -> Result<Self, ResourceError> {
        let mut r = Self::zeroed();
        r.build_into(data, keys, random_hash, iv)?;
        Ok(r)
    }

    pub fn num_parts(&self) -> usize {
        self.num_parts
    }

    pub fn transfer_size(&self) -> usize {
        self.total_size as usize
    }

    pub fn resource_hash(&self) -> &[u8; 32] {
        &self.resource_hash
    }

    pub fn expected_proof(&self) -> &[u8; 32] {
        &self.expected_proof
    }

    /// Raw ciphertext chunk for part `i` — sent as-is (packet context RESOURCE).
    pub fn part(&self, i: usize) -> Option<&[u8]> {
        if i >= self.num_parts {
            return None;
        }
        let total = self.total_size as usize;
        Some(&self.buf[i * SDU..((i + 1) * SDU).min(total)])
    }

    /// The single-segment advertisement for this resource (`encrypted` set, full hashmap).
    pub fn advertisement(&self) -> ResourceAdv {
        let mut adv = ResourceAdv {
            transfer_size: self.total_size,
            data_size: self.data_size,
            num_parts: self.num_parts as u32,
            resource_hash: self.resource_hash,
            random_hash: self.random_hash,
            original_hash: self.resource_hash,
            segment_index: 1,
            total_segments: 1,
            flags: ResourceFlags {
                encrypted: true,
                ..Default::default()
            },
            hashmap_len: self.num_parts * MAPHASH_LEN,
            ..Default::default()
        };
        for (i, mh) in self.map_hashes[..self.num_parts].iter().enumerate() {
            adv.hashmap[i * MAPHASH_LEN..(i + 1) * MAPHASH_LEN].copy_from_slice(mh);
        }
        adv
    }

    /// Part indices to (re)send for a parsed request, in wire order (sender-side RESOURCE_REQ
    /// service, mirroring rns-protocol `handle_request`'s hash matching). Requests addressed to a
    /// different resource hash return zero parts (Python's link routes RESOURCE_REQs by hash and
    /// ignores non-matching ones).
    pub fn requested_parts(&self, req: &PartRequestView<'_>) -> ([usize; MAX_PARTS], usize) {
        let mut idx = [0usize; MAX_PARTS];
        let mut n = 0;
        if req.resource_hash != self.resource_hash {
            return (idx, n);
        }
        for (i, mh) in self.map_hashes[..self.num_parts].iter().enumerate() {
            if req.requested_hashes().any(|h| h == *mh) {
                idx[n] = i;
                n += 1;
            }
        }
        (idx, n)
    }

    /// Check a delivery proof (`resource_hash(32) || proof(32)`). Exact-length like Python;
    /// additionally requires the leading resource hash to match (honest proofs always do).
    pub fn validate_proof(&self, proof: &[u8]) -> bool {
        proof.len() == PROOF_LEN
            && proof[..32] == self.resource_hash
            && proof[32..] == self.expected_proof
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundState {
    Transferring,
    Assembled,
    Corrupt,
}

/// Receiver side of a single-segment resource: slots parts by map hash into a fixed buffer,
/// reassembles (Token decrypt + hash verify) and produces the delivery proof. ~3.8 KiB —
/// statically place on MCU.
pub struct InboundResource {
    buf: [u8; TRANSFER_MAX],
    resource_hash: [u8; 32],
    random_hash: [u8; RANDOM_HASH_SIZE],
    proof: [u8; 32],
    transfer_size: u32,
    data_size: u32,
    data_len: u16,
    num_parts: u8,
    consecutive_completed: u8,
    received: [bool; MAX_PARTS],
    map_hashes: [[u8; MAPHASH_LEN]; MAX_PARTS],
    state: InboundState,
    /// Receive/request window; host grows on completed batches and shrinks on timeouts.
    pub window: WindowState,
}

impl core::fmt::Debug for InboundResource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InboundResource")
            .field("state", &self.state)
            .field("transfer_size", &self.transfer_size)
            .field("num_parts", &self.num_parts)
            .field("consecutive_completed", &self.consecutive_completed)
            .field("resource_hash", &self.resource_hash)
            .finish_non_exhaustive()
    }
}

impl InboundResource {
    /// Validate an advertisement against the lite honest-subset rules (see module docs) and the
    /// internal consistency of the advertised sizes; returns the derived `(map_hashes,
    /// num_parts)`. Shared by [`from_advertisement`] and [`from_advertisement_into`].
    fn validate_adv(
        adv: &ResourceAdv,
    ) -> Result<([[u8; MAPHASH_LEN]; MAX_PARTS], usize), ResourceError> {
        if adv.flags.compressed {
            return Err(ResourceError::CompressedUnsupported);
        }
        if adv.flags.has_metadata {
            return Err(ResourceError::MetadataUnsupported);
        }
        if adv.flags.split || adv.total_segments != 1 || adv.segment_index != 1 {
            return Err(ResourceError::SplitUnsupported);
        }
        if adv.flags.is_request || adv.flags.is_response || adv.request_id_len != 0 {
            return Err(ResourceError::RequestResponseUnsupported);
        }
        if !adv.flags.encrypted {
            return Err(ResourceError::EncryptionRequired);
        }

        let transfer = adv.transfer_size as usize;
        let data_size = adv.data_size as usize;
        if transfer > TRANSFER_MAX || data_size > DATA_MAX {
            return Err(ResourceError::TooLarge);
        }
        // Minimum token: IV + one AES block + HMAC.
        if transfer < TOKEN_OVERHEAD + 16 {
            return Err(ResourceError::InvalidAdvertisement);
        }
        // The advertised sizes must describe one uncompressed Token blob exactly.
        if token_len(RANDOM_HASH_SIZE + data_size) != transfer {
            return Err(ResourceError::InvalidAdvertisement);
        }
        let num_parts = transfer.div_ceil(SDU);
        if adv.num_parts as usize != num_parts {
            return Err(ResourceError::InvalidAdvertisement);
        }
        // Full hashmap must arrive with the ADV (always true for lite-sized resources).
        if adv.hashmap_len != num_parts * MAPHASH_LEN {
            return Err(ResourceError::InvalidAdvertisement);
        }

        let mut map_hashes = [[0u8; MAPHASH_LEN]; MAX_PARTS];
        for (i, mh) in map_hashes.iter_mut().take(num_parts).enumerate() {
            mh.copy_from_slice(&adv.hashmap[i * MAPHASH_LEN..(i + 1) * MAPHASH_LEN]);
        }
        Ok((map_hashes, num_parts))
    }

    /// Accept an advertisement IN PLACE into `self` (typically heap-resident — the ~3.7 KiB
    /// `buf` would otherwise be a by-value stack temp that pressures the MCU task stack).
    pub fn from_advertisement_into(&mut self, adv: &ResourceAdv) -> Result<(), ResourceError> {
        let (map_hashes, num_parts) = Self::validate_adv(adv)?;
        self.buf.fill(0);
        self.resource_hash = adv.resource_hash;
        self.random_hash = adv.random_hash;
        self.proof = [0u8; 32];
        self.transfer_size = adv.transfer_size;
        self.data_size = adv.data_size;
        self.data_len = 0;
        self.num_parts = num_parts as u8;
        self.consecutive_completed = 0;
        self.received = [false; MAX_PARTS];
        self.map_hashes = map_hashes;
        self.state = InboundState::Transferring;
        self.window = WindowState::new();
        Ok(())
    }

    pub fn from_advertisement(adv: &ResourceAdv) -> Result<Self, ResourceError> {
        let (map_hashes, num_parts) = Self::validate_adv(adv)?;
        Ok(Self {
            buf: [0u8; TRANSFER_MAX],
            resource_hash: adv.resource_hash,
            random_hash: adv.random_hash,
            proof: [0u8; 32],
            transfer_size: adv.transfer_size,
            data_size: adv.data_size,
            data_len: 0,
            num_parts: num_parts as u8,
            consecutive_completed: 0,
            received: [false; MAX_PARTS],
            map_hashes,
            state: InboundState::Transferring,
            window: WindowState::new(),
        })
    }

    pub fn state(&self) -> InboundState {
        self.state
    }

    pub fn num_parts(&self) -> usize {
        self.num_parts as usize
    }

    pub fn resource_hash(&self) -> &[u8; 32] {
        &self.resource_hash
    }

    /// Advertised plaintext data size (informational; the hash check is the authority).
    pub fn data_size(&self) -> usize {
        self.data_size as usize
    }

    fn expected_part_len(&self, i: usize) -> usize {
        let total = self.transfer_size as usize;
        if i + 1 == self.num_parts as usize {
            total - i * SDU
        } else {
            SDU
        }
    }

    /// Slot a received part (raw ciphertext chunk) by map hash within the current receive window.
    /// Returns true when it filled a previously-empty slot; duplicates, tampered parts and
    /// out-of-window arrivals return false (rns-protocol's replay-guarded scan, plus an exact
    /// length check so buffer placement stays sound).
    pub fn receive_part(&mut self, part: &[u8]) -> bool {
        if self.state != InboundState::Transferring {
            return false;
        }
        let total = self.num_parts as usize;
        let mh = get_map_hash(part, &self.random_hash);
        let start = self.consecutive_completed as usize;
        let end = (start + self.window.window).min(total);
        for i in start..end {
            if !self.received[i]
                && self.map_hashes[i] == mh
                && part.len() == self.expected_part_len(i)
            {
                let off = i * SDU;
                self.buf[off..off + part.len()].copy_from_slice(part);
                self.received[i] = true;
                while (self.consecutive_completed as usize) < total
                    && self.received[self.consecutive_completed as usize]
                {
                    self.consecutive_completed += 1;
                }
                return true;
            }
        }
        false
    }

    pub fn is_complete(&self) -> bool {
        self.consecutive_completed as usize == self.num_parts as usize
    }

    /// Emit a RESOURCE_REQ for the missing parts in the current window. The lite receiver always
    /// holds the full hashmap, so the exhausted flag is never set. Returns the request length.
    pub fn build_part_request(&self, out: &mut [u8]) -> Result<usize, ResourceError> {
        if self.state != InboundState::Transferring || self.is_complete() {
            return Err(ResourceError::InvalidState);
        }
        let total = self.num_parts as usize;
        let start = self.consecutive_completed as usize;
        let end = (start + self.window.window).min(total);

        let mut missing = 0usize;
        for &got in &self.received[start..end] {
            if !got {
                missing += 1;
                if missing >= self.window.window {
                    break;
                }
            }
        }
        let needed = 1 + 32 + missing * MAPHASH_LEN;
        if out.len() < needed {
            return Err(ResourceError::OutputTooSmall);
        }

        out[0] = HASHMAP_IS_NOT_EXHAUSTED;
        out[1..33].copy_from_slice(&self.resource_hash);
        let mut pos = 33;
        let mut count = 0usize;
        for i in start..end {
            if !self.received[i] {
                out[pos..pos + MAPHASH_LEN].copy_from_slice(&self.map_hashes[i]);
                pos += MAPHASH_LEN;
                count += 1;
                if count >= self.window.window {
                    break;
                }
            }
        }
        Ok(pos)
    }

    /// Reassemble: Token-decrypt the concatenated parts in place, strip the embedded random hash
    /// and verify the resource hash over the plaintext. Returns the payload length; the payload is
    /// then available via [`Self::data`] and the proof via [`Self::build_proof`].
    pub fn assemble(&mut self, keys: &LinkKeys) -> Result<usize, ResourceError> {
        if self.state != InboundState::Transferring {
            return Err(ResourceError::InvalidState);
        }
        if !self.is_complete() {
            return Err(ResourceError::Incomplete);
        }
        let total = self.transfer_size as usize;
        // Decrypt failure marks the transfer Corrupt (Python sets CORRUPT on any assemble error).
        let n = match token_decrypt_in_place(keys.combined(), &mut self.buf[..total]) {
            Ok(n) => n,
            Err(e) => {
                self.state = InboundState::Corrupt;
                return Err(ResourceError::Crypto(e));
            }
        };
        if n < RANDOM_HASH_SIZE {
            self.state = InboundState::Corrupt;
            return Err(ResourceError::Corrupt);
        }
        let data_off = 16 + RANDOM_HASH_SIZE;
        let data_len = n - RANDOM_HASH_SIZE;
        let calculated =
            compute_resource_hash(&self.buf[data_off..data_off + data_len], &self.random_hash);
        if calculated != self.resource_hash {
            self.state = InboundState::Corrupt;
            return Err(ResourceError::HashMismatch);
        }
        self.proof = compute_expected_proof(
            &self.buf[data_off..data_off + data_len],
            &self.resource_hash,
        );
        self.data_len = data_len as u16;
        self.state = InboundState::Assembled;
        Ok(data_len)
    }

    /// The reassembled payload (after a successful [`Self::assemble`]).
    pub fn data(&self) -> Option<&[u8]> {
        if self.state != InboundState::Assembled {
            return None;
        }
        let off = 16 + RANDOM_HASH_SIZE;
        Some(&self.buf[off..off + self.data_len as usize])
    }

    /// Write the 64-byte delivery proof (`resource_hash || SHA-256(data || resource_hash)`),
    /// sent as a PROOF packet with context RESOURCE_PRF.
    pub fn build_proof(&self, out: &mut [u8]) -> Result<usize, ResourceError> {
        if self.state != InboundState::Assembled {
            return Err(ResourceError::InvalidState);
        }
        if out.len() < PROOF_LEN {
            return Err(ResourceError::OutputTooSmall);
        }
        out[..32].copy_from_slice(&self.resource_hash);
        out[32..PROOF_LEN].copy_from_slice(&self.proof);
        Ok(PROOF_LEN)
    }
}

/// Sender ADV retry cap before the transfer fails (rns-protocol `MAX_ADV_RETRIES`).
pub const MAX_ADV_RETRIES: usize = 4;
/// Receiver processing grace added to the ADV deadline (rns-protocol `PROCESSING_GRACE`, 1 s).
pub const ADV_PROCESSING_GRACE_MS: u64 = 1_000;
/// RTT multiplier for the ADV deadline (rns-link `TRAFFIC_TIMEOUT_FACTOR`).
pub const TRAFFIC_TIMEOUT_FACTOR: u64 = 6;

/// Verdict of [`AdvWatchdog::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvWatchdogAction {
    /// Deadline not reached (or the watchdog has concluded) — do nothing.
    Wait,
    /// Re-send the stored advertisement; the deadline restarts from this poll's `now_ms`.
    Resend,
    /// Retries exhausted — fail the transfer (terminal; later polls return `Wait`).
    Failed,
}

/// Advertisement watchdog for the sender (rns-protocol `OutboundTransfer::check_timeout`):
/// until the receiver's first `RESOURCE_REQ`, the ADV is re-sent after
/// `rtt * TRAFFIC_TIMEOUT_FACTOR + ADV_PROCESSING_GRACE_MS`, up to [`MAX_ADV_RETRIES`]
/// times, then the transfer fails. Clock-free per the module split: the host owns the
/// transfer state machine and drives [`poll`](Self::poll) from its tick with its own
/// clock and measured RTT, re-sending its stored ADV on [`AdvWatchdogAction::Resend`].
#[derive(Debug, Clone, Copy)]
pub struct AdvWatchdog {
    marked_ms: u64,
    retries: usize,
    concluded: bool,
}

impl AdvWatchdog {
    /// Start the watchdog when the first ADV is sent.
    pub const fn new(sent_at_ms: u64) -> Self {
        Self {
            marked_ms: sent_at_ms,
            retries: 0,
            concluded: false,
        }
    }

    /// Deadline for one ADV round: `rtt * TRAFFIC_TIMEOUT_FACTOR + ADV_PROCESSING_GRACE_MS`.
    pub const fn deadline_ms(rtt_ms: u64) -> u64 {
        rtt_ms
            .saturating_mul(TRAFFIC_TIMEOUT_FACTOR)
            .saturating_add(ADV_PROCESSING_GRACE_MS)
    }

    /// The receiver responded (first `RESOURCE_REQ` served): the watchdog is done.
    pub fn request_seen(&mut self) {
        self.concluded = true;
    }

    pub const fn retries(&self) -> usize {
        self.retries
    }

    /// Mirror of the trusted `check_timeout`: strictly-greater-than-deadline fires.
    pub fn poll(&mut self, now_ms: u64, rtt_ms: u64) -> AdvWatchdogAction {
        if self.concluded || now_ms.saturating_sub(self.marked_ms) <= Self::deadline_ms(rtt_ms) {
            return AdvWatchdogAction::Wait;
        }
        if self.retries < MAX_ADV_RETRIES {
            self.retries += 1;
            self.marked_ms = now_ms;
            AdvWatchdogAction::Resend
        } else {
            self.concluded = true;
            AdvWatchdogAction::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> LinkKeys {
        LinkKeys::derive(&[0x33; 32], &[0x55; 32], &[0xCD; 16])
    }

    fn sample_outbound(len: usize) -> OutboundResource {
        let mut data = [0u8; DATA_MAX];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        OutboundResource::build(&data[..len], &test_keys(), &[0xAB; 4], &[0x11; 16]).unwrap()
    }

    #[test]
    fn consts_match_reference_values() {
        assert_eq!(SDU, 464); // MTU - HEADER_MAXSIZE - IFAC_MIN
        assert_eq!(LINK_MDU, 431); // Python RNS.Link.MDU
        assert_eq!(hashmap_max_len(LINK_MDU), 74); // Python HASHMAP_MAX_LEN
        assert_eq!(hashmap_max_len(415), 70); // LoRa-typical MDU (rns-protocol test)
        assert_eq!(TRANSFER_MAX, 3712);
        assert_eq!(DATA_MAX, 3659);
        assert_eq!(token_len(RANDOM_HASH_SIZE + DATA_MAX), TRANSFER_MAX);
    }

    #[test]
    fn flags_roundtrip_all_bytes() {
        for b in 0..=0x3F_u8 {
            assert_eq!(ResourceFlags::from_byte(b).to_byte(), b);
        }
        // Reserved high bits are dropped on decode (mirrors rns-protocol's field extraction).
        assert_eq!(ResourceFlags::from_byte(0xFF).to_byte(), 0x3F);
    }

    #[test]
    fn adv_pack_parse_roundtrip() {
        let out = sample_outbound(1000);
        let adv = out.advertisement();
        let mut buf = [0u8; ADV_PACKED_MAX];
        let n = adv.pack(&mut buf).unwrap();
        assert!(n <= ADV_PACKED_MAX);
        let back = ResourceAdv::parse(&buf[..n]).unwrap();
        assert_eq!(back, adv);

        // With a request id present (still parses, rejected only at accept time).
        let mut with_q = adv;
        with_q.request_id_len = 16;
        with_q.request_id[..16].copy_from_slice(&[0x42; 16]);
        let n = with_q.pack(&mut buf).unwrap();
        assert_eq!(ResourceAdv::parse(&buf[..n]).unwrap(), with_q);
    }

    #[test]
    fn adv_parse_is_total_on_truncation() {
        let out = sample_outbound(1500);
        let mut buf = [0u8; ADV_PACKED_MAX];
        let n = out.advertisement().pack(&mut buf).unwrap();
        // Every prefix must return a clean error, never panic.
        for cut in 0..n {
            assert!(ResourceAdv::parse(&buf[..cut]).is_err());
            assert!(ResourceAdv::rejection_hash(&buf[..cut]).is_err());
        }
        // Trailing garbage after a whole map is ignored (single-object decode).
        let mut extended = [0u8; ADV_PACKED_MAX + 4];
        extended[..n].copy_from_slice(&buf[..n]);
        assert!(ResourceAdv::parse(&extended[..n + 4]).is_ok());
    }

    #[test]
    fn rejection_hash_matches_full_rust_large_segment() {
        use rns_protocol::resource::ResourceFlags as FullFlags;
        use rns_protocol::resource_adv::ResourceAdvertisement;
        let mut adv = ResourceAdvertisement::new(
            40_000,
            39_936,
            87,
            [0x45; 32],
            std::vec![0x22; 4],
            FullFlags {
                encrypted: true,
                ..Default::default()
            },
            &[[0x13; 4]; 74],
            LINK_MDU,
        );
        adv.original_hash = [0x99; 32];
        let bytes = adv.pack();
        assert!(bytes.len() > ADV_PACKED_MAX);
        assert_eq!(ResourceAdv::parse(&bytes), Err(ResourceError::TooLarge));
        assert_eq!(ResourceAdv::rejection_hash(&bytes), Ok(adv.resource_hash));
        for cut in 0..bytes.len() {
            assert!(ResourceAdv::rejection_hash(&bytes[..cut]).is_err());
        }
        let mut malformed = bytes.clone();
        malformed[2] = b'd'; // Duplicate field: no partial hash may escape.
        assert!(ResourceAdv::rejection_hash(&malformed).is_err());
    }

    #[test]
    fn adv_parse_rejects_malformed() {
        let out = sample_outbound(600);
        let mut buf = [0u8; ADV_PACKED_MAX];
        let n = out.advertisement().pack(&mut buf).unwrap();

        // Wrong map arity.
        let mut bad = buf;
        bad[0] = 0x8A;
        assert!(ResourceAdv::parse(&bad[..n]).is_err());
        // Not a map.
        bad[0] = 0x91;
        assert!(ResourceAdv::parse(&bad[..n]).is_err());
        // Unknown key.
        let mut bad = buf;
        bad[2] = b'z'; // first key char ('t')
        assert_eq!(
            ResourceAdv::parse(&bad[..n]),
            Err(ResourceError::InvalidAdvertisement)
        );
        // Duplicate key.
        let mut bad = buf;
        bad[2] = b'd'; // 't' -> 'd', so 'd' appears twice
        assert_eq!(
            ResourceAdv::parse(&bad[..n]),
            Err(ResourceError::InvalidAdvertisement)
        );
        // Oversized u64 int for t.
        let mut w = MpWriter {
            out: &mut buf,
            pos: 0,
        };
        w.put(&[0x8B, 0xA1, b't', 0xCF]).unwrap();
        w.put(&u64::MAX.to_be_bytes()).unwrap();
        let pos = w.pos;
        assert_eq!(
            ResourceAdv::parse(&buf[..pos + 1]),
            Err(ResourceError::TooLarge)
        );
    }

    #[test]
    fn adv_parse_rejects_bad_field_shapes() {
        // Hashmap not a multiple of MAPHASH_LEN: shrink m's bin length (m is the final field).
        let out = sample_outbound(600);
        let adv = out.advertisement();
        let mut buf = [0u8; ADV_PACKED_MAX];
        let n = adv.pack(&mut buf).unwrap();
        let m_len_idx = n - 1 - adv.hashmap_len;
        assert_eq!(buf[m_len_idx - 1], 0xC4);
        let mut bad = buf;
        bad[m_len_idx] -= 1;
        assert_eq!(
            ResourceAdv::parse(&bad[..n - 1]),
            Err(ResourceError::InvalidAdvertisement)
        );
        // Hashmap beyond the lite part cap parses to a clean TooLarge, never a copy overflow.
        let over_len = MAX_PARTS * MAPHASH_LEN + MAPHASH_LEN;
        let extra = over_len - adv.hashmap_len;
        let mut widened = [0u8; ADV_PACKED_MAX + MAX_PARTS * MAPHASH_LEN];
        widened[..n].copy_from_slice(&buf[..n]);
        widened[m_len_idx] = over_len as u8;
        assert_eq!(
            ResourceAdv::parse(&widened[..n + extra]),
            Err(ResourceError::TooLarge)
        );
        // Wrong hash / random-tag / request-id lengths fail on the first offending field.
        for (key, len) in [(b'h', 31u8), (b'r', 5), (b'q', (REQUEST_ID_MAX + 1) as u8)] {
            let mut fb = [0u8; 64];
            let mut w = MpWriter {
                out: &mut fb,
                pos: 0,
            };
            w.put(&[0x8B, 0xA1, key, 0xC4, len]).unwrap();
            w.put(&[0u8; 40][..len as usize]).unwrap();
            let pos = w.pos;
            assert_eq!(
                ResourceAdv::parse(&fb[..pos]),
                Err(ResourceError::InvalidAdvertisement)
            );
        }
    }

    #[test]
    fn inbound_rejects_unsupported_and_inconsistent_advs() {
        let out = sample_outbound(1000);
        let adv = out.advertisement();

        let mut a = adv;
        a.flags.compressed = true;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::CompressedUnsupported
        );
        let mut a = adv;
        a.flags.has_metadata = true;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::MetadataUnsupported
        );
        let mut a = adv;
        a.flags.split = true;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::SplitUnsupported
        );
        let mut a = adv;
        a.total_segments = 2;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::SplitUnsupported
        );
        let mut a = adv;
        a.segment_index = 2;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::SplitUnsupported
        );
        let mut a = adv;
        a.request_id_len = 4;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::RequestResponseUnsupported
        );
        let mut a = adv;
        a.flags.is_request = true;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::RequestResponseUnsupported
        );
        let mut a = adv;
        a.flags.is_response = true;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::RequestResponseUnsupported
        );
        let mut a = adv;
        a.flags.encrypted = false;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::EncryptionRequired
        );
        let mut a = adv;
        a.transfer_size = (TRANSFER_MAX + 1) as u32;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::TooLarge
        );
        let mut a = adv;
        a.data_size = (DATA_MAX + 1) as u32;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::TooLarge
        );
        let mut a = adv;
        a.data_size += 16; // breaks the token-size consistency check
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::InvalidAdvertisement
        );
        let mut a = adv;
        a.num_parts += 1;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::InvalidAdvertisement
        );
        let mut a = adv;
        a.hashmap_len -= MAPHASH_LEN;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::InvalidAdvertisement
        );
        let mut a = adv;
        a.transfer_size = 32; // below the one-block token minimum
        a.num_parts = 1;
        assert_eq!(
            InboundResource::from_advertisement(&a).unwrap_err(),
            ResourceError::InvalidAdvertisement
        );
    }

    #[test]
    fn full_transfer_roundtrip_multi_part() {
        let keys = test_keys();
        let mut data = [0u8; 2000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        let out = OutboundResource::build(&data, &keys, &[0xAB; 4], &[0x11; 16]).unwrap();
        assert_eq!(out.num_parts(), 5);
        assert_eq!(out.transfer_size(), token_len(4 + 2000));

        // ADV over the wire.
        let mut advbuf = [0u8; ADV_PACKED_MAX];
        let n = out.advertisement().pack(&mut advbuf).unwrap();
        let adv = ResourceAdv::parse(&advbuf[..n]).unwrap();
        let mut inb = InboundResource::from_advertisement(&adv).unwrap();

        // Window: part 4 is outside the initial window of 4 and must be refused for now.
        assert!(!inb.receive_part(out.part(4).unwrap()));

        // First window of parts, with a duplicate and a tampered copy rejected.
        for i in 0..4 {
            let part = out.part(i).unwrap();
            assert!(inb.receive_part(part));
            assert!(!inb.receive_part(part)); // duplicate
        }
        let p4 = out.part(4).unwrap();
        let mut tampered = [0u8; SDU];
        tampered[..p4.len()].copy_from_slice(p4);
        tampered[0] ^= 0xFF;
        assert!(!inb.receive_part(&tampered[..p4.len()]));

        // Receiver requests the remainder; sender serves it.
        let mut req = [0u8; REQUEST_MAX];
        let rn = inb.build_part_request(&mut req).unwrap();
        let view = PartRequestView::parse(&req[..rn]).unwrap();
        assert!(!view.wants_more_hashmap);
        assert_eq!(view.resource_hash, *out.resource_hash());
        assert_eq!(view.requested_count(), 1);
        let (idx, cnt) = out.requested_parts(&view);
        assert_eq!((idx[0], cnt), (4, 1));
        // A request addressed to a different resource hash is ignored (Python link routing).
        let mut foreign = req;
        foreign[1] ^= 0xFF;
        let fview = PartRequestView::parse(&foreign[..rn]).unwrap();
        assert_eq!(out.requested_parts(&fview).1, 0);
        assert!(inb.receive_part(out.part(4).unwrap()));
        assert!(inb.is_complete());
        assert_eq!(
            inb.build_part_request(&mut req),
            Err(ResourceError::InvalidState)
        );

        // Reassemble, verify, prove.
        let len = inb.assemble(&keys).unwrap();
        assert_eq!(len, 2000);
        assert_eq!(inb.data().unwrap(), &data[..]);
        let mut proof = [0u8; PROOF_LEN];
        assert_eq!(inb.build_proof(&mut proof).unwrap(), PROOF_LEN);
        assert!(out.validate_proof(&proof));

        // Tampered / wrong-length proofs are refused.
        let mut bad = proof;
        bad[40] ^= 0x01;
        assert!(!out.validate_proof(&bad));
        assert!(!out.validate_proof(&proof[..63]));
    }

    #[test]
    fn single_part_and_bounds() {
        let keys = test_keys();
        let out = OutboundResource::build(b"tiny", &keys, &[0x01; 4], &[0x02; 16]).unwrap();
        assert_eq!(out.num_parts(), 1);
        assert!(out.part(1).is_none());

        let mut advbuf = [0u8; ADV_PACKED_MAX];
        let n = out.advertisement().pack(&mut advbuf).unwrap();
        let adv = ResourceAdv::parse(&advbuf[..n]).unwrap();
        let mut inb = InboundResource::from_advertisement(&adv).unwrap();
        assert_eq!(inb.assemble(&keys), Err(ResourceError::Incomplete));
        assert!(inb.receive_part(out.part(0).unwrap()));
        assert_eq!(inb.assemble(&keys).unwrap(), 4);
        assert_eq!(inb.data().unwrap(), b"tiny");
        // Second assemble is refused; parts no longer accepted.
        assert_eq!(inb.assemble(&keys), Err(ResourceError::InvalidState));
        assert!(!inb.receive_part(out.part(0).unwrap()));

        // Max payload builds to exactly MAX_PARTS; one byte more is rejected.
        let big = [0x5A; DATA_MAX + 1];
        assert!(OutboundResource::build(&big[..DATA_MAX], &keys, &[0x01; 4], &[0x02; 16]).is_ok());
        assert_eq!(
            OutboundResource::build(&big, &keys, &[0x01; 4], &[0x02; 16]).unwrap_err(),
            ResourceError::TooLarge
        );
    }

    #[test]
    fn assemble_with_wrong_keys_fails_closed() {
        let keys = test_keys();
        let out =
            OutboundResource::build(b"secret payload", &keys, &[0x01; 4], &[0x02; 16]).unwrap();
        let mut advbuf = [0u8; ADV_PACKED_MAX];
        let n = out.advertisement().pack(&mut advbuf).unwrap();
        let mut inb =
            InboundResource::from_advertisement(&ResourceAdv::parse(&advbuf[..n]).unwrap())
                .unwrap();
        assert!(inb.receive_part(out.part(0).unwrap()));
        let wrong = LinkKeys::derive(&[0x99; 32], &[0x55; 32], &[0xCD; 16]);
        assert_eq!(
            inb.assemble(&wrong),
            Err(ResourceError::Crypto(CryptoError::AuthenticationFailed))
        );
        // Failed decrypt marks the transfer Corrupt: no retry, no parts, no data, no proof.
        assert_eq!(inb.state(), InboundState::Corrupt);
        assert_eq!(inb.assemble(&keys), Err(ResourceError::InvalidState));
        assert!(!inb.receive_part(out.part(0).unwrap()));
        assert!(inb.data().is_none());
        let mut proof = [0u8; PROOF_LEN];
        assert_eq!(
            inb.build_proof(&mut proof),
            Err(ResourceError::InvalidState)
        );
    }

    #[test]
    fn request_parse_bounds_and_exhausted_form() {
        // Too short for flag + resource hash.
        assert!(PartRequestView::parse(&[]).is_err());
        assert!(PartRequestView::parse(&[0x00; 32]).is_err());
        // Exhausted form needs 4 more bytes.
        assert!(PartRequestView::parse(&[0xFF; 33]).is_err());
        let mut req = [0u8; 1 + 4 + 32 + 8];
        req[0] = HASHMAP_IS_EXHAUSTED;
        req[1..5].copy_from_slice(&[0xAA; 4]);
        req[5..37].copy_from_slice(&[0xBB; 32]);
        req[37..45].copy_from_slice(&[0xCC; 8]);
        let view = PartRequestView::parse(&req).unwrap();
        assert!(view.wants_more_hashmap);
        assert_eq!(view.last_map_hash, Some([0xAA; 4]));
        assert_eq!(view.resource_hash, [0xBB; 32]);
        assert_eq!(view.requested_count(), 2);
        // A trailing partial hash is ignored, not an error (chunks_exact parity).
        let view = PartRequestView::parse(&req[..44]).unwrap();
        assert_eq!(view.requested_count(), 1);
        // Unknown flag byte is treated as not-exhausted (Python: only 0xFF means exhausted).
        let mut plain = [0u8; 33];
        plain[0] = 0x42;
        let view = PartRequestView::parse(&plain).unwrap();
        assert!(!view.wants_more_hashmap);
    }

    // Golden ADV vectors generated with Python RNS 1.4.2 `umsgpack.packb` (validated by
    // `RNS.Resource.ResourceAdvertisement.unpack`) — upstream-only vectors, never re-derived.
    #[test]
    fn adv_codec_matches_python_rns_vectors() {
        fn unhex(s: &str) -> std::vec::Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        }
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        let r = [0xA1, 0xB2, 0xC3, 0xD4];
        let o = [0x55u8; 32];

        // (transfer, data, n, q_len, flags, hashmap_len, python_hex)
        let vectors = [
            (
                3712u32,
                3659u32,
                8u32,
                0usize,
                0x01u8,
                32usize,
                "8ba174cd0e80a164cd0e4ba16e08a168c420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa172c404a1b2c3d4a16fc4205555555555555555555555555555555555555555555555555555555555555555a16901a16c01a171c0a16601a16dc420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ),
            (
                128,
                127,
                1,
                16,
                0x3F,
                4,
                "8ba174cc80a1647fa16e01a168c420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa172c404a1b2c3d4a16fc4205555555555555555555555555555555555555555555555555555555555555555a16901a16c01a171c41042424242424242424242424242424242a1663fa16dc40400010203",
            ),
            (
                65536,
                65535,
                8,
                0,
                0x00,
                32,
                "8ba174ce00010000a164cdffffa16e08a168c420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa172c404a1b2c3d4a16fc4205555555555555555555555555555555555555555555555555555555555555555a16901a16c01a171c0a16600a16dc420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ),
        ];
        for (t, d, n, q_len, f, m_len, hex) in vectors {
            let mut adv = ResourceAdv {
                transfer_size: t,
                data_size: d,
                num_parts: n,
                resource_hash: h,
                random_hash: r,
                original_hash: o,
                segment_index: 1,
                total_segments: 1,
                request_id_len: q_len,
                flags: ResourceFlags::from_byte(f),
                hashmap_len: m_len,
                ..Default::default()
            };
            adv.request_id[..q_len].copy_from_slice(&[0x42; REQUEST_ID_MAX][..q_len]);
            adv.hashmap[..m_len].copy_from_slice(&h[..m_len]);

            let golden = unhex(hex);
            let mut buf = [0u8; ADV_PACKED_MAX];
            let pn = adv.pack(&mut buf).unwrap();
            assert_eq!(&buf[..pn], golden.as_slice());
            assert_eq!(ResourceAdv::parse(&golden).unwrap(), adv);
        }
    }

    #[test]
    fn map_hash_collision_detected() {
        let hashes = [[1u8; 4], [2u8; 4], [3u8; 4]];
        assert!(!has_map_hash_collision(&hashes));
        let dup = [[1u8; 4], [2u8; 4], [1u8; 4]];
        assert!(has_map_hash_collision(&dup));
    }

    // Regression: a very-slow demotion can clamp `window` below an already-raised `window_min`;
    // the next promoted grow must not underflow `window - window_min` (Python's signed comparison
    // is simply false there).
    #[test]
    fn window_grow_survives_demote_then_promote() {
        let mut w = WindowState::new();
        for _ in 0..6 {
            w.grow(1000);
        }
        assert_eq!((w.window, w.window_min, w.window_max), (10, 7, 10));
        for _ in 0..VERY_SLOW_RATE_THRESHOLD {
            w.grow(RATE_VERY_SLOW - 1);
        }
        assert_eq!(
            (w.window, w.window_min, w.window_max),
            (WINDOW_MAX_VERY_SLOW, 7, WINDOW_MAX_VERY_SLOW)
        );
        for _ in 0..FAST_RATE_THRESHOLD + 1 {
            w.grow(RATE_FAST + 1);
        }
        assert_eq!(w.window_max, WINDOW_MAX_FAST);
        assert_eq!(w.window, 5);
        assert_eq!(w.window_min, 7); // unchanged: window has not outgrown the band
    }

    // Rate 0 (host has no estimate — the common clockless-MCU case) must not count as a
    // very-slow round and demote the ceiling.
    #[test]
    fn window_grow_rate_zero_is_neutral() {
        let mut w = WindowState::new();
        for _ in 0..8 {
            w.grow(0);
        }
        assert_eq!(w.window_max, WINDOW_MAX_SLOW);
        assert_eq!(w.very_slow_rate_rounds, 0);
        assert_eq!(w.window, WINDOW_MAX_SLOW.min(WINDOW_INITIAL + 8));
    }

    #[test]
    fn window_state_grows_and_shrinks_like_reference() {
        let mut w = WindowState::new();
        assert_eq!((w.window, w.window_min, w.window_max), (4, 2, 10));
        // Sustained fast rounds promote the ceiling.
        for _ in 0..FAST_RATE_THRESHOLD {
            w.grow(RATE_FAST + 1);
        }
        assert_eq!(w.window_max, WINDOW_MAX_FAST);
        // Sustained very-slow rounds demote and clamp.
        let mut w = WindowState::new();
        for _ in 0..VERY_SLOW_RATE_THRESHOLD + 3 {
            w.grow(RATE_VERY_SLOW - 1);
        }
        assert_eq!(w.window_max, WINDOW_MAX_VERY_SLOW);
        assert!(w.window <= w.window_max);
        // Shrink floors at window_min.
        for _ in 0..20 {
            w.shrink();
        }
        assert_eq!(w.window, w.window_min);
    }

    #[test]
    fn adv_watchdog_resends_then_fails() {
        let rtt_ms = 50;
        let deadline = AdvWatchdog::deadline_ms(rtt_ms);
        assert_eq!(deadline, 50 * 6 + 1_000);

        let mut w = AdvWatchdog::new(1_000);
        // Boundary is strictly-greater (trusted `elapsed() <= timeout` waits).
        assert_eq!(w.poll(1_000 + deadline, rtt_ms), AdvWatchdogAction::Wait);
        let mut now = 1_000;
        for round in 1..=MAX_ADV_RETRIES {
            now += deadline + 1;
            assert_eq!(w.poll(now, rtt_ms), AdvWatchdogAction::Resend);
            assert_eq!(w.retries(), round);
            // Deadline restarted from the resend.
            assert_eq!(w.poll(now + deadline, rtt_ms), AdvWatchdogAction::Wait);
        }
        now += deadline + 1;
        assert_eq!(w.poll(now, rtt_ms), AdvWatchdogAction::Failed);
        // Terminal: no further actions.
        assert_eq!(w.poll(now + 10 * deadline, rtt_ms), AdvWatchdogAction::Wait);
    }

    #[test]
    fn adv_watchdog_inert_after_request_seen() {
        let mut w = AdvWatchdog::new(0);
        w.request_seen();
        assert_eq!(w.poll(u64::MAX, 1), AdvWatchdogAction::Wait);
        assert_eq!(w.retries(), 0);
    }

    #[test]
    fn adv_watchdog_deadline_saturates() {
        assert_eq!(AdvWatchdog::deadline_ms(u64::MAX), u64::MAX);
    }
}

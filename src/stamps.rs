//! Proof-of-work stamp primitives in fixed point, without heap or floats.
//!
//! Ported from the trusted `rns-identity` stamps module (Python reference
//! `RNS/Stamps.py`, 1.6.0). Costs and values carry 8 fractional bits: a cost
//! of 1.0 is 256. Searches are resumable and take candidates from the caller,
//! so the crate never needs an RNG and a firmware loop is never blocked.

use sha2::{Digest, Sha256};

/// Size of message and key stamps (`RNS.Stamps.STAMP_SIZE`).
pub const STAMP_SIZE: usize = 32;
/// Size of detached destination and path-request stamps (`Identity.STAMPLENGTH`).
pub const NETWORK_STAMP_SIZE: usize = 14;
pub const MANTISSA_BITS: u32 = 33;
pub const COST_FP_BITS: u32 = 8;
pub const COST_FP: u32 = 1 << COST_FP_BITS;
pub const STAMP_COST_CAP_FP: u16 = 100 * 256;
/// Fixed-point value of a stamp whose hash is zero.
pub const MAX_VALUE_FP: u32 = 256 * COST_FP;

pub const TAB_DIGEST: &str = "55ba3ce1df224895b0dfdc102eb4359fc2f5a7efefee68df0cc90c8a8ac24f48";
pub const PRM_DIGEST: &str = "21436fc98e76a12cad7c52ebeb6ab76c2ae93b4cd768949df7fdd4e2f98c378d";

/// `floor(2^33 * 2^(f/256))` for `f` in `0..256`, copied verbatim from
/// upstream. Never compute these: the table is the wire contract.
pub const TAB: [u64; 256] = [
    0x200000000,
    0x201635f4b,
    0x202c7b53f,
    0x2042d0287,
    0x2059347ce,
    0x206fa85c2,
    0x20862bd0d,
    0x209cbee5e,
    0x20b361a62,
    0x20ca141c7,
    0x20e0d653b,
    0x20f7a856e,
    0x210e8a30e,
    0x21257becc,
    0x213c7d958,
    0x21538f363,
    0x216ab0d9f,
    0x2181e28bc,
    0x21992456e,
    0x21b076467,
    0x21c7d865a,
    0x21df4abfb,
    0x21f6cd5ff,
    0x220e6051a,
    0x222603a02,
    0x223db756b,
    0x22557b80d,
    0x226d5029e,
    0x2285355d5,
    0x229d2b269,
    0x22b531914,
    0x22cd48a8e,
    0x22e57078f,
    0x22fda90d2,
    0x2315f2711,
    0x232e4cb06,
    0x2346b7d6d,
    0x235f33f02,
    0x2377c1080,
    0x23905f2a5,
    0x23a90e62d,
    0x23c1cebd6,
    0x23daa045f,
    0x23f383087,
    0x240c7710c,
    0x24257c6af,
    0x243e9322f,
    0x2457bb44f,
    0x2470f4dce,
    0x248a3ff70,
    0x24a39c9f6,
    0x24bd0ae23,
    0x24d68acbc,
    0x24f01c683,
    0x2509bfc3e,
    0x252374eb2,
    0x253d3bea3,
    0x255714cda,
    0x2570ffa1b,
    0x258afc72e,
    0x25a50b4dc,
    0x25bf2c3ec,
    0x25d95f527,
    0x25f3a4957,
    0x260dfc146,
    0x262865dbd,
    0x2642e1f89,
    0x265d70775,
    0x26781164c,
    0x2692c4cdc,
    0x26ad8abf2,
    0x26c86345b,
    0x26e34e6e7,
    0x26fe4c463,
    0x27195cda0,
    0x27348036e,
    0x274fb669c,
    0x276aff7fd,
    0x27865b862,
    0x27a1ca89d,
    0x27bd4c982,
    0x27d8e1be3,
    0x27f48a095,
    0x28104586c,
    0x282c1443e,
    0x2847f64e1,
    0x2863ebb2a,
    0x287ff47f0,
    0x289c10c0c,
    0x28b840854,
    0x28d483da3,
    0x28f0dacd1,
    0x290d456b8,
    0x2929c3c32,
    0x294655e1a,
    0x2962fbd4d,
    0x297fb5aa6,
    0x299c83702,
    0x29b96533f,
    0x29d65b03b,
    0x29f364ed3,
    0x2a1082fe8,
    0x2a2db5459,
    0x2a4afbd07,
    0x2a6856ad3,
    0x2a85c5e9e,
    0x2aa34994b,
    0x2ac0e1bbd,
    0x2ade8e6d6,
    0x2afc4fb7c,
    0x2b1a25a92,
    0x2b38104ff,
    0x2b560fba9,
    0x2b7423f75,
    0x2b924d14b,
    0x2bb08b213,
    0x2bcede2b5,
    0x2bed4641b,
    0x2c0bc372e,
    0x2c2a55cd9,
    0x2c48fd607,
    0x2c67ba3a3,
    0x2c868c699,
    0x2ca573fd7,
    0x2cc47104a,
    0x2ce3838e1,
    0x2d02aba89,
    0x2d21e9633,
    0x2d413cccf,
    0x2d60a5f4e,
    0x2d8024ea1,
    0x2d9fb9bba,
    0x2dbf6478c,
    0x2ddf2530b,
    0x2dfefbf2a,
    0x2e1ee8cde,
    0x2e3eebd1d,
    0x2e5f050dd,
    0x2e7f34914,
    0x2e9f7a6ba,
    0x2ebfd6ac8,
    0x2ee049635,
    0x2f00d29fb,
    0x2f2172715,
    0x2f4228e7d,
    0x2f62f612e,
    0x2f83da026,
    0x2fa4d4c5f,
    0x2fc5e66d9,
    0x2fe70f092,
    0x30084ea87,
    0x3029a55ba,
    0x304b13329,
    0x306c983d7,
    0x308e348c4,
    0x30afe82f3,
    0x30d1b3368,
    0x30f395b26,
    0x31158fb31,
    0x3137a148f,
    0x3159ca845,
    0x317c0b75a,
    0x319e642d6,
    0x31c0d4bc1,
    0x31e35d322,
    0x3205fda05,
    0x3228b6172,
    0x324b86a75,
    0x326e6f619,
    0x32917056b,
    0x32b489979,
    0x32d7bb34e,
    0x32fb053fb,
    0x331e67c8f,
    0x3341e2e19,
    0x3365769aa,
    0x338923054,
    0x33ace8329,
    0x33d0c633c,
    0x33f4bd1a0,
    0x3418ccf6b,
    0x343cf5db1,
    0x346137d89,
    0x348593008,
    0x34aa07647,
    0x34ce9515e,
    0x34f33c266,
    0x3517fca78,
    0x353cd6aaf,
    0x3561ca426,
    0x3586d77fa,
    0x35abfe747,
    0x35d13f32b,
    0x35f699cc4,
    0x361c0e531,
    0x36419cd93,
    0x366745709,
    0x368d082b6,
    0x36b2e51bc,
    0x36d8dc53e,
    0x36feede5f,
    0x372519e44,
    0x374b60614,
    0x3771c16f3,
    0x37983d209,
    0x37bed387e,
    0x37e584b7a,
    0x380c50c28,
    0x383337bb0,
    0x385a39b3f,
    0x388156bff,
    0x38a88ef1f,
    0x38cfe25ca,
    0x38f751131,
    0x391edb280,
    0x394680aea,
    0x396e41b9d,
    0x39961e5cd,
    0x39be16aab,
    0x39e62ab6b,
    0x3a0e5a940,
    0x3a36a6561,
    0x3a5f0e101,
    0x3a8791d59,
    0x3ab031b9f,
    0x3ad8edd0c,
    0x3b01c62d9,
    0x3b2abae3f,
    0x3b53cc07b,
    0x3b7cf9ac7,
    0x3ba643e60,
    0x3bcfaac83,
    0x3bf92e66f,
    0x3c22ced63,
    0x3c4c8c29e,
    0x3c7666762,
    0x3ca05dcf1,
    0x3cca7248c,
    0x3cf4a3f78,
    0x3d1ef2ef9,
    0x3d495f454,
    0x3d73e90cf,
    0x3d9e905b1,
    0x3dc955443,
    0x3df437dcc,
    0x3e1f38396,
    0x3e4a566ed,
    0x3e759291b,
    0x3ea0ecb6d,
    0x3ecc64f31,
    0x3ef7fb5b3,
    0x3f23b0044,
    0x3f4f83033,
    0x3f7b746d2,
    0x3fa784571,
    0x3fd3b2d65,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StampError {
    /// Fixed-point cost above 25600 (cost 100), which upstream rejects.
    FpOutOfRange(u16),
}

/// Wire encoding: integer byte first.
pub const fn fp_to_bytes(fp: u16) -> [u8; 2] {
    fp.to_be_bytes()
}

/// Not clamped: wire bytes can carry up to 65535.
pub const fn fp_from_bytes(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

/// Largest stamp hash that meets a cost, as a 264-bit big-endian integer.
/// Cost 0 gives `2^256`, which is why 32 bytes are not enough.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StampTarget([u8; 33]);

impl StampTarget {
    /// A stamp meets the cost when its hash is at most the target.
    pub fn accepts(&self, hash: &[u8; 32]) -> bool {
        self.0[0] != 0 || hash[..] <= self.0[1..]
    }

    pub const fn to_be_bytes(&self) -> [u8; 33] {
        self.0
    }
}

pub fn target_from_fp(fp: u16) -> Result<StampTarget, StampError> {
    if fp > STAMP_COST_CAP_FP {
        return Err(StampError::FpOutOfRange(fp));
    }
    let exponent = 256 * COST_FP - u32::from(fp);
    let (whole, fraction) = (exponent / COST_FP, exponent % COST_FP);
    // `(TAB[f] << i) >> 33`; `i` is at least 156, so no bits are lost.
    let shift = whole - MANTISSA_BITS;
    let mantissa = TAB[fraction as usize];
    let mut target = [0u8; 33];
    for bit in 0..=MANTISSA_BITS {
        if (mantissa >> bit) & 1 == 1 {
            let position = (shift + bit) as usize;
            target[32 - position / 8] |= 1 << (position % 8);
        }
    }
    Ok(StampTarget(target))
}

/// A zero-round workblock is the material itself; network stamps use it.
pub const fn stamp_workblock_zero_rounds(material: &[u8]) -> &[u8] {
    material
}

/// Unfinalized hash state over a workblock, reusable for every candidate.
pub fn workblock_prefix(workblock: &[u8]) -> Sha256 {
    let mut prefix = Sha256::new();
    prefix.update(workblock);
    prefix
}

/// `SHA256(workblock || stamp)` from a [`workblock_prefix`].
pub fn stamp_hash(prefix: &Sha256, stamp: &[u8]) -> [u8; 32] {
    let mut hasher = prefix.clone();
    hasher.update(stamp);
    hasher.finalize().into()
}

/// Fixed-point value of a stamp hash, `0..=65536`.
pub fn stamp_value_fp_from_hash(hash: &[u8; 32]) -> u32 {
    let mut leading_zeros = 0usize;
    for byte in hash {
        if *byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    if leading_zeros == 256 {
        return MAX_VALUE_FP;
    }
    // The 34 bits from the leading one, zero-padded past the end of the hash.
    let mut mantissa = 0u64;
    for offset in 0..=MANTISSA_BITS as usize {
        let position = leading_zeros + offset;
        let bit = if position < 256 {
            (hash[position / 8] >> (7 - position % 8)) & 1
        } else {
            0
        };
        mantissa = (mantissa << 1) | u64::from(bit);
    }
    let not_above = TAB.partition_point(|entry| *entry <= mantissa) as u32;
    ((leading_zeros as u32 + 1) << COST_FP_BITS) - not_above
}

pub fn stamp_value_fp(workblock: &[u8], stamp: &[u8]) -> u32 {
    stamp_value_fp_from_hash(&stamp_hash(&workblock_prefix(workblock), stamp))
}

pub fn stamp_valid_fp(stamp: &[u8], target_fp: u16, workblock: &[u8]) -> Result<bool, StampError> {
    Ok(target_from_fp(target_fp)?.accepts(&stamp_hash(&workblock_prefix(workblock), stamp)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress<const N: usize> {
    Searching {
        attempts: u64,
    },
    /// `value_fp` is the stamp's real fixed-point value, not the cost.
    Complete {
        stamp: [u8; N],
        value_fp: u32,
    },
    Exhausted,
    Cancelled,
}

/// One caller-owned search for an `N`-byte detached stamp over a workblock.
/// The attempt limit bounds even an infeasible cost.
#[derive(Clone)]
pub struct StampSearch<const N: usize> {
    prefix: Sha256,
    target: StampTarget,
    attempts: u64,
    limit: u64,
    progress: Progress<N>,
}

/// Search for a 14-byte destination or path-request stamp.
pub type NetworkStampSearch = StampSearch<NETWORK_STAMP_SIZE>;

impl<const N: usize> StampSearch<N> {
    /// Costs above 25600 are rejected, as upstream generation rejects them.
    /// A cost of 0 accepts the first candidate.
    pub fn new(workblock: &[u8], cost_fp: u16, attempt_limit: u64) -> Result<Self, StampError> {
        Self::with_prefix(workblock_prefix(workblock), cost_fp, attempt_limit)
    }

    /// Like [`Self::new`], from a [`workblock_prefix`] built incrementally.
    pub fn with_prefix(
        prefix: Sha256,
        cost_fp: u16,
        attempt_limit: u64,
    ) -> Result<Self, StampError> {
        Ok(Self {
            prefix,
            target: target_from_fp(cost_fp)?,
            attempts: 0,
            limit: attempt_limit,
            progress: if attempt_limit == 0 {
                Progress::Exhausted
            } else {
                Progress::Searching { attempts: 0 }
            },
        })
    }

    pub fn progress(&self) -> Progress<N> {
        self.progress
    }

    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    /// Cancel an active search. Terminal results remain stable.
    pub fn cancel(&mut self) {
        if matches!(self.progress, Progress::Searching { .. }) {
            self.progress = Progress::Cancelled;
        }
    }

    /// Test one candidate; a terminal search ignores it.
    pub fn offer(&mut self, candidate: &[u8; N]) -> Progress<N> {
        if !matches!(self.progress, Progress::Searching { .. }) {
            return self.progress;
        }
        let hash = stamp_hash(&self.prefix, candidate);
        self.attempts += 1;
        self.progress = if self.target.accepts(&hash) {
            Progress::Complete {
                stamp: *candidate,
                value_fp: stamp_value_fp_from_hash(&hash),
            }
        } else if self.attempts == self.limit {
            Progress::Exhausted
        } else {
            Progress::Searching {
                attempts: self.attempts,
            }
        };
        self.progress
    }

    /// Test at most `attempt_budget` candidates, each filled by `fill` from
    /// the caller's cryptographic RNG.
    pub fn step(&mut self, attempt_budget: u32, mut fill: impl FnMut(&mut [u8; N])) -> Progress<N> {
        let mut candidate = [0u8; N];
        for _ in 0..attempt_budget {
            if !matches!(self.progress, Progress::Searching { .. }) {
                break;
            }
            fill(&mut candidate);
            self.offer(&candidate);
        }
        self.progress
    }
}

/// Search for an X25519 key whose public half stamps some material, as used
/// by link-request stamps. The caller generates each candidate key pair,
/// offers the public key, and keeps the private key of the one that
/// completes. Only ever use the result as an X25519 key.
#[derive(Clone)]
pub struct KeyStampSearch(StampSearch<STAMP_SIZE>);

impl KeyStampSearch {
    /// Key stamps hash the material itself, without workblock expansion.
    pub fn new(material: &[u8], cost_fp: u16, attempt_limit: u64) -> Result<Self, StampError> {
        StampSearch::new(material, cost_fp, attempt_limit).map(Self)
    }

    pub fn progress(&self) -> Progress<STAMP_SIZE> {
        self.0.progress()
    }

    pub fn attempts(&self) -> u64 {
        self.0.attempts()
    }

    pub fn cancel(&mut self) {
        self.0.cancel();
    }

    /// Test one candidate public key; `Complete` carries it back as `stamp`.
    pub fn offer(&mut self, public_key: &[u8; 32]) -> Progress<STAMP_SIZE> {
        self.0.offer(public_key)
    }
}

/// Link-request stamp cost cap (`Transport.LINK_COST_CAP`), in fixed point.
pub const LINK_COST_CAP_FP: u16 = 40 * 256;
/// Lower bound for both stamp generation timeouts (`max(0.020, v)`), in milliseconds.
pub const STAMP_TIMEOUT_FLOOR_MS: u32 = 20;
/// `Transport.DESTINATION_COST`, 23.5.
pub const DESTINATION_COST_FP: u16 = 6016;
/// `Transport.DESTINATION_VALUE`, 25.0.
pub const DESTINATION_VALUE_FP: u16 = 6400;
/// `Transport.PR_COST`, 15.8 as `cost_to_fp` rounds it.
pub const PR_COST_FP: u16 = 4045;
/// `Transport.PR_VALUE`, 15.8 as `cost_to_fp` rounds it.
pub const PR_VALUE_FP: u16 = 4045;
/// `Transport.LR_COST`, 12.5.
pub const LR_COST_FP: u16 = 3200;
/// `Transport.PR_STAMP_TIMEOUT` and `LINK_STAMP_TIMEOUT`, 15 s.
pub const STAMP_TIMEOUT_MS: u32 = 15_000;

/// Network stamp switches and costs, as Python keeps them on `Transport`.
/// Costs are fixed point (1.0 = 256). Every switch defaults to upstream, so
/// nothing is enforced and nothing is generated until the host opts in.
/// The link-request and announce-emission fields are carried for parity and
/// are not consumed yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StampPolicy {
    /// `STAMPS_ENABLED`: check announce and path-request stamps.
    pub stamps_enabled: bool,
    /// `STAMPS_ENFORCED`: drop announces and path requests without a valid stamp.
    pub stamps_enforced: bool,
    /// `LR_STAMPS_ENFORCED`.
    pub lr_stamps_enforced: bool,
    /// `STAMP_DESTINATIONS`.
    pub stamp_destinations: bool,
    /// `STAMP_PRS`: stamp path requests this node originates.
    pub stamp_prs: bool,
    /// `STAMP_LRS`.
    pub stamp_lrs: bool,
    /// `ALWAYS_STAMP_LRS`.
    pub always_stamp_lrs: bool,
    /// `DESTINATION_COST`: required announce stamp value.
    pub destination_cost_fp: u16,
    /// `DESTINATION_VALUE`.
    pub destination_value_fp: u16,
    /// `PR_COST`: required path-request stamp value.
    pub pr_cost_fp: u16,
    /// `PR_VALUE`: value of path-request stamps this node generates.
    pub pr_value_fp: u16,
    /// `LR_COST`.
    pub lr_cost_fp: u16,
    /// `LINK_STAMP_TIMEOUT`, in milliseconds.
    pub lr_stamp_timeout_ms: u32,
    /// `PR_STAMP_TIMEOUT`, in milliseconds.
    pub pr_stamp_timeout_ms: u32,
}

impl StampPolicy {
    pub const DEFAULT: Self = Self {
        stamps_enabled: true,
        stamps_enforced: false,
        lr_stamps_enforced: false,
        stamp_destinations: false,
        stamp_prs: false,
        stamp_lrs: true,
        always_stamp_lrs: false,
        destination_cost_fp: DESTINATION_COST_FP,
        destination_value_fp: DESTINATION_VALUE_FP,
        pr_cost_fp: PR_COST_FP,
        pr_value_fp: PR_VALUE_FP,
        lr_cost_fp: LR_COST_FP,
        lr_stamp_timeout_ms: STAMP_TIMEOUT_MS,
        pr_stamp_timeout_ms: STAMP_TIMEOUT_MS,
    };

    /// Python `min(v, STAMP_COST_CAP)`.
    pub const fn clamp_cost_fp(fp: u16) -> u16 {
        if fp > STAMP_COST_CAP_FP {
            STAMP_COST_CAP_FP
        } else {
            fp
        }
    }

    /// Python `min(v, LINK_COST_CAP)`.
    pub const fn clamp_link_cost_fp(fp: u16) -> u16 {
        if fp > LINK_COST_CAP_FP {
            LINK_COST_CAP_FP
        } else {
            fp
        }
    }

    /// Python `max(0.020, v)`.
    pub const fn clamp_timeout_ms(ms: u32) -> u32 {
        if ms < STAMP_TIMEOUT_FLOOR_MS {
            STAMP_TIMEOUT_FLOOR_MS
        } else {
            ms
        }
    }

    /// The `enable_stamping` switch.
    pub fn enable_stamping(&mut self) {
        self.stamp_destinations = true;
        self.stamp_prs = true;
        self.stamp_lrs = true;
    }

    /// The `enforce_stamps` switch.
    pub fn enforce(&mut self) {
        self.stamps_enforced = true;
        self.lr_stamps_enforced = true;
    }

    /// Python `Interface.destination_cost`: the interface value, else the global, capped.
    pub const fn interface_destination_cost_fp(&self, interface_cost_fp: Option<u16>) -> u16 {
        Self::clamp_cost_fp(match interface_cost_fp {
            Some(fp) => fp,
            None => self.destination_cost_fp,
        })
    }

    /// Python `Interface.pr_cost`: the interface value, else the global, capped.
    pub const fn interface_pr_cost_fp(&self, interface_cost_fp: Option<u16>) -> u16 {
        Self::clamp_cost_fp(match interface_cost_fp {
            Some(fp) => fp,
            None => self.pr_cost_fp,
        })
    }
}

impl Default for StampPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::{String, ToString};
    use std::vec::Vec;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn table_matches_upstream_digests() {
        assert_eq!(TAB.len() as u32, COST_FP);
        assert_eq!(TAB[0], 1 << MANTISSA_BITS);
        assert!(TAB.windows(2).all(|pair| pair[1] > pair[0]));
        let joined = TAB.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        assert_eq!(hex(&sha256(joined.as_bytes())), TAB_DIGEST);
        let parameters = format!(
            "master|{TAB_DIGEST}|{MANTISSA_BITS}|{}|{COST_FP_BITS}|{COST_FP}|",
            TAB.len()
        );
        assert_eq!(hex(&sha256(parameters.as_bytes())), PRM_DIGEST);
    }

    #[test]
    fn integer_cost_target_is_a_power_of_two() {
        for cost in 0..=100u16 {
            let target = target_from_fp(cost * 256).unwrap().to_be_bytes();
            let position = 256 - cost as usize;
            let mut expected = [0u8; 33];
            expected[32 - position / 8] = 1 << (position % 8);
            assert_eq!(target, expected, "cost {cost}");
        }
        assert_eq!(target_from_fp(25601), Err(StampError::FpOutOfRange(25601)));
    }

    #[test]
    fn cost_bytes_round_trip() {
        assert_eq!(fp_to_bytes(3200), [12, 128]);
        assert_eq!(fp_from_bytes([0xff, 0xff]), 65535);
        for fp in [0, 1, 255, 256, 3200, 25600, 65535] {
            assert_eq!(fp_from_bytes(fp_to_bytes(fp)), fp);
        }
    }

    #[test]
    fn value_edges() {
        assert_eq!(stamp_value_fp_from_hash(&[0u8; 32]), 65536);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(stamp_value_fp_from_hash(&one), 65535);
        assert_eq!(stamp_value_fp_from_hash(&[0xff; 32]), 0);
        let mut top = [0u8; 32];
        top[0] = 0x80;
        assert_eq!(stamp_value_fp_from_hash(&top), 255);
    }

    #[test]
    fn value_is_the_highest_cost_a_hash_meets() {
        for index in 0..2000u32 {
            let mut hash = sha256(format!("stamp-sample-{index}").as_bytes());
            for bit in 0..(index % 40) as usize {
                hash[bit / 8] &= !(0x80 >> (bit % 8));
            }
            let value = stamp_value_fp_from_hash(&hash);
            let capped = value.min(u32::from(STAMP_COST_CAP_FP)) as u16;
            assert!(target_from_fp(capped).unwrap().accepts(&hash), "{index}");
            if capped < STAMP_COST_CAP_FP {
                assert!(
                    !target_from_fp(capped + 1).unwrap().accepts(&hash),
                    "{index}"
                );
            }
        }
    }

    #[test]
    fn zero_round_workblock_is_the_material() {
        assert_eq!(stamp_workblock_zero_rounds(b"material"), b"material");
        let mut joined = Vec::from(&b"material"[..]);
        joined.extend_from_slice(b"stamp");
        assert_eq!(
            stamp_hash(&workblock_prefix(b"material"), b"stamp"),
            sha256(&joined)
        );
    }

    fn counter_fill<const N: usize>(seed: &mut u64) -> impl FnMut(&mut [u8; N]) + '_ {
        move |candidate| {
            *seed += 1;
            let digest = sha256(&seed.to_be_bytes());
            candidate.copy_from_slice(&digest[..N]);
        }
    }

    #[test]
    fn resumable_search_finds_a_valid_stamp_whatever_the_slicing() {
        let run = |slice| {
            let mut seed = 0u64;
            let mut search = NetworkStampSearch::new(b"material", 6 * 256 + 128, 1 << 20).unwrap();
            loop {
                match search.step(slice, counter_fill(&mut seed)) {
                    Progress::Searching { .. } => {}
                    Progress::Complete { stamp, value_fp } => {
                        assert_eq!(stamp_valid_fp(&stamp, 6 * 256 + 128, b"material"), Ok(true));
                        assert_eq!(value_fp, stamp_value_fp(b"material", &stamp));
                        assert!(value_fp >= 6 * 256 + 128);
                        return (stamp, search.attempts());
                    }
                    other => panic!("{other:?}"),
                }
            }
        };
        assert_eq!(run(1), run(4096));
    }

    #[test]
    fn zero_cost_accepts_the_first_candidate_with_its_real_value() {
        let mut search = StampSearch::<STAMP_SIZE>::new(b"m", 0, 5).unwrap();
        let candidate = [0xff; 32];
        let Progress::Complete { stamp, value_fp } = search.offer(&candidate) else {
            panic!("cost 0 must complete");
        };
        assert_eq!(stamp, candidate);
        assert_eq!(value_fp, stamp_value_fp(b"m", &candidate));
        assert_eq!(search.attempts(), 1);
    }

    #[test]
    fn budgets_exhaustion_cancellation_and_terminal_states() {
        assert_eq!(
            StampSearch::<14>::new(b"m", 25601, 1).err(),
            Some(StampError::FpOutOfRange(25601))
        );
        let mut empty = NetworkStampSearch::new(b"m", 256, 0).unwrap();
        assert_eq!(
            empty.step(u32::MAX, |_| panic!("no candidate expected")),
            Progress::Exhausted
        );
        let mut seed = 0;
        let mut hard = NetworkStampSearch::new(b"m", STAMP_COST_CAP_FP, 3).unwrap();
        assert_eq!(
            hard.step(0, counter_fill(&mut seed)),
            Progress::Searching { attempts: 0 }
        );
        assert_eq!(
            hard.step(2, counter_fill(&mut seed)),
            Progress::Searching { attempts: 2 }
        );
        assert_eq!(
            hard.step(u32::MAX, counter_fill(&mut seed)),
            Progress::Exhausted
        );
        assert_eq!(hard.attempts(), 3);
        hard.cancel();
        assert_eq!(hard.offer(&[0; 14]), Progress::Exhausted);
        let mut cancelled = NetworkStampSearch::new(b"m", STAMP_COST_CAP_FP, 9).unwrap();
        cancelled.cancel();
        assert_eq!(
            cancelled.step(u32::MAX, counter_fill(&mut seed)),
            Progress::Cancelled
        );
        assert_eq!(cancelled.attempts(), 0);
    }

    #[test]
    fn key_search_accepts_the_offered_public_key() {
        let mut search = KeyStampSearch::new(b"material", 4 * 256, 1 << 16).unwrap();
        let mut seed = 0u64;
        loop {
            seed += 1;
            let key = sha256(&seed.to_be_bytes());
            match search.offer(&key) {
                Progress::Searching { .. } => {}
                Progress::Complete { stamp, value_fp } => {
                    assert_eq!(stamp, key);
                    assert_eq!(stamp_valid_fp(&key, 4 * 256, b"material"), Ok(true));
                    assert_eq!(value_fp, stamp_value_fp(b"material", &key));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn policy_switches_and_clamps_follow_upstream() {
        let mut p = StampPolicy::default();
        p.enable_stamping();
        assert!(p.stamp_destinations && p.stamp_prs && p.stamp_lrs && !p.stamps_enforced);
        let mut p = StampPolicy::default();
        p.enforce();
        assert!(p.stamps_enforced && p.lr_stamps_enforced && !p.stamp_prs);
        assert_eq!(StampPolicy::clamp_cost_fp(30_000), 25_600);
        assert_eq!(StampPolicy::clamp_link_cost_fp(41 * 256), 40 * 256);
        assert_eq!(StampPolicy::clamp_timeout_ms(1), 20);
        assert_eq!(p.interface_pr_cost_fp(Some(1280)), 1280);
        assert_eq!(p.interface_pr_cost_fp(None), 4045);
        assert_eq!(p.interface_destination_cost_fp(Some(u16::MAX)), 25_600);
    }
}

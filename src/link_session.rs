//! Responder-side Reticulum Link state and packet helpers.
//!
//! The host supplies monotonic millisecond time, entropy and packet I/O. Accepted
//! requests use AES-256 and are answered with MTU 500; malformed signalling and
//! unsupported modes are rejected. Call [`ResponderSession::tick`] to advance
//! timeouts and act on its result. No method starts a timer or transmits packets.
//! Application authorization remains separate from Link establishment and identity proof.

use crate::constants::{DESTINATION_LENGTH, MTU, PUBLIC_KEY_LENGTH};
use crate::crypto::CryptoError;
use crate::identity::{LocalIdentity, identity_hash};
use crate::link::{
    LinkError, LinkKeys, LinkRequestView, MODE_AES256_CBC, SignallingData, build_link_proof,
    compute_link_id, link_decrypt, link_encrypt, verify_identification,
};
use crate::wire::{
    DestinationType, HeaderType, PacketContext, PacketFlags, PacketHeader, PacketType,
    TransportType,
};

/// Trusted `ESTABLISHMENT_TIMEOUT_PER_HOP`.
const ESTABLISHMENT_PER_HOP_MS: u64 = 6_000;
/// Trusted `KEEPALIVE_DEFAULT` / `KEEPALIVE_MAX`.
const KEEPALIVE_DEFAULT_MS: u64 = 360_000;
const KEEPALIVE_MIN_MS: u64 = 5_000;
/// Trusted `STALE_TIME_DEFAULT`; peer-reported RTTs saturate here.
const STALE_TIME_DEFAULT_MS: u64 = 720_000;
const STALE_FACTOR: u64 = 2;
const STALE_GRACE_MS: u64 = 5_000;
const KEEPALIVE_TIMEOUT_FACTOR: u64 = 4;

/// Keepalive payloads, sent unencrypted.
pub const KEEPALIVE_REQUEST: u8 = 0xFF;
pub const KEEPALIVE_RESPONSE: u8 = 0xFE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Handshake,
    Active,
    Stale,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    Link(LinkError),
    Crypto(CryptoError),
    /// The packet is not valid in the session's state.
    State,
}

impl From<LinkError> for SessionError {
    fn from(value: LinkError) -> Self {
        Self::Link(value)
    }
}

impl From<CryptoError> for SessionError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// What an inbound Link packet meant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Received {
    /// The RTT packet activated the Link.
    Activated,
    /// The initiator proved this identity. The first identity wins; later ones are ignored.
    Identified([u8; PUBLIC_KEY_LENGTH]),
    /// Decrypted application data of this length, in the caller's buffer.
    Data(usize),
    /// A keepalive; answer with [`ResponderSession::keepalive_response`] when `respond`.
    Keepalive { respond: bool },
    /// An encrypted close payload began with this Link's ID; the session closed.
    Closed,
    /// No application event: unsupported context or a payload ignored by its
    /// context handler. A repeated valid identification still refreshes liveness.
    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickAction {
    None,
    /// The handshake never completed; the session closed silently.
    Expired,
    /// No word from the peer for the stale time.
    Stale,
    /// Stale grace elapsed. The host should call [`ResponderSession::teardown`]
    /// and send its close payload if available; this action alone does not close.
    Teardown,
}

/// Header of a packet on a Link: HEADER_1, broadcast, addressed to the link id.
pub const fn link_header(
    link_id: [u8; DESTINATION_LENGTH],
    packet_type: PacketType,
    context: PacketContext,
) -> PacketHeader {
    PacketHeader {
        flags: PacketFlags {
            header_type: HeaderType::Header1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    }
}

/// Responder state for a destination owned by the host. The session key is
/// wiped when this value is dropped; entering `Closed` does not itself wipe it.
/// The host must route packets to the correct session and enforce peer policy.
pub struct ResponderSession {
    link_id: [u8; DESTINATION_LENGTH],
    keys: LinkKeys,
    state: SessionState,
    request_ms: u64,
    establishment_timeout_ms: u64,
    rtt_ms: Option<u64>,
    keepalive_ms: u64,
    stale_ms: u64,
    last_inbound_ms: u64,
    last_outbound_ms: Option<u64>,
    activated_ms: Option<u64>,
    stale_since_ms: Option<u64>,
    remote_identity_hash: Option<[u8; DESTINATION_LENGTH]>,
}

impl ResponderSession {
    /// Parse an accepted LINKREQUEST and write its LRPROOF payload into `proof`.
    /// Returns a session in `Handshake` and the proof length. The caller must
    /// verify that the request targets its `destination_hash` and that `identity`
    /// is the associated signing identity; this function does not check that binding.
    /// Supply fresh cryptographic `ephemeral_x25519`, the received hop count, and
    /// monotonic `now_ms`. It does not transmit the proof or authorize the initiator.
    pub fn accept(
        identity: &LocalIdentity,
        destination_hash: &[u8; DESTINATION_LENGTH],
        request: &[u8],
        hops: u8,
        ephemeral_x25519: &[u8; 32],
        now_ms: u64,
        proof: &mut [u8],
    ) -> Result<(Self, usize), SessionError> {
        let view = LinkRequestView::parse(request)?;
        if view.signalling.mode != MODE_AES256_CBC {
            return Err(LinkError::UnsupportedMode.into());
        }
        let signalling = SignallingData::try_new(MODE_AES256_CBC, MTU as u32)?;
        let link_id = compute_link_id(destination_hash, request);
        let proof_len = build_link_proof(identity, ephemeral_x25519, &link_id, signalling, proof)?;
        let keys = LinkKeys::derive(ephemeral_x25519, &view.peer_x25519_pub, &link_id);
        let session = Self {
            link_id,
            keys,
            state: SessionState::Handshake,
            request_ms: now_ms,
            establishment_timeout_ms: ESTABLISHMENT_PER_HOP_MS
                .saturating_mul(u64::from(hops.max(1)))
                .saturating_add(KEEPALIVE_DEFAULT_MS),
            rtt_ms: None,
            keepalive_ms: KEEPALIVE_DEFAULT_MS,
            stale_ms: STALE_TIME_DEFAULT_MS,
            last_inbound_ms: now_ms,
            last_outbound_ms: None,
            activated_ms: None,
            stale_since_ms: None,
            remote_identity_hash: None,
        };
        Ok((session, proof_len))
    }

    pub const fn link_id(&self) -> [u8; DESTINATION_LENGTH] {
        self.link_id
    }

    pub const fn state(&self) -> SessionState {
        self.state
    }

    pub const fn rtt_ms(&self) -> Option<u64> {
        self.rtt_ms
    }

    pub const fn keepalive_ms(&self) -> u64 {
        self.keepalive_ms
    }

    /// Identity hash of the identified initiator.
    pub const fn remote_identity_hash(&self) -> Option<[u8; DESTINATION_LENGTH]> {
        self.remote_identity_hash
    }

    /// Handle a packet already routed to this Link; no header or destination
    /// validation occurs here. Decrypted bytes may be written to `plaintext`
    /// before a context-specific check fails, so consume only the returned event.
    /// Authentication failures leave session state unchanged.
    ///
    /// Application data requires `Active` or `Stale`; identification can arrive
    /// during `Handshake`. The first valid identity is retained, but later valid
    /// identifications still refresh liveness. An authenticated RTT with invalid
    /// RTT encoding activates using the local measurement. Keepalive requests are
    /// unencrypted and can revive a stale session. The caller applies authorization
    /// and replay policy before acting on application data.
    pub fn receive(
        &mut self,
        context: PacketContext,
        payload: &[u8],
        now_ms: u64,
        plaintext: &mut [u8],
    ) -> Result<Received, SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::State);
        }
        match context {
            PacketContext::Keepalive => {
                if self.state == SessionState::Handshake || payload != [KEEPALIVE_REQUEST] {
                    return Ok(Received::Ignored);
                }
                self.record_inbound(now_ms);
                let respond = self
                    .last_outbound_ms
                    .is_none_or(|sent| now_ms.saturating_sub(sent) >= self.keepalive_ms);
                Ok(Received::Keepalive { respond })
            }
            PacketContext::Lrrtt => {
                if self.state != SessionState::Handshake {
                    return Err(SessionError::State);
                }
                let len = link_decrypt(&self.keys, payload, plaintext)?;
                let local_rtt = now_ms.saturating_sub(self.request_ms);
                let rtt =
                    peer_rtt_ms(&plaintext[..len]).map_or(local_rtt, |peer| peer.max(local_rtt));
                self.rtt_ms = Some(rtt);
                // Trusted `KEEPALIVE_MAX / KEEPALIVE_MAX_RTT` = 360 / 1.75 = 1440 / 7.
                self.keepalive_ms =
                    (rtt.saturating_mul(1_440) / 7).clamp(KEEPALIVE_MIN_MS, KEEPALIVE_DEFAULT_MS);
                self.stale_ms = self.keepalive_ms.saturating_mul(STALE_FACTOR);
                self.state = SessionState::Active;
                self.activated_ms = Some(now_ms);
                self.last_inbound_ms = now_ms;
                Ok(Received::Activated)
            }
            PacketContext::LinkIdentify => {
                let len = link_decrypt(&self.keys, payload, plaintext)?;
                let Some(public_key) = verify_identification(&self.link_id, &plaintext[..len])
                else {
                    return Err(CryptoError::AuthenticationFailed.into());
                };
                self.record_inbound(now_ms);
                if self.remote_identity_hash.is_some() {
                    return Ok(Received::Ignored);
                }
                self.remote_identity_hash = Some(identity_hash(&public_key));
                Ok(Received::Identified(public_key))
            }
            PacketContext::LinkClose => {
                let len = link_decrypt(&self.keys, payload, plaintext)?;
                if len < DESTINATION_LENGTH || plaintext[..DESTINATION_LENGTH] != self.link_id {
                    return Ok(Received::Ignored);
                }
                self.state = SessionState::Closed;
                Ok(Received::Closed)
            }
            PacketContext::None => {
                if self.state == SessionState::Handshake {
                    return Err(SessionError::State);
                }
                let len = link_decrypt(&self.keys, payload, plaintext)?;
                self.record_inbound(now_ms);
                Ok(Received::Data(len))
            }
            _ => Ok(Received::Ignored),
        }
    }

    /// Encrypt application data in `Active` or `Stale` state and record
    /// `now_ms` as outbound activity on success. Supply fresh, unpredictable IV
    /// bytes and keep plaintext within [`crate::link::LINK_MDU`]; the Token helper
    /// allows a larger buffer ceiling. Success constructs a payload, not proof of
    /// transmission or delivery.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        iv: &[u8; 16],
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize, SessionError> {
        if !matches!(self.state, SessionState::Active | SessionState::Stale) {
            return Err(SessionError::State);
        }
        let len = link_encrypt(&self.keys, plaintext, iv, out)?;
        self.last_outbound_ms = Some(now_ms);
        Ok(len)
    }

    /// Return the unencrypted keepalive answer and record outbound activity.
    /// The host sends it only when the receive event requests a response. This
    /// method does not check state or transmit the answer.
    pub fn keepalive_response(&mut self, now_ms: u64) -> [u8; 1] {
        self.last_outbound_ms = Some(now_ms);
        [KEEPALIVE_RESPONSE]
    }

    /// Close locally and try to encrypt a LINKCLOSE payload into `out` using a
    /// fresh, unpredictable IV. Returns its length on success. `None` means either
    /// the session was already closed or encryption/output capacity failed; the
    /// session is closed in both cases. The host transmits any returned payload.
    pub fn teardown(&mut self, iv: &[u8; 16], out: &mut [u8]) -> Option<usize> {
        if self.state == SessionState::Closed {
            return None;
        }
        let len = link_encrypt(&self.keys, &self.link_id, iv, out).ok();
        self.state = SessionState::Closed;
        len
    }

    /// Advance handshake, stale and grace timers using monotonic `now_ms`.
    /// Handshake expiry closes immediately. Stale-grace expiry returns
    /// [`TickAction::Teardown`] repeatedly until the host tears down or inbound
    /// traffic revives the session. No packet is sent by this method.
    pub fn tick(&mut self, now_ms: u64) -> TickAction {
        match self.state {
            SessionState::Handshake => {
                if now_ms.saturating_sub(self.request_ms) > self.establishment_timeout_ms {
                    self.state = SessionState::Closed;
                    return TickAction::Expired;
                }
                TickAction::None
            }
            SessionState::Active => {
                let latest = self.activated_ms.map_or(self.last_inbound_ms, |activated| {
                    activated.max(self.last_inbound_ms)
                });
                if now_ms.saturating_sub(latest) >= self.stale_ms {
                    self.state = SessionState::Stale;
                    self.stale_since_ms = Some(now_ms);
                    return TickAction::Stale;
                }
                TickAction::None
            }
            SessionState::Stale => {
                let grace = self
                    .rtt_ms
                    .unwrap_or(1_000)
                    .saturating_mul(KEEPALIVE_TIMEOUT_FACTOR)
                    .saturating_add(STALE_GRACE_MS);
                if self
                    .stale_since_ms
                    .is_some_and(|since| now_ms.saturating_sub(since) >= grace)
                {
                    return TickAction::Teardown;
                }
                TickAction::None
            }
            SessionState::Closed => TickAction::None,
        }
    }

    fn record_inbound(&mut self, now_ms: u64) {
        self.last_inbound_ms = now_ms;
        if self.state == SessionState::Stale {
            self.state = SessionState::Active;
            self.stale_since_ms = None;
        }
    }
}

/// The initiator's measured RTT, a msgpack float. NaN and negative values never count; larger ones
/// saturate at the default stale time.
fn peer_rtt_ms(plaintext: &[u8]) -> Option<u64> {
    let seconds = match plaintext {
        [0xcb, rest @ ..] if rest.len() == 8 => f64::from_be_bytes(rest.try_into().ok()?),
        [0xca, rest @ ..] if rest.len() == 4 => {
            f64::from(f32::from_be_bytes(rest.try_into().ok()?))
        }
        _ => return None,
    };
    if seconds.is_nan() || seconds < 0.0 {
        return None;
    }
    let millis = seconds * 1_000.0;
    Some(if millis >= STALE_TIME_DEFAULT_MS as f64 {
        STALE_TIME_DEFAULT_MS
    } else {
        millis as u64
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{LINK_REQUEST_LEN, LinkProofView, build_identification, build_link_request};

    const DESTINATION: [u8; 16] = [0xD7; 16];
    const INITIATOR_X: [u8; 32] = [0x33; 32];

    fn responder() -> LocalIdentity {
        LocalIdentity::from_private_key(&[0x41; 64])
    }

    fn request() -> [u8; LINK_REQUEST_LEN] {
        let mut request = [0u8; LINK_REQUEST_LEN];
        build_link_request(
            &INITIATOR_X,
            &[0x44; 32],
            SignallingData::new(MODE_AES256_CBC, MTU as u32),
            &mut request,
        )
        .unwrap();
        request
    }

    fn accepted(now_ms: u64) -> (ResponderSession, LinkKeys) {
        let request = request();
        let mut proof = [0u8; 99];
        let (session, len) = ResponderSession::accept(
            &responder(),
            &DESTINATION,
            &request,
            1,
            &[0x55; 32],
            now_ms,
            &mut proof,
        )
        .unwrap();
        let view = LinkProofView::parse(&proof[..len]).unwrap();
        assert!(view.validate(responder().public_key(), &session.link_id()));
        let keys = LinkKeys::derive(&INITIATOR_X, &view.responder_x25519_pub, &session.link_id());
        (session, keys)
    }

    fn sealed(keys: &LinkKeys, plaintext: &[u8]) -> ([u8; 128], usize) {
        let mut out = [0u8; 128];
        let len = link_encrypt(keys, plaintext, &[0x66; 16], &mut out).unwrap();
        (out, len)
    }

    fn rtt(seconds: f64) -> [u8; 9] {
        let mut out = [0xcb; 9];
        out[1..].copy_from_slice(&seconds.to_be_bytes());
        out
    }

    fn activate(session: &mut ResponderSession, keys: &LinkKeys, now_ms: u64, seconds: f64) {
        let (packet, len) = sealed(keys, &rtt(seconds));
        let mut buf = [0u8; 64];
        assert_eq!(
            session.receive(PacketContext::Lrrtt, &packet[..len], now_ms, &mut buf),
            Ok(Received::Activated)
        );
    }

    #[test]
    fn offered_mtus_above_the_base_are_answered_with_the_base() {
        let mut request = request();
        request[64..].copy_from_slice(&SignallingData::new(MODE_AES256_CBC, 1_500).pack());
        let mut proof = [0u8; 99];
        let (_, len) = ResponderSession::accept(
            &responder(),
            &DESTINATION,
            &request,
            1,
            &[0x55; 32],
            0,
            &mut proof,
        )
        .unwrap();
        let view = LinkProofView::parse(&proof[..len]).unwrap();
        assert_eq!(view.signalling.mtu, MTU as u32);
        request[64..].copy_from_slice(&SignallingData::new(0, 500).pack());
        assert_eq!(
            ResponderSession::accept(
                &responder(),
                &DESTINATION,
                &request,
                1,
                &[1; 32],
                0,
                &mut proof
            )
            .err(),
            Some(SessionError::Link(LinkError::UnsupportedMode))
        );
    }

    #[test]
    fn rtt_activates_and_scales_keepalive_and_stale_times() {
        let (mut session, keys) = accepted(1_000);
        let mut buf = [0u8; 64];
        let (data, len) = sealed(&keys, b"early");
        assert_eq!(
            session.receive(PacketContext::None, &data[..len], 1_100, &mut buf),
            Err(SessionError::State)
        );
        activate(&mut session, &keys, 1_400, 0.25);
        assert_eq!(session.rtt_ms(), Some(400));
        // 400 ms × 360 / 1.75 = 82.3 s; stale at twice that.
        assert_eq!(session.keepalive_ms(), 82_285);
        assert_eq!(session.tick(1_400 + 2 * 82_285 - 1), TickAction::None);
        assert_eq!(session.tick(1_400 + 2 * 82_285), TickAction::Stale);
        // Grace is four RTTs plus five seconds.
        let stale_at = 1_400 + 2 * 82_285;
        assert_eq!(session.tick(stale_at + 6_599), TickAction::None);
        assert_eq!(session.tick(stale_at + 6_600), TickAction::Teardown);
        let mut close = [0u8; 80];
        let len = session.teardown(&[7; 16], &mut close).unwrap();
        assert_eq!(len, 80);
        let mut plain = [0u8; 64];
        let n = link_decrypt(&keys, &close[..len], &mut plain).unwrap();
        assert_eq!(&plain[..n], &session.link_id());
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.teardown(&[7; 16], &mut close).is_none());
    }

    #[test]
    fn peer_rtt_is_bounded_and_falls_back_to_the_measured_one() {
        assert_eq!(peer_rtt_ms(&rtt(1.5)), Some(1_500));
        assert_eq!(peer_rtt_ms(&rtt(f64::NAN)), None);
        assert_eq!(peer_rtt_ms(&rtt(-1.0)), None);
        assert_eq!(peer_rtt_ms(&rtt(1e9)), Some(STALE_TIME_DEFAULT_MS));
        let mut float32 = [0xca; 5];
        float32[1..].copy_from_slice(&0.5f32.to_be_bytes());
        assert_eq!(peer_rtt_ms(&float32), Some(500));
        assert_eq!(peer_rtt_ms(&[0x01]), None);
        let (mut session, keys) = accepted(0);
        activate(&mut session, &keys, 3_000, f64::NAN);
        assert_eq!(session.rtt_ms(), Some(3_000));
        assert_eq!(
            session.keepalive_ms(),
            KEEPALIVE_DEFAULT_MS.min(3_000 * 1_440 / 7)
        );
    }

    #[test]
    fn unfinished_handshakes_expire_after_the_trusted_establishment_window() {
        let (mut session, _) = accepted(0);
        assert_eq!(session.tick(366_000), TickAction::None);
        assert_eq!(session.tick(366_001), TickAction::Expired);
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn the_first_identity_wins_from_the_handshake_on() {
        let (mut session, keys) = accepted(0);
        let owner = LocalIdentity::from_private_key(&[0x71; 64]);
        let mut identify = [0u8; 128];
        build_identification(&owner, &session.link_id(), &mut identify).unwrap();
        let mut packet = [0u8; 256];
        let len = link_encrypt(&keys, &identify, &[9; 16], &mut packet).unwrap();
        let mut buf = [0u8; 256];
        assert_eq!(
            session.receive(PacketContext::LinkIdentify, &packet[..len], 10, &mut buf),
            Ok(Received::Identified(*owner.public_key()))
        );
        assert_eq!(session.remote_identity_hash(), Some(*owner.identity_hash()));
        let other = LocalIdentity::from_private_key(&[0x72; 64]);
        build_identification(&other, &session.link_id(), &mut identify).unwrap();
        let len = link_encrypt(&keys, &identify, &[9; 16], &mut packet).unwrap();
        assert_eq!(
            session.receive(PacketContext::LinkIdentify, &packet[..len], 20, &mut buf),
            Ok(Received::Ignored)
        );
        assert_eq!(session.remote_identity_hash(), Some(*owner.identity_hash()));
        // Signed for another Link: refused.
        build_identification(&other, &[0; 16], &mut identify).unwrap();
        let len = link_encrypt(&keys, &identify, &[9; 16], &mut packet).unwrap();
        assert!(
            session
                .receive(PacketContext::LinkIdentify, &packet[..len], 30, &mut buf)
                .is_err()
        );
    }

    #[test]
    fn keepalives_are_echoed_once_per_interval_and_revive_a_stale_link() {
        let (mut session, keys) = accepted(0);
        let mut buf = [0u8; 16];
        assert_eq!(
            session.receive(PacketContext::Keepalive, &[KEEPALIVE_REQUEST], 0, &mut buf),
            Ok(Received::Ignored)
        );
        activate(&mut session, &keys, 1_000, 1.0);
        assert_eq!(
            session.receive(
                PacketContext::Keepalive,
                &[KEEPALIVE_REQUEST],
                2_000,
                &mut buf
            ),
            Ok(Received::Keepalive { respond: true })
        );
        assert_eq!(session.keepalive_response(2_000), [KEEPALIVE_RESPONSE]);
        let interval = session.keepalive_ms();
        assert_eq!(
            session.receive(
                PacketContext::Keepalive,
                &[KEEPALIVE_REQUEST],
                2_001,
                &mut buf
            ),
            Ok(Received::Keepalive { respond: false })
        );
        assert_eq!(
            session.receive(
                PacketContext::Keepalive,
                &[KEEPALIVE_REQUEST],
                2_000 + interval,
                &mut buf
            ),
            Ok(Received::Keepalive { respond: true })
        );
        let stale_at = 2_000 + interval + session.stale_ms;
        assert_eq!(session.tick(stale_at), TickAction::Stale);
        assert_eq!(
            session.receive(
                PacketContext::Keepalive,
                &[KEEPALIVE_REQUEST],
                stale_at + 1,
                &mut buf
            ),
            Ok(Received::Keepalive { respond: true })
        );
        assert_eq!(session.state(), SessionState::Active);
        assert_eq!(
            session.receive(
                PacketContext::Keepalive,
                &[KEEPALIVE_RESPONSE],
                stale_at + 2,
                &mut buf
            ),
            Ok(Received::Ignored)
        );
    }

    #[test]
    fn data_round_trips_and_a_peer_close_closes() {
        let (mut session, keys) = accepted(0);
        activate(&mut session, &keys, 100, 0.1);
        let (packet, len) = sealed(&keys, b"status?");
        let mut buf = [0u8; 128];
        assert_eq!(
            session.receive(PacketContext::None, &packet[..len], 200, &mut buf),
            Ok(Received::Data(7))
        );
        assert_eq!(&buf[..7], b"status?");
        let mut out = [0u8; 128];
        let len = session.seal(b"ok", &[3; 16], &mut out, 210).unwrap();
        let n = link_decrypt(&keys, &out[..len], &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ok");
        // A forged frame changes nothing.
        let mut forged = packet;
        forged[20] ^= 1;
        assert!(
            session
                .receive(PacketContext::None, &forged[..len], 220, &mut buf)
                .is_err()
        );
        let (close, len) = sealed(&keys, &[0u8; 16]);
        assert_eq!(
            session.receive(PacketContext::LinkClose, &close[..len], 230, &mut buf),
            Ok(Received::Ignored)
        );
        let (close, len) = sealed(&keys, &session.link_id());
        assert_eq!(
            session.receive(PacketContext::LinkClose, &close[..len], 240, &mut buf),
            Ok(Received::Closed)
        );
        assert_eq!(
            session.receive(PacketContext::None, &packet[..len], 250, &mut buf),
            Err(SessionError::State)
        );
    }

    #[test]
    fn link_headers_address_the_link() {
        let header = link_header([5; 16], PacketType::Proof, PacketContext::Lrproof);
        assert_eq!(header.flags.destination_type, DestinationType::Link);
        assert_eq!(header.destination_hash, [5; 16]);
        assert!(header.transport_id.is_none());
    }
}

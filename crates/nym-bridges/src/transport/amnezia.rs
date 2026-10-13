//! AmneziaWG translator between amneziawg-go clients and the colocated plain WireGuard node.
//!
//! Handshakes keep their WireGuard message type because mac1 is computed over it; only their
//! padding, trailers and header protection change. Cookie and transport types (H3/H4) are not
//! authenticated and are rewritten in place. AmneziaWG 1.0 is the case without S3/S4, ranges,
//! header protection or trailers, so one framing serves both protocol versions.

use std::{
    net::{Ipv6Addr, SocketAddr},
    ops::{Range, RangeInclusive},
};

use bytes::{Buf, BytesMut};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};

use crate::types::Sufficiency;
pub use crate::types::amnezia::{AmneziaParams, ClientOptions, PROTOCOL_AWG_1_0, PROTOCOL_AWG_3_1};

const DEFAULT_PORT: u16 = 51830;

const INIT_SIZE: usize = 148;
const RESPONSE_SIZE: usize = 92;
const COOKIE_SIZE: usize = 64;
const TRANSPORT_MIN_SIZE: usize = 32;
/// Type, receiver index and counter; the rest of a transport message is AEAD ciphertext.
const TRANSPORT_HEADER_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

const INIT_TYPE: u32 = 1;
const RESPONSE_TYPE: u32 = 2;
const COOKIE_TYPE: u32 = 3;
const TRANSPORT_TYPE: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// (UDP) Address to listen on
    pub listen: SocketAddr,
    /// Maximum number of concurrent client sessions to allow
    pub connection_limit: Option<usize>,
    /// Wire format served on this port, `PROTOCOL_AWG_1_0` (1) or `PROTOCOL_AWG_3_1` (2)
    #[serde(default = "protocol_awg_1_0")]
    pub protocol_version: u16,
    /// AmneziaWG parameters shared with clients, generated when missing
    pub params: Option<AmneziaParams>,
}

fn protocol_awg_1_0() -> u16 {
    PROTOCOL_AWG_1_0
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: (Ipv6Addr::UNSPECIFIED, DEFAULT_PORT).into(),
            connection_limit: Default::default(),
            protocol_version: PROTOCOL_AWG_1_0,
            params: Default::default(),
        }
    }
}

impl crate::transport::GenerateServerConfig for ServerConfig {
    fn generate_config<R: rand::CryptoRng + ?Sized>(mut self, rng: &mut R) -> Self {
        if self.params.is_some() {
            return self;
        }
        // Response stays smaller than the initiation (92 + S2 < 148 + S1), so the bridge never
        // answers with more bytes than it received. Disjoint halves keep H3 and H4 apart, within
        // the i32 range amneziawg clients accept.
        let init_pkt_junk_size = rng.random_range(16..=150);
        let half = i32::MAX as u32 / 2;
        let mut params = AmneziaParams {
            init_pkt_junk_size,
            response_pkt_junk_size: rng.random_range(16..init_pkt_junk_size + 56),
            under_load_pkt_magic_header: rng.random_range(5..half / 2),
            transport_pkt_magic_header: rng.random_range(half..half + half / 2),
            cookie_pkt_junk_size: 0,
            transport_pkt_junk_size: 0,
            under_load_pkt_magic_header_max: None,
            transport_pkt_magic_header_max: None,
            header_protection_key: None,
            random_trailers: false,
        };
        if self.protocol_version == PROTOCOL_AWG_3_1 {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            params.cookie_pkt_junk_size = rng.random_range(16..=64);
            // Every data packet carries S4, so keep it small: the client MTU drops by S4.
            params.transport_pkt_junk_size = rng.random_range(12..=24);
            params.header_protection_key = Some(key.iter().map(|b| format!("{b:02x}")).collect());
            params.random_trailers = true;
        }
        self.params = Some(params);
        self
    }
}

impl Sufficiency for ServerConfig {
    // Operator supplied params must also keep the response smaller than the initiation, and a 1.0
    // port must not carry 3.1 fields.
    fn is_sufficient(&self) -> bool {
        let Some(p) = &self.params else {
            return false;
        };
        let version_ok = match self.protocol_version {
            PROTOCOL_AWG_1_0 => p.is_awg_1_0(),
            PROTOCOL_AWG_3_1 => true,
            _ => false,
        };
        version_ok
            && p.is_sufficient()
            && p.response_pkt_junk_size < p.init_pkt_junk_size + 56
            && Framing::new(p).is_some()
    }
}

/// [`AmneziaParams`] parsed once for the per-datagram path.
#[derive(Debug, Clone)]
pub struct Framing {
    init_padding: usize,
    response_padding: usize,
    cookie_padding: usize,
    transport_padding: usize,
    under_load_headers: RangeInclusive<u32>,
    transport_headers: RangeInclusive<u32>,
    key: Option<[u8; 32]>,
    random_trailers: bool,
}

impl Framing {
    /// `None` when the header protection key is not 32 hex encoded bytes.
    pub fn new(params: &AmneziaParams) -> Option<Self> {
        let key = match &params.header_protection_key {
            Some(hex) => {
                let mut key = [0u8; 32];
                for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
                    *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
                }
                (hex.len() == 64).then_some(key)?;
                Some(key)
            }
            None => None,
        };
        Some(Self {
            init_padding: params.init_pkt_junk_size as usize,
            response_padding: params.response_pkt_junk_size as usize,
            cookie_padding: params.cookie_pkt_junk_size as usize,
            transport_padding: params.transport_pkt_junk_size as usize,
            under_load_headers: params.under_load_headers(),
            transport_headers: params.transport_headers(),
            key,
            random_trailers: params.random_trailers,
        })
    }

    /// Turn an AmneziaWG datagram into plain WireGuard in place, returning where the WireGuard
    /// message sits in `buf`. `None` for junk, decoys or anything that is not AmneziaWG.
    pub fn decode(&self, buf: &mut [u8]) -> Option<Range<usize>> {
        let nonce = self
            .key
            .and_then(|_| buf.get(..NONCE_SIZE)?.try_into().ok());
        let mut mask = [0u8; 4];
        if let (Some(key), Some(nonce)) = (&self.key, &nonce) {
            keystream(key, nonce, &mut mask);
        }
        let header = |offset: usize| {
            let b = buf.get(offset..offset + 4)?;
            Some(u32::from_le_bytes([
                b[0] ^ mask[0],
                b[1] ^ mask[1],
                b[2] ^ mask[2],
                b[3] ^ mask[3],
            ]))
        };

        // Same order as amneziawg-go: a padded handshake size wins only if its header matches,
        // otherwise the datagram can still be transport data of the same length.
        let handshakes = [
            (
                self.init_padding,
                INIT_SIZE,
                INIT_TYPE..=INIT_TYPE,
                INIT_TYPE,
            ),
            (
                self.response_padding,
                RESPONSE_SIZE,
                RESPONSE_TYPE..=RESPONSE_TYPE,
                RESPONSE_TYPE,
            ),
            (
                self.cookie_padding,
                COOKIE_SIZE,
                self.under_load_headers.clone(),
                COOKIE_TYPE,
            ),
        ];
        let (padding, len, msg_type) = handshakes
            .into_iter()
            .find_map(|(padding, size, headers, msg_type)| {
                let expected = padding + size;
                let fits = buf.len() == expected || self.random_trailers && buf.len() > expected;
                (fits && header(padding).is_some_and(|h| headers.contains(&h)))
                    .then_some((padding, size, msg_type))
            })
            .or_else(|| {
                let padding = self.transport_padding;
                (buf.len() >= padding + TRANSPORT_MIN_SIZE
                    && header(padding).is_some_and(|h| self.transport_headers.contains(&h)))
                .then(|| (padding, buf.len() - padding, TRANSPORT_TYPE))
            })?;

        let msg = &mut buf[padding..padding + len];
        if let (Some(key), Some(nonce)) = (&self.key, &nonce) {
            let protected = if msg_type == TRANSPORT_TYPE {
                TRANSPORT_HEADER_SIZE
            } else {
                len
            };
            keystream(key, nonce, &mut msg[..protected]);
        }
        msg[..4].copy_from_slice(&msg_type.to_le_bytes());
        Some(padding..padding + len)
    }

    /// Padding in front of transport packets: receivers that leave this much headroom before the
    /// message let [`Framing::encode`] work without a copy.
    pub fn transport_padding(&self) -> usize {
        self.transport_padding
    }

    /// Turn the plain WireGuard message at `buf[headroom..]` into AmneziaWG in place. `false` if it
    /// is not WireGuard. Reply trailers stay short enough that a response or cookie reply is never
    /// larger than the initiation that caused it.
    pub fn encode(&self, buf: &mut BytesMut, headroom: usize) -> bool {
        let Some(msg_type) = buf
            .get(headroom..headroom + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        else {
            return false;
        };
        let mut rng = rand::rng();
        let len = buf.len() - headroom;
        let init_size = INIT_SIZE + self.init_padding;
        let (padding, protected, header, trailer_room) = match msg_type {
            INIT_TYPE => (self.init_padding, len, INIT_TYPE, 0),
            RESPONSE_TYPE => (
                self.response_padding,
                len,
                RESPONSE_TYPE,
                init_size.saturating_sub(RESPONSE_SIZE + self.response_padding + 1),
            ),
            COOKIE_TYPE => (
                self.cookie_padding,
                len,
                rng.random_range(self.under_load_headers.clone()),
                init_size.saturating_sub(COOKIE_SIZE + self.cookie_padding + 1),
            ),
            TRANSPORT_TYPE => (
                self.transport_padding,
                TRANSPORT_HEADER_SIZE.min(len),
                rng.random_range(self.transport_headers.clone()),
                0,
            ),
            _ => return false,
        };

        buf[headroom..headroom + 4].copy_from_slice(&header.to_le_bytes());
        if padding <= headroom {
            buf.advance(headroom - padding);
        } else {
            let mut padded = BytesMut::zeroed(padding);
            padded.extend_from_slice(&buf[headroom..]);
            *buf = padded;
        }
        rng.fill_bytes(&mut buf[..padding]);
        if self.random_trailers && trailer_room > 0 {
            let start = buf.len();
            buf.resize(start + rng.random_range(0..trailer_room), 0);
            rng.fill_bytes(&mut buf[start..]);
        }
        if let Some(key) = &self.key {
            let mut nonce = [0u8; NONCE_SIZE];
            nonce.copy_from_slice(&buf[..NONCE_SIZE]);
            keystream(key, &nonce, &mut buf[padding..padding + protected]);
        }
        true
    }
}

/// AmneziaWG header protection: ChaCha20 keyed by the shared key, nonce from the padding.
fn keystream(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], data: &mut [u8]) {
    ChaCha20::new(key.into(), nonce.into()).apply_keystream(data);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transport::GenerateServerConfig;

    /// S1 = 44 and S2 = 52 put padded handshakes on sizes real transport packets also use
    /// (32 + 16k), so classification must rely on the header, not only the length.
    fn awg_1_0() -> AmneziaParams {
        AmneziaParams {
            init_pkt_junk_size: 44,
            response_pkt_junk_size: 52,
            under_load_pkt_magic_header: 1_766_607_858,
            transport_pkt_magic_header: 2_028_465_083,
            cookie_pkt_junk_size: 0,
            transport_pkt_junk_size: 0,
            under_load_pkt_magic_header_max: None,
            transport_pkt_magic_header_max: None,
            header_protection_key: None,
            random_trailers: false,
        }
    }

    fn awg_3_1() -> AmneziaParams {
        AmneziaParams {
            cookie_pkt_junk_size: 20,
            transport_pkt_junk_size: 16,
            under_load_pkt_magic_header_max: Some(1_766_607_958),
            transport_pkt_magic_header_max: Some(2_028_465_183),
            header_protection_key: Some(
                "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0".into(),
            ),
            random_trailers: true,
            ..awg_1_0()
        }
    }

    fn framing(params: &AmneziaParams) -> Framing {
        Framing::new(params).unwrap()
    }

    fn wg_msg(msg_type: u32, len: usize) -> BytesMut {
        let mut msg = BytesMut::zeroed(len);
        msg[..4].copy_from_slice(&msg_type.to_le_bytes());
        msg[4..]
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = i as u8);
        msg
    }

    fn round_trip(params: &AmneziaParams, msg_type: u32, len: usize) -> BytesMut {
        let framing = framing(params);
        let plain = wg_msg(msg_type, len);
        let mut wire = plain.clone();
        assert!(framing.encode(&mut wire, 0));

        let mut decoded = wire.clone();
        let msg = framing.decode(&mut decoded).unwrap();
        assert_eq!(decoded[msg], plain[..], "type {msg_type} len {len}");
        wire
    }

    #[test]
    fn awg_1_0_messages_round_trip() {
        let p = awg_1_0();
        assert_eq!(round_trip(&p, INIT_TYPE, INIT_SIZE).len(), INIT_SIZE + 44);
        assert_eq!(
            round_trip(&p, RESPONSE_TYPE, RESPONSE_SIZE).len(),
            RESPONSE_SIZE + 52
        );
        assert_eq!(round_trip(&p, COOKIE_TYPE, COOKIE_SIZE).len(), COOKIE_SIZE);
        for len in [TRANSPORT_MIN_SIZE, 1420] {
            let wire = round_trip(&p, TRANSPORT_TYPE, len);
            assert_eq!(wire.len(), len);
            assert_eq!(wire[..4], p.transport_pkt_magic_header.to_le_bytes());
        }
    }

    #[test]
    fn awg_3_1_messages_round_trip() {
        let p = awg_3_1();
        assert_eq!(round_trip(&p, INIT_TYPE, INIT_SIZE).len(), INIT_SIZE + 44);
        // Replies carry random trailers.
        assert!(round_trip(&p, RESPONSE_TYPE, RESPONSE_SIZE).len() >= RESPONSE_SIZE + 52);
        assert!(round_trip(&p, COOKIE_TYPE, COOKIE_SIZE).len() >= COOKIE_SIZE + 20);
        for len in [TRANSPORT_MIN_SIZE, 1420] {
            assert_eq!(round_trip(&p, TRANSPORT_TYPE, len).len(), len + 16);
        }
    }

    #[test]
    fn handshake_bytes_covered_by_mac1_are_untouched_without_header_protection() {
        for (msg_type, len, padding) in [
            (INIT_TYPE, INIT_SIZE, 44),
            (RESPONSE_TYPE, RESPONSE_SIZE, 52),
        ] {
            let plain = wg_msg(msg_type, len);
            let mut wire = plain.clone();
            assert!(framing(&awg_1_0()).encode(&mut wire, 0));
            assert_eq!(wire[padding..], plain[..]);
        }
    }

    #[test]
    fn header_protection_hides_types_but_not_ciphertext() {
        let p = awg_3_1();
        for _ in 0..32 {
            let plain = wg_msg(INIT_TYPE, INIT_SIZE);
            let mut wire = plain.clone();
            assert!(framing(&p).encode(&mut wire, 0));
            assert_ne!(wire[44..48], INIT_TYPE.to_le_bytes());
        }
        let plain = wg_msg(TRANSPORT_TYPE, 1420);
        let mut wire = plain.clone();
        assert!(framing(&p).encode(&mut wire, 0));
        assert_ne!(wire[16..32], plain[..16]);
        assert_eq!(
            wire[16 + TRANSPORT_HEADER_SIZE..],
            plain[TRANSPORT_HEADER_SIZE..]
        );
    }

    #[test]
    fn header_protection_matches_amneziawg_go_keystream() {
        // golang.org/x/crypto/chacha20 NewUnauthenticatedCipher, key 00..1f, nonce a0..ab
        let expected = "f7baf7e4cc1bfeaea3e5885e99ca209f520adea739997a357f85ab6e14007197\
                        598afb967692ece398007de8563b9c10de4228eca19f9510dc4a495468779733";
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; NONCE_SIZE] = std::array::from_fn(|i| 0xa0 + i as u8);
        let mut out = [0u8; 64];
        keystream(&key, &nonce, &mut out);
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn reply_trailers_vary_but_never_outgrow_the_initiation() {
        let framing = framing(&awg_3_1());
        let init_size = INIT_SIZE + 44;
        for (msg_type, len, padded) in [
            (RESPONSE_TYPE, RESPONSE_SIZE, RESPONSE_SIZE + 52),
            (COOKIE_TYPE, COOKIE_SIZE, COOKIE_SIZE + 20),
        ] {
            let sizes: std::collections::BTreeSet<usize> = (0..200)
                .map(|_| {
                    let mut wire = wg_msg(msg_type, len);
                    assert!(framing.encode(&mut wire, 0));
                    wire.len()
                })
                .collect();
            assert!(sizes.len() > 1, "type {msg_type} replies all {sizes:?}");
            assert!(
                sizes.iter().all(|s| (padded..init_size).contains(s)),
                "{sizes:?}"
            );
        }
    }

    #[test]
    fn transport_encodes_into_headroom_without_copying() {
        let framing = framing(&awg_3_1());
        let headroom = framing.transport_padding();
        let mut buf = BytesMut::zeroed(headroom);
        buf.extend_from_slice(&wg_msg(TRANSPORT_TYPE, 1420));
        let start = buf.as_ptr();

        assert!(framing.encode(&mut buf, headroom));
        assert_eq!(buf.as_ptr(), start);
        assert_eq!(buf.len(), headroom + 1420);
    }

    #[test]
    fn trailers_are_stripped_from_handshakes() {
        let framing = framing(&awg_3_1());
        let plain = wg_msg(RESPONSE_TYPE, RESPONSE_SIZE);
        let mut wire = plain.clone();
        assert!(framing.encode(&mut wire, 0));
        wire.extend_from_slice(&[0xee; 37]);

        let msg = framing.decode(&mut wire).unwrap();
        assert_eq!(wire[msg], plain[..]);
    }

    #[test]
    fn transport_sizes_never_collide_with_handshakes() {
        for params in [awg_1_0(), awg_3_1()] {
            let framing = framing(&params);
            for len in (TRANSPORT_MIN_SIZE..=1500).step_by(16) {
                let plain = wg_msg(TRANSPORT_TYPE, len);
                let mut wire = plain.clone();
                assert!(framing.encode(&mut wire, 0));
                let msg = framing.decode(&mut wire).unwrap();
                assert_eq!(wire[msg], plain[..], "transport len {len}");
            }
        }
    }

    #[test]
    fn awg_3_1_transport_is_never_misread_as_a_trailing_cookie() {
        // With trailers on, any datagram longer than a padded cookie can match the H3 range, so a
        // wide range drops real transport packets (about 2 per 100k at a 92k-wide range).
        let framing = framing(&awg_3_1());
        let misread = (0..100_000)
            .filter(|i| {
                let len = TRANSPORT_MIN_SIZE + 16 * (i % 88);
                let mut wire = wg_msg(TRANSPORT_TYPE, len);
                assert!(framing.encode(&mut wire, 0));
                let msg = framing.decode(&mut wire);
                msg.map(|m| m.len()) != Some(len)
            })
            .count();
        assert_eq!(misread, 0);
    }

    #[test]
    fn junk_and_plain_wireguard_are_dropped() {
        for params in [awg_1_0(), awg_3_1()] {
            let framing = framing(&params);
            assert_eq!(framing.decode(&mut [0xAB; 57]), None);
            assert_eq!(framing.decode(&mut [0u8; 3]), None);
            assert_eq!(framing.decode(&mut wg_msg(TRANSPORT_TYPE, 1420)), None);
            assert!(!framing.encode(&mut wg_msg(9, 64), 0));
        }
        assert_eq!(
            framing(&awg_1_0()).decode(&mut wg_msg(INIT_TYPE, INIT_SIZE)),
            None
        );
    }

    #[test]
    fn generated_params_are_sufficient() {
        let mut rng = rand::rng();
        for protocol_version in [PROTOCOL_AWG_1_0, PROTOCOL_AWG_3_1] {
            for _ in 0..1000 {
                let cfg = ServerConfig {
                    protocol_version,
                    ..Default::default()
                }
                .generate_config(&mut rng);
                let p = cfg.params.as_ref().unwrap();
                assert!(cfg.is_sufficient(), "{p:?}");
                assert!(*p.transport_headers().end() <= i32::MAX as u32);
                assert_eq!(p.is_awg_1_0(), protocol_version == PROTOCOL_AWG_1_0);
            }
        }
    }

    #[test]
    fn insufficient_server_configs() {
        let amplifying = AmneziaParams {
            response_pkt_junk_size: 44 + 60,
            ..awg_1_0()
        };
        let awg_3_1_on_1_0_port = ServerConfig {
            params: Some(awg_3_1()),
            ..Default::default()
        };
        assert!(
            !ServerConfig {
                params: Some(amplifying),
                ..Default::default()
            }
            .is_sufficient()
        );
        assert!(!awg_3_1_on_1_0_port.is_sufficient());
        assert!(
            ServerConfig {
                protocol_version: PROTOCOL_AWG_3_1,
                ..awg_3_1_on_1_0_port
            }
            .is_sufficient()
        );
    }
}

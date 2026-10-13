//! AmneziaWG 1.0 translator between amneziawg-go clients and the colocated plain WireGuard node.
//!
//! Handshakes keep their WireGuard message type because mac1 is computed over it; only their junk
//! prefix (S1/S2) is added or stripped. Cookie and transport types (H3/H4) are not authenticated
//! and are rewritten in place.

use std::net::{Ipv6Addr, SocketAddr};

use bytes::BytesMut;
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};

use crate::types::Sufficiency;
pub use crate::types::amnezia::{AmneziaParams, ClientOptions};

const DEFAULT_PORT: u16 = 51830;

const INIT_SIZE: usize = 148;
const RESPONSE_SIZE: usize = 92;
const COOKIE_SIZE: usize = 64;
const TRANSPORT_MIN_SIZE: usize = 32;

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
    /// AmneziaWG parameters shared with clients, generated when missing
    pub params: Option<AmneziaParams>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: (Ipv6Addr::UNSPECIFIED, DEFAULT_PORT).into(),
            connection_limit: Default::default(),
            params: Default::default(),
        }
    }
}

impl crate::transport::GenerateServerConfig for ServerConfig {
    fn generate_config<R: rand::CryptoRng + ?Sized>(mut self, rng: &mut R) -> Self {
        if self.params.is_none() {
            // Response stays smaller than the initiation (92 + S2 < 148 + S1), so the bridge
            // never answers with more bytes than it received.
            let init_pkt_junk_size = rng.random_range(15..=150);
            // Disjoint halves keep H3 and H4 distinct; i32 range for amneziawg clients.
            let half = i32::MAX as u32 / 2;
            self.params = Some(AmneziaParams {
                init_pkt_junk_size,
                response_pkt_junk_size: rng.random_range(15..init_pkt_junk_size + 56),
                under_load_pkt_magic_header: rng.random_range(5..half),
                transport_pkt_magic_header: rng.random_range(half..2 * half),
            });
        }
        self
    }
}

impl Sufficiency for ServerConfig {
    // Operator supplied params must also keep the response smaller than the initiation.
    fn is_sufficient(&self) -> bool {
        self.params.as_ref().is_some_and(|p| {
            p.is_sufficient() && p.response_pkt_junk_size < p.init_pkt_junk_size + 56
        })
    }
}

/// Turn an AmneziaWG datagram into plain WireGuard in place, returning the offset where the
/// WireGuard message starts. `None` for junk or anything that is not an AmneziaWG message.
pub fn decode(params: &AmneziaParams, buf: &mut [u8]) -> Option<usize> {
    let init_junk = params.init_pkt_junk_size as usize;
    let response_junk = params.response_pkt_junk_size as usize;
    let header = |offset: usize| {
        buf.get(offset..offset + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    // Same order as amneziawg-go: a padded handshake size wins only if its header matches,
    // otherwise the datagram can still be transport data of the same length.
    let (offset, msg_type) = match buf.len() {
        n if n == INIT_SIZE + init_junk && header(init_junk) == Some(INIT_TYPE) => {
            (init_junk, INIT_TYPE)
        }
        n if n == RESPONSE_SIZE + response_junk && header(response_junk) == Some(RESPONSE_TYPE) => {
            (response_junk, RESPONSE_TYPE)
        }
        COOKIE_SIZE if header(0) == Some(params.under_load_pkt_magic_header) => (0, COOKIE_TYPE),
        n if n >= TRANSPORT_MIN_SIZE && header(0) == Some(params.transport_pkt_magic_header) => {
            (0, TRANSPORT_TYPE)
        }
        _ => return None,
    };

    buf[offset..offset + 4].copy_from_slice(&msg_type.to_le_bytes());
    Some(offset)
}

/// Turn a plain WireGuard message into AmneziaWG in place. `false` if `msg` is not WireGuard.
pub fn encode(params: &AmneziaParams, msg: &mut BytesMut) -> bool {
    let Some(msg_type) = msg
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    else {
        return false;
    };
    let (junk, header) = match msg_type {
        INIT_TYPE => (params.init_pkt_junk_size, INIT_TYPE),
        RESPONSE_TYPE => (params.response_pkt_junk_size, RESPONSE_TYPE),
        COOKIE_TYPE => (0, params.under_load_pkt_magic_header),
        TRANSPORT_TYPE => (0, params.transport_pkt_magic_header),
        _ => return false,
    };

    msg[..4].copy_from_slice(&header.to_le_bytes());
    if junk > 0 {
        let mut padded = BytesMut::zeroed(junk as usize);
        rand::rng().fill_bytes(&mut padded);
        padded.extend_from_slice(msg);
        *msg = padded;
    }
    true
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transport::GenerateServerConfig;

    fn params() -> AmneziaParams {
        AmneziaParams {
            init_pkt_junk_size: 40,
            response_pkt_junk_size: 50,
            under_load_pkt_magic_header: 1_766_607_858,
            transport_pkt_magic_header: 2_028_465_083,
        }
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

    fn round_trip(msg_type: u32, len: usize, padded_len: usize, header: u32) {
        let plain = wg_msg(msg_type, len);
        let mut wire = plain.clone();

        assert!(encode(&params(), &mut wire));
        assert_eq!(wire.len(), padded_len);
        let offset = padded_len - len;
        assert_eq!(wire[offset..offset + 4], header.to_le_bytes());

        assert_eq!(decode(&params(), &mut wire), Some(offset));
        assert_eq!(wire[offset..], plain[..]);
    }

    #[test]
    fn handshake_messages_round_trip() {
        let p = params();
        round_trip(INIT_TYPE, INIT_SIZE, INIT_SIZE + 40, INIT_TYPE);
        round_trip(
            RESPONSE_TYPE,
            RESPONSE_SIZE,
            RESPONSE_SIZE + 50,
            RESPONSE_TYPE,
        );
        round_trip(
            COOKIE_TYPE,
            COOKIE_SIZE,
            COOKIE_SIZE,
            p.under_load_pkt_magic_header,
        );
    }

    #[test]
    fn handshake_bytes_covered_by_mac1_are_untouched() {
        for (msg_type, len, junk) in [
            (INIT_TYPE, INIT_SIZE, 40),
            (RESPONSE_TYPE, RESPONSE_SIZE, 50),
        ] {
            let plain = wg_msg(msg_type, len);
            let mut wire = plain.clone();
            assert!(encode(&params(), &mut wire));
            assert_eq!(wire[junk..], plain[..]);
        }
    }

    #[test]
    fn transport_messages_round_trip() {
        let p = params();
        round_trip(
            TRANSPORT_TYPE,
            TRANSPORT_MIN_SIZE,
            TRANSPORT_MIN_SIZE,
            p.transport_pkt_magic_header,
        );
        round_trip(TRANSPORT_TYPE, 1420, 1420, p.transport_pkt_magic_header);
    }

    #[test]
    fn transport_with_padded_handshake_size_is_transport() {
        let mut wire = wg_msg(TRANSPORT_TYPE, INIT_SIZE + 40);
        assert!(encode(&params(), &mut wire));

        assert_eq!(decode(&params(), &mut wire), Some(0));
        assert_eq!(wire[..4], TRANSPORT_TYPE.to_le_bytes());
    }

    #[test]
    fn junk_and_plain_wireguard_are_dropped() {
        assert_eq!(decode(&params(), &mut [0xAB; 57]), None);
        assert_eq!(decode(&params(), &mut [0u8; 3]), None);
        assert_eq!(decode(&params(), &mut wg_msg(INIT_TYPE, INIT_SIZE)), None);
        assert_eq!(decode(&params(), &mut wg_msg(TRANSPORT_TYPE, 1420)), None);
        assert!(!encode(&params(), &mut wg_msg(9, 64)));
    }

    #[test]
    fn generated_params_are_sufficient() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let cfg = ServerConfig::default().generate_config(&mut rng);
            let p = cfg.params.as_ref().unwrap();
            assert!(cfg.is_sufficient());
            assert!(
                RESPONSE_SIZE + (p.response_pkt_junk_size as usize)
                    < INIT_SIZE + p.init_pkt_junk_size as usize
            );
            assert!(p.transport_pkt_magic_header <= i32::MAX as u32);
        }
    }

    #[test]
    fn amplifying_params_are_insufficient() {
        let mut p = params();
        p.response_pkt_junk_size = p.init_pkt_junk_size + 60;
        let cfg = ServerConfig {
            params: Some(p),
            ..Default::default()
        };
        assert!(!cfg.is_sufficient());
    }
}

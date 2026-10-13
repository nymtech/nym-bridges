// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal compatible Types shared between [`nym-bridges`](https://docs.rs/nym-bridges) and other crates.
//!
//! ## Abstract
//!
//! - This crate contains all types necessary for interaction with crates (nym-vpn-lib-types) and others
//! - Types visible via bindings should contain proper attributes and feature gated to `uniffi-bindings` for uniffi, `typescript-bindings` for TypeScript bindings.
//! - TypeScript bindings use serde for conversion from Rust to TS and feature-gated to `typescript-bindings`.
//! - Be mindful of limitations of TypeScript and uniffi limitations. Keep exported types simple.
//!
//! ## Dependency considerations
//!
//! Please keep direct dependencies to other crates to a minimum to avoid dependency conflicts which can happen, especially when using it in other large projects such as Tauri.

//! ## Supported bindings
//!
//! 1. [uniffi](https://mozilla.github.io/uniffi-rs/latest/) bindings (feature flag: uniffi-bindings). The following limitations apply:
//! - Namespaces are not supported, all exported types should have unique names.
//! - Not all types are supported or can be bridged. Keep exported types simple.
//!
//! 2. TypeScript bindings using [ts-rs](https://docs.rs/ts-rs) (feature flag: `typescript-bindings`). Serialization ([using serde](https://docs.rs/serde)) uses `snake_case`.
//!
//!    Run the following command to generate TypeScript bindings:
//!    ```sh
//!    cargo test -p nym-vpn-lib-types -F typescript-bindings
//!    ```
//!
//! ## Serde support
//!
//! Serde can be enabled using `serde` feature flag.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "typescript-bindings")]
use ts_rs::TS;

#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

use std::net::SocketAddr as BridgeSocketAddr;
#[cfg(feature = "uniffi-bindings")]
use std::str::FromStr;
#[cfg(feature = "uniffi-bindings")]
uniffi::custom_type!(BridgeSocketAddr, String, {
    remote,
    try_lift: |val| Ok(BridgeSocketAddr::from_str(&val)?),
    lower: |val| val.to_string()
});

/// Whether this transport has sufficient details to dial: at least one address and a non-blank
/// identity pin (the pin is what the certificate is verified against, so a transport without one is
/// unusable regardless of addresses). Callers picking "any advertised transport" should filter on
/// this — see [`PersistedClientConfig::usable_transports`].
pub trait Sufficiency {
    fn is_sufficient(&self) -> bool;
}

/// Trait allowing types to indicate the name of the transport type with which they are associated.
pub trait TransportAssociation {
    fn transport_name(&self) -> String;
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct PersistedClientConfig {
    pub version: String,
    pub transports: Vec<ClientConfig>,
    /// AmneziaWG translator profiles, one per protocol version the bridge serves. Clients pick a
    /// version they speak, so old and new profiles can run side by side during upgrades.
    #[cfg_attr(feature = "serde", serde(default))]
    pub amnezia: Vec<amnezia::ClientOptions>,
}

impl PersistedClientConfig {
    pub fn get_addrs(&self) -> Vec<BridgeSocketAddr> {
        let mut addrs = Vec::new();
        for transport in &self.transports {
            match transport {
                ClientConfig::QuicPlain(params) => addrs.extend(&params.addresses),
                ClientConfig::TlsPlain(params) => addrs.extend(&params.addresses),
                ClientConfig::SshPlain(params) => addrs.extend(&params.addresses),
            }
        }
        addrs
    }

    /// The transports that are actually usable (see [`ClientConfig::is_usable`]),
    /// in the order they were listed. A caller wanting to dial "any advertised
    /// transport" should try these in order rather than assuming a single one.
    pub fn usable_transports(&self) -> impl Iterator<Item = &ClientConfig> {
        self.transports.iter().filter(|t| t.is_sufficient())
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "transport_type", content = "args"))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ClientConfig {
    QuicPlain(quic::ClientOptions),
    TlsPlain(tls::ClientOptions),
    SshPlain(ssh::ClientOptions),
}

impl From<quic::ClientOptions> for ClientConfig {
    fn from(value: quic::ClientOptions) -> Self {
        ClientConfig::QuicPlain(value)
    }
}

impl From<tls::ClientOptions> for ClientConfig {
    fn from(value: tls::ClientOptions) -> Self {
        ClientConfig::TlsPlain(value)
    }
}

impl ClientConfig {
    /// Candidate bridge socket addresses, regardless of transport kind.
    pub fn addresses(&self) -> &[BridgeSocketAddr] {
        match self {
            ClientConfig::QuicPlain(o) => &o.addresses,
            ClientConfig::TlsPlain(o) => &o.addresses,
            ClientConfig::SshPlain(o) => &o.addresses,
        }
    }
}

impl Sufficiency for ClientConfig {
    fn is_sufficient(&self) -> bool {
        match self {
            ClientConfig::QuicPlain(o) => o.is_sufficient(),
            ClientConfig::TlsPlain(o) => o.is_sufficient(),
            ClientConfig::SshPlain(o) => o.is_sufficient(),
        }
    }
}

impl TransportAssociation for ClientConfig {
    fn transport_name(&self) -> String {
        match self {
            ClientConfig::QuicPlain(o) => o.transport_name(),
            ClientConfig::TlsPlain(o) => o.transport_name(),
            ClientConfig::SshPlain(o) => o.transport_name(),
        }
    }
}

impl From<ssh::ClientOptions> for ClientConfig {
    fn from(value: ssh::ClientOptions) -> Self {
        ClientConfig::SshPlain(value)
    }
}

pub mod quic {
    use crate::{Sufficiency, TransportAssociation};
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr as BridgeSocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

    pub const TRANSPORT_NAME: &str = "quic_plain";

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub struct QuicPlainClientOptions {
        /// Address describing the remote transport server. This is a vec to support multiple addresses
        /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
        /// as the key material should not be used across multiple instances.
        ///
        /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
        #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
        pub addresses: Vec<BridgeSocketAddr>,

        /// Override hostname used for certificate verification
        pub host: Option<String>,

        /// Use identity public key to verify server self signed certificate
        pub id_pubkey: String,
    }

    impl Sufficiency for QuicPlainClientOptions {
        fn is_sufficient(&self) -> bool {
            !self.addresses.is_empty() && !self.id_pubkey.trim().is_empty()
        }
    }

    impl TransportAssociation for QuicPlainClientOptions {
        fn transport_name(&self) -> String {
            TRANSPORT_NAME.to_string()
        }
    }

    pub type ClientOptions = QuicPlainClientOptions;
}

pub mod tls {
    use crate::{Sufficiency, TransportAssociation};
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr as BridgeSocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

    pub const TRANSPORT_NAME: &str = "tls_plain";

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub struct TlsPlainClientOptions {
        /// Address describing the remote transport server. This is a vec to support multiple addresses
        /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
        /// as the key material should not be used across multiple instances.
        ///
        /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
        #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
        pub addresses: Vec<BridgeSocketAddr>,

        /// Override hostname used for certificate verification
        pub host: Option<String>,

        /// Use identity public key to verify server self signed certificate base64 encoded
        pub id_pubkey: String,
    }

    impl Sufficiency for TlsPlainClientOptions {
        fn is_sufficient(&self) -> bool {
            !self.addresses.is_empty() && !self.id_pubkey.trim().is_empty()
        }
    }

    impl TransportAssociation for TlsPlainClientOptions {
        fn transport_name(&self) -> String {
            TRANSPORT_NAME.to_string()
        }
    }

    pub type ClientOptions = TlsPlainClientOptions;
}

pub mod ssh {
    use crate::{Sufficiency, TransportAssociation};
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

    pub const TRANSPORT_NAME: &str = "ssh_plain";

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub struct SshPlainClientOptions {
        /// Address describing the remote transport server. This is a vec to support multiple addresses
        /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
        /// as the key material should not be used across multiple instances.
        ///
        /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
        #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
        pub addresses: Vec<SocketAddr>,

        /// Use identity public key to verify the server's ed25519 SSH host key, base64 encoded
        pub id_pubkey: String,

        /// User identity sent as part of a basic auth on the clients behalf.
        pub username: Option<String>,

        /// Base64 encoded ed25519 private key shared out-of-band with the server, used to
        /// authenticate this client via SSH `publickey` - the `none` auth method is explicitly
        /// disallowed. The server must be configured with the same value (as `client_auth_key`)
        /// so it can derive the matching public key and recognize it.
        pub client_auth_key: String,

        /// SSH identification string the client should present during the handshake, in place of
        /// the underlying SSH library's default. Purely for on-the-wire fingerprint management -
        /// the server does not check or validate it.
        pub client_banner: Option<String>,
    }

    impl Sufficiency for SshPlainClientOptions {
        fn is_sufficient(&self) -> bool {
            !self.addresses.is_empty()
                && !self.id_pubkey.trim().is_empty()
                && !self.client_auth_key.trim().is_empty()
        }
    }

    impl TransportAssociation for SshPlainClientOptions {
        fn transport_name(&self) -> String {
            TRANSPORT_NAME.to_string()
        }
    }

    pub type ClientOptions = SshPlainClientOptions;
}

pub mod amnezia {
    use crate::Sufficiency;
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::{net::SocketAddr, ops::RangeInclusive};

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

    /// AmneziaWG 1.0 framing: S1/S2 handshake padding, fixed H3/H4.
    pub const PROTOCOL_AWG_1_0: u16 = 1;
    /// AmneziaWG 3.1 framing: adds S3/S4 padding, H3/H4 ranges, header protection and trailers.
    pub const PROTOCOL_AWG_3_1: u16 = 2;

    /// Largest junk prefix amneziawg clients accept on a handshake message.
    pub const MAX_JUNK_SIZE: u16 = 1280;
    /// S4 cap: every data packet carries it, and mobile clients keep only 60 bytes of MTU headroom.
    pub const MAX_TRANSPORT_JUNK_SIZE: u16 = 32;
    /// Widest H3/H4 range allowed with random trailers. A receiver accepts any datagram longer than
    /// a padded cookie reply as a possible cookie, so a transport packet is misread with odds of
    /// range width / 2^32; 255 keeps that below one in 16 million.
    pub const MAX_HEADER_RANGE_WITH_TRAILERS: u32 = 255;
    /// Header protection takes its ChaCha20 nonce from the first padding bytes of a datagram.
    pub const HEADER_PROTECTION_NONCE_SIZE: u16 = 12;

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    /// Handshake message types (H1/H2) stay standard: WireGuard's mac1 covers them, so a bridge in
    /// front of plain WireGuard cannot rewrite them. Only the padding around them changes.
    pub struct AmneziaParams {
        /// S1 - random bytes prepended to the handshake initiation.
        pub init_pkt_junk_size: u16,
        /// S2 - random bytes prepended to the handshake response.
        pub response_pkt_junk_size: u16,
        /// H3 - message type replacing the cookie reply type (lower end of the range).
        pub under_load_pkt_magic_header: u32,
        /// H4 - message type replacing the transport data type (lower end of the range).
        pub transport_pkt_magic_header: u32,
        /// S3 - random bytes prepended to the cookie reply (AmneziaWG 3.1).
        #[cfg_attr(feature = "serde", serde(default))]
        pub cookie_pkt_junk_size: u16,
        /// S4 - random bytes prepended to every transport packet (AmneziaWG 3.1).
        #[cfg_attr(feature = "serde", serde(default))]
        pub transport_pkt_junk_size: u16,
        /// Upper end of the H3 range, H3 when absent (AmneziaWG 3.1).
        #[cfg_attr(feature = "serde", serde(default))]
        #[cfg_attr(feature = "typescript-bindings", ts(optional))]
        pub under_load_pkt_magic_header_max: Option<u32>,
        /// Upper end of the H4 range, H4 when absent (AmneziaWG 3.1).
        #[cfg_attr(feature = "serde", serde(default))]
        #[cfg_attr(feature = "typescript-bindings", ts(optional))]
        pub transport_pkt_magic_header_max: Option<u32>,
        /// Hex encoded 32 byte ChaCha20 key masking every message header (AmneziaWG 3.1).
        #[cfg_attr(feature = "serde", serde(default))]
        #[cfg_attr(feature = "typescript-bindings", ts(optional))]
        pub header_protection_key: Option<String>,
        /// Handshake and cookie messages may carry random trailing bytes (AmneziaWG 3.1).
        #[cfg_attr(feature = "serde", serde(default))]
        pub random_trailers: bool,
    }

    impl AmneziaParams {
        pub fn under_load_headers(&self) -> RangeInclusive<u32> {
            let max = self.under_load_pkt_magic_header_max;
            self.under_load_pkt_magic_header..=max.unwrap_or(self.under_load_pkt_magic_header)
        }

        pub fn transport_headers(&self) -> RangeInclusive<u32> {
            let max = self.transport_pkt_magic_header_max;
            self.transport_pkt_magic_header..=max.unwrap_or(self.transport_pkt_magic_header)
        }

        /// No AmneziaWG 3.1 fields set, so an AmneziaWG 1.0 client reads these params correctly.
        pub fn is_awg_1_0(&self) -> bool {
            self.cookie_pkt_junk_size == 0
                && self.transport_pkt_junk_size == 0
                && self.under_load_pkt_magic_header_max.is_none()
                && self.transport_pkt_magic_header_max.is_none()
                && self.header_protection_key.is_none()
                && !self.random_trailers
        }
    }

    impl Sufficiency for AmneziaParams {
        // H3/H4 ranges must not reach plain WireGuard types (1-4) or overlap, padded initiation and
        // response must differ in size (148 + S1 != 92 + S2), and header protection needs a nonce
        // worth of padding on every message type.
        fn is_sufficient(&self) -> bool {
            let paddings = [
                self.init_pkt_junk_size,
                self.response_pkt_junk_size,
                self.cookie_pkt_junk_size,
                self.transport_pkt_junk_size,
            ];
            let (h3, h4) = (self.under_load_headers(), self.transport_headers());
            let key_ok = self.header_protection_key.as_ref().is_none_or(|key| {
                key.len() == 64
                    && key.bytes().all(|b| b.is_ascii_hexdigit())
                    && paddings.iter().all(|s| *s >= HEADER_PROTECTION_NONCE_SIZE)
            });
            paddings.iter().all(|s| *s <= MAX_JUNK_SIZE)
                && self.transport_pkt_junk_size <= MAX_TRANSPORT_JUNK_SIZE
                && self.init_pkt_junk_size + 56 != self.response_pkt_junk_size
                && *h3.start() > 4
                && *h4.start() > 4
                && !h3.is_empty()
                && !h4.is_empty()
                && (h3.end() < h4.start() || h4.end() < h3.start())
                && (!self.random_trailers
                    || [&h3, &h4]
                        .iter()
                        .all(|h| h.end() - h.start() <= MAX_HEADER_RANGE_WITH_TRAILERS))
                && key_ok
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub struct AmneziaClientOptions {
        /// Translator wire format, [`PROTOCOL_AWG_1_0`] or [`PROTOCOL_AWG_3_1`]. Clients skip
        /// versions they do not know.
        pub protocol_version: u16,

        /// UDP addresses of the bridge translator (IPv4/IPv6 pair of the same bridge).
        #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
        pub addresses: Vec<SocketAddr>,

        pub params: AmneziaParams,
    }

    impl Sufficiency for AmneziaClientOptions {
        // A 1.0 profile must not carry 3.1 fields an amneziawg 1.0 client would ignore.
        fn is_sufficient(&self) -> bool {
            let version_ok = match self.protocol_version {
                PROTOCOL_AWG_1_0 => self.params.is_awg_1_0(),
                PROTOCOL_AWG_3_1 => true,
                _ => false,
            };
            !self.addresses.is_empty() && self.params.is_sufficient() && version_ok
        }
    }

    pub type ClientOptions = AmneziaClientOptions;
}

#[cfg(test)]
mod test {
    use crate::{ClientConfig, PersistedClientConfig, Sufficiency, amnezia};

    const RAW_V0_CLIENT_CONFIG: &str = r#"{"version":"0","transports":[{"transport_type":"quic_plain","args":{"addresses":["139.162.33.226:4443","[2400:8901::2000:faff:fea6:87f2]:4443"],"host":"netdna.bootstrapcdn.com","id_pubkey":"9JC91ZiszhIn3n4FG+MDYE/lYwhGdpHGWQTKUqGl+sE="}}]}"#;

    /// The initial version of the bridge descriptors that are provided by the gateways use a snake case
    /// for the enum differentiator. This test validates that under normal circumstances that the descriptor
    /// is parsed as  expected. The only situation under which the enum differentiator has a different format
    /// is when using the `typescript-bindings` feature.
    #[test]
    fn ensure_bridge_v0_parsing_compatibility() -> Result<(), Box<dyn std::error::Error>> {
        // Parse the JSON to verify structure
        let parsed: PersistedClientConfig = serde_json::from_str(RAW_V0_CLIENT_CONFIG)?;

        // Verify version
        assert_eq!(parsed.version, "0");

        // Verify transport type
        let params = match &parsed.transports[0] {
            ClientConfig::QuicPlain(p) => p,
            ClientConfig::TlsPlain(_) => return Err("expected quic transport args".into()),
            ClientConfig::SshPlain(_) => return Err("expected quic transport args".into()),
        };

        // Verify addresses contain our test IPs
        let addresses = &params.addresses;

        let address_strings: Vec<String> = addresses.iter().map(|v| v.to_string()).collect();

        // Should contain both IPv4 and IPv6 addresses with port 4443
        assert!(
            address_strings
                .iter()
                .any(|addr| addr.contains("139.162.33.226:4443"))
        );
        assert!(
            address_strings
                .iter()
                .any(|addr| addr.contains("[2400:8901::2000:faff:fea6:87f2]:4443"))
        );

        // Verify host field
        assert_eq!(params.host, Some("netdna.bootstrapcdn.com".to_string()),);

        // Descriptors from bridges without a translator carry no amnezia params
        assert!(parsed.amnezia.is_empty());

        Ok(())
    }

    fn amnezia_options() -> amnezia::ClientOptions {
        amnezia::ClientOptions {
            protocol_version: amnezia::PROTOCOL_AWG_1_0,
            addresses: vec!["139.162.33.226:51830".parse().unwrap()],
            params: amnezia::AmneziaParams {
                init_pkt_junk_size: 40,
                response_pkt_junk_size: 50,
                under_load_pkt_magic_header: 1_766_607_858,
                transport_pkt_magic_header: 2_028_465_083,
                cookie_pkt_junk_size: 0,
                transport_pkt_junk_size: 0,
                under_load_pkt_magic_header_max: None,
                transport_pkt_magic_header_max: None,
                header_protection_key: None,
                random_trailers: false,
            },
        }
    }

    #[test]
    fn amnezia_params_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let mut config: PersistedClientConfig = serde_json::from_str(RAW_V0_CLIENT_CONFIG)?;
        config.amnezia = vec![amnezia_options()];

        let parsed: PersistedClientConfig = serde_json::from_str(&serde_json::to_string(&config)?)?;

        assert_eq!(parsed, config);
        Ok(())
    }

    #[test]
    fn amnezia_sufficiency() {
        assert!(amnezia_options().is_sufficient());

        let mut colliding_header = amnezia_options();
        colliding_header.params.transport_pkt_magic_header =
            colliding_header.params.under_load_pkt_magic_header;
        assert!(!colliding_header.is_sufficient());

        let mut plain_header = amnezia_options();
        plain_header.params.transport_pkt_magic_header = 4;
        assert!(!plain_header.is_sufficient());

        let mut same_size = amnezia_options();
        same_size.params.response_pkt_junk_size = same_size.params.init_pkt_junk_size + 56;
        assert!(!same_size.is_sufficient());

        let mut no_addresses = amnezia_options();
        no_addresses.addresses.clear();
        assert!(!no_addresses.is_sufficient());
    }

    fn awg_3_1_options() -> amnezia::ClientOptions {
        let mut options = amnezia_options();
        options.protocol_version = amnezia::PROTOCOL_AWG_3_1;
        options.params.cookie_pkt_junk_size = 20;
        options.params.transport_pkt_junk_size = 16;
        options.params.under_load_pkt_magic_header_max = Some(1_766_607_958);
        options.params.transport_pkt_magic_header_max = Some(2_028_465_183);
        options.params.header_protection_key = Some("ab".repeat(32));
        options.params.random_trailers = true;
        options
    }

    #[test]
    fn amnezia_3_1_sufficiency() {
        assert!(awg_3_1_options().is_sufficient());

        let mut short_padding = awg_3_1_options();
        short_padding.params.transport_pkt_junk_size = 8;
        assert!(!short_padding.is_sufficient());

        let mut mtu_eating_padding = awg_3_1_options();
        mtu_eating_padding.params.transport_pkt_junk_size = amnezia::MAX_TRANSPORT_JUNK_SIZE + 1;
        assert!(!mtu_eating_padding.is_sufficient());

        let mut overlapping = awg_3_1_options();
        overlapping.params.random_trailers = false;
        overlapping.params.under_load_pkt_magic_header_max = Some(2_050_000_000);
        assert!(!overlapping.is_sufficient());

        let mut colliding_with_trailers = awg_3_1_options();
        colliding_with_trailers
            .params
            .transport_pkt_magic_header_max =
            Some(2_028_465_083 + amnezia::MAX_HEADER_RANGE_WITH_TRAILERS + 1);
        assert!(!colliding_with_trailers.is_sufficient());

        let mut bad_key = awg_3_1_options();
        bad_key.params.header_protection_key = Some("zz".repeat(32));
        assert!(!bad_key.is_sufficient());

        let mut downgraded = awg_3_1_options();
        downgraded.protocol_version = amnezia::PROTOCOL_AWG_1_0;
        assert!(!downgraded.is_sufficient());

        let mut unknown = awg_3_1_options();
        unknown.protocol_version = 99;
        assert!(!unknown.is_sufficient());
    }
}

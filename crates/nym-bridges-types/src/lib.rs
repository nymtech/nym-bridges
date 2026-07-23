//! Nym Bridge Types
//!
//!

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "typescript-bindings")]
use ts_rs::TS;

#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

use std::net::SocketAddr;
#[cfg(feature = "uniffi-bindings")]
use std::str::FromStr;
#[cfg(feature = "uniffi-bindings")]
uniffi::custom_type!(SocketAddr, String, {
    remote,
    try_lift: |val| Ok(SocketAddr::from_str(&val)?),
    lower: |val| val.to_string()
});

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub struct PersistedClientConfig {
    pub version: String,
    pub transports: Vec<PersistedTransportConfig>,
}

impl PersistedClientConfig {
    pub fn get_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        for transport in &self.transports {
            match &transport.config {
                ClientConfig::QuicPlain(params) => addrs.extend(&params.addresses),
                ClientConfig::TlsPlain(params) => addrs.extend(&params.addresses),
            }
        }
        addrs
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub struct PersistedTransportConfig {
    pub name: String,
    pub version: String,
    pub config: ClientConfig,
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "transport_type", content = "args"))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "typescript-bindings",
    derive(TS),
    ts(export),
    ts(export_to = "bindings.ts")
)]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
pub enum ClientConfig {
    QuicPlain(quic::ClientOptions),
    TlsPlain(tls::ClientOptions),
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

pub mod quic {
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
    pub struct QuicPlainClientOptions {
        /// Address describing the remote transport server. This is a vec to support multiple addresses
        /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
        /// as the key material should not be used across multiple instances.
        ///
        /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
        pub addresses: Vec<SocketAddr>,

        /// Override hostname used for certificate verification
        pub host: Option<String>,

        /// Use identity public key to verify server self signed certificate
        pub id_pubkey: String,
    }

    pub type ClientOptions = QuicPlainClientOptions;
}

pub mod tls {
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
    #[cfg_attr(
        feature = "typescript-bindings",
        derive(TS),
        ts(export),
        ts(export_to = "bindings.ts")
    )]
    #[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
    pub struct TlsPlainClientOptions {
        /// Address describing the remote transport server. This is a vec to support multiple addresses
        /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
        /// as the key material should not be used across multiple instances.
        ///
        /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
        pub addresses: Vec<SocketAddr>,

        /// Override hostname used for certificate verification
        pub host: Option<String>,

        /// Use identity public key to verify server self signed certificate base64 encoded
        pub id_pubkey: String,
    }

    pub type ClientOptions = TlsPlainClientOptions;
}

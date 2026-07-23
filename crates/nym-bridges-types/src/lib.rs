//! Nym Bridge Types
//!
//!

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct PersistedClientConfig {
    pub version: String,
    pub transports: Vec<ClientConfig>,
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct PersistedTransportConfig {
    pub name: String,
    pub version: String,
    pub config: ClientConfig,
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "transport_type", content = "args"))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub struct ClientOptions {
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
}

pub mod tls {
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;

    #[derive(Debug, PartialEq, Clone)]
    #[cfg_attr(feature = "typescript-bindings", serde(rename_all = "camelCase"))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub struct ClientOptions {
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
}

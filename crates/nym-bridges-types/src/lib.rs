// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

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
}

impl PersistedClientConfig {
    pub fn get_addrs(&self) -> Vec<BridgeSocketAddr> {
        let mut addrs = Vec::new();
        for transport in &self.transports {
            match transport {
                ClientConfig::QuicPlain(params) => addrs.extend(&params.addresses),
                ClientConfig::TlsPlain(params) => addrs.extend(&params.addresses),
            }
        }
        addrs
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
    use std::net::SocketAddr as BridgeSocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

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

    pub type ClientOptions = QuicPlainClientOptions;
}

pub mod tls {
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr as BridgeSocketAddr;

    #[cfg(feature = "typescript-bindings")]
    use ts_rs::TS;

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

    pub type ClientOptions = TlsPlainClientOptions;
}

#[cfg(test)]
mod test {
    use crate::{ClientConfig, PersistedClientConfig};

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

        Ok(())
    }
}

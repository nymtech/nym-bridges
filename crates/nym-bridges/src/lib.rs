// Copyright 2025 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nym Transport Bridges library.
//!
//! This crate provides the transport and configuration primitives used by Nym bridge runners and
//! tooling.
//!
//! The primary responsibilities are:
//! - server-side transport configuration for QUIC and TLS listeners,
//! - client-side transport parameters derived from server configuration,
//! - forwarding/session/connection building blocks for bridge implementations.
//!
//! The repository binaries (for example, `nym-bridge` and `bridge-cfg`) use this crate as their
//! shared core.
//!
//! # Shared Types Crate
//!
//! This crate re-exports [`nym-bridges-types`](https://docs.rs/nym-bridges-types) as [`types`].
//!
//! These shared types can be consumed directly when integrating across crates or language bindings.
//!
//! # Example: Simple Client Connection Establishment
//!
//! ```rust no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(),anyhow::Error>{
//! use anyhow::anyhow;
//! use nym_bridges::connection::{BridgeConn, SOCKET_OPEN_NOP};
//! use nym_bridges::config::parse_persisted_config_json;
//! use nym_bridges::forward::UdpForwarder;
//! use tokio_util::sync::CancellationToken;
//!
//! let client_config_str = r#"{"version":"0","transports":[{"transport_type":"quic_plain","args":{"addresses":["139.162.33.226:4443","[2400:8901::2000:faff:fea6:87f2]:4443"],"host":"netdna.bootstrapcdn.com","id_pubkey":"9JC91ZiszhIn3n4FG+MDYE/lYwhGdpHGWQTKUqGl+sE="}}]}"#;
//! let shutdown_token = CancellationToken::new();
//! let entry_bridge_params = parse_persisted_config_json(client_config_str)?;
//! let transport_params = entry_bridge_params
//!     .transports
//!     .first()
//!     .ok_or(anyhow!("no config provided"))?;
//!
//! let bridge_conn = BridgeConn::try_connect(
//!     transport_params.clone(),
//!     shutdown_token.clone(),
//!     #[cfg(any(target_os = "linux", target_os = "android"))]
//!     SOCKET_OPEN_NOP,
//! )
//! .await?;
//!
//! let remote_addr = bridge_conn.endpoint();
//! let (listen_addr, join_handle) = UdpForwarder::launch_initiator(
//!     bridge_conn,
//!     None,
//!     None,
//!     shutdown_token.clone(),
//! )
//! .await?;
//!
//! # Ok::<(), anyhow::Error>(())
//! # }
//! ```
//!
//! # Example: Parse and Convert Configuration
//!
//! ```
//! use nym_bridges::config::PersistedServerConfig;
//! use nym_bridges::types::PersistedClientConfig;
//!
//! let server_toml = r#"
//! public_ips = ["192.168.0.1", "fe80::1"]
//!
//! [forward]
//! address = "[::1]:51822"
//!
//! [[transports]]
//! transport_type = "quic_plain"
//!
//! [transports.args]
//! stateless_retry = false
//! listen = "[::]:4443"
//! identity_key = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk="
//! "#;
//!
//! let server_cfg = PersistedServerConfig::parse(server_toml)?;
//! let client_cfg = PersistedClientConfig::try_from(&server_cfg)?;
//! assert_eq!(client_cfg.version, "0");
//! # Ok::<(), anyhow::Error>(())
//! ```

/// Persisted server/client configuration types and conversion from server transport config to
/// client connection parameters.
pub mod config;
/// Runtime components for creating connections over configured transports.
pub mod connection;
/// Crate-specific error types.
pub mod error;
/// Runtime components for forwarding client traffic over established transport connections.
pub mod forward;
/// Stored state and config for established connection.
pub mod session;
/// Protocol-specific transport implementations.
pub mod transport;
// mod stats;

pub use nym_bridges_types as types;

#[allow(unused)]
#[cfg(test)]
pub(crate) mod test_utils {
    use std::env;
    use std::str::FromStr;
    use std::sync::Once;
    use tracing_subscriber::filter::LevelFilter;

    static SUBSCRIBER_INIT: Once = Once::new();

    #[allow(unused)]
    pub fn init_subscriber(maybe_level: Option<LevelFilter>) {
        SUBSCRIBER_INIT.call_once(|| {
            let lf = maybe_level.unwrap_or_else(|| {
                let level = env::var("RUST_LOG_LEVEL").unwrap_or("error".into());
                LevelFilter::from_str(&level).unwrap()
            });

            tracing_subscriber::fmt().with_max_level(lf).init();
        });
    }
}

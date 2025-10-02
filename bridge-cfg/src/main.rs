//! Configuration Tool for Nym Bridge Service
//!
//! The initial [bridge transport runner](../nym-bridge/) is designed to use the Identity Key of the
//! gateway node to sign certificates guaranteeing the authenticity and security of the established
//! TLS handshakes. The listener process will need access to this key in order to do so.
//! Additionally the runner is designed to proxy traffic received in successful connections to a
//! local service, for the initial deployment alongside a `nym-node` this is the wireguard service
//! used for DVPN connections.
//!
//! In order to accomplish this the `bridge-cfg` tool is designed to
//!
//!
//! - Parse the Nym Node Config for relevant info
//!     - Identity Keys (path → key) that are used by the nym-node for use in the listener
//!     - Public IP address
//!     - Wireguard listen port
//! - Store listener config in the local node config location
//!
//! The relevant fields that are adapted are described by:
//!
//! * Ensure Identity Key file path maps to the proper key material available in node descriptors.
//!     - `nym-bridge.transports[..].args.private_ed25519_identity_key_file =
//!       <nym-node.storage_paths.keys.private_ed25519_identity_key_file>`
//! * Configure the correct address to proxy client traffic received in successful connections to
//!   the local wireguard listener
//!     - `nym-bridge.forward.address =
//!       <nym-node.host.public_ips[0]>:<nym-node.wireguard.announced_port>`
//!

use anyhow::Result;
use clap::Parser;
use nym_config::{DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILENAME, NYM_DIR, must_get_home};
use tracing::error;

use std::path::{Path, PathBuf};

mod bridge_client_config;
use bridge_client_config::BridgeClientConfig;
mod bridge_config;
use bridge_config::BridgeConfig;
mod node_config;
use node_config::NodeConfig;

#[derive(Debug, Parser, PartialEq)]
#[clap(name = "config-args")]
struct ConfigArgs {
    #[clap(short = 'd', long = "dir", conflicts_with = "id")]
    /// Provide a path to the `nym-node` configuration that will be used to populate the bridge
    /// config. If none is provided the default configuration path for the default `nym-node` ID
    /// will be assumed, unless an alternate node ID is provided using the `--id` flag.
    /// (default: `$HOME/.nym/nym-nodes/$NYMNODE_ID/config/`)
    node_config_dir: Option<PathBuf>,

    /// Node ID used for the nym-node. This is used to construct a default path using a custom ID to
    /// the `nym-node` configuration that will be used to populate the bridge config.
    #[clap(long, conflicts_with = "node_config_dir", default_value = Self::DEFAULT_NYMNODE_ID)]
    id: String,

    #[clap(short = 'i', long = "in")]
    /// Provide a path to the input location for a populated bridge configuration. If none is
    /// provided, default values will be used for required fields.
    bridge_config_path_in: Option<PathBuf>,

    #[clap(short = 'o', long = "out")]
    /// Provide a path to the output location for the populated bridge configuration. If none is
    /// provided, the default location for nym configuration files is used.
    bridge_config_path_out: Option<PathBuf>,

    #[clap(long = "gen")]
    /// If key material is either not specified, or files do not exist at the specified path generate
    /// the key material.
    generate_keys: bool,

    #[clap(long, requires = "generate_keys")]
    /// DANGER -- Re-generate transport key material, even if it already exists. Overwritten keys will not be
    /// recoverable unless saved elsewhere.
    ///
    /// NOTE: if `--dry-run` is specified this will NOT actually overwrite existing keys.
    allow_overwrite: bool,

    /// Print the resulting config files wih diff info without persisting the changes.
    #[clap(long)]
    dry_run: bool,
}

impl ConfigArgs {
    const DEFAULT_NYMNODES_DIR: &str = "nym-nodes";
    const DEFAULT_NYMNODE_ID: &str = "default-nym-node";
    const DEFAULT_BRIDGE_CONFIG_FILENAME: &str = "bridges.toml";
    const DEFAULT_BRIDGE_CLIENT_CONFIG_FILENAME: &str = "client_bridge_params.json";

    /// Derive default path to nym-node's config directory.
    /// It should get resolved to `$HOME/.nym/nym-nodes/<id>/config`
    fn default_config_directory<P: AsRef<Path>>(id: P) -> PathBuf {
        must_get_home()
            .join(NYM_DIR)
            .join(Self::DEFAULT_NYMNODES_DIR)
            .join(id)
            .join(DEFAULT_CONFIG_DIR)
    }

    fn adapt_config_files(&self) -> Result<()> {
        let node_config_dir = self
            .node_config_dir
            .clone()
            .unwrap_or(Self::default_config_directory(&self.id));

        // try to parse the bridge config or get a default and keep a copy unmodified for diff
        let (bridge_config_orig, mut bridge_config) = match &self.bridge_config_path_in {
            Some(path) => {
                let cfg = BridgeConfig::parse_from_file(path)?;
                (Some(cfg.clone()), cfg)
            }
            None => (None, BridgeConfig::default()),
        };

        // try to parse the existing bridge client_config if it exists
        let bridge_client_config_orig = bridge_config.maybe_parse_client_config()?;
        let bridge_client_config_path = bridge_config.get_or_set_client_config_path(
            node_config_dir.join(Self::DEFAULT_BRIDGE_CLIENT_CONFIG_FILENAME),
        );

        // parse the node configuration
        let node_config_path = node_config_dir.join(DEFAULT_CONFIG_FILENAME);
        let node_config_orig = NodeConfig::parse_from_file(&node_config_path)?;
        let mut node_config = node_config_orig.clone();

        // if any key material needs to be generated, generate it.
        if self.generate_keys {
            bridge_config.generate_keys(self.allow_overwrite, &node_config_dir)?;
        }

        // adapt the nym-bridge configuration
        let forward_address = node_config.get_forward_address();
        bridge_config.set_forward_address(forward_address);

        // adapt the nym-node configuration
        node_config.set_bridge_client_config_path(&bridge_client_config_path);

        // generate the client configuration for this bridge configuration
        let bridge_client_config = BridgeClientConfig::try_from(&bridge_config)?;

        let bridge_config_path_out = self
            .bridge_config_path_out
            .clone()
            .unwrap_or(node_config_dir.join(Self::DEFAULT_BRIDGE_CONFIG_FILENAME));

        // persist or display changes made to configs
        if self.dry_run {
            // print diff for files to be modified (with key materials redacted if using --gen)
            node_config.print_diff(&node_config_orig, &node_config_path);
            bridge_client_config.print_diff(
                bridge_client_config_orig.as_ref(),
                bridge_client_config_path,
            );
            bridge_config.print_diff(bridge_config_orig.as_ref(), Some(bridge_config_path_out));
        } else {
            // bridge config
            bridge_config.serialize_to_file(bridge_config_path_out)?;
            bridge_config.persist_keys()?;

            // nym-node
            println!();
            node_config.serialize_to_file(&node_config_path)?;

            // bridge client config
            println!();
            bridge_client_config.serialize_to_file(bridge_client_config_path)?;
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = ConfigArgs::parse();

    if let Err(e) = args.adapt_config_files() {
        error!("config adaptation failed: {e}");
    }

    Ok(())
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use nym_bridges::config::{ForwardConfig, PersistedServerConfig, TransportServerConfig};
//     use toml_edit::DocumentMut;

//     #[test]
//     fn adapt_existing_bridge_config() {
//         let filepath = Path::new(env!("CARGO_MANIFEST_DIR"))
//             .join("test")
//             .join("config.toml");

//         assert!(filepath.exists(), "Test config file should exist");
//         let node_config = NodeConfig::parse_from_file(&filepath).unwrap();

//         let tls_config = nym_bridges::transport::tls::ServerConfig {
//             identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
//             listen: "[::]:443".parse().unwrap(),
//             ..Default::default()
//         };

//         let quic_config = nym_bridges::transport::quic::ServerConfig {
//             private_ed25519_identity_key_file: Some(PathBuf::from("/etc/nym/ed25519_identity_key")),
//             listen: "[::]:443".parse().unwrap(),
//             connection_limit: Some(10_000),
//             ..Default::default()
//         };
//         let bridge_config = PersistedServerConfig {
//             public_ips: vec!["192.168.0.1".into(), "fe80::1".into()],
//             forward: ForwardConfig {
//                 address: "[::1]:5000".parse().unwrap(),
//             },
//             client_params_path: None,
//             transports: vec![
//                 TransportServerConfig::TlsPlain(tls_config),
//                 TransportServerConfig::QuicPlain(quic_config),
//             ],
//         };
//         let out_str = toml::to_string(&bridge_config).unwrap();
//         let bridge_config = out_str.parse::<DocumentMut>().unwrap();

//         let run_args = ConfigArgs {
//             generate_keys:false,
//             node_config_dir: None,
//             id: "".into(),
//             bridge_config_path_in: None,
//             bridge_config_path_out: None,
//             allow_overwrite: false,
//             dry_run: false,
//         };

//         // let resultant_config = adapt_config(&node_config, &bridge_config);
//         let resultant_config = run_args.adapt_config_files();
//         let resultant_config_str = resultant_config.to_string();
//         let resultant_config: PersistedServerConfig =
//             toml::from_str(&resultant_config_str).unwrap();

//         // Check that the forward address points to the correct wireguard listener
//         assert_eq!(
//             resultant_config.forward.address,
//             "1.1.1.1:51822".parse().unwrap(),
//         );
//         // Check that the identity key files point to the correct locations and any other
//         // config options were left as original.
//         resultant_config
//             .transports
//             .iter()
//             .for_each(|transport| match transport {
//                 TransportServerConfig::QuicPlain(cfg) => {
//                     assert!(cfg.identity_key.is_none());
//                     assert_eq!(cfg.listen, "[::]:443".parse().unwrap());
//                     assert_eq!(cfg.connection_limit, Some(10_000));
//                 }
//                 TransportServerConfig::TlsPlain(cfg) => {
//                     assert!(cfg.identity_key.is_none());
//                     assert_eq!(cfg.listen, "[::]:443".parse().unwrap());
//                 }
//             });
//     }
// }

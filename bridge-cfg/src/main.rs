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

struct RunOptions {
    generate_keys: bool,
    allow_overwrite: bool,
}

struct ConfigRun {
    opts: RunOptions,
    paths: PathInfo,
    input: ConfigsIn,
}

impl ConfigRun {
    fn adapt_configs(&self) -> Result<ConfigsOut> {
        // adapt the nym-node configuration
        let mut node_cfg = self.input.node_cfg.clone();

        let mut bridge_cfg = self.input.bridge_cfg.clone().unwrap_or_default();

        // if any key material needs to be generated, generate it.
        if self.opts.generate_keys {
            bridge_cfg.generate_keys(self.opts.allow_overwrite, &self.paths.key_dir)?;
        }

        // adapt the nym-bridge configuration
        let forward_address = node_cfg.get_forward_address();
        bridge_cfg.set_forward_address(forward_address);
        bridge_cfg.set_client_config_path(&self.paths.bridge_client_cfg_path);

        // adapt the nym-node configuration
        node_cfg.set_bridge_client_config_path(&self.paths.bridge_client_cfg_path);

        // generate the client configuration for this bridge configuration
        let bridge_client_cfg = BridgeClientConfig::try_from(&bridge_cfg)?;

        Ok(ConfigsOut {
            bridge_cfg,
            node_cfg,
            bridge_client_cfg,
        })
    }
}

#[derive(Debug, Default)]
struct PathInfo {
    bridge_cfg_path_in: Option<PathBuf>,
    bridge_cfg_path_out: PathBuf,
    node_cfg_path: PathBuf,
    bridge_client_cfg_path: PathBuf,
    key_dir: PathBuf,
}

struct ConfigsIn {
    /// Stand in object containing Nym Node configuration.
    ///
    /// This is required for the initial version of config parsing as the nym-bridge is intended to be run together
    /// with a nym-node, and so several of the nym-bridge options are (for now) derived from the values in the
    /// nym-node configuration. (nym-bridge public_ips depends on nym=node public_ips, nym-bridge forward address
    /// depends on nym-node public_ips and wg announced port).
    node_cfg: NodeConfig,

    /// Stand in object for incoming / pre-existing bridge configuration.
    ///
    /// If this is None then adaptation will start by instantiating a BridgeConfig from default and generating the
    /// required identity key material.
    bridge_cfg: Option<BridgeConfig>,

    /// Stand in object for incoming / pre-existing bridge client parameters.
    ///
    /// This is really only used for comparison if the dry-run option is given so as to provide diff information.
    /// The value will be re-generated based on any changes during the run.
    bridge_client_cfg: Option<BridgeClientConfig>,
}

struct ConfigsOut {
    bridge_cfg: BridgeConfig,
    node_cfg: NodeConfig,
    bridge_client_cfg: BridgeClientConfig,
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

#[cfg(test)]
mod test {
    use super::*;
    use nym_bridges::config::{
        ClientConfig, ForwardConfig, PersistedClientConfig, PersistedServerConfig,
        TransportServerConfig,
    };
    use tempdir::TempDir;

    #[test]
    fn create_fresh_bridge_config() -> Result<()> {
        let node_cfg_filepath = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("config.toml");

        let tmp_dir = TempDir::new("bridges")?;
        let bridge_client_cfg_path = tmp_dir
            .path()
            .join(ConfigArgs::DEFAULT_BRIDGE_CLIENT_CONFIG_FILENAME);
        let bridge_cfg_path_out = tmp_dir
            .path()
            .join(ConfigArgs::DEFAULT_BRIDGE_CONFIG_FILENAME);

        assert!(node_cfg_filepath.exists(), "Test config file should exist");
        let node_config = NodeConfig::parse_from_file(&node_cfg_filepath).unwrap();

        let configs_in = ConfigsIn {
            bridge_cfg: None,
            node_cfg: node_config,
            bridge_client_cfg: None,
        };

        let config_run = ConfigRun {
            opts: RunOptions {
                generate_keys: true,
                allow_overwrite: false,
            },
            paths: PathInfo {
                bridge_cfg_path_in: None,
                bridge_cfg_path_out,
                node_cfg_path: node_cfg_filepath,
                bridge_client_cfg_path,
                key_dir: tmp_dir.path().to_path_buf(),
            },
            input: configs_in,
        };

        let ConfigsOut {
            bridge_cfg,
            node_cfg,
            bridge_client_cfg,
        } = config_run
            .adapt_configs()
            .expect("error occurred while adapting configs");

        Ok(())
    }

    #[test]
    fn adapt_existing_bridge_config() {
        let node_cfg_filepath = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("config.toml");

        assert!(node_cfg_filepath.exists(), "Test config file should exist");
        let node_config = NodeConfig::parse_from_file(&node_cfg_filepath).unwrap();

        // let tls_config = nym_bridges::transport::tls::ServerConfig {
        //     identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
        //     listen: "[::]:443".parse().unwrap(),
        //     ..Default::default()
        // };

        let test_identity_priv = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=";
        let test_identity_pub = "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=";
        let quic_config = nym_bridges::transport::quic::ServerConfig {
            // private_ed25519_identity_key_file: Some(PathBuf::from(preexisting_quic_key_path)),
            identity_key: Some(test_identity_priv.into()),
            listen: "[::]:443".parse().unwrap(),
            connection_limit: Some(10_000),
            ..Default::default()
        };
        let bridge_config = PersistedServerConfig {
            public_ips: vec!["192.168.0.1".into(), "fe80::1".into()],
            forward: ForwardConfig {
                address: "[::1]:5000".parse().unwrap(),
            },
            client_params_path: None,
            transports: vec![
                TransportServerConfig::QuicPlain(quic_config),
                // TransportServerConfig::TlsPlain(tls_config),
            ],
        };
        let out_str = toml::to_string(&bridge_config).unwrap();
        let bridge_config =
            BridgeConfig::parse(out_str).expect("failed to parse bridge configuration");

        let configs_in = ConfigsIn {
            bridge_cfg: Some(bridge_config),
            node_cfg: node_config,
            bridge_client_cfg: None,
        };

        let config_run = ConfigRun {
            opts: RunOptions {
                generate_keys: true,
                allow_overwrite: false,
            },
            paths: PathInfo {
                node_cfg_path: node_cfg_filepath,
                // we are not using any other element of the path really
                // (and nothing will be stored during this test)
                ..Default::default()
            },
            input: configs_in,
        };

        let ConfigsOut {
            bridge_cfg,
            node_cfg,
            bridge_client_cfg,
        } = config_run
            .adapt_configs()
            .expect("error occurred while adapting configs");

        let bridge_config_out: PersistedServerConfig =
            toml::from_str(&bridge_cfg.serialize()).unwrap();

        // Check that the forward address points to the correct wireguard listener
        assert_eq!(
            bridge_config_out.forward.address,
            "1.1.1.1:51822".parse().unwrap()
        );

        // check that no new keys were generated
        assert!(bridge_cfg.keys.is_empty());

        // check that the paths to the bridge client params file all point to the expected location.
        assert_eq!(
            node_cfg.get_bridge_client_config_path().unwrap(),
            config_run.paths.bridge_client_cfg_path
        );
        assert_eq!(
            bridge_config_out.client_params_path.unwrap(),
            config_run.paths.bridge_client_cfg_path
        );

        // Check that the identity key files point to the correct locations and any other
        // config options were left as original.
        bridge_config_out
            .transports
            .iter()
            .for_each(|transport| match transport {
                TransportServerConfig::QuicPlain(cfg) => {
                    assert_eq!(cfg.identity_key, Some(test_identity_priv.into()));
                    assert_eq!(cfg.listen, "[::]:443".parse().unwrap());
                    assert_eq!(cfg.connection_limit, Some(10_000));
                }
                TransportServerConfig::TlsPlain(_cfg) => todo!(),
            });

        let client_params_out =
            PersistedClientConfig::parse_json(&bridge_client_cfg.serialize().unwrap()).unwrap();
        client_params_out
            .transports
            .iter()
            .for_each(|transport| match transport {
                ClientConfig::QuicPlain(cfg) => {
                    assert_eq!(cfg.id_pubkey, test_identity_pub);
                    assert!(cfg.addresses.contains(&"[fe80::1]:443".parse().unwrap()));
                    assert!(cfg.addresses.contains(&"192.168.0.1:443".parse().unwrap()));
                }
                ClientConfig::TlsPlain(_cfg) => todo!(),
            });
    }

    /// Test playing with and clarifying the ways that you are (or are not) meant to interact with DocumentMut
    #[test]
    fn document_mut() -> Result<()> {
        let preexisting_quic_key_path = "/etc/nym/ed25519_identity_key";
        let quic_config = nym_bridges::transport::quic::ServerConfig {
            private_ed25519_identity_key_file: Some(PathBuf::from(preexisting_quic_key_path)),
            listen: "[::]:443".parse().unwrap(),
            connection_limit: Some(10_000),
            ..Default::default()
        };
        let bridge_config = PersistedServerConfig {
            public_ips: vec!["192.168.0.1".into(), "fe80::1".into()],
            forward: ForwardConfig {
                address: "[::1]:5000".parse().unwrap(),
            },
            client_params_path: None,
            transports: vec![
                TransportServerConfig::QuicPlain(quic_config),
                // TransportServerConfig::TlsPlain(tls_config),
            ],
        };
        let out_str = toml::to_string(&bridge_config).unwrap();
        let bridge_config =
            BridgeConfig::parse(out_str).expect("failed to parse bridge configuration");

        assert!(bridge_config.inner.contains_key("forward"));
        assert!(
            bridge_config.inner["forward"]
                .as_table()
                .unwrap()
                .contains_key("address")
        );
        assert!(
            bridge_config
                .inner
                .get("forward")
                .unwrap()
                .get("address")
                .is_some()
        );
        assert!(bridge_config.inner["forward"]["address"].is_str());

        let expected_panic = std::panic::catch_unwind(|| {
            bridge_config.inner["forward"]["missing_field"].is_str();
        });
        assert!(expected_panic.is_err());

        Ok(())
    }
}

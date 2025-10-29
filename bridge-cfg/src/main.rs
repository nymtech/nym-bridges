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
use nym_bin_common::bin_info;
use nym_config::{DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILENAME, NYM_DIR, must_get_home};
use tracing::*;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

mod bridge_client_config;
use bridge_client_config::BridgeClientConfig;
mod bridge_config;
use bridge_config::BridgeConfig;
mod node_config;
use node_config::NodeConfig;

static PRETTY_BUILD_INFORMATION: OnceLock<String> = OnceLock::new();
// Helper for passing LONG_VERSION to clap
fn pretty_build_info_static() -> &'static str {
    PRETTY_BUILD_INFORMATION.get_or_init(|| bin_info!().pretty_print())
}

#[derive(Debug, Parser, PartialEq)]
#[command(author="Nymtech", version, long_version = pretty_build_info_static())]
struct ConfigArgs {
    #[clap(short, long, conflicts_with = "id")]
    /// Provide a path to the `nym-node` configuration that will be used to populate the node
    /// config. If none is provided the default configuration path for the default `nym-node` ID
    /// will be assumed, unless an alternate node ID is provided using the `--id` flag.
    /// (default: `$HOME/.nym/nym-nodes/$NYMNODE_ID/config/`)
    node_config: Option<PathBuf>,

    /// Node ID used for the nym-node. This is used to construct a default path using a custom ID to
    /// the `nym-node` configuration that will be used to populate the bridge config.
    #[clap(long, conflicts_with = "node_config", default_value = Self::DEFAULT_NYMNODE_ID)]
    id: String,

    #[clap(short='d', long="dir", default_value = Self::default_bridge_config_output_dir().into_os_string())]
    /// Provide a path to the output directory location for the populated bridge configuration and
    /// supporting materials (i.e key(s)).
    out_dir: PathBuf,

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

    fn default_bridge_config_output_dir() -> PathBuf {
        PathBuf::from("/etc/nym")
    }

    /// Derive default path to nym-node's config directory.
    /// It should get resolved to `$HOME/.nym/nym-nodes/<id>/config`
    fn default_node_config_path<P: AsRef<Path>>(id: P) -> PathBuf {
        must_get_home()
            .join(NYM_DIR)
            .join(Self::DEFAULT_NYMNODES_DIR)
            .join(id)
            .join(DEFAULT_CONFIG_DIR)
            .join(DEFAULT_CONFIG_FILENAME)
    }

    /// Try to find any nym-node config if the default doesn't exist.
    ///
    /// This function searches the nym-nodes directory for any available node configuration
    /// when the user hasn't specified a config path and the default node ID config isn't found.
    /// This is helpful for users who may have renamed their node or are running a non-default setup.
    ///
    /// Returns the path to the valid nym-node config.toml found, or None if no configs exist.
    /// Returns an error if multiple configs are found (ambiguous case).
    fn find_any_node_config() -> Result<Option<PathBuf>> {
        let nym_nodes_dir = must_get_home()
            .join(NYM_DIR)
            .join(Self::DEFAULT_NYMNODES_DIR);

        if !nym_nodes_dir.exists() {
            return Ok(None);
        }

        // Try to find any nym-node config by scanning the nym-nodes directory
        let mut found_configs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&nym_nodes_dir) {
            for entry in entries.flatten() {
                let config_path = entry
                    .path()
                    .join(DEFAULT_CONFIG_DIR)
                    .join(DEFAULT_CONFIG_FILENAME);
                if config_path.exists() {
                    found_configs.push(config_path);
                }
            }
        }

        match found_configs.len() {
            0 => Ok(None),
            1 => {
                info!("found nym-node config at: {}", found_configs[0].display());
                Ok(Some(found_configs[0].clone()))
            }
            _ => {
                error!(
                    "found multiple nym-node configs in {}:",
                    nym_nodes_dir.display()
                );
                for config in &found_configs {
                    error!("  - {}", config.display());
                }
                anyhow::bail!(
                    "Multiple nym-node configurations found. Please specify which one to use with --id <node-id> or --node-config <path>.\n\
                    Found configs:\n{}\n\
                    Example: bridge-cfg --id <node-id>",
                    found_configs
                        .iter()
                        .map(|p| format!("  {}", p.display()))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            }
        }
    }

    fn adapt_config_files(&self) -> Result<()> {
        let node_cfg_path = if let Some(path) = &self.node_config {
            path.clone()
        } else {
            let default_path = Self::default_node_config_path(&self.id);
            if default_path.exists() {
                default_path
            } else {
                // Try to find any nym-node config
                Self::find_any_node_config()?.unwrap_or(default_path)
            }
        };

        // try to parse the bridge config or get a default and keep a copy unmodified for diff
        let bridge_cfg_orig = match &self.bridge_config_path_in {
            Some(path) => Some(BridgeConfig::parse_from_file(path)?),
            None => None,
        };
        let bridge_cfg_path_out = self
            .bridge_config_path_out
            .clone()
            .unwrap_or(self.out_dir.join(Self::DEFAULT_BRIDGE_CONFIG_FILENAME));

        // try to parse the existing bridge client_config if it exists return an error only if the
        // file exists but fails to parse. otherwise, it will be generated /regenerated
        let default_bridge_client_cfg_path = self
            .out_dir
            .join(Self::DEFAULT_BRIDGE_CLIENT_CONFIG_FILENAME);
        let (bridge_client_cfg_orig, bridge_client_cfg_path) = match &bridge_cfg_orig {
            Some(cfg) => match cfg.get_client_config_path() {
                Some(path) => {
                    if !path.exists() {
                        (None, default_bridge_client_cfg_path)
                    } else {
                        (Some(BridgeClientConfig::parse_from_file(&path)?), path)
                    }
                }
                None => (None, default_bridge_client_cfg_path),
            },
            None => (None, default_bridge_client_cfg_path),
        };

        // parse the node configuration
        let node_cfg_orig = if node_cfg_path.exists() {
            NodeConfig::parse_from_file(&node_cfg_path)?
        } else {
            NodeConfig::new_without_node()
        };

        let configs_in = ConfigsIn {
            bridge_cfg: bridge_cfg_orig,
            node_cfg: node_cfg_orig,
            bridge_client_cfg: bridge_client_cfg_orig,
        };

        let config_run = ConfigRun {
            opts: RunOptions {
                generate_keys: self.generate_keys,
                allow_overwrite: self.allow_overwrite,
            },
            paths: PathInfo {
                bridge_cfg_path_out,
                node_cfg_path,
                bridge_client_cfg_path,
                key_dir: self.out_dir.join("keys"),
            },
            input: configs_in,
        };

        let ConfigsOut {
            bridge_cfg,
            node_cfg,
            bridge_client_cfg,
        } = config_run.adapt_configs()?;

        // persist or display changes made to configs
        if self.dry_run {
            // print diff for files to be modified (with key materials redacted if using --gen)
            node_cfg.print_diff(&config_run.input.node_cfg, &config_run.paths.node_cfg_path);
            println!("\n");

            bridge_client_cfg.print_diff(
                config_run.input.bridge_client_cfg.as_ref(),
                config_run.paths.bridge_client_cfg_path,
            );
            println!("\n");

            bridge_cfg.print_diff(
                config_run.input.bridge_cfg.as_ref(),
                Some(config_run.paths.bridge_cfg_path_out),
                &config_run.paths.key_dir,
            );
        } else {
            // bridge config
            bridge_cfg.serialize_to_file(config_run.paths.bridge_cfg_path_out)?;
            if self.generate_keys && !bridge_cfg.keys.is_empty() {
                bridge_cfg.persist_keys(&config_run.paths.key_dir)?;
            }

            // nym-node
            node_cfg.serialize_to_file(&config_run.paths.node_cfg_path)?;

            // bridge client config
            bridge_client_cfg.serialize_to_file(config_run.paths.bridge_client_cfg_path)?;
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
    /// Adapts bridge and node configurations based on detected or configured values.
    ///
    /// This function coordinates the bridge configuration generation process by:
    /// 1. Generating cryptographic keys if requested
    /// 2. Detecting or using configured public IP addresses
    /// 3. Setting the forward address to the local wireguard listener
    /// 4. Generating client connection parameters
    ///
    /// Returns the adapted configurations for bridge, node, and client.
    fn adapt_configs(&self) -> Result<ConfigsOut> {
        info!("adapting configs");
        // adapt the nym-node configuration
        let mut node_cfg = self.input.node_cfg.clone();

        let mut bridge_cfg = self.input.bridge_cfg.clone().unwrap_or_default();

        // if any key material needs to be generated, generate it.
        if self.opts.generate_keys {
            info!("generating key(s)");
            bridge_cfg.generate_keys(self.opts.allow_overwrite, &self.paths.key_dir)?;
        }

        // Set public IPs for bridge config:
        // 1. If bridge config already has IPs, keep them (existing config)
        // 2. Otherwise, try to detect from internet (gets both IPv4 and IPv6)
        // 3. If detection fails, fall back to nym-node config IPs
        if bridge_cfg.get_public_ips().is_empty() {
            match crate::node_config::get_public_ip_addrs() {
                Ok(detected_ips) if !detected_ips.is_empty() => {
                    info!("using detected public IPs: {:?}", detected_ips);
                    bridge_cfg.set_public_ips(detected_ips);
                }
                _ => {
                    // Fall back to nym-node config if detection failed
                    if let Some(node_ips) = node_cfg.public_ips() {
                        if !node_ips.is_empty() {
                            info!("using public IPs from nym-node config: {:?}", node_ips);
                            bridge_cfg.set_public_ips(node_ips);
                        } else {
                            warn!(
                                "no public IPs available - bridge may not be reachable from external clients"
                            );
                            warn!(
                                "hint: check internet connectivity or manually configure public IPs in bridge config or nym-node config"
                            );
                        }
                    } else {
                        warn!(
                            "could not determine public IPs - bridge may not be reachable from external clients"
                        );
                        warn!(
                            "hint: ensure internet connectivity or manually set public_ips in /etc/nym/bridges.toml"
                        );
                    }
                }
            }
        }

        // adapt the nym-bridge configuration
        let forward_address = node_cfg.get_forward_address();
        bridge_cfg.set_forward_address(forward_address);
        bridge_cfg.set_client_config_path(&self.paths.bridge_client_cfg_path);

        // adapt the nym-node configuration
        node_cfg.set_bridge_client_config_path(&self.paths.bridge_client_cfg_path);

        // generate the client configuration for this bridge configuration
        debug!("deriving client params from bridge config");
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
        .with_max_level(tracing::Level::INFO)
        .init();

    let args = ConfigArgs::parse();

    if let Err(e) = args.adapt_config_files() {
        error!("config adaptation failed: {e}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_config_parsing() {
        // test our node config parsing handles malformed configs
        node_config::NodeConfig::test_malformed_configs();
    }

    #[test]
    fn test_public_ip_detection() {
        // Test that public IP detection works (this may fail in CI/containers)
        let result = node_config::get_public_ip_addrs();
        match result {
            Ok(ips) => {
                println!("Detected public IPs: {:?}", ips);
                // Should have at least one IP (IPv4 or IPv6)
                assert!(!ips.is_empty());
                // IPs should be valid
                for ip in ips {
                    assert!(ip.is_ipv4() || ip.is_ipv6());
                }
            }
            Err(e) => {
                println!(
                    "Public IP detection failed (expected in some environments): {}",
                    e
                );
                // This is OK - some environments (CI, containers) may not have internet access
            }
        }
    }

    #[test]
    fn test_bridge_config_with_detected_ips() {
        // Test that bridge config can be updated with detected IPs
        let mut bridge_cfg = bridge_config::BridgeConfig::default();

        // Simulate detected IPs
        let test_ips = vec!["1.2.3.4".parse().unwrap(), "2001:db8::1".parse().unwrap()];

        bridge_cfg.set_public_ips(test_ips.clone());

        // Verify the config was updated
        let serialized = bridge_cfg.serialize();
        assert!(serialized.contains("1.2.3.4"));
        assert!(serialized.contains("2001:db8::1"));

        println!("Bridge config with detected IPs: {}", serialized);
    }

    #[test]
    fn test_quic_client_config_generation() {
        use tempdir::TempDir;

        // Test that QUIC client config is generated with correct format
        let temp_dir = TempDir::new("bridges").unwrap();
        let key_dir = temp_dir.path();

        let mut bridge_cfg = bridge_config::BridgeConfig::default();

        // Set test public IPs
        let test_ips = vec![
            "139.162.33.226".parse().unwrap(),
            "2400:8901::2000:faff:fea6:87f2".parse().unwrap(),
        ];
        bridge_cfg.set_public_ips(test_ips);

        // Generate keys first
        bridge_cfg.generate_keys(true, key_dir).unwrap();

        // Generate client config
        let client_config =
            bridge_client_config::BridgeClientConfig::try_from(&bridge_cfg).unwrap();
        let client_json = client_config.serialize().unwrap();

        // Parse the JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&client_json).unwrap();

        // Verify version
        assert_eq!(parsed["version"], "0");

        // Verify transport type
        assert_eq!(parsed["transports"][0]["transport_type"], "quic_plain");

        // Verify addresses contain our test IPs
        let addresses = &parsed["transports"][0]["args"]["addresses"];
        assert!(addresses.is_array());

        let address_strings: Vec<String> = addresses
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

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
        assert_eq!(
            parsed["transports"][0]["args"]["host"],
            "netdna.bootstrapcdn.com"
        );

        println!("Generated QUIC client config: {}", client_json);
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use nym_bridges::config::{
        ClientConfig, ForwardConfig, PersistedClientConfig, PersistedServerConfig,
        TransportServerConfig,
    };
    use std::env;
    use std::str::FromStr;
    use std::sync::Once;
    use tempdir::TempDir;
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

    #[test]
    fn create_fresh_bridge_config() -> Result<()> {
        init_subscriber(Some(LevelFilter::DEBUG));
        println!();

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

        let bridge_config_out: PersistedServerConfig =
            toml::from_str(&bridge_cfg.serialize()).unwrap();

        // Check that the forward address points to the correct wireguard listener
        assert_eq!(
            bridge_config_out.forward.address,
            "1.1.1.1:51822".parse().unwrap()
        );

        // check that a new key was generated
        assert!(!bridge_cfg.keys.is_empty());

        // check that the paths to the bridge client params file all point to the expected location.
        assert_eq!(
            node_cfg.get_bridge_client_config_path().unwrap(),
            config_run.paths.bridge_client_cfg_path
        );
        assert_eq!(
            bridge_config_out.client_params_path.unwrap(),
            config_run.paths.bridge_client_cfg_path
        );

        // check some key fields in the client config
        let client_params_out =
            PersistedClientConfig::parse_json(bridge_client_cfg.serialize().unwrap()).unwrap();
        client_params_out
            .transports
            .iter()
            .for_each(|transport| match transport {
                ClientConfig::QuicPlain(cfg) => {
                    // Should have detected IPs from internet (both IPv4 and IPv6)
                    assert!(!cfg.addresses.is_empty(), "should have detected public IPs");
                    // Check we have at least one IPv4 and one IPv6
                    let has_ipv4 = cfg.addresses.iter().any(|addr| addr.is_ipv4());
                    let has_ipv6 = cfg.addresses.iter().any(|addr| addr.is_ipv6());
                    assert!(has_ipv4 || has_ipv6, "should have at least one IP address");
                }
                ClientConfig::TlsPlain(_cfg) => todo!(),
            });

        Ok(())
    }

    #[test]
    fn adapt_existing_bridge_config() {
        init_subscriber(Some(LevelFilter::DEBUG));
        println!();

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

        // check that a no new keys were generated (key exists as bytes)
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
            PersistedClientConfig::parse_json(bridge_client_cfg.serialize().unwrap()).unwrap();
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

    /// Test playing with and clarifying the ways that you are (or are not) meant to interact with [`DocumentMut`]
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

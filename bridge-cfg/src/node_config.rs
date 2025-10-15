//! Minimal Node Config adapter
//!
//! This module contains a subset of the configuration stored for use in running a Nym node. This
//! allows us to parse the config (which is not exposed as part of a public crate) for only the
//! relevant fields used when adapting the configuration for use in the `nym-bridge` service.
//!
//! [Original Config](https://github.com/nymtech/nym/blob/develop/nym-node/src/config/mod.rs)

#[cfg(test)]
use anyhow::anyhow;
use anyhow::{Context, Result};
use toml_edit::DocumentMut;
use tracing::*;

use std::{
    fs::File,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct NodeConfig {
    inner: NodeConfigInner,
}

#[derive(Clone, Debug)]
enum NodeConfigInner {
    /// This is meant to be used when a nym node configuration is available and can be used to
    /// get the few parameters that we need and also propagate the change to the nym node config
    /// for the path to the file containing client bridge params.
    File { inner: DocumentMut },

    /// If there is no nym-node config available this option makes it possible to still do the
    /// automatic setup for the nym bridge service.
    Default,
}

impl NodeConfig {
    fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        let inner = NodeConfigInner::File {
            inner: config_str
                .as_ref()
                .parse::<DocumentMut>()
                .context("failed to parse config")?,
        };
        Ok(Self { inner })
    }

    pub fn parse_from_file(path: &PathBuf) -> Result<Self> {
        let mut config_file = File::open(path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;

        Self::parse(config_str)
    }

    pub fn new_without_node() -> Self {
        Self {
            inner: NodeConfigInner::Default,
        }
    }

    pub fn get_forward_address(&self) -> SocketAddr {
        // Make sure that a public IP exists in the node config before constructing the local forward address
        let public_ips = self.public_ips();
        debug!("found public IPs: {public_ips:?}");
        let address = if let Some(ips) = public_ips {
            ips[0]
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let port = self.get_wireguard_port();
        SocketAddr::new(address, port)
    }

    pub fn public_ips(&self) -> Option<Vec<IpAddr>> {
        match &self.inner {
            NodeConfigInner::Default => match get_public_ip_addrs() {
                Ok(public_ips) => {
                    if public_ips.is_empty() {
                        warn!(
                            "no public IPs detected; check your internet connectivity or manually configure public_ips in nym-node config"
                        );
                        None
                    } else {
                        Some(public_ips)
                    }
                }
                Err(e) => {
                    error!("failed to get public IPs: {e}");
                    error!(
                        "hint: check internet connectivity or manually set 'host.public_ips' in your nym-node config at $HOME/.nym/nym-nodes/{{NODE_ID}}/config/config.toml"
                    );
                    None
                }
            },
            NodeConfigInner::File { inner } => {
                if let Some(host) = inner.get("host") {
                    host.get("public_ips")
                        .and_then(|v| v.as_array())
                        .map(|public_ips| {
                            public_ips
                                .iter()
                                .filter_map(|s| s.as_str().and_then(|s| s.parse::<IpAddr>().ok()))
                                .collect()
                        })
                } else {
                    None
                }
            }
        }
    }

    fn get_wireguard_port(&self) -> u16 {
        match &self.inner {
            NodeConfigInner::Default => 51822u16,
            NodeConfigInner::File { inner } => {
                if let Some(wireguard) = inner.get("wireguard") {
                    // Try announced_tunnel_port first (newer format)
                    if let Some(announced_tunnel_port) = wireguard.get("announced_tunnel_port") {
                        announced_tunnel_port.as_integer().unwrap_or(51822) as u16
                    }
                    // Fallback to announced_port (older format)
                    else if let Some(announced_port) = wireguard.get("announced_port") {
                        announced_port.as_integer().unwrap_or(51822) as u16
                    } else {
                        51822u16
                    }
                } else {
                    51822u16
                }
            }
        }
    }

    pub fn set_bridge_client_config_path(&mut self, path: &Path) {
        debug!("setting client_param_filepath for node config: {path:?}");
        match &mut self.inner {
            NodeConfigInner::Default => {}
            NodeConfigInner::File { inner } => {
                if !inner.contains_key("gateway_tasks") {
                    inner["gateway_tasks"] = toml_edit::table();
                }
                if let Some(gateway_tasks) = inner.get("gateway_tasks")
                    && let Some(gateway_tasks_table) = gateway_tasks.as_table()
                    && !gateway_tasks_table.contains_key("storage_paths")
                {
                    inner["gateway_tasks"]["storage_paths"] = toml_edit::table();
                }
                inner["gateway_tasks"]["storage_paths"]["bridge_client_params"] =
                    toml_edit::value(path.to_str().unwrap())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn get_bridge_client_config_path(&self) -> Result<PathBuf> {
        match &self.inner {
            NodeConfigInner::Default => Ok(PathBuf::new()),
            NodeConfigInner::File { inner } => {
                if let Some(gateway_tasks) = inner.get("gateway_tasks")
                    && let Some(storage_paths) = gateway_tasks.get("storage_paths")
                    && let Some(bridge_client_params) = storage_paths.get("bridge_client_params")
                    && let Some(path_str) = bridge_client_params.as_str()
                {
                    return path_str
                        .parse()
                        .context("bridge client params in node config improperly formatted");
                }
                Err(anyhow!("missing bridge client params entry"))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn test_malformed_configs() {
        use tempdir::TempDir;

        let temp_dir = TempDir::new("nym_bridge_test").unwrap();

        let config1 = r#"
[host]
public_ips = ["127.0.0.1"]
"#;
        let file1_path = temp_dir.path().join("config1.toml");
        std::fs::write(&file1_path, config1).unwrap();
        let node_config1 = NodeConfig::parse_from_file(&file1_path).unwrap();
        assert_eq!(node_config1.get_wireguard_port(), 51822);

        let config2 = r#"
[host]
public_ips = ["1.2.3.4"]

[wireguard]
enabled = true
bind_address = '[::]:51822'
announced_tunnel_port = 12345
announced_metadata_port = 51830
"#;
        let file2_path = temp_dir.path().join("config2.toml");
        std::fs::write(&file2_path, config2).unwrap();
        let node_config2 = NodeConfig::parse_from_file(&file2_path).unwrap();
        assert_eq!(node_config2.get_wireguard_port(), 12345);
        let ips = node_config2.public_ips();
        assert!(ips.is_some());
        assert!(ips.unwrap().contains(&"1.2.3.4".parse().unwrap()));

        let config3 = r#"
[host]
public_ips = ["127.0.0.1"]

[wireguard]
announced_port = 9999
"#;
        let file3_path = temp_dir.path().join("config3.toml");
        std::fs::write(&file3_path, config3).unwrap();
        let node_config3 = NodeConfig::parse_from_file(&file3_path).unwrap();
        assert_eq!(node_config3.get_wireguard_port(), 9999);

        let config4 = r#"
# Empty config
"#;
        let file4_path = temp_dir.path().join("config4.toml");
        std::fs::write(&file4_path, config4).unwrap();
        let node_config4 = NodeConfig::parse_from_file(&file4_path).unwrap();
        assert_eq!(node_config4.get_wireguard_port(), 51822);
        assert_eq!(node_config4.public_ips(), None);

        let config5 = r#"
[host]
public_ips = ["invalid-ip", "127.0.0.1", "1.2.3.4"]
"#;
        let file5_path = temp_dir.path().join("config5.toml");
        std::fs::write(&file5_path, config5).unwrap();
        let node_config5 = NodeConfig::parse_from_file(&file5_path).unwrap();
        let ips = node_config5.public_ips();
        assert!(ips.is_some());
        assert_eq!(ips.unwrap().len(), 2);

        let real_world_config = r#"
[host]
public_ips = [
'1.2.3.4',
]

[wireguard]
enabled = true
bind_address = '[::]:51822'
announced_tunnel_port = 51822
announced_metadata_port = 51830

[gateway_tasks.storage_paths]
clients_storage = '/root/.nym/nym-nodes/default-nym-node/data/clients.sqlite'
stats_storage = '/root/.nym/nym-nodes/default-nym-node/data/stats.sqlite'
cosmos_mnemonic = '/root/.nym/nym-nodes/default-nym-node/data/cosmos_mnemonic'
"#;
        let file6_path = temp_dir.path().join("config6.toml");
        std::fs::write(&file6_path, real_world_config).unwrap();
        let node_config6 = NodeConfig::parse_from_file(&file6_path).unwrap();
        assert_eq!(node_config6.get_wireguard_port(), 51822);
        let ips = node_config6.public_ips();
        assert!(ips.is_some());
        assert!(ips.unwrap().contains(&"1.2.3.4".parse().unwrap()));

        let integrated_config = r#"
[host]
public_ips = [
'1.2.3.4',
]

[wireguard]
enabled = true
bind_address = '0.0.0.0:51822'
announced_tunnel_port = 51822
announced_metadata_port = 51830

[gateway_tasks.storage_paths]
clients_storage = '/root/.nym/nym-nodes/default-nym-node/data/clients.sqlite'
stats_storage = '/root/.nym/nym-nodes/default-nym-node/data/stats.sqlite'
cosmos_mnemonic = '/root/.nym/nym-nodes/default-nym-node/data/cosmos_mnemonic'
bridge_client_params = '/etc/nym/client_bridge_params.json'
"#;
        let file7_path = temp_dir.path().join("config7.toml");
        std::fs::write(&file7_path, integrated_config).unwrap();
        let node_config7 = NodeConfig::parse_from_file(&file7_path).unwrap();
        assert_eq!(node_config7.get_wireguard_port(), 51822);
        let ips = node_config7.public_ips();
        assert!(ips.is_some());
        assert!(ips.unwrap().contains(&"1.2.3.4".parse().unwrap()));

        println!("All malformed config tests passed!");
    }

    pub fn serialize(&self) -> String {
        match &self.inner {
            NodeConfigInner::Default => String::new(),
            NodeConfigInner::File { inner } => inner.to_string(),
        }
    }

    pub fn serialize_to_file(&self, path: &PathBuf) -> Result<()> {
        if matches!(self.inner, NodeConfigInner::Default) {
            warn!("no nym-node config found, using default values for bridge configuration");
            return Ok(());
        }

        let mut out_file = std::fs::File::create(path)?;
        out_file
            .write_all(self.serialize().as_bytes())
            .context("failed to serialize bridge config to file")
    }

    pub fn print_diff(&self, other: &Self, path: &PathBuf) {
        if matches!(&self.inner, NodeConfigInner::Default)
            && matches!(&other.inner, NodeConfigInner::Default)
        {
            return;
        }

        let old = other.serialize();
        let new = self.serialize();
        let diff = similar::TextDiff::from_lines(&old, &new);

        println!(" > {path:?}:");
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                similar::ChangeTag::Delete => "-",
                similar::ChangeTag::Insert => "+",
                similar::ChangeTag::Equal => " ",
            };

            print!("{sign} {change}");
        }
    }
}

/// Detects public IP addresses by querying external services.
///
/// This function attempts to detect both IPv4 and IPv6 addresses for the current host
/// by making HTTP requests to ipify.org services. IPv4 detection failure is treated as
/// an error, while IPv6 detection failure is expected in many environments and logged
/// as a debug message.
///
/// Returns a Vec of detected IP addresses (may contain 0, 1, or 2 addresses).
pub fn get_public_ip_addrs() -> Result<Vec<IpAddr>> {
    info!("attempting to fetch public IPs from api.ipify.org");
    let mut ips = Vec::new();

    // URLs for IPv4 and IPv6 services
    let ipv4_url = "https://api.ipify.org?format=json";
    let ipv6_url = "https://api6.ipify.org?format=json";

    // Fetch IPv4 address
    match reqwest::blocking::get(ipv4_url).and_then(|r| r.json::<serde_json::Value>()) {
        Ok(ipv4_response) => {
            if let Some(ipv4) = ipv4_response.get("ip") {
                if let Some(ipv4_str) = ipv4.as_str() {
                    match ipv4_str.parse::<IpAddr>() {
                        Ok(addr) => {
                            debug!("detected public IPv4: {}", addr);
                            ips.push(addr);
                        }
                        Err(e) => warn!("failed to parse IPv4 address '{}': {}", ipv4_str, e),
                    }
                }
            } else {
                warn!("no IPv4 address in response");
            }
        }
        Err(e) => warn!("failed to fetch IPv4 address: {}", e),
    }

    // Fetch IPv6 address (non-fatal if it fails)
    match reqwest::blocking::get(ipv6_url).and_then(|r| r.json::<serde_json::Value>()) {
        Ok(ipv6_response) => {
            if let Some(ipv6) = ipv6_response.get("ip") {
                if let Some(ipv6_str) = ipv6.as_str() {
                    match ipv6_str.parse::<IpAddr>() {
                        Ok(addr) => {
                            debug!("detected public IPv6: {}", addr);
                            ips.push(addr);
                        }
                        Err(e) => warn!("failed to parse IPv6 address '{}': {}", ipv6_str, e),
                    }
                }
            } else {
                debug!("no IPv6 address in response");
            }
        }
        Err(e) => debug!(
            "failed to fetch IPv6 address (this is normal if IPv6 is not available): {}",
            e
        ),
    }

    Ok(ips)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;

    #[test]
    fn parse_test_node_config() {
        let filepath = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("config.toml");

        assert!(filepath.exists(), "Test config file should exist");

        let node_config = NodeConfig::parse_from_file(&filepath).unwrap();
        assert!(
            node_config
                .public_ips()
                .expect("failed to parse IPs")
                .contains(&"1.1.1.1".parse().unwrap())
        );
        assert!(
            node_config
                .public_ips()
                .expect("failed to parse IPs")
                .contains(&"2a01::1".parse().unwrap())
        );

        assert_eq!(node_config.get_wireguard_port(), 51822);
    }

    #[test]
    fn test_malformed_configs() {
        NodeConfig::test_malformed_configs();
    }

    #[test]
    fn test_default_config() {
        let config = NodeConfig::new_without_node();
        assert_eq!(config.get_wireguard_port(), 51822);
        // public_ips() might return None or Some depending on network
        let _ = config.public_ips();
    }

    #[test]
    fn test_integrated_config_parsing() {
        use tempdir::TempDir;

        let temp_dir = TempDir::new("nym_bridge_integrated_test").unwrap();

        // Test config that already has bridge integration
        let integrated_config = r#"
[host]
public_ips = ['1.2.3.4']

[wireguard]
enabled = true
announced_tunnel_port = 51822

[gateway_tasks.storage_paths]
bridge_client_params = '/etc/nym/client_bridge_params.json'
"#;
        let file_path = temp_dir.path().join("integrated_config.toml");
        std::fs::write(&file_path, integrated_config).unwrap();

        let node_config = NodeConfig::parse_from_file(&file_path).unwrap();

        // Test that we can read the bridge client config path
        let bridge_path = node_config.get_bridge_client_config_path().unwrap();
        assert_eq!(
            bridge_path,
            std::path::PathBuf::from("/etc/nym/client_bridge_params.json")
        );

        // Test other functions work
        assert_eq!(node_config.get_wireguard_port(), 51822);
        let ips = node_config.public_ips();
        assert!(ips.is_some());
        assert!(ips.unwrap().contains(&"1.2.3.4".parse().unwrap()));

        println!("Integrated config parsing test passed!");
    }
}

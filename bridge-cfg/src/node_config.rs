//! Minimal Node Config adapter
//!
//! This module contains a subset of the configuration stored for use in running a Nym node. This
//! allows us to parse the config (which is not exposed as part of a public crate) for only the
//! relevant fields used when adapting the configuration for use in the `nym-bridge` service.
//!
//! [Original Config](https://github.com/nymtech/nym/blob/develop/nym-node/src/config/mod.rs)

use anyhow::{Context, Result, anyhow};
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

    fn public_ips(&self) -> Option<Vec<IpAddr>> {
        match &self.inner {
            NodeConfigInner::Default => match get_public_ip_addrs() {
                Ok(public_ips) => {
                    if public_ips.is_empty() {
                        None
                    } else {
                        Some(public_ips)
                    }
                }
                Err(e) => {
                    error!("failed to get public IPs: {e}");
                    None
                }
            },
            NodeConfigInner::File { inner } => {
                let public_ips = inner["host"]["public_ips"].as_array()?;
                public_ips
                    .iter()
                    .map(|s| s.as_str().unwrap().parse::<IpAddr>().ok())
                    .filter(Option::is_some)
                    .collect()
            }
        }
    }

    fn get_wireguard_port(&self) -> u16 {
        match &self.inner {
            NodeConfigInner::Default => 51822u16,
            NodeConfigInner::File { inner } => inner["wireguard"]["announced_port"]
                .as_integer()
                .unwrap_or(51822) as u16,
        }
    }

    pub fn set_bridge_client_config_path(&mut self, path: &Path) {
        debug!("setting client_param_filepath for node config: {path:?}");
        match &mut self.inner {
            NodeConfigInner::Default => {}
            NodeConfigInner::File { inner } => {
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
                inner["gateway_tasks"]["storage_paths"]["bridge_client_params"]
                    .as_str()
                    .ok_or(anyhow!("missing bridge client params entry"))?
                    .parse()
                    .context("bridge client params in node config improperly formatted")
            }
        }
    }

    pub fn serialize(&self) -> String {
        match &self.inner {
            NodeConfigInner::Default => String::new(),
            NodeConfigInner::File { inner } => inner.to_string(),
        }
    }

    pub fn serialize_to_file(&self, path: &PathBuf) -> Result<()> {
        if matches!(self.inner, NodeConfigInner::Default) {
            error!("attempted tp serialize \"Default\" node config to file");
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

fn get_public_ip_addrs() -> Result<Vec<IpAddr>> {
    info!("attempting to fetch public IPs from api.ipify.org");
    let mut ips = Vec::new();

    // URLs for IPv4 and IPv6 services
    let ipv4_url = "https://api.ipify.org?format=json";
    let ipv6_url = "https://api6.ipify.org?format=json";

    // Fetch IPv4 address
    let ipv4_response: serde_json::Value = reqwest::blocking::get(ipv4_url)?.json()?;
    if let Some(ipv4) = ipv4_response.get("ip") {
        debug!("Public IPv4 Address: {}", ipv4);
        ips.push(
            ipv4.as_str()
                .ok_or(anyhow!("failed to parse ipv4 addr"))?
                .parse()?,
        )
    } else {
        warn!("Could not retrieve IPv4 address");
    }

    // Fetch IPv6 address
    let ipv6_response: serde_json::Value = reqwest::blocking::get(ipv6_url)?.json()?;
    if let Some(ipv6) = ipv6_response.get("ip") {
        debug!("Public IPv6 Address: {}", ipv6);
        ips.push(
            ipv6.as_str()
                .ok_or(anyhow!("failed to parse ipv6 addr"))?
                .parse()?,
        )
    } else {
        debug!("Could not retrieve IPv6 address");
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
}

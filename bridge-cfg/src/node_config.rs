//! Minimal Node Config adapter
//!
//! This module contains a subset of the configuration stored for use in running a Nym node. This
//! allows us to parse the config (which is not exposed as part of a public crate) for only the
//! relevant fields used when adapting the configuration for use in the `nym-bridge` service.
//!
//! [Original Config](https://github.com/nymtech/nym/blob/develop/nym-node/src/config/mod.rs)

use anyhow::{Context, Result};
use toml_edit::DocumentMut;

use std::{
    fs::File,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct NodeConfig {
    inner: DocumentMut,
}

impl NodeConfig {
    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            inner: config_str
                .as_ref()
                .parse::<DocumentMut>()
                .context("failed to parse config")?,
        })
    }

    pub fn parse_from_file(path: &PathBuf) -> Result<Self> {
        let mut config_file = File::open(path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;
        Self::parse(config_str)
    }

    pub fn get_forward_address(&self) -> SocketAddr {
        // Make sure that a public IP exists in the node config before constructing the local forward address
        let public_ips = self.public_ips();
        let address = if let Some(ips) = public_ips {
            ips[0]
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let port = self.inner["wireguard"]["announced_port"]
            .as_integer()
            .unwrap_or(51822) as u16;
        SocketAddr::new(address, port)
    }

    fn public_ips(&self) -> Option<Vec<IpAddr>> {
        let public_ips = self.inner["host"]["public_ips"].as_array()?;
        public_ips
            .iter()
            .map(|s| s.as_str().unwrap().parse::<IpAddr>().ok())
            .filter(Option::is_some)
            .collect()
    }

    pub fn set_bridge_client_config_path(&mut self, path: &Path) {
        self.inner["gateway_tasks"]["storage_paths"]["bridge_client_params"] =
            toml_edit::value(path.to_str().unwrap());
    }

    pub fn serialize(&self) -> String {
        self.inner.to_string()
    }

    pub fn serialize_to_file(&self, path: &PathBuf) -> Result<()> {
        let mut out_file = std::fs::File::create(path)?;
        out_file
            .write_all(self.serialize().as_bytes())
            .context("failed to serialize bridge config to file")
    }

    pub fn print_diff(&self, other: &Self, path: &PathBuf) {
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

        assert!(node_config.inner["wireguard"]["enabled"].as_bool().unwrap());
        assert_eq!(
            node_config.inner["wireguard"]["announced_port"]
                .as_integer()
                .unwrap(),
            51822
        );
        assert_eq!(
            node_config.inner["wireguard"]["bind_address"]
                .as_str()
                .unwrap(),
            "0.0.0.0:51822",
        );
    }
}

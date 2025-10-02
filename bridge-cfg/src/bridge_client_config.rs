use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use nym_bridges::config::{self, PersistedClientConfig, PersistedServerConfig};

use crate::bridge_config::BridgeConfig;

#[derive(Debug, Clone)]
pub(crate) struct BridgeClientConfig {
    inner: config::PersistedClientConfig,
}

impl BridgeClientConfig {
    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            // TODO: this will try to pare toml, not json
            inner: PersistedClientConfig::parse(config_str)?,
        })
    }

    pub fn parse_from_file(path: &PathBuf) -> Result<Self> {
        let mut config_file = File::open(path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;
        Self::parse(config_str)
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(&self.inner).context("bridge client config failed to serialize")
    }

    pub fn serialize_to_file(&self, path: PathBuf) -> Result<()> {
        let mut out_file = std::fs::File::create(path)?;
        out_file
            .write_all(self.serialize()?.as_bytes())
            .context("failed to serialize bridge config to file")
    }

    pub fn print_diff(&self, other: Option<&Self>, path: PathBuf) {
        let old = other
            .and_then(|s| Self::serialize(s).ok())
            .unwrap_or_default();
        let new = self.serialize().unwrap();
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

impl TryFrom<&BridgeConfig> for BridgeClientConfig {
    type Error = anyhow::Error;

    fn try_from(value: &BridgeConfig) -> Result<Self> {
        let cfg_str = value.serialize();
        let bridge_cfg = PersistedServerConfig::parse(cfg_str).unwrap();
        let client_cfg = PersistedClientConfig::try_from(&bridge_cfg)?;
        Ok(Self { inner: client_cfg })
    }
}

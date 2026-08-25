use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use nym_bridges::config::{
    self, PersistedClientConfig, PersistedServerConfig, TransportServerConfig,
    parse_persisted_config_json,
};
use nym_bridges::transport::GeneratedKeyMaterial;
use nym_bridges::types::Sufficiency;

use crate::bridge_config::BridgeConfig;

#[derive(Debug, Clone)]
pub(crate) struct BridgeClientConfig {
    inner: config::PersistedClientConfig,
}

impl BridgeClientConfig {
    /// Parses `config_str` as JSON -- matching [`Self::serialize`], which always writes JSON
    /// (client params are never persisted as TOML, unlike the bridge/node configs).
    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            inner: parse_persisted_config_json(config_str)
                .context("failed to parse client params json")?,
        })
    }

    pub fn parse_from_file(path: &PathBuf) -> Result<Self> {
        let mut config_file = File::open(path)
            .with_context(|| format!("failed to open client params at {path:?}"))?;
        let mut config_str = String::new();
        config_file
            .read_to_string(&mut config_str)
            .with_context(|| format!("failed to read client params at {path:?}"))?;
        Self::parse(config_str)
            .with_context(|| format!("failed to parse client params at {path:?}"))
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
        let tmp = tempdir::TempDir::new("tmp")?;

        let cfg_str = value.serialize();
        let mut bridge_cfg = PersistedServerConfig::parse(cfg_str).unwrap();

        if !value.keys.is_empty() {
            value.persist_keys(tmp.path())?;
            for transport in &mut bridge_cfg.transports {
                let file = match transport {
                    TransportServerConfig::QuicPlain(cfg) => {
                        &mut cfg.private_ed25519_identity_key_file
                    }
                    TransportServerConfig::TlsPlain(cfg) => {
                        &mut cfg.private_ed25519_identity_key_file
                    }
                    TransportServerConfig::SshPlain(cfg) => {
                        &mut cfg.private_ed25519_identity_key_file
                    }
                };
                redirect_generated_key(file, tmp.path(), &value.keys);
            }
        }

        for transport in &bridge_cfg.transports {
            if !transport.is_sufficient() {
                bail!(
                    "the {} transport has no key material configured -- re-run with `--gen` to \
                     generate it, or set `identity_key`/`private_ed25519_identity_key_file` \
                     (and, for ssh_plain, `client_auth_key`) directly in the bridge config",
                    transport_kind(transport)
                );
            }
        }

        let client_cfg = PersistedClientConfig::try_from(&bridge_cfg)?;
        Ok(Self { inner: client_cfg })
    }
}

fn transport_kind(transport: &TransportServerConfig) -> &'static str {
    match transport {
        TransportServerConfig::QuicPlain(_) => "quic_plain",
        TransportServerConfig::TlsPlain(_) => "tls_plain",
        TransportServerConfig::SshPlain(_) => "ssh_plain",
    }
}

/// If `file` points at one of the keys `generate_keys` just generated (matched by filename --
/// the real, final destination may not exist on disk yet, e.g. under `--dry-run`), redirect it to
/// wherever that key's bytes were actually staged (`tmp`) so `get_id_pubkey()` can read real
/// bytes from it. Left untouched if `file` doesn't match any freshly generated key -- e.g. it
/// already points at a real, pre-existing key file (the nym-node's own key, say).
fn redirect_generated_key(file: &mut Option<PathBuf>, tmp: &Path, keys: &[GeneratedKeyMaterial]) {
    let Some(name) = file.as_ref().and_then(|p| p.file_name()) else {
        return;
    };
    if keys.iter().any(|k| k.path.file_name() == Some(name)) {
        *file = Some(tmp.join(name));
    }
}

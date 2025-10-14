use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::transport::{quic, tls};

// ====================================[ Server Side ]====================================

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct ForwardConfig {
    /// Target address where client traffic will be forwarded.
    pub address: SocketAddr,
}

/// Configuration parameters by transport type.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(tag = "transport_type", content = "args")]
#[serde(rename_all = "snake_case")]
pub enum TransportServerConfig {
    QuicPlain(quic::ServerConfig),
    TlsPlain(tls::ServerConfig),
}

impl From<quic::ServerConfig> for TransportServerConfig {
    fn from(value: quic::ServerConfig) -> Self {
        TransportServerConfig::QuicPlain(value)
    }
}

impl From<tls::ServerConfig> for TransportServerConfig {
    fn from(value: tls::ServerConfig) -> Self {
        TransportServerConfig::TlsPlain(value)
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct PersistedServerConfig {
    /// Configuration responsible for handling client traffic forwarding to the listening nym-node.
    pub forward: ForwardConfig,

    /// Path to file containing client parameters associated with current config.
    /// As this is optional if no path is provided, no client params will be written.
    /// Similarly the client parameters will only be written if this persisted config
    /// is written (i.e. using the `bridge-cfg`` tool).
    pub client_params_path: Option<std::path::PathBuf>,

    /// Set of public IPs that address the listening host (usually and Ipv4 and IPv6 pair)
    pub public_ips: Vec<String>,

    /// Set of specifications for launching transport listeners.
    pub transports: Vec<TransportServerConfig>,
}

#[allow(unused)]
impl PersistedServerConfig {
    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        toml::from_str(config_str.as_ref()).context("failed to parse config")
    }

    pub fn parse_file(config_path: &PathBuf) -> Result<Self> {
        let mut config_file = fs::File::open(config_path)?;
        let mut config = vec![];
        config_file.read_to_end(&mut config)?;
        toml::from_slice(&config).context("failed to parse config")
    }
}

// ====================================[ Client Side ]====================================

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(tag = "transport_type", content = "args")]
#[serde(rename_all = "snake_case")]
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

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct PersistedClientConfig {
    pub version: String,
    pub transports: Vec<ClientConfig>,
}

#[allow(unused)]
impl PersistedClientConfig {
    pub fn parse_json(config_str: impl AsRef<str>) -> Result<Self> {
        serde_json::from_str(config_str.as_ref()).context("failed to parse config")
    }

    pub fn parse_json_file(config_path: PathBuf) -> Result<Self> {
        let mut config_file = fs::File::open(config_path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;
        Self::parse_json(config_str)
    }

    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        toml::from_str(config_str.as_ref()).context("failed to parse config")
    }

    pub fn parse_file(config_path: PathBuf) -> Result<Self> {
        let mut config_file = fs::File::open(config_path)?;
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str)?;
        Self::parse(config_str)
    }
}

impl TryFrom<&PersistedServerConfig> for PersistedClientConfig {
    type Error = anyhow::Error;
    fn try_from(value: &PersistedServerConfig) -> Result<Self> {
        let ips: Vec<IpAddr> = value
            .public_ips
            .iter()
            .map(|ip_str| {
                ip_str
                    .parse()
                    .expect("failed to parse public IP '{ip_str}' as IpAddr")
            })
            .collect();

        let mut transports = vec![];
        for transport in &value.transports {
            match transport {
                TransportServerConfig::QuicPlain(cfg) => {
                    let port = cfg.listen.port();
                    let addresses = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
                    let id_pubkey = cfg.get_id_pubkey()?.to_string();
                    transports.push(ClientConfig::QuicPlain(quic::ClientOptions {
                        addresses,
                        host: Some("netdna.bootstrapcdn.com".to_string()),
                        id_pubkey,
                    }));
                }
                TransportServerConfig::TlsPlain(cfg) => {
                    let port = cfg.listen.port();
                    let addresses = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
                    let id_pubkey = cfg.get_id_pubkey()?.to_string();
                    transports.push(ClientConfig::TlsPlain(tls::ClientOptions {
                        addresses,
                        host: Some("netdna.bootstrapcdn.com".to_string()),
                        id_pubkey,
                    }));
                }
            }
        }
        Ok(Self {
            version: "0".into(),
            transports,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn serialize_and_deserialize_server_config() -> Result<()> {
        let quic_cfg1 = quic::ServerConfig {
            listen: "[::1]:4433".parse().unwrap(),
            stateless_retry: Default::default(),
            block: Default::default(),
            connection_limit: Default::default(),
            identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
            private_ed25519_identity_key_file: None,
        };
        let tls_cfg1 = tls::ServerConfig {
            listen: "[::1]:4443".parse().unwrap(),
            connection_limit: Default::default(),
            identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
            private_ed25519_identity_key_file: None,
        };

        let cfg = PersistedServerConfig {
            forward: ForwardConfig {
                address: "[::1]:50001".parse().unwrap(),
            },
            client_params_path: None,
            public_ips: vec!["192.168.0.1".into(), "fe80::1".into()],
            transports: vec![quic_cfg1.into(), tls_cfg1.into()],
        };

        let example_server_config = r#"
public_ips = ["192.168.0.1", "fe80::1"]

[forward]
address = "[::1]:50001"

[[transports]]
transport_type = "quic_plain"

[transports.args]
stateless_retry = false
listen = "[::1]:4433"
identity_key = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk="

[[transports]]
transport_type = "tls_plain"

[transports.args]
listen = "[::1]:4443"
identity_key = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk="
"#;

        let parsed_cfg = PersistedServerConfig::parse(example_server_config)?;

        assert_eq!(cfg, parsed_cfg);

        Ok(())
    }

    #[test]
    fn serialize_and_deserialize_client_config() -> Result<()> {
        let quic_cfg1 = quic::ClientOptions {
            addresses: vec!["192.168.100.3:443".parse().unwrap()],
            host: None,
            id_pubkey: "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=".into(),
        };
        let tls_cfg1 = tls::ClientOptions {
            addresses: vec!["123.45.67.89:443".parse().unwrap()],
            host: Some("alt.domain.com".into()),
            id_pubkey: "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=".into(),
        };

        let cfg = PersistedClientConfig {
            version: "v0.0.0".into(),
            transports: vec![quic_cfg1.into(), tls_cfg1.into()],
        };

        let serialized_cfg = toml::to_string(&cfg)?;

        let parsed_cfg = PersistedClientConfig::parse(serialized_cfg)?;

        assert_eq!(cfg, parsed_cfg);
        Ok(())
    }

    #[test]
    fn conversion() -> Result<()> {
        let quic_cfg1 = quic::ServerConfig {
            listen: "[::1]:4433".parse().unwrap(),
            stateless_retry: Default::default(),
            block: Default::default(),
            connection_limit: Default::default(),
            identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
            private_ed25519_identity_key_file: None,
        };
        let tls_cfg1 = tls::ServerConfig {
            listen: "[::1]:4443".parse().unwrap(),
            connection_limit: Default::default(),
            identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
            private_ed25519_identity_key_file: None,
        };

        let cfg = PersistedServerConfig {
            forward: ForwardConfig {
                address: "[::1]:50001".parse().unwrap(),
            },
            client_params_path: None,
            public_ips: vec!["192.168.0.1".into(), "fe80::1".into()],
            transports: vec![quic_cfg1.into(), tls_cfg1.into()],
        };

        let client_config = PersistedClientConfig::try_from(&cfg)?;

        let expected_quic = quic::ClientOptions {
            addresses: vec![
                "192.168.0.1:4433".parse().unwrap(),
                "[fe80::1]:4433".parse().unwrap(),
            ],
            host: Some("netdna.bootstrapcdn.com".to_string()),
            id_pubkey: "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=".into(),
        };
        let expected_tls = tls::ClientOptions {
            addresses: vec![
                "192.168.0.1:4443".parse().unwrap(),
                "[fe80::1]:4443".parse().unwrap(),
            ],
            host: Some("netdna.bootstrapcdn.com".to_string()),
            id_pubkey: "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=".into(),
        };

        for transport in client_config.transports {
            match transport {
                ClientConfig::QuicPlain(cc) => assert_eq!(cc, expected_quic),
                ClientConfig::TlsPlain(cc) => assert_eq!(cc, expected_tls),
            }
        }
        Ok(())
    }
}

use super::*;
use nym_bridges::config::{
    ClientConfig, ForwardConfig, PersistedServerConfig, TransportServerConfig,
    parse_persisted_config_json,
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

    let bridge_config_out: PersistedServerConfig = toml::from_str(&bridge_cfg.serialize()).unwrap();

    // Check that the forward address points to the correct wireguard listener
    assert_eq!(
        bridge_config_out.forward.address,
        "1.1.1.1:51822".parse().unwrap()
    );

    // check that a new key was generated for each of the three default transports
    assert_eq!(bridge_cfg.keys.len(), 3);

    // check that the paths to the bridge client params file all point to the expected location.
    assert_eq!(
        node_cfg.get_bridge_client_config_path().unwrap(),
        config_run.paths.bridge_client_cfg_path
    );
    assert_eq!(
        bridge_config_out.client_params_path.unwrap(),
        config_run.paths.bridge_client_cfg_path
    );

    // check some key fields in the client config -- the default template now configures
    // quic_plain, tls_plain, and ssh_plain, so all three should come back sufficient.
    use nym_bridges::types::Sufficiency;
    let client_params_out =
        parse_persisted_config_json(bridge_client_cfg.serialize().unwrap()).unwrap();
    assert_eq!(client_params_out.transports.len(), 3);
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
            ClientConfig::TlsPlain(_) | ClientConfig::SshPlain(_) => {
                assert!(
                    transport.is_sufficient(),
                    "{transport:?} should be sufficient"
                );
            }
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

    let test_identity_priv = "fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=";
    let test_identity_pub = "gyKl6DN9hgdPGhEzdf9gY4Ha2GzrOwSzLCguxeTVTJU=";
    let quic_config = nym_bridges::transport::quic::ServerConfig {
        // private_ed25519_identity_key_file: Some(PathBuf::from(preexisting_quic_key_path)),
        identity_key: Some(test_identity_priv.into()),
        listen: "[::]:443".parse().unwrap(),
        connection_limit: Some(10_000),
        ..Default::default()
    };
    let tls_config = nym_bridges::transport::tls::ServerConfig {
        identity_key: Some(test_identity_priv.into()),
        listen: "[::]:8443".parse().unwrap(),
        connection_limit: Some(10_000),
        ..Default::default()
    };
    let ssh_config = nym_bridges::transport::ssh::ServerConfig {
        identity_key: Some(test_identity_priv.into()),
        listen: "[::]:8422".parse().unwrap(),
        connection_limit: Some(10_000),
        expected_username: Some("bridge-client".into()),
        client_auth_key: Some(test_identity_priv.into()),
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
            TransportServerConfig::TlsPlain(tls_config),
            TransportServerConfig::SshPlain(ssh_config),
        ],
    };
    let out_str = toml::to_string(&bridge_config).unwrap();
    let bridge_config = BridgeConfig::parse(out_str).expect("failed to parse bridge configuration");

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

    let bridge_config_out: PersistedServerConfig = toml::from_str(&bridge_cfg.serialize()).unwrap();

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
            TransportServerConfig::TlsPlain(cfg) => {
                assert_eq!(cfg.identity_key, Some(test_identity_priv.into()));
                assert_eq!(cfg.listen, "[::]:8443".parse().unwrap());
                assert_eq!(cfg.connection_limit, Some(10_000));
            }
            TransportServerConfig::SshPlain(cfg) => {
                assert_eq!(cfg.identity_key, Some(test_identity_priv.into()));
                assert_eq!(cfg.listen, "[::]:8422".parse().unwrap());
                assert_eq!(cfg.connection_limit, Some(10_000));
            }
        });

    let client_params_out =
        parse_persisted_config_json(bridge_client_cfg.serialize().unwrap()).unwrap();
    client_params_out
        .transports
        .iter()
        .for_each(|transport| match transport {
            ClientConfig::QuicPlain(cfg) => {
                assert_eq!(cfg.id_pubkey, test_identity_pub);
                assert!(cfg.addresses.contains(&"[fe80::1]:443".parse().unwrap()));
                assert!(cfg.addresses.contains(&"192.168.0.1:443".parse().unwrap()));
            }
            ClientConfig::TlsPlain(cfg) => {
                assert_eq!(cfg.id_pubkey, test_identity_pub);
                assert!(cfg.addresses.contains(&"[fe80::1]:8443".parse().unwrap()));
                assert!(cfg.addresses.contains(&"192.168.0.1:8443".parse().unwrap()));
            }
            ClientConfig::SshPlain(cfg) => {
                assert_eq!(cfg.id_pubkey, test_identity_pub);
                assert!(cfg.addresses.contains(&"[fe80::1]:8422".parse().unwrap()));
                assert!(cfg.addresses.contains(&"192.168.0.1:8422".parse().unwrap()));
                assert_eq!(cfg.username, Some("bridge-client".into()));
            }
        });
}

/// `TlsPlain`/`SshPlain` transports used to make `BridgeClientConfig::try_from` panic
/// (`todo!()`) whenever key generation ran, since only `QuicPlain` was handled. Confirm the
/// full `--gen` pipeline now runs cleanly for all three transport kinds, generating
/// independent key material for each and producing a sufficient client config for each.
#[test]
fn adapt_config_generates_keys_for_every_transport_kind() {
    use nym_bridges::types::Sufficiency;

    init_subscriber(Some(LevelFilter::DEBUG));
    println!();

    let node_cfg_filepath = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test")
        .join("config.toml");
    let node_config = NodeConfig::parse_from_file(&node_cfg_filepath).unwrap();

    let bridge_config = PersistedServerConfig {
        public_ips: vec!["192.168.0.1".into(), "fe80::1".into()],
        forward: ForwardConfig {
            address: "[::1]:5000".parse().unwrap(),
        },
        client_params_path: None,
        transports: vec![
            TransportServerConfig::QuicPlain(nym_bridges::transport::quic::ServerConfig {
                listen: "[::]:443".parse().unwrap(),
                ..Default::default()
            }),
            TransportServerConfig::TlsPlain(nym_bridges::transport::tls::ServerConfig {
                listen: "[::]:444".parse().unwrap(),
                ..Default::default()
            }),
            TransportServerConfig::SshPlain(nym_bridges::transport::ssh::ServerConfig {
                listen: "[::]:445".parse().unwrap(),
                ..Default::default()
            }),
        ],
    };
    let out_str = toml::to_string(&bridge_config).unwrap();
    let bridge_config = BridgeConfig::parse(out_str).expect("failed to parse bridge configuration");

    let tmp_dir = TempDir::new("bridges").unwrap();
    let config_run = ConfigRun {
        opts: RunOptions {
            generate_keys: true,
            allow_overwrite: false,
        },
        paths: PathInfo {
            node_cfg_path: node_cfg_filepath,
            key_dir: tmp_dir.path().to_path_buf(),
            ..Default::default()
        },
        input: ConfigsIn {
            bridge_cfg: Some(bridge_config),
            node_cfg: node_config,
            bridge_client_cfg: None,
        },
    };

    let ConfigsOut {
        bridge_cfg,
        bridge_client_cfg,
        ..
    } = config_run
        .adapt_configs()
        .expect("error occurred while adapting configs");

    // all three transports needed generation, and each should get its own key.
    assert_eq!(bridge_cfg.keys.len(), 3);

    let bridge_config_out: PersistedServerConfig = toml::from_str(&bridge_cfg.serialize()).unwrap();
    for transport in &bridge_config_out.transports {
        assert!(
            transport.is_sufficient(),
            "generated {transport:?} should be sufficient"
        );
    }

    let client_params_out =
        parse_persisted_config_json(bridge_client_cfg.serialize().unwrap()).unwrap();
    assert_eq!(client_params_out.transports.len(), 3);
    for transport in &client_params_out.transports {
        assert!(
            transport.is_sufficient(),
            "derived client config {transport:?} should be sufficient"
        );
    }
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
    let bridge_config = BridgeConfig::parse(out_str).expect("failed to parse bridge configuration");

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

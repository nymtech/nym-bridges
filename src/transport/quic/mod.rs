#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, RawFd};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::crypto::rustls::QuicServerConfig;
use quinn_proto::{IdleTimeout, TransportConfig, congestion};
use serde::{Deserialize, Serialize};
use tracing::*;

use crate::connection::make_socket;
use crate::error::TransportError;
use crate::transport::tls::certs::{IdentityBasedVerifier, ServerConfigSource};

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const DEFAULT_SOCK_ADDR: &str = "[::]:4443";

/// Session Keepalive interval to prevent sessions from closing due to lull in user traffic.
///
/// ```txt
/// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
///
/// ... Only one side of any given connection needs keep-alive enabled for the connection to
/// be preserved. Must be set lower than the idle_timeout of both peers to be effective.
/// ```
/// Default idle timeout is 30s. Our clients set to 60s  using [`QUIC_SESSION_IDLE_TIMEOUT`] to be
/// safe.
const QUIC_SESSION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

lazy_static::lazy_static! {
    /// Session Idle Timeout Interval -- if nothing is sent within this interval then the session
    /// will proceed with a healthy close. This is intentionally set higher than the
    /// [`QUIC_SESSION_KEEPALIVE_INTERVAL`] as we do not want a low period in traffic to result
    /// in a tunnel closing.
    static ref QUIC_SESSION_IDLE_TIMEOUT: IdleTimeout = IdleTimeout::from(quinn::VarInt::from_u32(60_000));
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// Enable stateless retries
    pub stateless_retry: bool,
    /// Address to listen on
    pub listen: SocketAddr,
    /// Client address to block
    pub block: Option<SocketAddr>,
    /// Maximum number of concurrent connections to allow
    pub connection_limit: Option<usize>,

    /// Base64 encoded Identity Key, for use in ED25519 based self signed certs
    pub identity_key: Option<String>,

    /// Path to file containing PKCS8 PEM ed25519 identity private key, for use in ED25519 based self signed certs
    pub private_ed25519_identity_key_file: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_SOCK_ADDR.parse().unwrap(),
            connection_limit: Default::default(),
            block: Default::default(),
            stateless_retry: false,
            identity_key: Default::default(),
            private_ed25519_identity_key_file: Default::default(),
        }
    }
}

impl ServerConfig {
    fn get_crypto_source(&self) -> Result<ServerConfigSource> {
        // parse either key or file
        if let Some(ref base64_key) = self.identity_key {
            ServerConfigSource::from_identity_base64(base64_key)
        } else if let Some(ref key_path) = self.private_ed25519_identity_key_file {
            ServerConfigSource::from_pkcs8_pem_file(key_path)
        } else {
            Err(anyhow!("no crypto source provided"))
        }
    }

    fn build_server_config(&self) -> Result<rustls::ServerConfig> {
        self.get_crypto_source()?.into_server_config()
    }

    pub fn get_id_pubkey(&self) -> Result<String> {
        let crypto_source = self.get_crypto_source()?;

        let public_id = crypto_source.public_identity();
        Ok(BASE64_STANDARD.encode(&public_id[..]))
    }
}

pub fn create_endpoint(options: &ServerConfig) -> Result<quinn::Endpoint> {
    let mut server_crypto = options.build_server_config()?;

    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    quinn::Endpoint::server(server_config, options.listen).context("failed to create QUIC endpoint")
}

// ====================================[ Client Side ]====================================

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ClientOptions {
    /// Address describing the remote transport server. This is a vec to support multiple addresses
    /// so as to support both IPv4 and IPv6. These addresses are meant to describe a single bridge
    /// as the key material should not be used across multiple instances.
    ///
    /// Must parse as a valid [`std::net::SocketAddr`] - e.g. `123.45.67.89:443`
    pub addresses: Vec<SocketAddr>,

    /// Override hostname used for certificate verification
    pub host: Option<String>,

    /// Use identity public key to verify server self signed certificate
    pub id_pubkey: String,
}

struct InnerClientOptions {
    pub addresses: Vec<SocketAddr>,
    pub host: Option<String>,
    pub id_pubkey: VerifyingKey,
}

impl TryFrom<&ClientOptions> for InnerClientOptions {
    type Error = TransportError;
    fn try_from(value: &ClientOptions) -> Result<Self, Self::Error> {
        let id_pubkey = Self::parse_base64_pubkey(&value.id_pubkey)?;

        Ok(Self {
            addresses: value.addresses.clone(),
            host: value.host.clone(),
            id_pubkey,
        })
    }
}

impl InnerClientOptions {
    fn parse_base64_pubkey(key: impl AsRef<str>) -> Result<VerifyingKey, TransportError> {
        let mut pubkey_bytes = [0u8; 32];
        BASE64_STANDARD
            .decode_slice(key.as_ref(), &mut pubkey_bytes)
            .map_err(|e| {
                TransportError::config_err(format!(
                    "failed to decode Quic bridge public key as base64: {e}"
                ))
            })?;
        VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| TransportError::config_err(format!("bad Quic bridge public key: {e}")))
    }

    fn get_ipv4(&self) -> Option<SocketAddr> {
        self.addresses.iter().find(|s| s.is_ipv4()).cloned()
    }
}

pub async fn transport_conn(
    options: &ClientOptions,
    #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: impl FnOnce(RawFd),
) -> Result<quinn::Connection, TransportError> {
    info!("initializing from transport identity pubkey");
    let inner_options = InnerClientOptions::try_from(options)?;

    let transport_endpoint = inner_options
        .get_ipv4()
        .ok_or(TransportError::config_err("No IPv4 endpoint provided"))?;

    let client_config = create_quic_config(&inner_options)?;

    let bind_addr = match transport_endpoint.is_ipv4() {
        true => (Ipv4Addr::UNSPECIFIED, 0).into(),
        false => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = make_socket(Some(bind_addr)).map_err(TransportError::SocketIo)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    on_socket_open(socket.as_raw_fd());

    let runtime =
        quinn::default_runtime().ok_or_else(|| TransportError::other("no async runtime found"))?;
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        Default::default(),
        None,
        runtime
            .wrap_udp_socket(socket)
            .map_err(TransportError::SocketIo)?,
        runtime,
    )
    .map_err(TransportError::SocketIo)?;
    endpoint.set_default_client_config(client_config);

    // If no hostname is provided use the IP address of the remote server as the hostname.
    let addr_host = transport_endpoint.ip().to_string();
    let host = options.host.as_deref().unwrap_or(&addr_host);

    endpoint
        .connect(transport_endpoint, host)?
        .await
        .map_err(TransportError::QuicProto)
}
/// Create a client configuration for the quinn Quic client.
///
/// This sets the following properties to prepare the connection:
/// - adds hostname(s) from options to TLS alt names (if any)
/// - sets the TLS server cert verifier to our custom handler based on the pre-shared bridge pubkey
/// - sets TLS ALPN protocol header to HTTP
/// - sets keepalive_interval and max_idle_timeout to prevent sessions from closing during idle
/// - sets congestion controller to more fault tolerant BBR algorithm
/// - prevent server opening streams to client by setting uni and bidi streams to 0
///
/// All other properties are default.
fn create_quic_config(options: &InnerClientOptions) -> Result<quinn::ClientConfig, TransportError> {
    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap_or(&Arc::new(rustls::crypto::ring::default_provider()))
        .clone();

    let alt_names = options.host.clone().map(|h| vec![h]);
    let verifier = IdentityBasedVerifier::builder(&options.id_pubkey)
        .with_alt_names(alt_names)
        .with_crypto_provider(crypto_provider.clone())
        .build()
        .map_err(|e| {
            TransportError::Config(format!(
                "failed to initialize quic cert verifier from options: {e}"
            ))
        })?;

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| TransportError::other(format!("rustls client config init failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let quic_client_config = QuicClientConfig::try_from(client_crypto)
        .map_err(|e| TransportError::config_err(format!("invalid tls crypto config: {e}")))?;

    let mut transport_cfg = TransportConfig::default();
    // Set keepalive_interval and max_idle_timeout to prevent sessions from closing during idle
    transport_cfg.keep_alive_interval(Some(QUIC_SESSION_KEEPALIVE_INTERVAL));
    transport_cfg.max_idle_timeout(Some(*QUIC_SESSION_IDLE_TIMEOUT));

    // set congestion control to more fault tolerant BBR
    transport_cfg.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

    // Prevent server opening streams to client by setting uni and bidi streams to 0 (we just have
    // no reason to allow this for now).
    transport_cfg.max_concurrent_bidi_streams(0_u32.into());
    transport_cfg.max_concurrent_uni_streams(0_u32.into());

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    client_config.transport_config(Arc::new(transport_cfg));

    Ok(client_config)
}

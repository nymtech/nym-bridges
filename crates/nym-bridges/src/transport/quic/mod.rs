#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, RawFd};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use futures::future;
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

/// How long the client waits for the server to close a finished connection on
/// its own (see the `TransportCloser` impl below) before giving up and
/// forcing the close itself.
///
/// This is deliberately independent of [`QUIC_SESSION_IDLE_TIMEOUT`]: idle
/// timeout is suppressed by [`QUIC_SESSION_KEEPALIVE_INTERVAL`] for as long as
/// the connection object is alive, precisely so healthy-but-quiet tunnels
/// don't get dropped -- which means it would never fire here either, and
/// can't be relied on as a backstop for a peer that never closes.
const GRACEFUL_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

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
    fn get_crypto_source(&self) -> Result<ServerConfigSource, TransportError> {
        // parse either key or file
        if let Some(ref base64_key) = self.identity_key {
            ServerConfigSource::from_identity_base64(base64_key)
        } else if let Some(ref key_path) = self.private_ed25519_identity_key_file {
            ServerConfigSource::from_pkcs8_pem_file(key_path)
        } else {
            Err(TransportError::config_err("no crypto source provided"))
        }
    }

    fn build_server_config(&self) -> Result<rustls::ServerConfig, TransportError> {
        self.get_crypto_source()?.into_server_config()
    }

    pub fn get_id_pubkey(&self) -> Result<String, TransportError> {
        let crypto_source = self.get_crypto_source()?;

        let public_id = crypto_source.public_identity();
        Ok(BASE64_STANDARD.encode(&public_id[..]))
    }
}

impl crate::transport::GenerateServerConfig for ServerConfig {
    fn generate_config<R: rand::CryptoRng + ?Sized>(mut self, rng: &mut R) -> Self {
        if self.identity_key.is_none() && self.private_ed25519_identity_key_file.is_none() {
            self.identity_key = Some(ServerConfigSource::generate(rng).to_base64());
        }
        self
    }
}

impl crate::types::Sufficiency for ServerConfig {
    /// Whether this config has an identity key source (inline or file-backed) to build a
    /// listener from -- see [`ServerConfig::get_crypto_source`].
    fn is_sufficient(&self) -> bool {
        self.identity_key.is_some() || self.private_ed25519_identity_key_file.is_some()
    }
}

impl crate::transport::ExternalizeKeyMaterial for ServerConfig {
    fn externalize_keys(
        mut self,
        dir: &std::path::Path,
    ) -> Result<(Self, Vec<crate::transport::GeneratedKeyMaterial>), TransportError> {
        let generated = crate::transport::externalize_identity(
            &mut self.identity_key,
            &mut self.private_ed25519_identity_key_file,
            dir,
            "quic_ed25519_identity.pem",
        )?;
        Ok((self, generated))
    }
}

pub fn create_endpoint(options: &ServerConfig) -> Result<quinn::Endpoint, TransportError> {
    let mut server_crypto = options.build_server_config()?;

    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok(quinn::Endpoint::server(server_config, options.listen)?)
}

// ====================================[ Client Side ]====================================

pub use crate::types::quic::ClientOptions;

/// Only the side that _received_ data last can be sure it has all been
/// delivered to the application -- see [`quinn::Connection::close`]'s docs
/// under "Gracefully closing a connection". If we closed proactively here
/// instead, our peer could observe our CONNECTION_CLOSE frame before it has
/// drained everything we already sent it, and would report that as a bare
/// connection-lost error rather than a clean end of stream.
///
/// So instead of closing, wait for the peer to close first -- it does this
/// once its own forwarding loop finishes draining what we sent (see the
/// server's `handle_quic_connection_inner`). If that doesn't happen within
/// [`GRACEFUL_CLOSE_TIMEOUT`], force the close ourselves rather than leaking
/// the connection: `max_idle_timeout` is *not* a backstop here, since
/// `keep_alive_interval` keeps this connection looking active (and thus
/// exempt from idle timeout) for as long as we hold it open waiting.
impl crate::connection::TransportCloser for quinn::Connection {
    fn close(self: Box<Self>) -> futures::future::BoxFuture<'static, ()> {
        Box::pin(async move {
            if tokio::time::timeout(GRACEFUL_CLOSE_TIMEOUT, self.closed())
                .await
                .is_err()
            {
                debug!("peer did not close connection in time, forcing close");
                quinn::Connection::close(&self, 0u32.into(), b"done");
            }
        })
    }
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
            // Trim so a directory value padded with incidental whitespace still verifies as SNI.
            host: value
                .host
                .as_deref()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty()),
            id_pubkey,
        })
    }
}

impl InnerClientOptions {
    fn parse_base64_pubkey(key: impl AsRef<str>) -> Result<VerifyingKey, TransportError> {
        let mut pubkey_bytes = [0u8; 32];
        // Trim so a directory value padded with incidental whitespace still base64-decodes.
        BASE64_STANDARD
            .decode_slice(key.as_ref().trim(), &mut pubkey_bytes)
            .map_err(|e| {
                TransportError::config_err(format!(
                    "failed to decode Quic bridge public key as base64: {e}"
                ))
            })?;
        VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| TransportError::config_err(format!("bad Quic bridge public key: {e}")))
    }
}

/// Attempt a Quic connection against every provided address concurrently, and take whichever
/// succeeds first -- similar in spirit to "happy eyeballs" (RFC 8305), except we don't stagger
/// the attempts since Quic's connection setup is a handful of UDP packets rather than a stateful
/// TCP handshake, so racing all candidates up front costs little.
///
/// The losing attempts are dropped (and their sockets closed) once a winner completes. Each
/// individual attempt is bounded by `connect_timeout`; since every address is raced concurrently
/// rather than tried in sequence, that same duration bounds the call as a whole. If no address
/// completes its handshake in time, returns [`TransportError::TimedOut`].
pub async fn transport_conn(
    options: &ClientOptions,
    #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: impl Fn(RawFd),
    connect_timeout: Duration,
) -> Result<quinn::Connection, TransportError> {
    info!("initializing from transport identity pubkey");
    let inner_options = InnerClientOptions::try_from(options)?;

    if inner_options.addresses.is_empty() {
        return Err(TransportError::config_err("No endpoint provided"));
    }

    let client_config = create_quic_config(&inner_options)?;

    // If no hostname is provided use the IP address of the first candidate as the SNI hostname.
    let addr_host = inner_options.addresses[0].ip().to_string();
    let host = options.host.as_deref().unwrap_or(&addr_host);

    let attempts = inner_options.addresses.iter().map(|&addr| {
        Box::pin(connect_one(
            addr,
            host,
            client_config.clone(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            &on_socket_open,
            connect_timeout,
        ))
    });

    let (conn, _losing_attempts) = future::select_ok(attempts).await.inspect_err(|e| {
        warn!(
            "failed to connect to any of {} endpoint(s): {e}",
            inner_options.addresses.len()
        );
    })?;

    Ok(conn)
}

/// Opens a socket against `addr` and drives the Quic handshake to completion, failing with
/// [`TransportError::TimedOut`] (and closing the endpoint) if it doesn't finish within
/// `connect_timeout`.
async fn connect_one(
    addr: SocketAddr,
    host: &str,
    client_config: quinn::ClientConfig,
    #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: &impl Fn(RawFd),
    connect_timeout: Duration,
) -> Result<quinn::Connection, TransportError> {
    let bind_addr = match addr.is_ipv4() {
        true => (Ipv4Addr::UNSPECIFIED, 0).into(),
        false => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = make_socket(Some(bind_addr)).map_err(TransportError::SocketIo)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    on_socket_open(socket.as_raw_fd());

    let runtime =
        quinn::default_runtime().ok_or_else(|| TransportError::other("no async runtime found"))?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        Default::default(),
        None,
        runtime
            .wrap_udp_socket(socket)
            .map_err(TransportError::SocketIo)?,
        runtime,
    )
    .map_err(TransportError::SocketIo)?;

    let connecting = endpoint
        .connect_with(client_config, addr, host)
        .map_err(TransportError::Quic)?;

    match tokio::time::timeout(connect_timeout, connecting).await {
        Ok(connection) => connection.map_err(TransportError::QuicProto),
        Err(_) => {
            tracing::warn!("QUIC bridge connection to {addr} timed out after {connect_timeout:?}");
            endpoint.close(0u32.into(), b"timeout");
            // TimedOut has no error_state_reason, so tunnel_monitor propagates it as
            // TunnelMonitorEvent::Down { error_state_reason: None }, which triggers
            // ConnectingState::reconnect() with a different gateway selection.
            Err(TransportError::TimedOut(connect_timeout))
        }
    }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::transport::{ExternalizeKeyMaterial, GenerateServerConfig};

    #[test]
    fn sufficiency_reflects_whether_key_material_is_present() {
        use crate::types::Sufficiency;

        assert!(!ServerConfig::default().is_sufficient());
        assert!(
            ServerConfig::default()
                .generate_config(&mut rand::rng())
                .is_sufficient()
        );
    }

    #[test]
    fn quic_generate_config_embeds_fresh_identity_inline() {
        let config = ServerConfig::default().generate_config(&mut rand::rng());

        assert!(config.identity_key.is_some());
        assert!(config.private_ed25519_identity_key_file.is_none());
    }

    #[test]
    fn quic_externalize_keys_moves_inline_identity_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = ServerConfig::default().generate_config(&mut rand::rng());

        let (config, generated) = config.externalize_keys(dir.path()).unwrap();

        assert!(config.identity_key.is_none());
        assert_eq!(
            config.private_ed25519_identity_key_file,
            Some(dir.path().join("quic_ed25519_identity.pem"))
        );
        assert_eq!(generated.len(), 1);
        assert_eq!(
            generated[0].path,
            dir.path().join("quic_ed25519_identity.pem")
        );

        // persist the material at the path externalize_keys embedded in the config, and confirm
        // it round-trips through the normal key-loading path from there.
        std::fs::write(&generated[0].path, &generated[0].pem_bytes).unwrap();
        assert!(
            ServerConfigSource::from_pkcs8_pem_file(
                config.private_ed25519_identity_key_file.as_ref().unwrap()
            )
            .is_ok()
        );
    }
}

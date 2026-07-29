use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use russh::keys::ssh_key;
use russh::{Channel, ChannelId, ChannelOpenFailure, ChannelStream, Preferred, Pty};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::*;

use crate::error::TransportError;
use crate::transport::tls::certs::ServerConfigSource;

const DEFAULT_SOCK_ADDR: &str = "[::]:4422";

/// Default user name presented/expected during SSH auth when neither side has configured one.
/// The transport doesn't have a notion of separate users; the `none` auth method is always used,
/// and the username is only checked as a shared-secret-like gate between client and server.
const DEFAULT_SSH_USER: &str = "ubuntu";

/// Stream produced by the server side of the transport once a client has opened a channel.
pub type ServerChannelStream = ChannelStream<russh::server::Msg>;
/// Stream produced by the client side of the transport once its channel is open.
pub type ClientChannelStream = ChannelStream<russh::client::Msg>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// Address to listen on
    pub listen: SocketAddr,

    /// Maximum number of concurrent connections to allow
    pub connection_limit: Option<usize>,

    /// Base64 encoded Identity Key, for use as the ed25519 SSH host key. Used only if
    /// `private_ed25519_identity_key_file` is not provided.
    pub identity_key: Option<String>,

    /// Path to file containing PKCS8 PEM ed25519 identity private key, for use as the ed25519 SSH
    /// host key.
    pub private_ed25519_identity_key_file: Option<PathBuf>,

    pub expected_username: Option<String>,

    /// SSH banner presented to clients during authentication. Purely informational (e.g. a
    /// notice or greeting) - not required for and not checked as part of establishing a
    /// connection. This same value is copied into the generated client configuration so
    /// consumers of that configuration know what banner to expect ahead of time.
    pub banner: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_SOCK_ADDR.parse().unwrap(),
            connection_limit: Default::default(),
            identity_key: Default::default(),
            private_ed25519_identity_key_file: Default::default(),
            expected_username: Default::default(),
            banner: Default::default(),
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

    fn build_server_config(&self) -> Result<russh::server::Config> {
        let source = self.get_crypto_source()?;
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&source.identity_seed());
        let host_key: russh::keys::PrivateKey = keypair.into();

        Ok(russh::server::Config {
            inactivity_timeout: Some(Duration::from_secs(60)),
            auth_rejection_time: Duration::from_secs(3),
            auth_rejection_time_initial: Some(Duration::from_secs(3)),
            keys: vec![host_key],
            preferred: Preferred {
                key: std::borrow::Cow::Borrowed(&[ssh_key::Algorithm::Ed25519]),
                ..Preferred::default()
            },
            ..Default::default()
        })
    }

    pub fn get_id_pubkey(&self) -> Result<String> {
        let crypto_source = self.get_crypto_source()?;
        let public_id = crypto_source.public_identity();
        Ok(BASE64_STANDARD.encode(&public_id[..]))
    }

    /// Username a connecting client must present via the `none` auth method, falling back to
    /// [`DEFAULT_SSH_USER`] if none was configured.
    pub fn expected_username(&self) -> String {
        self.expected_username
            .clone()
            .unwrap_or_else(|| DEFAULT_SSH_USER.to_string())
    }
}

/// Build the shared SSH server configuration (host key + kex/algorithm preferences) used to
/// handshake every accepted connection.
pub fn create_listener(options: &ServerConfig) -> Result<Arc<russh::server::Config>> {
    Ok(Arc::new(options.build_server_config()?))
}

/// Handler for a single accepted TCP connection. Uses the `none` auth method, only checking that
/// the client's presented username matches `expected_username` (the transport has no notion of
/// distinct users beyond that), and hands the first opened channel back to the caller via
/// `channel_tx` so that further handling (framing, forwarding, etc.) is left entirely up to the
/// application driving the accept loop.
///
/// Only a plain "session" channel used to carry opaque forwarded bytes is supported. Everything
/// else an SSH client can normally ask for - running commands, allocating a pty, subsystems, X11
/// or TCP/IP forwarding - is explicitly refused rather than left to whatever the library's
/// default behavior happens to be, since this is meant to be a narrow, single-purpose transport
/// rather than a general-purpose SSH server.
struct ConnectionHandler {
    channel_tx: Option<oneshot::Sender<Channel<russh::server::Msg>>>,
    expected_username: String,
    banner: Option<String>,
}

impl ConnectionHandler {
    /// Send an explicit channel-request failure back to the client instead of leaving the
    /// request without any response.
    fn deny_channel_request(
        session: &mut russh::server::Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        session.channel_failure(channel)
    }
}

impl russh::server::Handler for ConnectionHandler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.banner.clone())
    }

    async fn auth_none(&mut self, user: &str) -> Result<russh::server::Auth, Self::Error> {
        if user == self.expected_username {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        if let Some(tx) = self.channel_tx.take() {
            let _ = tx.send(channel);
        }
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<russh::server::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Self::deny_channel_request(session, channel)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Self::deny_channel_request(session, channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Self::deny_channel_request(session, channel)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Self::deny_channel_request(session, channel)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Self::deny_channel_request(session, channel)
    }
}

/// Perform the SSH handshake over an already-accepted TCP stream and wait for the client to open
/// its (single) channel, returning it as a plain `AsyncRead + AsyncWrite` stream.
///
/// The session's background message pump is spawned onto its own task since it must keep running
/// for the lifetime of the connection to drive the returned stream's I/O; it exits on its own once
/// the returned stream is dropped and the client disconnects.
pub async fn accept(
    config: Arc<russh::server::Config>,
    expected_username: String,
    banner: Option<String>,
    stream: TcpStream,
) -> Result<ServerChannelStream, TransportError> {
    let (channel_tx, channel_rx) = oneshot::channel();
    let handler = ConnectionHandler {
        channel_tx: Some(channel_tx),
        expected_username,
        banner,
    };

    let running = russh::server::run_stream(config, stream, handler).await?;

    tokio::spawn(async move {
        if let Err(err) = running.await {
            warn!("ssh session ended with error: {err}");
        }
    });

    let channel = channel_rx
        .await
        .map_err(|_| TransportError::other("ssh session closed before a channel was opened"))?;

    Ok(channel.into_stream())
}

// ====================================[ Client Side ]====================================

pub use crate::types::ssh::ClientOptions;

struct InnerClientOptions {
    pub addresses: Vec<SocketAddr>,
    pub id_pubkey: VerifyingKey,
    pub username: Option<String>,
}

impl TryFrom<&ClientOptions> for InnerClientOptions {
    type Error = TransportError;
    fn try_from(value: &ClientOptions) -> Result<Self, Self::Error> {
        let id_pubkey = Self::parse_base64_pubkey(&value.id_pubkey)?;

        Ok(Self {
            addresses: value.addresses.clone(),
            id_pubkey,
            username: value.username.clone(),
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
                    "failed to decode SSH bridge public key as base64: {e}"
                ))
            })?;
        VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| TransportError::config_err(format!("bad SSH bridge public key: {e}")))
    }
}

/// Client-side handler responsible only for pinning the server's ed25519 host key against the
/// configured identity public key.
struct ClientHandler {
    id_pubkey: VerifyingKey,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let Some(ed25519_key) = server_public_key.key_data().ed25519() else {
            return Ok(false);
        };
        Ok(ed25519_key.0 == self.id_pubkey.to_bytes())
    }
}

pub async fn transport_conn(
    options: &ClientOptions,
) -> Result<ClientChannelStream, TransportError> {
    info!("initializing from transport identity pubkey");
    let inner_options = InnerClientOptions::try_from(options)?;

    let addr = *inner_options
        .addresses
        .first()
        .ok_or_else(|| TransportError::config_err("no ssh bridge address configured"))?;

    let mut client_config = russh::client::Config::default();
    client_config.preferred.key = std::borrow::Cow::Borrowed(&[ssh_key::Algorithm::Ed25519]);
    let client_config = Arc::new(client_config);

    let handler = ClientHandler {
        id_pubkey: inner_options.id_pubkey,
    };

    let mut handle = russh::client::connect(client_config, addr, handler).await?;

    let username = inner_options.username.unwrap_or(DEFAULT_SSH_USER.into());
    let auth = handle.authenticate_none(&username).await?;
    if !auth.success() {
        return Err(TransportError::other("ssh server rejected authentication"));
    }

    let channel = handle
        .channel_open_session()
        .await
        .context("failed to open ssh channel")
        .map_err(|e| TransportError::other(e.to_string()))?;

    Ok(channel.into_stream())
}

#[cfg(test)]
mod test;

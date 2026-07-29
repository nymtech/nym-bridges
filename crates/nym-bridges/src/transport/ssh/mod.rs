use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use russh::keys::ssh_key;
use russh::{Channel, ChannelStream, Preferred};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::*;

use crate::error::TransportError;
use crate::transport::tls::certs::ServerConfigSource;

const DEFAULT_SOCK_ADDR: &str = "[::]:4422";

/// User name presented during SSH auth. The transport doesn't have a notion of separate users, so
/// the client just authenticates with the `none` method under a fixed placeholder name.
const SSH_USER: &str = "nym-bridge";

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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_SOCK_ADDR.parse().unwrap(),
            connection_limit: Default::default(),
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
}

/// Build the shared SSH server configuration (host key + kex/algorithm preferences) used to
/// handshake every accepted connection.
pub fn create_listener(options: &ServerConfig) -> Result<Arc<russh::server::Config>> {
    Ok(Arc::new(options.build_server_config()?))
}

/// Handler for a single accepted TCP connection. Accepts `none` auth unconditionally (the
/// transport has no notion of distinct users) and hands the first opened channel back to the
/// caller via `channel_tx` so that further handling (framing, forwarding, etc.) is left entirely
/// up to the application driving the accept loop.
struct ConnectionHandler {
    channel_tx: Option<oneshot::Sender<Channel<russh::server::Msg>>>,
}

impl russh::server::Handler for ConnectionHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
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
}

/// Perform the SSH handshake over an already-accepted TCP stream and wait for the client to open
/// its (single) channel, returning it as a plain `AsyncRead + AsyncWrite` stream.
///
/// The session's background message pump is spawned onto its own task since it must keep running
/// for the lifetime of the connection to drive the returned stream's I/O; it exits on its own once
/// the returned stream is dropped and the client disconnects.
pub async fn accept(
    config: Arc<russh::server::Config>,
    stream: TcpStream,
) -> Result<ServerChannelStream, TransportError> {
    let (channel_tx, channel_rx) = oneshot::channel();
    let handler = ConnectionHandler {
        channel_tx: Some(channel_tx),
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
}

impl TryFrom<&ClientOptions> for InnerClientOptions {
    type Error = TransportError;
    fn try_from(value: &ClientOptions) -> Result<Self, Self::Error> {
        let id_pubkey = Self::parse_base64_pubkey(&value.id_pubkey)?;

        Ok(Self {
            addresses: value.addresses.clone(),
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

    let auth = handle.authenticate_none(SSH_USER).await?;
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
mod test {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn client_server_handshake_and_echo() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();
        let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());
        let id_pubkey = BASE64_STANDARD.encode(verifying_key.to_bytes());

        let server_cfg = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            connection_limit: None,
            identity_key: Some(identity_key),
            private_ed25519_identity_key_file: None,
        };

        let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = create_listener(&server_cfg).unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut chan_stream = accept(config, stream).await.unwrap();

            let mut buf = [0u8; 5];
            chan_stream.read_exact(&mut buf).await.unwrap();
            chan_stream.write_all(&buf).await.unwrap();
        });

        let client_opts = ClientOptions {
            addresses: vec![addr],
            id_pubkey,
        };
        let mut client_stream = transport_conn(&client_opts).await.unwrap();
        client_stream.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 5];
        client_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_rejects_mismatched_host_key() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let identity_key = BASE64_STANDARD.encode(signing_key.to_bytes());

        // Client is configured to pin a *different* identity than the server actually presents.
        let wrong_pubkey = BASE64_STANDARD.encode(
            SigningKey::generate(&mut rand::rng())
                .verifying_key()
                .to_bytes(),
        );

        let server_cfg = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            connection_limit: None,
            identity_key: Some(identity_key),
            private_ed25519_identity_key_file: None,
        };

        let listener = TcpListener::bind(server_cfg.listen).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = create_listener(&server_cfg).unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = accept(config, stream).await;
        });

        let client_opts = ClientOptions {
            addresses: vec![addr],
            id_pubkey: wrong_pubkey,
        };
        let result = transport_conn(&client_opts).await;
        assert!(result.is_err());

        let _ = server_task.await;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, RawFd};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::VerifyingKey;
use futures::future;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::*;

use crate::error::TransportError;
use crate::transport::tls::certs::{IdentityBasedVerifier, ServerConfigSource};

pub(crate) mod certs;

const DEFAULT_SOCK_ADDR: &str = "[::]:4443";

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ServerConfig {
    /// Address to listen on
    pub listen: SocketAddr,

    /// Maximum number of concurrent connections to allow
    pub connection_limit: Option<usize>,

    /// Base64 encoded Identity Key string. This is used to secure connections using ED25519 self
    /// signed certificates. Used only if `private_ed25519_identity_key_file` is not provided.
    pub identity_key: Option<String>,

    /// Path to file containing ed25519 identity private key, for use in ED25519 based self signed certs
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
            "tls_ed25519_identity.pem",
        )?;
        Ok((self, generated))
    }
}

pub fn create_listener(options: &ServerConfig) -> Result<TlsAcceptor, TransportError> {
    let server_crypto = options.build_server_config()?;

    Ok(TlsAcceptor::from(Arc::new(server_crypto)))
}

// ====================================[ Client Side ]====================================

pub use crate::types::tls::ClientOptions;

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
}

/// Attempt a TCP connection against every provided address concurrently, and take whichever
/// succeeds first -- similar in spirit to "happy eyeballs" (RFC 8305), except we don't stagger
/// the attempts (see the equivalent Quic helper in `transport::quic` for why that's a reasonable
/// simplification here too, given we're only ever racing a handful of candidates).
///
/// The losing attempts are dropped (and their sockets closed) once a winner completes.
/// `connect_timeout` bounds the TCP-connect race and the subsequent TLS handshake with the
/// winner together, as a single unit; if that combined step doesn't finish in time, returns
/// [`TransportError::TimedOut`].
pub async fn transport_conn(
    options: &ClientOptions,
    #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: impl Fn(RawFd),
    connect_timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TransportError> {
    info!("initializing from transport identity pubkey");
    let inner_options = InnerClientOptions::try_from(options)?;
    let verif_key = inner_options.id_pubkey;

    if inner_options.addresses.is_empty() {
        return Err(TransportError::config_err("No endpoint provided"));
    }

    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap_or(&Arc::new(rustls::crypto::ring::default_provider()))
        .clone();

    let alt_names = inner_options.host.clone().map(|h| vec![h]);
    let verifier = IdentityBasedVerifier::builder(&verif_key)
        .with_alt_names(alt_names)
        .with_crypto_provider(crypto_provider.clone())
        .build()
        .map_err(|e| {
            TransportError::Config(format!(
                "failed to initialize quic cert verifier from options: {e}"
            ))
        })?;

    let client_crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| TransportError::other(format!("rustls client config init failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_crypto));

    // If no hostname is provided use the IP address of the first candidate as the hostname.
    let addr_host = inner_options.addresses[0].ip().to_string();
    let host = inner_options.host.clone().unwrap_or(addr_host);
    let sni = ServerName::try_from(host).unwrap();

    let attempts = inner_options.addresses.iter().map(|&addr| {
        Box::pin(connect_one(
            addr,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            &on_socket_open,
        ))
    });

    let connect = async {
        let (stream, _losing_attempts) = future::select_ok(attempts).await.inspect_err(|e| {
            warn!(
                "failed to connect to any of {} endpoint(s): {e}",
                inner_options.addresses.len()
            );
        })?;

        connector
            .connect(sni, stream)
            .await
            .map_err(TransportError::from)
    };

    match tokio::time::timeout(connect_timeout, connect).await {
        Ok(result) => result,
        Err(_) => {
            warn!("TLS bridge connection timed out after {connect_timeout:?}");
            Err(TransportError::TimedOut(connect_timeout))
        }
    }
}

async fn connect_one(
    addr: SocketAddr,
    #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: &impl Fn(RawFd),
) -> Result<TcpStream, TransportError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(TransportError::SocketIo)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    on_socket_open(socket.as_raw_fd());

    socket.connect(addr).await.map_err(TransportError::SocketIo)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transport::GenerateServerConfig;

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
    fn generate_config_reuses_provided_identity_without_generating() {
        let config = ServerConfig {
            identity_key: Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".into()),
            ..Default::default()
        }
        .generate_config(&mut rand::rng());

        assert_eq!(
            config.identity_key,
            Some("fditK5JfNM/88mLWd3ccbLasSrHA5dw1wj+/+1bfGWk=".to_string())
        );
        assert!(config.private_ed25519_identity_key_file.is_none());
    }
}

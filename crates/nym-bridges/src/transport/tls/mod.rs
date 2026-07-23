use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::VerifyingKey;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
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

pub fn create_listener(options: &ServerConfig) -> Result<TlsAcceptor> {
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

pub async fn transport_conn(
    options: &ClientOptions,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    info!("initializing from transport identity pubkey");
    let inner_options = InnerClientOptions::try_from(options)?;

    let mut bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    BASE64_STANDARD.decode_slice(inner_options.id_pubkey, &mut bytes)?;
    let verif_key = VerifyingKey::from_bytes(&bytes)?;

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

    // If no hostname is provided use the IP address of the remote server as the hostname.
    let addr_host = inner_options.addresses[0].ip().to_string();
    let host = inner_options.host.clone().unwrap_or(addr_host);
    let sni = ServerName::try_from(host).unwrap();

    let stream = TcpStream::connect(&inner_options.addresses[..]).await?;
    connector
        .connect(sni, stream)
        .await
        .context("tls transport establishment failed")
}

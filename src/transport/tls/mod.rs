use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::*;

use crate::transport::tls::certs::IdentityBasedVerifier;
use crate::transport::tls::certs::ServerConfigSource;

pub use super::ClientOptions;

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
            let signing_key = SigningKey::read_pkcs8_pem_file(key_path)
                .map_err(|e| anyhow!("failed to parse identity key in {key_path:?}: {e}"))?;
            Ok(ServerConfigSource::from_identity(signing_key.to_bytes()))
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

pub async fn transport_conn(
    options: &ClientOptions,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    info!("initializing from transport identity pubkey");
    let mut bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    BASE64_STANDARD.decode_slice(&options.id_pubkey, &mut bytes)?;
    let verif_key = VerifyingKey::from_bytes(&bytes)?;

    let alt_names = options.alt_names_for_verification();
    let verifier = IdentityBasedVerifier::new_with_alt_names(&verif_key, alt_names).unwrap();

    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_crypto));

    let sni_str = options.effective_sni();
    if options.sni_override.is_some() {
        info!("using SNI override: {}", sni_str);
    }

    let sni = ServerName::try_from(sni_str).context("invalid SNI hostname")?;

    let stream = TcpStream::connect(&options.addresses[..]).await?;
    connector
        .connect(sni, stream)
        .await
        .context("tls transport establishment failed")
}

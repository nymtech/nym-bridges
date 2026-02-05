use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::prelude::*;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::crypto::rustls::QuicServerConfig;
use serde::{Deserialize, Serialize};
use tracing::*;

use crate::transport::tls::certs::{IdentityBasedVerifier, ServerConfigSource};

pub use super::ClientOptions;

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const DEFAULT_SOCK_ADDR: &str = "[::]:4443";

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

const DEFAULT_CLIENT_BIND_ADDR: &str = "[::]:0";

pub async fn transport_conn(options: &ClientOptions) -> Result<quinn::Connection> {
    info!("initializing from transport identity pubkey");
    let mut bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
    BASE64_STANDARD.decode_slice(&options.id_pubkey, &mut bytes)?;
    let verif_key = VerifyingKey::from_bytes(&bytes)?;

    let alt_names = options.alt_names_for_verification();
    let verifier = IdentityBasedVerifier::new_with_alt_names(&verif_key, alt_names).unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    let mut endpoint = quinn::Endpoint::client(DEFAULT_CLIENT_BIND_ADDR.parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let sni = options.effective_sni();
    if options.sni_override.is_some() {
        info!("using SNI override: {}", sni);
    }

    endpoint
        .connect(options.addresses[0], &sni)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))
}

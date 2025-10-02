use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant, io::Read};

use anyhow::{Result, Context};
use clap::Parser;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    signal,
};
use tokio_util::sync::CancellationToken;
use tracing::*;
use tracing::{error, info};
use serde::{Serialize, Deserialize};

use nym_bridges::config::{ClientConfig, PersistedClientConfig};
use nym_bridges::connection::copy_bidirectional;
use nym_bridges::transport::{quic, tls};

#[derive(Debug, Parser, PartialEq)]
#[clap(name = "args")]
struct Args {
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/nym/transports/client.toml"
    )]
    /// Path to the configuration for establishing transport connections
    config_path: PathBuf,
}



#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct ServiceConfig {
    pub ingress_addr: String,
    pub transport_cfg: PersistedClientConfig,
}

#[allow(unused)]
impl ServiceConfig {
    pub fn parse(config_str: impl AsRef<str>) -> Result<Self> {
        toml::from_str(config_str.as_ref()).context("failed to parse config")
    }

    pub fn parse_file(config_path: PathBuf) -> Result<Self> {
        let mut config_file = std::fs::File::open(config_path)?;
        let mut config = vec![];
        config_file.read_to_end(&mut config)?;
        toml::from_slice(&config).context("failed to parse config")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();
    let config = ServiceConfig::parse_file(args.config_path)?;

    // Setup for graceful shutdown
    let token = CancellationToken::new();
    let cloned_token = token.clone();

    // Launch the listener(s)
    info!("starting ");
    let task1_handle = tokio::spawn(launch_listener(cloned_token, config));

    info!("local forward running, waiting for shutdown");
    // If an interrupt signal is received cancel the original token
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("received shutdown signal");
            token.cancel();
        }
        Err(err) => {
            panic!("Unable to listen for shutdown signal: {err}");
        }
    }

    // Wait for tasks to complete
    task1_handle.await.unwrap();

    Ok(())
}

async fn launch_listener(token: CancellationToken, opt: ServiceConfig) {
    let listener = tokio::net::TcpListener::bind(&opt.ingress_addr)
        .await
        .expect("failed to launch listener 1");

    tracing::info!(
        "listener started for tcp {}",
        listener.local_addr().unwrap()
    );

    // For now Ony use the first transport client config to open a connection.
    let opt = Arc::new(opt.transport_cfg.transports[0].clone());
    loop {
        tokio::select! {
            // Use the provided token to listen to cancellation requests
            _ = token.cancelled() => {
                // The token was cancelled, task can shut down
                info!("listener 1 shutting down");
                return
            }
            r = listener.accept() => {
                match r {
                    Ok((socket, remote)) => {
                        debug!("accepted connection from {remote}");

                        tokio::spawn(process(socket, remote, opt.clone(), token.clone()));
                    }
                    Err(e) => error!("failed to accept connection: {e}"),
                }
            }
        }
    }
}

async fn process<RW>(
    conn: RW,
    ingress_addr: SocketAddr,
    opt: Arc<ClientConfig>,
    token: CancellationToken,
) where
    RW: AsyncWrite + AsyncRead + Unpin + Send,
{
    match opt.as_ref() {
        ClientConfig::QuicPlain(opt) => process_quic(conn, ingress_addr, opt, token).await,
        ClientConfig::TlsPlain(opt) => process_tls(conn, ingress_addr, opt, token).await,
    }
}

async fn process_quic<RW>(
    conn: RW,
    ingress_addr: SocketAddr,
    opt: &quic::ClientOptions,
    token: CancellationToken,
) where
    RW: AsyncWrite + AsyncRead + Unpin + Send,
{
    debug!("opening transport connection");
    let start = Instant::now();

    let transport_conn = match quic::transport_conn(opt).await {
        Ok(conn) => conn,
        Err(e) => {
            error!("failed to connect to transport conn: {}", e);
            return;
        }
    };

    debug!("transport connected in {:?}", start.elapsed());
    // Open the first stream that we receive and use it for transport. Other stream opens will be ignored
    let (egress_send, egress_recv) = match transport_conn.open_bi().await {
        Ok((wr, rd)) => (wr, rd),
        Err(e) => {
            error!("failed to connect to transport stream: {}", e);
            return;
        }
    };

    let (ingress_recv, ingress_send) = tokio::io::split(conn);

    if let Err(e) = copy_bidirectional(
        token,
        ingress_addr,
        ingress_recv,
        ingress_send,
        egress_recv,
        egress_send,
    )
    .await
    {
        info!("session to {ingress_addr} closed with error: {e}")
    }

    transport_conn.close(0u32.into(), b"done");
}

async fn process_tls<RW>(
    conn: RW,
    ingress_addr: SocketAddr,
    opt: &tls::ClientOptions,
    token: CancellationToken,
) where
    RW: AsyncWrite + AsyncRead + Unpin + Send,
{
    debug!("opening transport connection");
    let start = Instant::now();

    let transport_conn = match tls::transport_conn(opt).await {
        Ok(conn) => conn,
        Err(e) => {
            error!("failed to connect to transport conn: {}", e);
            return;
        }
    };

    debug!("transport connected in {:?}", start.elapsed());

    let (egress_recv, egress_send) = tokio::io::split(transport_conn);
    let (ingress_recv, ingress_send) = tokio::io::split(conn);

    if let Err(e) = copy_bidirectional(
        token,
        ingress_addr,
        ingress_recv,
        ingress_send,
        egress_recv,
        egress_send,
    )
    .await
    {
        info!("session to {ingress_addr} closed with error: {e}")
    }
}

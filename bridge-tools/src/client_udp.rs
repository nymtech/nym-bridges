use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::*;

use std::{io::Read, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use nym_bridges::config::{ClientConfig, PersistedClientConfig};
use nym_bridges::connection::process_udp;
use nym_bridges::session::Session;
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
    let task1_handle = tokio::spawn(listen_socket(cloned_token, config));

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
    if let Err(e) = task1_handle.await.unwrap() {
        info!("listener error: {e}");
    }
    info!("listener shutdown");

    Ok(())
}

pub async fn listen_socket(token: CancellationToken, opt: ServiceConfig) -> Result<()> {
    let socket = UdpSocket::bind(&opt.ingress_addr).await?;
    let socket = Arc::new(socket);

    info!("listener started for udp {}", &opt.ingress_addr);

    let mut buf = [0u8; 1500];

    tokio::select! {
        // Use the provided token to listen to cancellation requests before we receive any incoming packets
        _ = token.cancelled() => {
            // The token was cancelled, task can shut down
            info!("udp listener shutting down");
            return Ok(())
        }
        // listen for the first incoming packet before opening the transport connection
        //
        // the content of this first message is ignored in this test program because it is a hassle to make sure it is
        // wrapped properly and we launch in this order here to get the address of the remote.
        res = socket.recv_from(&mut buf) => {
            match res {
                Err(e) => return Err(e.into()),
                Ok((_, src)) => {

                    debug!("new receive from {src:?} opening transport connection");
                    handle_session(&opt, src, token, socket).await;
                }
            }
        }
    }
    Ok(())
}

async fn handle_session(
    opt: &ServiceConfig,
    src: SocketAddr,
    token: CancellationToken,
    socket: Arc<UdpSocket>,
) {
    match &opt.transport_cfg.transports[0] {
        ClientConfig::QuicPlain(opts) => {
            let session = Session::new(&src, &opts.addresses[0]); //todo: handle multiple addresses

            let span = info_span!(
                "connection",
                remote = %session.transport_remote(),
                session_id = %session.id()
            );

            if let Err(e) = quic_connection(session, opts, socket, token)
                .instrument(span)
                .await
            {
                error!("{e}");
            }
        }
        ClientConfig::TlsPlain(opts) => {
            let session = Session::new(&src, &opts.addresses[0]); //todo: handle multiple addresses

            let span = info_span!(
                "connection",
                remote = %session.transport_remote(),
                session_id = %session.id()
            );

            if let Err(e) = tls_connection(session, opts, socket, token)
                .instrument(span)
                .await
            {
                error!("{e}");
            }
        }
    };
}

async fn quic_connection(
    session: Session,
    opts: &quic::ClientOptions,
    socket: Arc<UdpSocket>,
    token: CancellationToken,
) -> Result<()> {
    let start = Instant::now();
    let conn = quic::transport_conn(opts)
        .await
        .context("failed to connect to transport conn")?;

    let (wr, rd) = conn
        .open_bi()
        .await
        .context("failed to connect to transport stream")?;

    debug!("quic transport connected in {:?}", start.elapsed());

    process_udp(rd, wr, socket, session, 1500, token).await;
    conn.close(0u32.into(), b"done");
    info!("end session");
    debug!("stats: {:?}", conn.stats());

    Ok(())
}

async fn tls_connection(
    session: Session,
    opts: &tls::ClientOptions,
    socket: Arc<UdpSocket>,
    token: CancellationToken,
) -> Result<()> {
    debug!("opening transport connection");
    let start = Instant::now();

    let transport_conn = tls::transport_conn(opts)
        .await
        .context("failed to connect to transport conn")?;

    debug!("tls transport connected in {:?}", start.elapsed());

    let (rd, wr) = tokio::io::split(transport_conn);

    process_udp(rd, wr, socket, session, 1500, token).await;
    info!("end session");

    Ok(())
}

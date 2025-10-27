use anyhow::{Context, Result};
use clap::Parser;
use nym_bin_common::bin_info;
use tokio::net::TcpStream;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::*;

use std::sync::{Arc, OnceLock};
use std::{net::SocketAddr, path::PathBuf};

use nym_bridges::{
    config::{ForwardConfig, PersistedServerConfig, TransportServerConfig},
    connection::process_udp,
    session::Session,
    transport::{quic, tls},
};

#[derive(Debug, Parser, PartialEq)]
#[command(author="Nymtech", version, long_version = pretty_build_info_static())]
struct Args {
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/nym/default-nym-node/bridges.toml"
    )]
    /// Specify the path to the config file to load. If no file path is provided, a default path
    /// will be assumed.
    config_path: PathBuf,
}

static PRETTY_BUILD_INFORMATION: OnceLock<String> = OnceLock::new();
// Helper for passing LONG_VERSION to clap
fn pretty_build_info_static() -> &'static str {
    PRETTY_BUILD_INFORMATION.get_or_init(|| bin_info!().pretty_print())
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
    let config = PersistedServerConfig::parse_file(&args.config_path)?;

    // Setup for graceful shutdown
    let token = CancellationToken::new();

    // Launch the listener(s)
    info!("starting up");
    let mut transport_listeners = tokio::task::JoinSet::new();
    for transport_config in config.transports {
        let cloned_token = token.clone();
        let fwd_config = config.forward.clone();

        match transport_config {
            TransportServerConfig::QuicPlain(options) => {
                transport_listeners.spawn(async {
                    let err_token = cloned_token.clone();
                    if let Err(e) = launch_quic_listener(cloned_token, fwd_config, options).await {
                        error!("Quic Listener failed: {e}");
                        err_token.cancel();
                    }
                });
            }
            TransportServerConfig::TlsPlain(options) => {
                transport_listeners.spawn(async {
                    let err_token = cloned_token.clone();
                    if let Err(e) = launch_tls_listener(cloned_token, fwd_config, options).await {
                        error!("TLS Listener failed: {e}");
                        err_token.cancel();
                    }
                });
            }
        }
    }

    info!("local forward running, waiting for shutdown");
    // If an interrupt signal is received cancel the original token
    tokio::select! {
        signal = signal::ctrl_c() => {
            match signal{
                Ok(()) => {
                    info!("received shutdown signal");
                    token.cancel();
                }
                Err(err) => {
                    panic!("Unable to listen for shutdown signal: {err}");
                }
            }
        }
        _ = token.cancelled() => {
            warn!("shutting down due to internal error");
        }
    }

    // Wait for tasks to complete
    transport_listeners.join_all().await;

    Ok(())
}

async fn launch_quic_listener(
    token: CancellationToken,
    fwd_cfg: ForwardConfig,
    options: quic::ServerConfig,
) -> Result<()> {
    let endpoint = quic::create_endpoint(&options)?;
    let address = endpoint.local_addr()?;

    tracing::info!("quic transport listening on {}", address);

    loop {
        tokio::select! {
            // Use the provided token to listen to cancellation requests
            _ = token.cancelled() => {
                // The token was cancelled, task can shut down
                info!("quic listener shutting down");
                return Ok(())
            }
            r = endpoint.accept() => {
                match r {
                    Some(conn)=> {

                        if options
                            .connection_limit
                            .is_some_and(|n| endpoint.open_connections() >= n)
                        {
                            info!("refusing due to open connection limit");
                            conn.refuse();
                        } else if Some(conn.remote_address()) == options.block {
                            info!("refusing blocked client IP address");
                            conn.refuse();
                        } else if options.stateless_retry && !conn.remote_address_validated() {
                            info!("requiring connection to validate its address");
                            conn.retry().unwrap();
                        } else {
                            let session_cancel = token.clone();
                            let client_addr = conn.remote_address();
                            tokio::spawn(handle_quic_connection(conn, client_addr, fwd_cfg.clone(), session_cancel));
                        }

                    }
                    None => warn!("listener closed"),
                }
            }
        }
    }
}

async fn launch_tls_listener(
    token: CancellationToken,
    fwd_cfg: ForwardConfig,
    options: tls::ServerConfig,
) -> Result<()> {
    let acceptor =
        tls::create_listener(&options).context("failed to initialize cryptographic config")?;

    let listener = tokio::net::TcpListener::bind(&options.listen).await?;
    tracing::info!("tls transport listening on {}", &options.listen);

    loop {
        tokio::select! {
            // Use the provided token to listen to cancellation requests
            _ = token.cancelled() => {
                // The token was cancelled, task can shut down
                info!("tls listener shutting down");
                return Ok(())
            }
            res = listener.accept() => {
                let (stream, address) = res?;
                let acceptor = acceptor.clone();
                let client_token = token.clone();
                let fwd = fwd_cfg.clone();

                let fut = async move {
                    let stream = acceptor.accept(stream).await?;
                    let session_cancel = client_token;

                    tokio::spawn(handle_tls_connection(stream, address, fwd, session_cancel));

                    Ok(()) as Result<()>
                };

                tokio::spawn(async move {
                    if let Err(err) = fut.await {
                        eprintln!("{err:?}");
                    }
                });
            }
        }
    }
}

pub async fn handle_tls_connection(
    conn: tokio_rustls::server::TlsStream<TcpStream>,
    transport_client_addr: SocketAddr,
    fwd_cfg: ForwardConfig,
    token: CancellationToken,
) {
    let session = Session::new(&fwd_cfg.address, &transport_client_addr);
    let span = info_span!(
        "connection",
        remote = %session.transport_remote(),
        session_id = %session.id()
    );
    async {
        debug!("accepted tls connection");

        if let Err(err) = handle_tls_connection_inner(conn, session, fwd_cfg, token).await {
            warn!("connection error: {err}");
        }
    }
    .instrument(span)
    .await;
}

async fn handle_tls_connection_inner(
    conn: tokio_rustls::server::TlsStream<TcpStream>,
    session: Session,
    fwd_cfg: ForwardConfig,
    token: CancellationToken,
) -> Result<()> {
    let session_token = token.child_token();

    let local_sock = Arc::new(tokio::net::UdpSocket::bind("[::]:0").await?);
    local_sock.connect(fwd_cfg.address).await?;

    let (recv, send) = tokio::io::split(conn);
    process_udp(recv, send, local_sock, session.clone(), 1500, session_token).await;

    info!("end session:"); // in theory handle session logging stats on close
    // debug!("stats: {:?}", session.stats());

    Ok(())
}

pub async fn handle_quic_connection(
    conn: quinn::Incoming,
    transport_client_addr: SocketAddr,
    fwd_cfg: ForwardConfig,
    token: CancellationToken,
) {
    let session = Session::new(&fwd_cfg.address, &transport_client_addr);
    let span = info_span!(
        "connection",
        remote = %session.transport_remote(),
        session_id = %session.id()
    );
    async {
        debug!("accepted quic connection");

        if let Err(err) = handle_quic_connection_inner(conn, session, fwd_cfg, token).await {
            warn!("connection error: {err}");
        }
    }
    .instrument(span)
    .await;
}

/// Listen for one stream open in the established Quic connection and bidirectionally proxy the
/// traffic.
async fn handle_quic_connection_inner(
    conn: quinn::Incoming,
    session: Session,
    fwd_cfg: ForwardConfig,
    token: CancellationToken,
) -> Result<()> {
    let connection = conn.await?;

    info!("established");
    let stream = connection.accept_bi().await;
    let (send, recv) = match stream {
        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
            info!("connection closed");
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
        Ok(s) => s,
    };

    let session_token = token.child_token();

    let local_sock = Arc::new(tokio::net::UdpSocket::bind("[::]:0").await?);
    local_sock.connect(fwd_cfg.address).await?;

    process_udp(recv, send, local_sock, session.clone(), 1500, session_token).await;

    connection.close(0u32.into(), b"done");
    info!("end session"); // in theory handle session logging stats on close
    debug!("stats: {:?}", connection.stats());

    Ok(())
}

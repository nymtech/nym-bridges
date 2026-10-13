use anyhow::{Context, Result};
use bytes::BytesMut;
use clap::Parser;
use nym_bin_common::bin_info;
use tokio::net::{TcpStream, UdpSocket};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::*;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use nym_bridges::{
    config::{ForwardConfig, PersistedServerConfig, TransportServerConfig},
    forward::responder::process_udp,
    session::Session,
    transport::{amnezia, quic, ssh, tls},
    types::Sufficiency,
};

/// WireGuard RejectAfterTime: a session silent for longer than this has no live keys left.
const AMNEZIA_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const AMNEZIA_MAX_DATAGRAM: usize = 65535;
/// Session cap when `connection_limit` is unset, so spoofed sources cannot exhaust sockets.
const AMNEZIA_DEFAULT_SESSION_LIMIT: usize = 10_000;
/// Replies from the node are WireGuard datagrams sized for a 1500 byte MTU.
const AMNEZIA_SESSION_BUF: usize = 2048;

/// Upstream socket per client, with the millis since listener start of its last datagram.
type AmneziaSession = (Arc<UdpSocket>, Arc<AtomicU64>);

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

    #[clap(long)]
    /// Print the `<port>/<protocol>` pairs (one per line) that the configured transports listen on,
    /// then exit without starting any listeners. Used by packaging to manage firewall rules.
    print_ports: bool,
}

static PRETTY_BUILD_INFORMATION: OnceLock<String> = OnceLock::new();
// Helper for passing LONG_VERSION to clap
fn pretty_build_info_static() -> &'static str {
    PRETTY_BUILD_INFORMATION.get_or_init(|| bin_info!().pretty_print())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = PersistedServerConfig::parse_file(&args.config_path)?;

    // handled before logging is initialized so that stdout contains only the port list
    if args.print_ports {
        for port in config.listen_ports() {
            println!("{port}");
        }
        return Ok(());
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

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
            TransportServerConfig::SshPlain(options) => {
                transport_listeners.spawn(async {
                    let err_token = cloned_token.clone();
                    if let Err(e) = launch_ssh_listener(cloned_token, fwd_config, options).await {
                        error!("SSH Listener failed: {e}");
                        err_token.cancel();
                    }
                });
            }
            TransportServerConfig::Amnezia(options) => {
                transport_listeners.spawn(async {
                    let err_token = cloned_token.clone();
                    if let Err(e) = launch_amnezia_listener(cloned_token, fwd_config, options).await
                    {
                        error!("Amnezia Listener failed: {e}");
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

async fn launch_ssh_listener(
    token: CancellationToken,
    fwd_cfg: ForwardConfig,
    options: ssh::ServerConfig,
) -> Result<()> {
    let config =
        ssh::create_listener(&options).context("failed to initialize cryptographic config")?;
    let expected_username = options.expected_username();
    let expected_client_pubkey = options
        .client_auth_pubkey()
        .context("failed to derive expected client public key")?;

    let listener = tokio::net::TcpListener::bind(&options.listen).await?;
    tracing::info!("ssh transport listening on {}", &options.listen);

    loop {
        tokio::select! {
            // Use the provided token to listen to cancellation requests
            _ = token.cancelled() => {
                // The token was cancelled, task can shut down
                info!("ssh listener shutting down");
                return Ok(())
            }
            res = listener.accept() => {
                let (stream, address) = res?;
                let config = config.clone();
                let expected_username = expected_username.clone();
                let client_token = token.clone();
                let fwd = fwd_cfg.clone();

                tokio::spawn(async move {
                    match ssh::accept(config, expected_username, expected_client_pubkey, stream).await {
                        Ok(chan_stream) => {
                            handle_ssh_connection(chan_stream, address, fwd, client_token).await;
                        }
                        Err(err) => {
                            // `accept` can fail for reasons other than authentication (protocol
                            // errors, pre-auth timeouts) - the peer's IP is logged specifically
                            // for auth failures, in `ConnectionHandler`'s auth callbacks, not here.
                            warn!("ssh handshake failed: {err}");
                        }
                    }
                });
            }
        }
    }
}

pub async fn handle_ssh_connection(
    stream: ssh::ServerChannelStream,
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
        debug!("accepted ssh connection");

        if let Err(err) = handle_ssh_connection_inner(stream, session, fwd_cfg, token).await {
            warn!("connection error: {err}");
        }
    }
    .instrument(span)
    .await;
}

async fn handle_ssh_connection_inner(
    stream: ssh::ServerChannelStream,
    session: Session,
    fwd_cfg: ForwardConfig,
    token: CancellationToken,
) -> Result<()> {
    let session_token = token.child_token();

    let local_sock = Arc::new(tokio::net::UdpSocket::bind("[::]:0").await?);
    local_sock.connect(fwd_cfg.address).await?;

    let (recv, send) = tokio::io::split(stream);
    process_udp(recv, send, local_sock, session.clone(), 1500, session_token).await;

    info!("end session:"); // in theory handle session logging stats on close

    Ok(())
}

async fn launch_amnezia_listener(
    token: CancellationToken,
    fwd_cfg: ForwardConfig,
    options: amnezia::ServerConfig,
) -> Result<()> {
    let socket = UdpSocket::bind(&options.listen).await?;
    tracing::info!("amnezia transport listening on {}", &options.listen);
    run_amnezia_listener(socket, token, fwd_cfg, options).await
}

/// Owns the session map; session tasks report back on `closed_rx` when they go idle.
async fn run_amnezia_listener(
    socket: UdpSocket,
    token: CancellationToken,
    fwd_cfg: ForwardConfig,
    options: amnezia::ServerConfig,
) -> Result<()> {
    if !options.is_sufficient() {
        anyhow::bail!("amnezia transport params are missing or invalid");
    }
    let params = options.params.context("missing amnezia params")?;
    let limit = options
        .connection_limit
        .unwrap_or(AMNEZIA_DEFAULT_SESSION_LIMIT);
    // Same family as the forward address; `[::]` cannot reach IPv4 on `bindv6only` hosts.
    let upstream_bind: SocketAddr = match fwd_cfg.address {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };

    let socket = Arc::new(socket);
    let started = Instant::now();
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
    let mut sessions = HashMap::new();
    let mut buf = vec![0u8; AMNEZIA_MAX_DATAGRAM];
    loop {
        let (len, client) = tokio::select! {
            _ = token.cancelled() => {
                info!("amnezia listener shutting down");
                return Ok(())
            }
            Some(client) = closed_rx.recv() => {
                sessions.remove(&client);
                continue;
            }
            res = socket.recv_from(&mut buf) => match res {
                Ok(res) => res,
                // Transient socket errors must not take down the other transports.
                Err(e) => {
                    warn!("amnezia receive failed: {e}");
                    continue;
                }
            },
        };
        // Junk and decoy packets are dropped before they can open a session.
        let Some(offset) = amnezia::decode(&params, &mut buf[..len]) else {
            continue;
        };

        let (upstream, last_seen) = match sessions.get(&client) {
            Some(session) => AmneziaSession::clone(session),
            None if sessions.len() >= limit => continue,
            None => {
                let upstream = async {
                    let upstream = UdpSocket::bind(upstream_bind).await?;
                    upstream.connect(fwd_cfg.address).await?;
                    Ok::<_, std::io::Error>(Arc::new(upstream))
                }
                .await;
                let Ok(upstream) =
                    upstream.inspect_err(|e| warn!("amnezia upstream socket failed: {e}"))
                else {
                    continue;
                };
                let session = (upstream, Arc::new(AtomicU64::new(0)));
                sessions.insert(client, session.clone());
                tokio::spawn(amnezia_session(
                    socket.clone(),
                    session.clone(),
                    client,
                    params.clone(),
                    closed_tx.clone(),
                    started,
                    token.clone(),
                ));
                session
            }
        };
        last_seen.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);

        upstream
            .send(&buf[offset..len])
            .await
            .inspect_err(|e| debug!("amnezia forward to {} failed: {e}", fwd_cfg.address))
            .ok();
    }
}

/// Carries the node's replies back to one client until the session goes idle.
async fn amnezia_session(
    socket: Arc<UdpSocket>,
    (upstream, last_seen): AmneziaSession,
    client: SocketAddr,
    params: amnezia::AmneziaParams,
    closed_tx: mpsc::UnboundedSender<SocketAddr>,
    started: Instant,
    token: CancellationToken,
) {
    let mut buf = BytesMut::new();
    loop {
        buf.clear();
        buf.reserve(AMNEZIA_SESSION_BUF);
        let res = tokio::select! {
            _ = token.cancelled() => break,
            res = tokio::time::timeout(AMNEZIA_SESSION_IDLE_TIMEOUT, upstream.recv_buf(&mut buf)) => res,
        };
        match res {
            Ok(Ok(_)) => {}
            // Client traffic alone keeps the session alive.
            Err(_)
                if started.elapsed()
                    < Duration::from_millis(last_seen.load(Ordering::Relaxed))
                        + AMNEZIA_SESSION_IDLE_TIMEOUT =>
            {
                continue;
            }
            _ => break,
        }
        if amnezia::encode(&params, &mut buf) {
            socket
                .send_to(&buf, client)
                .await
                .inspect_err(|e| debug!("amnezia reply to {client} failed: {e}"))
                .ok();
        }
    }
    closed_tx.send(client).ok();
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

#[cfg(test)]
mod test {
    use super::*;

    fn params() -> amnezia::AmneziaParams {
        amnezia::AmneziaParams {
            init_pkt_junk_size: 40,
            response_pkt_junk_size: 50,
            under_load_pkt_magic_header: 1_766_607_858,
            transport_pkt_magic_header: 2_028_465_083,
        }
    }

    fn wg_msg(msg_type: u8, len: usize) -> BytesMut {
        let mut msg = BytesMut::zeroed(len);
        msg[0] = msg_type;
        msg[4..].fill(0x5a);
        msg
    }

    fn encoded(mut msg: BytesMut) -> BytesMut {
        assert!(amnezia::encode(&params(), &mut msg));
        msg
    }

    /// Starts a listener forwarding to `node`, the stand-in for the node's WireGuard socket.
    async fn spawn_listener(node: &UdpSocket, connection_limit: Option<usize>) -> SocketAddr {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let listen = socket.local_addr().unwrap();
        let options = amnezia::ServerConfig {
            listen,
            connection_limit,
            params: Some(params()),
        };
        let fwd_cfg = ForwardConfig {
            address: node.local_addr().unwrap(),
        };
        tokio::spawn(run_amnezia_listener(
            socket,
            CancellationToken::new(),
            fwd_cfg,
            options,
        ));
        listen
    }

    async fn connected_client(listen: SocketAddr) -> UdpSocket {
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client.connect(listen).await.unwrap();
        client
    }

    #[tokio::test]
    async fn amnezia_listener_forwards_plain_wireguard_and_drops_junk() {
        let node = UdpSocket::bind("[::1]:0").await.unwrap();
        let listen = spawn_listener(&node, None).await;
        let client = connected_client(listen).await;
        let mut buf = vec![0u8; 2048];

        client.send(&[0xab; 57]).await.unwrap();
        let junk = tokio::time::timeout(Duration::from_millis(200), node.recv_from(&mut buf)).await;
        assert!(junk.is_err(), "junk must not reach the node");

        client.send(&encoded(wg_msg(1, 148))).await.unwrap();

        let (len, from) = node.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[..len], wg_msg(1, 148)[..]);
        node.send_to(&buf[..len], from).await.unwrap();

        let len = client.recv(&mut buf).await.unwrap();
        assert_eq!(len, 148 + 40);
        assert_eq!(buf[40..44], 1u32.to_le_bytes());
        assert_eq!(buf[44..len], wg_msg(1, 148)[4..]);
    }

    #[tokio::test]
    async fn amnezia_listener_forwards_to_ipv4_node() {
        let node = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = spawn_listener(&node, None).await;
        let client = connected_client(listen).await;
        let mut buf = vec![0u8; 2048];

        client.send(&encoded(wg_msg(1, 148))).await.unwrap();

        let (len, from) = node.recv_from(&mut buf).await.unwrap();
        assert!(from.is_ipv4());
        assert_eq!(buf[..len], wg_msg(1, 148)[..]);
    }

    #[tokio::test]
    async fn amnezia_listener_caps_sessions() {
        let node = UdpSocket::bind("[::1]:0").await.unwrap();
        let listen = spawn_listener(&node, Some(1)).await;
        let mut buf = vec![0u8; 2048];

        for forwarded in [true, false] {
            let client = connected_client(listen).await;
            client.send(&encoded(wg_msg(1, 148))).await.unwrap();
            let res =
                tokio::time::timeout(Duration::from_millis(200), node.recv_from(&mut buf)).await;
            assert_eq!(res.is_ok(), forwarded);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn amnezia_session_survives_client_only_traffic() {
        let node = UdpSocket::bind("[::1]:0").await.unwrap();
        let listen = spawn_listener(&node, None).await;
        let client = connected_client(listen).await;
        let mut buf = vec![0u8; 2048];

        // The node never replies; the session must keep its upstream socket past the idle timeout.
        let mut upstream = None;
        for _ in 0..3 {
            client.send(&encoded(wg_msg(4, 64))).await.unwrap();
            // Busy-poll so the paused clock cannot jump past the idle timeout mid-delivery.
            let from = loop {
                match node.try_recv_from(&mut buf) {
                    Ok((_, from)) => break from,
                    Err(_) => tokio::task::yield_now().await,
                }
            };
            assert_eq!(*upstream.get_or_insert(from), from);
            tokio::time::sleep(Duration::from_secs(150)).await;
        }
    }
}

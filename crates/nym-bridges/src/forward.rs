//! UDP forwarding between a local application socket and a bridge transport
//! connection.
//!
//! A forwarder always has two ends: a "forward" (egress) UDP socket facing the
//! wrapped application traffic, and a "transport" side (a
//! [`BridgeConn`](crate::connection::BridgeConn) or a per-session stream)
//! facing the bridge. There are two roles, split into the
//! [`initiator`](crate::forward::initiator) and
//! [`responder`](crate::forward::responder) submodules:
//!
//! - [`initiator`](crate::forward::initiator) runs on the side that owns a
//!   dedicated UDP socket per connection and does not yet know its peer's
//!   address; it learns the peer address from the first datagram it forwards,
//!   then `connect()`s the socket to it.
//! - [`responder`](crate::forward::responder) runs on the side whose UDP
//!   socket is shared across many sessions, so the peer address is already
//!   known (from the [`Session`](crate::session::Session)) and every datagram
//!   must be explicitly addressed and filtered by source.
//!
//! Both roles share the same steady-state forwarding loop (`udp_to_transport_task`
//! and `transport_to_udp_task`), parameterized over a `UdpPeer` trait so the
//! connected-vs-shared socket difference doesn't have to be duplicated.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UdpSocket,
    sync::mpsc::UnboundedSender,
    task::JoinHandle,
};
use tokio_util::{codec::LengthDelimitedCodec, sync::CancellationToken};
use tracing::*;

use crate::connection::BridgeConn;
use crate::connection::TransportCloser;
use crate::connection::make_socket;
use crate::error::TransportError;

/// Standard Ethernet II MTU, used to size per-datagram receive buffers.
const ETHERNET_V2_MTU: u16 = 1500;
/// Width, in bytes, of the length prefix used to frame datagrams over the
/// transport connection.
const LENGTH_DELIMITER_BYTELEN: usize = 2;
/// How long [`initiator::process_udp`] waits for the first datagram (used to
/// discover the peer address) before giving up.
const INITIAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Distinguishes how a forwarder's UDP socket should receive and send datagrams,
/// so the shared task loops below can be reused across both use cases.
trait UdpPeer: Send + Sync + 'static {
    /// Receive a single datagram, returning its length and source address.
    async fn recv(
        &self,
        sock: &UdpSocket,
        buf: &mut BytesMut,
        fwd_addr: SocketAddr,
    ) -> io::Result<(usize, SocketAddr)>;

    /// Send `data` to `dest`.
    async fn send(&self, sock: &UdpSocket, data: &[u8], dest: SocketAddr) -> io::Result<usize>;
}

/// The socket has already had `connect()` called against `fwd_addr`, so the kernel
/// only delivers datagrams from that peer -- used by [`initiator`], where each
/// forwarder owns a dedicated socket for the lifetime of one connection.
struct ConnectedPeer;

impl UdpPeer for ConnectedPeer {
    async fn recv(
        &self,
        sock: &UdpSocket,
        buf: &mut BytesMut,
        fwd_addr: SocketAddr,
    ) -> io::Result<(usize, SocketAddr)> {
        let len = sock.recv_buf(buf).await?;
        Ok((len, fwd_addr))
    }

    async fn send(&self, sock: &UdpSocket, data: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        sock.send(data).await
    }
}

/// The socket is shared across multiple peer sessions, so datagrams must be
/// explicitly addressed and filtered by source -- used by [`responder`], where one
/// socket multiplexes many sessions.
struct SharedPeer;

impl UdpPeer for SharedPeer {
    async fn recv(
        &self,
        sock: &UdpSocket,
        buf: &mut BytesMut,
        _fwd_addr: SocketAddr,
    ) -> io::Result<(usize, SocketAddr)> {
        sock.recv_buf_from(buf).await
    }

    async fn send(&self, sock: &UdpSocket, data: &[u8], dest: SocketAddr) -> io::Result<usize> {
        sock.send_to(data, dest).await
    }
}

/// Compares two socket addresses for equality, treating an IPv4 address and its
/// IPv4-mapped IPv6 equivalent as the same peer.
fn address_match(original: SocketAddr, incoming: SocketAddr) -> bool {
    if incoming == original {
        true
    } else {
        match (original.ip(), incoming.ip()) {
            (IpAddr::V4(orig), IpAddr::V6(_)) => {
                SocketAddr::from((orig.to_ipv6_mapped(), original.port())) == incoming
            }
            (IpAddr::V6(_), IpAddr::V4(inc)) => {
                original == SocketAddr::from((inc.to_ipv6_mapped(), incoming.port()))
            }
            _ => false,
        }
    }
}

/// Forwards datagrams received on `sock` to the transport side, framed with a
/// length prefix, until `token` is cancelled or an I/O error occurs.
///
/// Datagrams from any address other than `fwd_addr` are silently dropped.
/// `tr_label` is only used for tracing (it identifies the transport side of
/// the forward in log lines, since it may not have a `SocketAddr` of its own).
///
/// Assumes `peer` matches how `sock` was set up (connected vs. shared). On
/// error, this only reports the error upward -- it does not cancel `token`
/// itself; pair it with [`transport_to_udp_task`] via [`run_forward_pair`],
/// which is the single place responsible for cancelling the sibling task.
async fn udp_to_transport_task<W, P, TL>(
    peer: P,
    sock: Arc<UdpSocket>,
    mut framed_writer: W,
    fwd_addr: SocketAddr,
    tr_label: TL,
    mtu: u16,
    token: CancellationToken,
) -> Result<(), io::Error>
where
    W: Sink<bytes::Bytes, Error = io::Error> + Unpin + Send,
    P: UdpPeer,
    TL: std::fmt::Display,
{
    // allocate buffers of mtu size, and take ownership to ensure they can't be resized anymore
    let mut dn_buf = BytesMut::with_capacity(mtu as usize);

    let result = loop {
        tokio::select! {
            res = peer.recv(&sock, &mut dn_buf, fwd_addr) => {
                let (len, src) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        error!("error receiving from forward socket: {e}");
                        break Err(e);
                    }
                };

                if !address_match(fwd_addr, src) {
                    debug!("received {len}B from alt addr {src} -- ignoring");
                    //reset the buffer without any new allocations.
                    dn_buf.clear();
                    if !dn_buf.try_reclaim(mtu as usize) {
                        warn!("unable to reclaim bytes in buffer: {} ", dn_buf.capacity());
                    }
                    continue;
                }

                trace!(" <-{fwd_addr} read {len}B");
                if let Err(e) = framed_writer.send(dn_buf.copy_to_bytes(len)).await {
                    error!("error sending to transport connection: {e}");
                    break Err(e);
                }
                trace!(" {tr_label}<- wrote {len}B");

                //reset the buffer without any new allocations.
                dn_buf.clear();
                if !dn_buf.try_reclaim(mtu as usize) {
                    warn!("unable to reclaim bytes in buffer: {} ", dn_buf.capacity());
                }
            }
            _ = token.cancelled() => {
                debug!("end io copy from {fwd_addr}<->{tr_label}");
                break Ok(());
            }
        }
    };

    // Always attempt a clean shutdown of the transport write side so a proper
    // TLS close_notify (or transport-equivalent) is sent instead of just
    // dropping the socket, regardless of why the loop above ended.
    if let Err(e) = framed_writer.close().await {
        debug!("error closing transport connection: {e}");
    }

    result
}

/// Forwards length-prefixed frames read from `framed_reader` out to `fwd_addr`
/// on `sock`, until `token` is cancelled or an I/O error occurs.
///
/// A frame larger than a single datagram is sent as multiple UDP writes.
/// `tr_label` is only used for tracing, see [`udp_to_transport_task`].
///
/// Assumes `peer` matches how `sock` was set up (connected vs. shared). On
/// error, this only reports the error upward -- see [`run_forward_pair`] for
/// how sibling-task cancellation is handled.
async fn transport_to_udp_task<R, P, TL>(
    peer: P,
    mut framed_reader: R,
    sock: Arc<UdpSocket>,
    fwd_addr: SocketAddr,
    tr_label: TL,
    token: CancellationToken,
) -> Result<(), io::Error>
where
    R: Stream<Item = Result<bytes::BytesMut, io::Error>> + Unpin + Send,
    P: UdpPeer,
    TL: std::fmt::Display,
{
    loop {
        tokio::select! {
            res = framed_reader.next() => {
                match res {
                    None => {
                        info!("connection closed");
                        break;
                    }
                    Some(Ok(buf)) => {
                        let len = buf.len();
                        trace!("{tr_label}-> read {len}B");
                        let mut sent = 0;
                        let mut sends = 1;
                        while sent < len {
                            let len_sent = peer.send(&sock, &buf[sent..len], fwd_addr).await.map_err(|e| {
                                error!("error sending to egress socket: {e}");
                                e
                            })?;
                            sent += len_sent;
                            trace!(" ->{fwd_addr} wrote {len_sent}B {sends} send");
                            sends +=1;
                        }
                    }
                    Some(Err(e)) => {
                        error!("error reading from transport conn: {e}");
                        return Err(e);
                    }
                }
            }
            _ = token.cancelled() => {
                debug!("end io copy from {fwd_addr}<->{tr_label}");
                break;
            }
        }
    }
    Ok(())
}

/// Runs `recv_task` and `send_task` (the two halves of a forwarder spawned by
/// [`initiator::process_udp`] or [`responder::process_udp`]) concurrently, and
/// cancels `token` as soon as either one exits -- for any reason, success or
/// error -- so the other stops too.
///
/// This is the single place responsible for cross-task cancellation: the task
/// futures themselves only need to react to `token` being cancelled (via their
/// `token.cancelled()` select branch), never to cancel it. Callers must give
/// each task future its own clone of the *same* `token` passed here -- an
/// independent child token would not be affected by the cancellation this
/// function performs, defeating the purpose.
async fn run_forward_pair<F1, F2>(recv_task: F1, send_task: F2, token: CancellationToken)
where
    F1: Future<Output = Result<(), io::Error>> + Send + 'static,
    F2: Future<Output = Result<(), io::Error>> + Send + 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(recv_task);
    tasks.spawn(send_task);

    let mut token = Some(token);

    // Wait for both tasks to complete; if either one exits, make sure to cancel the other as well.
    while let Some(res) = tasks.join_next().await {
        if let Err(err) = res {
            error!("bridge udp forwarder join error: {err}");
        } else if let Ok(Err(err)) = res {
            error!("bridge udp forwarder error: {err}");
        }

        // Cancel all tasks if any of sub-tasks exit for any reason
        if let Some(token) = token.take() {
            token.cancel();
        }
    }
}

/// Entry point for launching the initiator side of a UDP forwarder.
///
/// See the [module docs](self) for how this relates to [`responder`].
pub struct UdpForwarder {}

impl UdpForwarder {
    /// Binds a fresh UDP socket and spawns a background task that forwards
    /// datagrams between it and `egress_conn`, learning the peer address from
    /// the first datagram received (see [`initiator::process_udp`]).
    ///
    /// Returns the local address the socket is bound to (so the caller can
    /// hand it to whatever local application should send/receive on it) and a
    /// handle to the spawned forwarding task. If `close_tx` is provided, a
    /// message is sent on it once the forwarder shuts down. `token` cancels
    /// the forwarder early.
    pub async fn launch_initiator(
        egress_conn: BridgeConn,
        bind_addr: Option<SocketAddr>,
        close_tx: Option<UnboundedSender<()>>,
        token: CancellationToken,
        initial_conn_timeout: Option<Duration>,
    ) -> Result<(SocketAddr, JoinHandle<()>), TransportError> {
        let bind_addr = bind_addr.unwrap_or(match egress_conn.endpoint.is_ipv4() {
            true => (Ipv4Addr::LOCALHOST, 0).into(),
            false => (Ipv6Addr::LOCALHOST, 0).into(),
        });
        let socket = make_socket(Some(bind_addr)).map_err(TransportError::SocketIo)?;
        let socket = Arc::new(UdpSocket::from_std(socket).map_err(TransportError::SocketIo)?);
        let local_addr = socket.local_addr().map_err(TransportError::SocketIo)?;

        info!("udp forwarder started listening on: {local_addr}",);

        Ok((
            local_addr,
            tokio::spawn(initiator::process_udp(
                egress_conn.reader,
                egress_conn.writer,
                egress_conn.closer,
                socket.clone(),
                ETHERNET_V2_MTU,
                close_tx,
                token,
                initial_conn_timeout,
            )),
        ))
    }
}

/// The side of a forwarder that owns a dedicated UDP socket per connection and
/// does not yet know its peer's address.
pub mod initiator {
    use super::*;

    /// Drives a single UDP forwarder over `sock` and the transport `reader`/`writer`.
    ///
    /// Blocks (without spawning) until either the first datagram is received on
    /// `sock` -- establishing the peer address the socket then `connect()`s to
    /// -- or `INITIAL_CONNECTION_TIMEOUT` elapses / `token` is cancelled, in
    /// which case the function returns having done nothing further. Once the
    /// peer address is established, spawns the steady-state forwarding tasks
    /// and runs until either side exits or `token` is cancelled, cancelling the
    /// other task in turn. `closer` is closed on every exit path, so the
    /// underlying transport connection (not just the `reader`/`writer` split
    /// from it) always ends cleanly. `close_tx`, if provided, is signalled
    /// once the forwarder has shut down.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_udp<R, W>(
        reader: R,
        writer: W,
        closer: Box<dyn TransportCloser>,
        sock: Arc<UdpSocket>,
        mtu: u16,
        // close_hook: Option<fn(SocketAddr)>,
        close_tx: Option<UnboundedSender<()>>,
        token: CancellationToken,
        initial_conn_timeout: Option<Duration>,
    ) where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        info!("starting udp forward");

        let mut dn_buf = BytesMut::with_capacity(mtu as usize);

        let mut framed_writer = LengthDelimitedCodec::builder()
            .length_field_length(LENGTH_DELIMITER_BYTELEN)
            .new_write(writer);

        let framed_reader = LengthDelimitedCodec::builder()
            .length_field_length(LENGTH_DELIMITER_BYTELEN)
            .new_read(reader);

        let conn_timeout = initial_conn_timeout.unwrap_or(INITIAL_CONNECTION_TIMEOUT);
        // receive (and forward) a first message to establish a consistent peer address
        let fwd_initial_recv_fut =
            tokio::time::timeout(conn_timeout, sock.recv_buf_from(&mut dn_buf));

        let fwd_addr = match token.run_until_cancelled(fwd_initial_recv_fut).await {
            Some(res) => {
                match res {
                    Ok(Ok((len, src))) => {
                        trace!(" <- [fw] read {len}B");
                        if let Err(e) = framed_writer.send(dn_buf.copy_to_bytes(len)).await {
                            debug!("error sending to transport connection: {e}");
                            None
                        } else {
                            trace!("[tr] <- wrote {len}B");
                            // keep track of the address of the sender for the initial write
                            Some(src)
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("error receiving from egress socket: {e}");
                        None
                    }
                    Err(_) => {
                        debug!("forwarder timed out");
                        None
                    }
                }
            }
            None => {
                debug!("forwarder cancelled before initial receive");
                None
            }
        };

        let Some(fwd_addr) = fwd_addr else {
            tokio::spawn(closer.close());
            if let Some(tx) = close_tx {
                tx.send(()).ok();
            }
            return;
        };

        if let Err(e) = sock.connect(fwd_addr).await {
            error!("udp sock config failure: {e}");
            tokio::spawn(closer.close());
            if let Some(tx) = close_tx {
                tx.send(()).ok();
            }
            return;
        }

        run_forward_pair(
            udp_to_transport_task(
                ConnectedPeer,
                sock.clone(),
                framed_writer,
                fwd_addr,
                "[tr]",
                mtu,
                token.clone(),
            ),
            transport_to_udp_task(
                ConnectedPeer,
                framed_reader,
                sock.clone(),
                fwd_addr,
                "[tr]",
                token.clone(),
            ),
            token,
        )
        .await;

        // End the underlying transport connection now that forwarding is done
        // with it -- see `TransportCloser` for why this is more than just the
        // write-half shutdown `udp_to_transport_task` already does, and why
        // it's spawned rather than awaited here (it may need to wait on the
        // peer, which we don't want to block the forwarder's own shutdown on;
        // `TransportCloser` impls are responsible for bounding that wait).
        tokio::spawn(closer.close());

        if let Some(tx) = close_tx {
            tx.send(()).ok();
        }

        info!("transport udp forwarder shutdown");
    }
}

/// The side of a forwarder whose UDP socket is shared across many sessions, so
/// the peer address is already known and every datagram must be filtered by
/// source address.
pub mod responder {
    use super::*;
    use crate::session::Session;

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// Drives a single UDP forwarder for `session` over the shared `sock` and
    /// the transport `rd`/`wr`.
    ///
    /// Unlike [`initiator::process_udp`], both peer addresses are already known
    /// (from `session`), so this immediately spawns the steady-state forwarding
    /// tasks and waits for both to complete or `token` to be cancelled.
    pub async fn process_udp<R, W>(
        rd: R,
        wr: W,
        sock: Arc<UdpSocket>,
        session: Session,
        // close_hook: Option<fn(SocketAddr)>,
        mtu: u16,
        token: CancellationToken,
    ) where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let tr_addr = session.transport_remote();
        let fw_addr = session.forward_remote();
        let local_fw_addr = sock.local_addr().unwrap();
        info!("starting udp forward {tr_addr:?}->([tr_local] -> {local_fw_addr:?}) -> {fw_addr:?}");

        let framed_writer = LengthDelimitedCodec::builder()
            .length_field_length(LENGTH_DELIMITER_BYTELEN)
            .new_write(LoggingIo::new(wr, "".into()));
        let framed_reader = LengthDelimitedCodec::builder()
            .length_field_length(LENGTH_DELIMITER_BYTELEN)
            .new_read(LoggingIo::new(rd, "".into()));

        run_forward_pair(
            udp_to_transport_task(
                SharedPeer,
                sock.clone(),
                framed_writer,
                fw_addr,
                tr_addr,
                mtu,
                token.clone(),
            ),
            transport_to_udp_task(
                SharedPeer,
                framed_reader,
                sock.clone(),
                fw_addr,
                tr_addr,
                token.clone(),
            ),
            token,
        )
        .await;

        drop(sock);
    }

    /// Wraps an [`AsyncRead`]/[`AsyncWrite`] to trace the number of bytes read
    /// and written, tagged with `name`.
    struct LoggingIo<T> {
        inner: T,
        name: String,
    }

    impl<T> LoggingIo<T> {
        fn new(inner: T, name: String) -> Self {
            Self { inner, name }
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for LoggingIo<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let before = buf.filled().len();
            let result = Pin::new(&mut self.inner).poll_read(cx, buf);

            if let Poll::Ready(Ok(())) = &result {
                let bytes_read = buf.filled().len() - before;
                if bytes_read > 0 {
                    trace!("{}: Read {} bytes", self.name, bytes_read,);
                }
            }

            result
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for LoggingIo<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let result = Pin::new(&mut self.inner).poll_write(cx, buf);

            if let Poll::Ready(Ok(bytes_written)) = &result
                && *bytes_written > 0
            {
                trace!("{}: Wrote {} bytes", self.name, bytes_written,);
            }

            result
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), tokio::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), tokio::io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use std::net::SocketAddr;

        #[test]
        fn addr_equality() {
            let addr1: SocketAddr = "[::ffff:178.79.168.250]:51822".parse().unwrap();
            let addr2: SocketAddr = "178.79.168.250:51822".parse().unwrap();
            assert_ne!(addr1, addr2);

            assert!(address_match(addr1, addr2));
            assert!(address_match(addr2, addr1));
            assert!(address_match(addr1, addr1));
            assert!(address_match(addr2, addr2));

            let addr3: SocketAddr = "192.168.1.1:51822".parse().unwrap(); // different address
            let addr4: SocketAddr = "178.79.168.250:9000".parse().unwrap(); // different port

            assert!(!address_match(addr1, addr3));
            assert!(!address_match(addr3, addr1));
            assert!(!address_match(addr2, addr3));
            assert!(!address_match(addr3, addr2));
            assert!(!address_match(addr1, addr4));
            assert!(!address_match(addr4, addr1));
            assert!(!address_match(addr2, addr4));
            assert!(!address_match(addr4, addr2));
        }
    }
}

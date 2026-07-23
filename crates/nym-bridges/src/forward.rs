use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
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
use crate::connection::make_socket;
use crate::error::TransportError;

const ETHERNET_V2_MTU: u16 = 1500;
const LENGTH_DELIMITER_BYTELEN: usize = 2;
const INITIAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct UdpForwarder {}

impl UdpForwarder {
    pub async fn launch(
        egress_conn: BridgeConn,
        bind_addr: Option<SocketAddr>,
        close_tx: Option<UnboundedSender<()>>,
        token: CancellationToken,
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
            tokio::spawn(process_udp(
                egress_conn.reader,
                egress_conn.writer,
                socket.clone(),
                ETHERNET_V2_MTU,
                close_tx,
                token,
            )),
        ))
    }
}

pub async fn process_udp<R, W>(
    reader: R,
    writer: W,
    sock: Arc<UdpSocket>,
    mtu: u16,
    // close_hook: Option<fn(SocketAddr)>,
    close_tx: Option<UnboundedSender<()>>,
    token: CancellationToken,
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

    // receive (and forward) a first message to establish a consistent peer address
    let fwd_initial_recv_fut =
        tokio::time::timeout(INITIAL_CONNECTION_TIMEOUT, sock.recv_buf_from(&mut dn_buf));

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
        if let Some(tx) = close_tx {
            tx.send(()).ok();
        }
        return;
    };

    if let Err(e) = sock.connect(fwd_addr).await {
        error!("udp sock config failure: {e}");
        if let Some(tx) = close_tx {
            tx.send(()).ok();
        }
        return;
    }

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(udp_to_transport_task(
        sock.clone(),
        framed_writer,
        fwd_addr,
        mtu,
        token.child_token(),
    ));
    tasks.spawn(transport_to_udp_task(
        framed_reader,
        sock.clone(),
        fwd_addr,
        token.child_token(),
    ));

    let mut token = Some(token);

    // Wait for both tasks to complete, if either one exits, make sure to cancel the other as well.
    while let Some(res) = tasks.join_next().await {
        if let Err(err) = res {
            tracing::error!("bridge udp forwarder join error: {err}");
        } else if let Ok(Err(err)) = res {
            tracing::error!("bridge udp forwarder error: {err}");
        }

        // Cancel all tasks if any of sub-tasks exit for any reason
        if let Some(token) = token.take() {
            token.cancel();
        }
    }

    if let Some(tx) = close_tx {
        tx.send(()).ok();
    }

    info!("transport udp forwarder shutdown");
}

// Assumes that the socket has already had `connect` called.
async fn udp_to_transport_task<W>(
    sock: Arc<UdpSocket>,
    mut framed_writer: W,
    fwd_addr: SocketAddr,
    mtu: u16,
    token: CancellationToken,
) -> Result<(), io::Error>
where
    W: Sink<bytes::Bytes, Error = io::Error> + Unpin + Send,
{
    // allocate buffers of mtu size, and take ownership to ensure they can't be resized anymore
    let mut dn_buf = BytesMut::with_capacity(mtu as usize);

    loop {
        tokio::select! {
            res = sock.recv_buf(&mut dn_buf) => {
                let len = res.map_err(|e| {
                    error!("error receiving from forward socket: {e}");
                    e
                })?;

                trace!(" <-{fwd_addr} read {len}B");
                framed_writer.send(dn_buf.copy_to_bytes(len)).await.map_err(|e| {
                    error!("error sending to transport connection: {e}");
                    e
                })?;
                trace!(" [tr]<- wrote {len}B");

                //reset the buffer without any new allocations.
                dn_buf.clear();
                if !dn_buf.try_reclaim(mtu as usize) {
                    warn!("unable to reclaim bytes in buffer: {} ", dn_buf.capacity());
                }
            }
            _ = token.cancelled() => {
                debug!("end io copy from {fwd_addr}<->[tr]");
                break;
            }
        }
    }
    Ok(())
}

// Assumes that the socket has already had `connect` called.
async fn transport_to_udp_task<R>(
    mut framed_reader: R,
    sock: Arc<UdpSocket>,
    fwd_addr: SocketAddr,
    token: CancellationToken,
) -> Result<(), io::Error>
where
    R: Stream<Item = Result<bytes::BytesMut, io::Error>> + Unpin + Send,
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
                        trace!("[tr]-> read {len}B");
                        let mut sent = 0;
                        let mut sends = 1;
                        while sent < len {
                            let len_sent = sock.send(&buf[sent..len]).await.map_err(|e| {
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
                debug!("end io copy");
                break;
            }
        }
    }
    Ok(())
}

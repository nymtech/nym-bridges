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
    pub async fn launch_initiator(
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
            tokio::spawn(initiator::process_udp(
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

pub mod initiator {
    use super::*;

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
}

pub mod responder {
    use super::*;
    use crate::session::Session;
    use std::net::IpAddr;

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

        let mut tasks = tokio::task::JoinSet::new();

        tasks.spawn(udp_to_transport_task(
            sock.clone(),
            wr,
            fw_addr,
            tr_addr,
            mtu,
            token.clone(),
        ));
        tasks.spawn(transport_to_udp_task(
            rd,
            sock.clone(),
            fw_addr,
            tr_addr,
            token.clone(),
        ));

        // Wait for both tasks to complete
        let _ = tasks.join_all().await;

        drop(sock);
    }

    async fn udp_to_transport_task<W>(
        sock: Arc<UdpSocket>,
        wr: W,
        fw_addr: SocketAddr,
        tr_addr: SocketAddr,
        mtu: u16,
        token: CancellationToken,
    ) -> Result<(), io::Error>
    where
        W: AsyncWrite + Unpin + Send,
    {
        // allocate buffers of mtu size, and take ownership to ensure they can't be resized anymore
        // let up_buf = &mut vec![0u8; mtu as usize].into_boxed_slice()[..];
        let mut dn_buf = BytesMut::with_capacity(mtu as usize);

        let mut wrf = LengthDelimitedCodec::builder()
            .length_field_length(2)
            .new_write(LoggingIo::new(wr, "".into()));

        loop {
            tokio::select! {
                res = sock.recv_buf_from(&mut dn_buf) => {
                    let (len, src) = res.map_err(|e| {
                        error!("error receiving from forward socket: {e}");
                        token.cancel();
                        e
                    })?;

                    if !address_match(fw_addr, src) {
                        debug!("received {len}B from alt addr {src} -- ignoring");
                        continue;
                    }

                    trace!(" <-{fw_addr} read {len}B");
                    wrf.send(dn_buf.copy_to_bytes(len)).await.map_err(|e| {
                        error!("error sending to transport connection: {e}");
                        token.cancel();
                        e
                    })?;
                    trace!(" {tr_addr}<- wrote {len}B");

                    //reset the buffer without any new allocations.
                    dn_buf.clear();
                    if !dn_buf.try_reclaim(mtu as usize) {
                        warn!("unable to reclaim bytes in buffer: {} ", dn_buf.capacity());
                    }
                }
                _ = token.cancelled() => {
                    debug!("end io copy from {fw_addr}<->{tr_addr}");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn transport_to_udp_task<R>(
        rd: R,
        sock: Arc<UdpSocket>,
        fw_addr: SocketAddr,
        tr_addr: SocketAddr,
        token: CancellationToken,
    ) -> Result<(), io::Error>
    where
        R: AsyncRead + Unpin + Send,
    {
        let mut rdf = LengthDelimitedCodec::builder()
            .length_field_length(2)
            .new_read(LoggingIo::new(rd, "".into()));

        loop {
            tokio::select! {
                res = rdf.next() => {
                    match res {
                        None => {
                            info!("connection closed");
                            break;
                        }
                        Some(Ok(buf)) => {
                            let len = buf.len();
                            trace!("{tr_addr}-> read {len}B");
                            let mut sent = 0;
                            let mut sends = 1;
                            while sent < len {
                                let len_sent = sock.send_to(&buf[sent..len], fw_addr).await.map_err(|e| {
                                    error!("error sending to egress socket: {e}");
                                    token.cancel();
                                    e
                                })?;
                                sent += len_sent;
                                trace!(" ->{fw_addr} wrote {len_sent}B {sends} send");
                                sends +=1;
                            }
                        }
                        Some(Err(e)) => {
                            error!("error reading from transport conn: {e}");
                            token.cancel();
                            return Err(e);
                        }
                    }
                }
                _ = token.cancelled() => {
                    debug!("end io copy from {fw_addr}<->{tr_addr}");
                    break;
                }
            }
        }
        Ok(())
    }

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

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

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

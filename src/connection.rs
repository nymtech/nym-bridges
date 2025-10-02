use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use bytes::{Buf, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::sync::CancellationToken;
use tracing::*;

use crate::session::Session;

pub async fn copy_bidirectional<IR, IS, ER, ES>(
    token: CancellationToken,
    ingress_addr: SocketAddr,
    mut ingress_recv: IR,
    mut ingress_send: IS,
    mut egress_recv: ER,
    mut egress_send: ES,
) -> Result<()>
where
    IR: AsyncRead + Unpin + Send,
    IS: AsyncWrite + Unpin + Send,
    ER: AsyncRead + Unpin + Send,
    ES: AsyncWrite + Unpin + Send,
{
    tokio::select! {
        res = tokio::io::copy(&mut egress_recv, &mut ingress_send) => {
            if let Err(e) = res {
                error!("failed to copy: {e}");
            } else {
                debug!("connection {ingress_addr} closed");
            }
        }
        res = tokio::io::copy(&mut ingress_recv, &mut egress_send) => {
            if let Err(e) = res {
                error!("failed to copy: {e}");
            } else {
                debug!("connection {ingress_addr} closed");
            }
        }
        _ = token.cancelled() => {
            debug!("closing connection from: {ingress_addr}");
        }
    }

    ingress_send.flush().await.unwrap_or_else(|e| {
        error!("failed to flush local connection on close: {}", e);
    });
    ingress_send.shutdown().await.unwrap_or_else(|e| {
        error!("failed to close ingress connection: {}", e);
    });
    egress_send.shutdown().await.unwrap_or_else(|e| {
        error!("failed to close egress connection: {}", e);
    });

    // Ok(session)
    Ok(())
}

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
) -> Result<()>
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
) -> Result<()>
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
                        return Err(e.into());
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
                trace!(
                    "{}: Read {} bytes {}",
                    self.name,
                    bytes_read,
                    hex::encode(buf.filled())
                );
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
            trace!(
                "{}: Wrote {} bytes {}",
                self.name,
                bytes_written,
                hex::encode(buf)
            );
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

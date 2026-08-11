#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::RawFd;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Instant,
};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::*;

use crate::transport::{quic, ssh, tls};
use crate::{config::ClientConfig, error::TransportError};
use nym_bridges_types::TransportAssociation;

pub(crate) fn make_socket(addr: Option<SocketAddr>) -> std::io::Result<std::net::UdpSocket> {
    let addr = addr.unwrap_or((Ipv4Addr::UNSPECIFIED, 0).into());
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(non_snake_case)]
pub fn SOCKET_OPEN_NOP(_: RawFd) {}

pub struct BridgeConn {
    /// Configured parameters from which this bridge connections was built
    #[allow(unused)] // we will want these later for metrics tracking
    pub(crate) params: ClientConfig,
    /// Remote address of the bridge transport connection
    pub(crate) endpoint: SocketAddr,
    pub(crate) reader: Box<dyn AsyncRead + Send + Unpin>,
    pub(crate) writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub(crate) closer: Box<dyn TransportCloser>,
}

/// Ends the underlying transport connection once a caller is done forwarding
/// over the `reader`/`writer` split from it -- distinct from shutting down
/// those halves, since for some transports the connection outlives the
/// stream they were split from.
///
/// Each transport implements this with whatever it needs beyond a plain
/// write-half shutdown. For TLS, the stream *is* the connection, so shutting
/// down the write half (which sends a `close_notify`) already ends the
/// connection cleanly and this is a no-op. For QUIC, `reader`/`writer` are
/// only one multiplexed stream on a [`quinn::Connection`] that outlives it --
/// see the `quinn::Connection` impl for why closing it is not just "call
/// `close()`".
pub trait TransportCloser: Send {
    fn close(self: Box<Self>) -> futures::future::BoxFuture<'static, ()>;
}

/// The TLS stream and connection are one and the same, so there's nothing
/// left to do beyond the write-half shutdown callers already perform.
impl TransportCloser for () {
    fn close(self: Box<Self>) -> futures::future::BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

impl BridgeConn {
    pub async fn try_connect(
        params: ClientConfig,
        token: CancellationToken,
        #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: impl FnOnce(RawFd),
    ) -> Result<Self, TransportError> {
        let start = Instant::now();

        match params {
            ClientConfig::QuicPlain(ref opts) => {
                let conn = token
                    .run_until_cancelled(quic::transport_conn(
                        opts,
                        #[cfg(any(target_os = "linux", target_os = "android"))]
                        on_socket_open,
                    ))
                    .await
                    .ok_or(TransportError::Cancelled)??;
                let endpoint = conn.remote_address();
                // .context("failed to connect to transport conn")?;
                let (writer, reader) = token
                    .run_until_cancelled(conn.open_bi())
                    .await
                    .ok_or(TransportError::Cancelled)??;
                // .context("failed to connect to transport stream")?;
                info!("quic transport connected in {:?}", start.elapsed());
                Ok(Self {
                    reader: Box::new(reader),
                    writer: Box::new(writer),
                    params,
                    endpoint,
                    closer: Box::new(conn),
                })
            }
            ClientConfig::TlsPlain(ref opts) => {
                let conn = token
                    .run_until_cancelled(tls::transport_conn(
                        opts,
                        #[cfg(any(target_os = "linux", target_os = "android"))]
                        on_socket_open,
                    ))
                    .await
                    .ok_or(TransportError::Cancelled)??;

                let endpoint = conn.get_ref().0.peer_addr()?;

                info!(
                    "{} transport connected in {:?}",
                    opts.transport_name(),
                    start.elapsed()
                );
                let (reader, writer) = tokio::io::split(conn);
                Ok(Self {
                    reader: Box::new(reader),
                    writer: Box::new(writer),
                    params,
                    endpoint,
                    closer: Box::new(()),
                })
            }
            ClientConfig::SshPlain(ref opts) => {
                let endpoint = *opts.addresses.first().ok_or_else(|| {
                    TransportError::config_err("no ssh bridge address configured")
                })?;
                let stream = token
                    .run_until_cancelled(ssh::transport_conn(opts))
                    .await
                    .ok_or(TransportError::Cancelled)??;
                let (reader, writer) = tokio::io::split(stream);
                info!("ssh transport connected in {:?}", start.elapsed());
                Ok(Self {
                    reader: Box::new(reader),
                    writer: Box::new(writer),
                    params,
                    endpoint,
                    closer: Box::new(()),
                })
            }
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// The parameters this connection was built from.
    pub fn params(&self) -> &ClientConfig {
        &self.params
    }

    /// Split into the raw duplex halves of the transport stream, for callers
    /// that want to frame it themselves (e.g. length-delimited datapath
    /// packets) rather than going through [`crate::forward::UdpForwarder`].
    ///
    /// The returned [`TransportCloser`] must be `close()`d once the caller is
    /// done forwarding over the reader/writer halves -- see its docs for why
    /// this is a separate step from shutting those halves down.
    pub fn into_parts(
        self,
    ) -> (
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
        Box<dyn TransportCloser>,
    ) {
        (self.reader, self.writer, self.closer)
    }
}

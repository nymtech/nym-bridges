#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::RawFd;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Instant,
};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::*;

use crate::transport::quic;
use crate::{config::ClientConfig, error::TransportError};

pub(crate) fn make_socket(addr: Option<SocketAddr>) -> std::io::Result<std::net::UdpSocket> {
    let addr = addr.unwrap_or((Ipv4Addr::UNSPECIFIED, 0).into());
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub struct BridgeConn {
    /// Configured parameters from which this bridge connections was built
    #[allow(unused)] // we will want these later for metrics tracking
    pub(crate) params: ClientConfig,
    /// Remote address of the bridge transport connection
    pub(crate) endpoint: SocketAddr,
    pub(crate) reader: Box<dyn AsyncRead + Send + Unpin>,
    pub(crate) writer: Box<dyn AsyncWrite + Send + Unpin>,
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
                })
            }
            ClientConfig::TlsPlain(ref _opts) => {
                error!("implementation in progress");
                Err(TransportError::other("implementation ongoing"))
            }
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

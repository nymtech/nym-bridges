use std::net::SocketAddr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::{AsRawFd, RawFd};

use tokio::net::{TcpSocket, TcpStream};

use crate::error::TransportError;

/// Opens a TCP connection to `addr`, calling `on_socket_open` with the socket before it connects
/// so Linux and Android callers can mark or bypass it.
pub(crate) async fn connect_one(
    addr: SocketAddr,
    #[cfg(any(target_os = "linux", target_os = "android"))] on_socket_open: &impl Fn(RawFd),
) -> Result<TcpStream, TransportError> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(TransportError::SocketIo)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    on_socket_open(socket.as_raw_fd());

    socket.connect(addr).await.map_err(TransportError::SocketIo)
}

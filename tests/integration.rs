use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

use std::env;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Once;
use std::task::{Context, Poll};
use std::time::Duration;

use nym_bridges::connection::process_udp;
use nym_bridges::session::Session;

mod sender;
use sender::*;

static SUBSCRIBER_INIT: Once = Once::new();

#[allow(unused)]
pub fn init_subscriber(maybe_level: Option<LevelFilter>) {
    SUBSCRIBER_INIT.call_once(|| {
        let lf = maybe_level.unwrap_or_else(|| {
            let level = env::var("RUST_LOG_LEVEL").unwrap_or("error".into());
            LevelFilter::from_str(&level).unwrap()
        });

        tracing_subscriber::fmt().with_max_level(lf).init();
    });
}

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

        if let Poll::Ready(Ok(bytes_written)) = &result {
            if *bytes_written > 0 {
                trace!(
                    "{}: Wrote {} bytes {}",
                    self.name,
                    bytes_written,
                    hex::encode(buf)
                );
            }
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

#[tokio::test]
async fn udp_length_delimited() {
    // let level = Some(tracing::level_filters::LevelFilter::TRACE);
    // init_subscriber(level);
    let (ct_conn, srv_conn) = tokio::io::duplex(1500);
    let ct_conn = LoggingIo::new(ct_conn, "CLIENT".to_string());
    let srv_conn = LoggingIo::new(srv_conn, "SERVER".to_string());

    let client_udp1 = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
    let client_udp2 = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
    client_udp2
        .connect(client_udp1.local_addr().unwrap())
        .await
        .unwrap();
    let client_session = Session::new(
        &client_udp2.local_addr().unwrap(),
        &"[::1]:1000".parse().unwrap(), // fake transport remote address
    );

    let server_udp1 = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
    let server_udp2 = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
    server_udp2
        .connect(server_udp1.local_addr().unwrap())
        .await
        .unwrap();
    let server_session = Session::new(
        &server_udp2.local_addr().unwrap(),
        &"[::1]:2001".parse().unwrap(), // fake transport remote address
    );

    let token = CancellationToken::new();
    let mtu = 1500;

    let mut threads = tokio::task::JoinSet::new();

    let (ct_conn_rd, ct_conn_wr) = tokio::io::split(ct_conn);
    threads.spawn(process_udp(
        ct_conn_rd,
        ct_conn_wr,
        client_udp1.clone(),
        client_session,
        mtu,
        token.clone(),
    ));

    let (srv_conn_rd, srv_conn_wr) = tokio::io::split(srv_conn);
    threads.spawn(process_udp(
        srv_conn_rd,
        srv_conn_wr,
        server_udp1.clone(),
        server_session,
        mtu,
        token.clone(),
    ));

    // server listening for incoming packet and echo them back across the connection
    let su2 = server_udp2.clone();
    let su_token = token.clone();
    tokio::spawn(async move {
        let mut buf = [0; 1500];
        loop {
            tokio::select! {
                _ = su_token.cancelled() => {
                    tracing::debug!("server closed");
                    return;
                }
                res = su2.recv(&mut buf) =>  {
                    let len = res.unwrap();
                    let len = su2.send(&buf[..len]).await.unwrap();
                    tracing::debug!("server echo {:?}B", len);
                }
            }
        }
    });

    // client listen for incoming packets and log
    let cu2 = client_udp2.clone();
    let cu_token = token.clone();
    threads.spawn(async move {
        let mut buf = [0; 1500];
        loop {
            tokio::select! {
                _ = cu_token.cancelled() => {
                    tracing::debug!("client closed");
                    return;
                }
                res = cu2.recv(&mut buf) => {
                    tracing::debug!("client recv {:?}B", res.unwrap());
                }
            }
        }
    });

    tracing::info!(
        "sending UDP packets {} -> {}",
        client_udp1.local_addr().unwrap(),
        client_udp2.local_addr().unwrap(),
    );

    // Example usage - configure your desired packet generation pattern
    let size = Size::Random { min: 64, max: 1400 };
    // let rate = Rate::Fixed(Duration::from_millis(100));
    let rate = Rate::Asap;
    let count = Count::N(5);
    let generator = Generator::new(size, rate, count);

    sender::send_packets(
        client_udp2,
        client_udp1.local_addr().unwrap(),
        generator,
        false,
    )
    .await;

    sleep(Duration::from_millis(1000)).await;
    token.cancel();
    threads.join_all().await;
}

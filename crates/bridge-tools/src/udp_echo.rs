use std::{io, net::SocketAddr, sync::Arc};

use clap::Parser;
use tokio::{net::UdpSocket, sync::mpsc};

#[derive(Parser, Debug, Clone)]
struct Args {
    #[clap(short = 'l', long = "listen", default_value = "[::1]:50001")]
    listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();
    let sock = UdpSocket::bind(args.listen_addr).await?;
    let r = Arc::new(sock);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    tracing::info!("listening for udp echo on {}", args.listen_addr);

    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx.recv().await {
            let len = s.send_to(&bytes, &addr).await.unwrap();
            if len > 0 {
                tracing::info!("{len:?} bytes sent to {addr:?}");
            }
        }
    });

    let mut buf = [0; 1500];
    loop {
        let (len, addr) = r.recv_from(&mut buf).await?;
        tracing::info!("{len:?} bytes received from {addr:?}");
        tx.send((buf[..len].to_vec(), addr)).await.unwrap();
    }
}

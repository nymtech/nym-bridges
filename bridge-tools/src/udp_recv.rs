//! UDP Packet Sender
//!
//! This binary is used to send packets to a udp target with specific rates and sizes
//! to test the fidelity of the UDP forwarder and the transport wrappers.
//!
//! Some effort is taken to make sure that this program is NOT throttled by allocation
//! and sends at the desired rates.

use std::{io, net::SocketAddr, sync::Arc};

use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;
use tokio::{net::UdpSocket, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing::*;

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(short, long)]
    // Value used to seed the prng used for packet generation.
    seed: Option<u64>,

    #[arg(short, long)]
    // Address to bind for the sending socket
    bind: Option<SocketAddr>,

    #[arg(short, conflicts_with = "very_verbose")]
    verbose: bool,

    #[arg(long = "vv", conflicts_with = "verbose")]
    very_verbose: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let level = match (args.verbose, args.very_verbose) {
        (false, false) => tracing::Level::INFO,
        (true, false) => tracing::Level::DEBUG,
        (false, true) => tracing::Level::TRACE,
        _ => panic!("verbosity arg conflict"),
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    let listen_addr = args.bind.unwrap_or("[::]:0".parse().unwrap());
    let sock = UdpSocket::bind(listen_addr).await?;
    let sock = Arc::new(sock);

    tracing::info!("receiving UDP packets -> {}", sock.local_addr().unwrap(),);

    // Example usage - configure your desired packet generation pattern
    let size = Size::Random { min: 64, max: 1400 };
    let generator = Generator::new(size, 5, args.seed);
    let expected = Receiver::new(generator);

    let token = CancellationToken::new();
    let cancel = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        println!("ctrl-c input");
        cancel.cancel();
    });

    receive_packets(sock, expected, args.very_verbose, token).await;

    Ok(())
}

async fn receive_packets(
    sock: Arc<UdpSocket>,
    mut receiver: Receiver,
    trace: bool,
    token: CancellationToken,
) {
    let mut buf = vec![0u8; 2_usize.pow(16)];
    while !receiver.completed() {
        tokio::select! {
            _ = token.cancelled() => {break}
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((len, src)) => {
                        let idx = if len >= 4 {
                            let mut ubuf = [0u8; 4];
                            ubuf.copy_from_slice(&buf[..4]);
                            u32::from_be_bytes(ubuf)
                        } else {
                            0
                        };
                        if trace {
                            trace!("recv pkt {src} {idx} - {len}B {}", hex::encode(&buf[..len]));
                        } else {
                            debug!("recv pkt {src} {idx} - {len}B",);
                        }
                        receiver.receive(Packet {
                            index: idx as usize,
                            size: len,
                            src: Some(src),
                            received_at: Some(Instant::now()),
                        });
                    }
                    Err(e) => {
                        error!("encountered error reading packets: {e}");
                        break;
                    }
                }
            }
        }
    }

    print_packets(receiver.check_missing());
}

fn print_packets(pkts: HashSet<&Packet>) {
    info!("{} missing", pkts.len());
    debug!("missing pkts:{:?}", pkts);
}

#[derive(Clone)]
#[allow(unused)]
enum Size {
    Fixed(usize),
    Random { min: usize, max: usize },
    Gradient { min: usize, max: usize, n: usize },
}

#[derive(Clone)]
struct Generator {
    size: Size,
    count: usize,
    n_sent: usize,
    rng: ChaCha20Rng,
}

impl Generator {
    fn new(size: Size, count: usize, seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => rand_chacha::ChaCha20Rng::seed_from_u64(s),
            None => rand_chacha::ChaCha20Rng::from_os_rng(),
        };

        Self {
            size,
            count,
            n_sent: 0,
            rng,
        }
    }

    fn next_packet(&mut self) -> Option<Packet> {
        if self.n_sent >= self.count {
            return None;
        }

        let p = Packet {
            size: self.generate_size(),
            index: self.n_sent,
            src: None,
            received_at: None,
        };

        self.n_sent += 1;
        Some(p)
    }

    fn generate_size(&mut self) -> usize {
        match &self.size {
            Size::Fixed(size) => *size,
            Size::Random { min, max } => self.rng.random_range(*min..=*max),
            Size::Gradient { min, max, n } => {
                let progress = (self.n_sent % n) as f64 / *n as f64;
                let size_range = *max - *min;
                *min + (size_range as f64 * progress) as usize
            }
        }
    }

    fn generate(&mut self) -> HashSet<Packet> {
        let mut packets = HashSet::new();
        while let Some(packet) = self.next_packet() {
            packets.insert(packet);
        }
        packets
    }
}

#[derive(Debug, Eq, Clone)]
#[allow(unused)]
struct Packet {
    index: usize,
    size: usize,
    src: Option<SocketAddr>,
    received_at: Option<Instant>,
}

impl std::hash::Hash for Packet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.size.hash(state);
    }
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.size == other.size
    }
}

#[derive(Clone)]
struct Receiver {
    expected: HashSet<Packet>,
    received: HashSet<Packet>,
    max_idx_received: usize,
}

impl Receiver {
    fn new(mut generator: Generator) -> Self {
        Self {
            expected: generator.generate(),
            received: HashSet::new(),
            max_idx_received: 0,
        }
    }

    fn receive(&mut self, packet: Packet) {
        self.received.insert(packet);
    }

    fn completed(&self) -> bool {
        let total_count = self.expected.len();
        self.received.len() >= total_count || self.max_idx_received >= total_count
    }

    fn check_missing(&self) -> HashSet<&Packet> {
        self.expected.difference(&self.received).collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_recv() {
        let receiver = Receiver {
            expected: HashSet::new(),
            received: HashSet::new(),
            max_idx_received: 0,
        };
        assert_eq!(receiver.check_missing(), HashSet::new());

        // Expected one, received none
        let expected: HashSet<Packet> = [Packet {
            index: 0,
            size: 12,
            src: None,
            received_at: None,
        }]
        .into_iter()
        .collect();
        let receiver = Receiver {
            expected: expected.clone(),
            received: HashSet::new(),
            max_idx_received: 0,
        };
        assert_eq!(receiver.check_missing(), expected.iter().collect());

        // sizes are non-overlapping so missing all expected packets.
        let mut genr = Generator::new(Size::Random { min: 10, max: 20 }, 10, Some(123));
        let expected = genr.generate();
        let mut genr = Generator::new(Size::Random { min: 21, max: 30 }, 10, Some(123));
        let received = genr.generate();
        let receiver = Receiver {
            expected: expected.clone(),
            received,
            max_idx_received: 0,
        };
        assert_eq!(receiver.check_missing(), expected.iter().collect());

        // sizes are non-overlapping so missing all expected packets.
        let mut genr = Generator::new(Size::Random { min: 10, max: 20 }, 10, Some(123));
        let expected = genr.clone().generate();

        let mut received = genr.generate();
        let pkt = received.iter().collect::<Vec<&Packet>>()[0].clone();
        received.remove(&pkt);

        let receiver = Receiver {
            expected: expected.clone(),
            received,
            max_idx_received: 0,
        };
        assert_eq!(receiver.check_missing(), [pkt].iter().collect());
    }
}

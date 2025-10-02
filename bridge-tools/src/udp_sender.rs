//! UDP Packet Sender
//!
//! This binary is used to send packets to a udp target with specific rates and sizes
//! to test the fidelity of the UDP forwarder and the transport wrappers.
//!
//! Some effort is taken to make sure that this program is NOT throttled by allocation
//! and sends at the desired rates.

use std::{collections::VecDeque, io, net::SocketAddr, sync::Arc, time::Duration};

use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::{
    net::UdpSocket,
    time::{Instant, sleep},
};
use tracing::*;

#[derive(Parser, Debug, Clone)]
struct Args {
    // Outgoing address to send test traffic towards
    address: SocketAddr,

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

    tracing::info!(
        "sending UDP packets {} -> {}",
        sock.local_addr().unwrap(),
        args.address
    );

    // Example usage - configure your desired packet generation pattern
    let size = Size::Random { min: 64, max: 1400 };
    let rate = Rate::Fixed(Duration::from_millis(1000));
    // let rate = Rate::Asap;
    let count = Count::N(5);
    let generator = Generator::new(size, rate, count, args.seed);

    send_packets(sock, args.address, generator, args.very_verbose).await;
    // print_packets(sock, args.address, generator, args.very_verbose).await;
    Ok(())
}

#[allow(unused)]
async fn print_packets(
    sock: Arc<UdpSocket>,
    target: SocketAddr,
    mut generator: Generator,
    trace: bool,
) {
    let mut packet_count = 0;

    while let Some(packet) = generator.next_packet().await {
        packet_count += 1;

        if trace {
            trace!("{packet_count} {}B  {}", packet.len(), hex::encode(&packet));
        } else {
            debug!("{packet_count} {}B pkt", packet.len());
        }
        generator.return_packet(packet);
    }
}

#[allow(unused)]
async fn send_packets(
    sock: Arc<UdpSocket>,
    target: SocketAddr,
    mut generator: Generator,
    trace: bool,
) {
    let mut packet_count = 0;

    while let Some(packet) = generator.next_packet().await {
        if trace {
            trace!("{packet_count} {}B  {}", packet.len(), hex::encode(&packet));
        } else {
            debug!("{packet_count} {}B pkt", packet.len());
        }

        match sock.send_to(&packet, target).await {
            Ok(len) => {
                packet_count += 1;
                tracing::info!(
                    "Sent packet #{} - {} bytes to {}",
                    packet_count,
                    len,
                    target
                );

                // Return the packet to the pool after sending
                generator.return_packet(packet);
            }
            Err(e) => {
                tracing::error!("Failed to send packet: {}", e);
                break;
            }
        }
    }
}

#[allow(unused)]
enum Rate {
    Fixed(Duration),
    Asap,
    Random { min: Duration, max: Duration },
}

#[allow(unused)]
enum Size {
    Fixed(usize),
    Random { min: usize, max: usize },
    Gradient { min: usize, max: usize, n: usize },
}

#[allow(unused)]
enum Count {
    N(usize),
    Unlimited,
}

struct Generator {
    size: Size,
    rate: Rate,
    count: Count,
    n_sent: usize,
    last_send: Option<Instant>,
    rng: ChaCha20Rng,
    packet_pool: PacketPool, // Add this
}

impl Generator {
    fn new(size: Size, rate: Rate, count: Count, seed: Option<u64>) -> Self {
        let max_size = match &size {
            Size::Fixed(s) => *s,
            Size::Random { max, .. } => *max,
            Size::Gradient { max, .. } => *max,
        };
        let rng = match seed {
            Some(s) => rand_chacha::ChaCha20Rng::seed_from_u64(s),
            None => rand_chacha::ChaCha20Rng::from_os_rng(),
        };
        if match size {
            Size::Fixed(s) => s < 4,
            Size::Random { min, .. } => min < 4,
            Size::Gradient { min, .. } => min < 4,
        } {
            error!("minimum packet size must be at least 4 bytes");
        }

        Self {
            size,
            rate,
            count,
            n_sent: 0,
            last_send: None,
            rng,
            packet_pool: PacketPool::new(10, max_size), // Pool of 10 buffers
        }
    }

    async fn next_packet(&mut self) -> Option<Vec<u8>> {
        if let Count::N(max_count) = self.count {
            if self.n_sent >= max_count {
                return None;
            }
        }
        self.apply_rate_limit().await;

        let packet_size = self.generate_size();

        // Get packet from pool (fastest option)
        let mut packet = self.packet_pool.get_packet(packet_size)?;

        // set the first four bytes to a be index for this packet
        let idx = self.n_sent as u32;
        packet[..4].copy_from_slice(&idx.to_be_bytes()[..]);

        self.n_sent += 1;
        Some(packet)
    }

    async fn apply_rate_limit(&mut self) {
        let now = Instant::now();

        if let Some(last_send) = self.last_send {
            let delay = match &self.rate {
                Rate::Fixed(duration) => *duration,
                Rate::Asap => Duration::from_nanos(0),
                Rate::Random { min, max } => {
                    let min_nanos = min.as_nanos() as u64;
                    let max_nanos = max.as_nanos() as u64;
                    let random_nanos = self.rng.random_range(min_nanos..=max_nanos);
                    Duration::from_nanos(random_nanos)
                }
            };

            let elapsed = now.duration_since(last_send);
            if elapsed < delay {
                sleep(delay - elapsed).await;
            }
        }

        self.last_send = Some(Instant::now());
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

    fn return_packet(&mut self, packet: Vec<u8>) {
        self.packet_pool.return_packet(packet);
    }
}

struct PacketPool {
    buffers: VecDeque<Vec<u8>>,
    max_size: usize,
}

impl PacketPool {
    fn new(pool_size: usize, max_packet_size: usize) -> Self {
        let mut buffers = VecDeque::with_capacity(pool_size);
        for _ in 0..pool_size {
            buffers.push_back(Vec::with_capacity(max_packet_size));
        }
        Self {
            buffers,
            max_size: max_packet_size,
        }
    }

    fn get_packet(&mut self, size: usize) -> Option<Vec<u8>> {
        if size > self.max_size {
            None
        } else if let Some(mut buf) = self.buffers.pop_front() {
            buf.clear();
            buf.resize(size, 0);
            Some(buf)
        } else {
            Some(vec![0u8; size])
        }
    }

    fn return_packet(&mut self, mut packet: Vec<u8>) {
        if packet.capacity() <= self.max_size && self.buffers.len() < self.buffers.capacity() {
            packet.clear();
            packet.resize(self.max_size, 0);
            self.buffers.push_back(packet);
        }
    }
}

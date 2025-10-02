use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::*;

use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::sleep;

#[allow(unused)]
pub async fn send_packets(
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
pub enum Rate {
    Fixed(Duration),
    Asap,
    Random { min: Duration, max: Duration },
}

#[allow(unused)]
pub enum Size {
    Fixed(usize),
    Random { min: usize, max: usize },
    Gradient { min: usize, max: usize, n: usize },
}

#[allow(unused)]
pub enum Count {
    N(usize),
    Unlimited,
}

pub struct Generator {
    size: Size,
    rate: Rate,
    count: Count,
    n_sent: usize,
    last_send: Option<Instant>,
    rng: rand::rngs::ThreadRng,
    packet_pool: PacketPool, // Add this
}

impl Generator {
    pub fn new(size: Size, rate: Rate, count: Count) -> Self {
        let max_size = match &size {
            Size::Fixed(s) => *s,
            Size::Random { max, .. } => *max,
            Size::Gradient { max, .. } => *max,
        };

        Self {
            size,
            rate,
            count,
            n_sent: 0,
            last_send: None,
            rng: rand::thread_rng(),
            packet_pool: PacketPool::new(10, max_size), // Pool of 10 buffers
        }
    }

    pub async fn next_packet(&mut self) -> Option<Vec<u8>> {
        if let Count::N(max_count) = self.count
            && self.n_sent >= max_count
        {
            return None;
        }
        self.apply_rate_limit().await;

        let packet_size = self.generate_size();

        // Get packet from pool (fastest option)
        let packet = self.packet_pool.get_packet(packet_size);

        // // If you want the incrementing pattern:
        // let mut packet = packet;
        // for (i, byte) in packet.iter_mut().enumerate() {
        //     *byte = ((self.state + i) % 256) as u8;
        // }

        // If you don't care about contents, just return it:
        self.n_sent += 1;
        packet
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
                    let random_nanos = self.rng.gen_range(min_nanos..=max_nanos);
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
            Size::Random { min, max } => self.rng.gen_range(*min..=*max),
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
    buffers: Vec<Vec<u8>>,
    max_size: usize,
}

impl PacketPool {
    fn new(pool_size: usize, max_packet_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            buffers.push(Vec::with_capacity(max_packet_size));
        }
        Self {
            buffers,
            max_size: max_packet_size,
        }
    }

    fn get_packet(&mut self, size: usize) -> Option<Vec<u8>> {
        if size > self.max_size {
            None
        } else if let Some(mut buf) = self.buffers.pop() {
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
            self.buffers.push(packet);
        }
    }
}

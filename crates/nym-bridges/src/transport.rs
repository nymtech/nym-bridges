pub mod quic;
pub mod tls;

/*
use crate::error::ForwardError;

/// Consistent trait for transports to generate and serialize their configurations.
pub trait Configurable {
    type Config;

    fn as_bytes(config: &Self::Config) -> &[u8];

    fn generate_config<R: rand::CryptoRng + rand::RngCore>(rand: &mut R) -> Self::Config;
}

// Trait for transport to receive data over a connection.
trait Receiver {
    fn receive(&mut self, data: &[u8]) -> Result<(), ForwardError>;
}

/// Trait for transports to send data over a connection.
trait Sender {
    fn send(&mut self, data: &[u8]) -> Result<(), ForwardError>;
}

/// Enum to represent different transport types.
enum TransportType {
    Quic,
}
*/

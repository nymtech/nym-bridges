use thiserror::Error;

/// Errors that can occur during the forwarding setup or steady state operation.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ForwardError {
    #[error("data store disconnected: {0}")]
    Config(anyhow::Error),
    #[error("setup failed: {0}")]
    Setup(anyhow::Error),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("quic conn error: {0}")]
    Quic(#[from] quinn::ConnectError),

    #[error("quic proto error: {0}")]
    QuicProto(#[from] quinn::ConnectionError),

    #[error("transport socket io error")]
    SocketIo(#[source] std::io::Error),

    #[error("insufficient or broken transport params: {0}")]
    Config(String),

    #[error("transport connection was cancelled")]
    Cancelled,

    #[error("transport error: {0}")]
    Other(String),
}

impl TransportError {
    pub fn config_err(s: impl AsRef<str>) -> Self {
        Self::Config(s.as_ref().to_string())
    }

    pub fn other(s: impl AsRef<str>) -> Self {
        Self::Other(s.as_ref().to_string())
    }
}

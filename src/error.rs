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

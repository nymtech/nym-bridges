pub mod config;
pub mod connection;
pub mod error;
pub mod session;
pub mod transport;
// mod stats;

/*
/// Forwarder for client connections,
///
/// Accept incoming ingress connections and establishes a transport connection to the server
/// over which it forwards data.
struct ClientForwarder {
    // Fields for client forwarder
}

/// Forwarder for server connections.
///
/// Accepts incoming transport connections and forwards them to the
/// appropriate local connection handler.
struct ServerForwarder {
    // Fields for server forwarder
}

impl ServerForwarder {
    pub fn new() -> Self {
        Self {
            // Initialize fields
        }
    }

    pub fn listen(&self) {
        // Implementation for listening to incoming connections
    }
}
*/

#[allow(unused)]
#[cfg(test)]
pub(crate) mod test_utils {
    use std::env;
    use std::str::FromStr;
    use std::sync::Once;
    use tracing_subscriber::filter::LevelFilter;

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
}

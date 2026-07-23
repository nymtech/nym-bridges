pub mod config;
pub mod connection;
pub mod error;
pub mod session;
pub mod transport;
// mod stats;
pub mod forward;

pub extern crate nym_bridges_types;
pub use nym_bridges_types as types;

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

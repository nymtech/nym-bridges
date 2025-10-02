use std::time::Instant;

pub struct SessionStatistics {
    conn_begin: Instant,

    /// total bytes sent
    pub total_bytes_sent: u64,
    /// total bytes received
    pub total_bytes_received: u64,

    /// total bytes of application data sent
    pub total_app_data_sent: u64,
    /// total bytes of application data received
    pub total_app_data_received: u64,

    /// time to establish transport connection (us)
    pub connection_establishment_time: u64,
    /// total connection duration (us)
    pub total_connection_duration: u64,
}

impl Default for SessionStatistics {
    fn default() -> Self {
        Self {
            conn_begin: Instant::now(),
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_app_data_sent: 0,
            total_app_data_received: 0,
            connection_establishment_time: 0,
            total_connection_duration: 0,
        }
    }
}

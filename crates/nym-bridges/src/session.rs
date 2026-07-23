use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

// use rand::{CryptoRng, RngCore};
use uuid::Uuid;

// use crate::stats::SessionStatistics;

#[derive(Clone)]
pub struct Session {
    inner: Arc<Mutex<InnerSession>>,
}

impl Session {
    pub fn new(fwd_remote: &SocketAddr, tr_remote: &SocketAddr) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerSession::new(*fwd_remote, *tr_remote))),
        }
    }

    pub fn transport_remote(&self) -> SocketAddr {
        self.inner.lock().unwrap().transport_remote
    }

    pub fn forward_remote(&self) -> SocketAddr {
        self.inner.lock().unwrap().forward_remote
    }

    pub fn id(&self) -> Uuid {
        self.inner.lock().unwrap().id
    }

    // pub fn stats(&self) -> &SessionStatistics {
    //     &self.inner.lock().unwrap().stats
    // }

    // pub fn stats_mut(&self) -> &mut SessionStatistics {
    //     &mut self.inner.lock().unwrap().stats
    // }
}

struct InnerSession {
    transport_remote: SocketAddr,
    forward_remote: SocketAddr,
    id: Uuid,
    // stats: SessionStatistics,
}

impl InnerSession {
    pub fn new(fwd_remote: SocketAddr, tr_remote: SocketAddr) -> Self {
        let mut rand_bytes = [0u8; 16];
        getrandom::fill(&mut rand_bytes).unwrap();
        let id = uuid::Builder::from_random_bytes(rand_bytes).into_uuid();

        Self {
            transport_remote: tr_remote,
            forward_remote: fwd_remote,
            id,
            // stats: SessionStatistics::default(),
        }
    }
}

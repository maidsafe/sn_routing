use crate::{
    quic_p2p::{Builder, Error},
    NetworkConfig, NetworkEvent, QuicP2p,
};
use crossbeam_channel::Sender;

pub struct NetworkService {
    quic_p2p: QuicP2p,
}

impl NetworkService {
    pub fn service(&self) -> &QuicP2p {
        &self.quic_p2p
    }

    pub fn service_mut(&mut self) -> &mut QuicP2p {
        &mut self.quic_p2p
    }

    pub fn next_msg_id(&mut self) -> u64 {
        // FIXME: actually implement that
        0
    }
}

pub struct NetworkBuilder {
    quic_p2p: Builder,
}

impl NetworkBuilder {
    pub fn new(event_tx: Sender<NetworkEvent>) -> Self {
        Self {
            quic_p2p: Builder::new(event_tx),
        }
    }

    pub fn with_config(self, config: NetworkConfig) -> Self {
        Self {
            quic_p2p: self.quic_p2p.with_config(config),
        }
    }

    pub fn build(self) -> Result<NetworkService, Error> {
        Ok(NetworkService {
            quic_p2p: self.quic_p2p.build()?,
        })
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{crypto, event::Event, peer::Peer, NetworkParams};
use ed25519_dalek::Keypair;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::mpsc;
use xor_name::XorName;

/// Information and state of our node
#[derive(Clone)]
pub(crate) struct Node {
    // Keep the secret key in Box to allow Clone while also preventing multiple copies to exist in
    // memory which might be insecure.
    // TODO: find a way to not require `Clone`.
    pub keypair: Arc<Keypair>,
    pub addr: SocketAddr,
    pub age: u8,
    pub network_params: NetworkParams,
    // TODO: move this event sender somewhere else. This is not an approprate place for it.
    event_tx: mpsc::UnboundedSender<Event>,
}

impl Node {
    pub(super) fn new(
        keypair: Keypair,
        addr: SocketAddr,
        age: u8,
        network_params: NetworkParams,
        event_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            keypair: Arc::new(keypair),
            addr,
            age,
            network_params,
            event_tx,
        }
    }

    pub fn peer(&self) -> Peer {
        Peer::new(self.name(), self.addr, self.age)
    }

    pub fn name(&self) -> XorName {
        crypto::name(&self.keypair.public)
    }

    pub fn send_event(&self, event: Event) {
        // Note: cloning the sender to avoid mutable access. Should have negligible cost.
        if self.event_tx.clone().send(event).is_err() {
            error!("Event receiver has been closed");
        }
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:<8}", hex_fmt::HexFmt(self.keypair.public.as_bytes()))
    }
}

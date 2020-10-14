// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{crypto, event::Event, NetworkParams};
use ed25519_dalek::Keypair;
use std::sync::Arc;
use tokio::sync::mpsc;
use xor_name::XorName;

/// Information and state of our node
#[derive(Clone)]
pub(crate) struct Node {
    // Keep the secret key in Box to allow Clone while also preventing multiple copies to exist in
    // memory which might be insecure.
    // TODO: find a way to not require `Clone`.
    pub keypair: Arc<Keypair>,
    pub network_params: NetworkParams,
    event_tx: mpsc::UnboundedSender<Event>,
}

impl Node {
    pub(super) fn new(
        keypair: Keypair,
        network_params: NetworkParams,
        event_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            keypair: Arc::new(keypair),
            network_params,
            event_tx,
        }
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

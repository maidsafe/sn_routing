// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Result,
    event::Event,
    id::{FullId, PublicId},
    location::DstLocation,
    message_filter::MessageFilter,
    messages::{Message, QueuedMessage, Variant},
    network_params::NetworkParams,
    node::NodeConfig,
    quic_p2p::{EventSenders, OurType, Token},
    rng::{self, MainRng},
    timer::Timer,
    transport::{PeerStatus, Transport},
};
use bytes::Bytes;
use crossbeam_channel::Sender;
use std::{collections::VecDeque, net::SocketAddr, slice};
use xor_name::XorName;

// Core components of the node.
pub(crate) struct Core {
    pub network_params: NetworkParams,
    pub full_id: FullId,
    pub transport: Transport,
    pub msg_filter: MessageFilter,
    pub msg_queue: VecDeque<QueuedMessage>,
    pub timer: Timer,
    pub rng: MainRng,
    user_event_tx: Sender<Event>,
}

impl Core {
    pub fn new(
        mut config: NodeConfig,
        timer_tx: Sender<u64>,
        transport_event_tx: EventSenders,
        user_event_tx: Sender<Event>,
    ) -> Self {
        let mut rng = config.rng;
        let full_id = config.full_id.unwrap_or_else(|| FullId::gen(&mut rng));

        config.transport_config.our_type = OurType::Node;
        let transport = match Transport::new(transport_event_tx, config.transport_config) {
            Ok(transport) => transport,
            Err(err) => panic!("Unable to start network transport: {:?}", err),
        };

        Self {
            network_params: config.network_params,
            full_id,
            transport,
            msg_filter: Default::default(),
            msg_queue: Default::default(),
            timer: Timer::new(timer_tx),
            rng,
            user_event_tx,
        }
    }

    pub fn resume(
        network_params: NetworkParams,
        full_id: FullId,
        transport: Transport,
        msg_filter: MessageFilter,
        msg_queue: VecDeque<QueuedMessage>,
        timer_tx: Sender<u64>,
        user_event_tx: Sender<Event>,
    ) -> Self {
        Self {
            network_params,
            full_id,
            transport,
            msg_filter,
            msg_queue,
            timer: Timer::new(timer_tx),
            rng: rng::new(),
            user_event_tx,
        }
    }

    pub fn id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.transport.our_connection_info().map_err(|err| {
            debug!("Failed to retrieve our connection info: {:?}", err);
            err.into()
        })
    }

    pub fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) {
        self.transport
            .send_message_to_targets(conn_infos, delivery_group_size, msg)
    }

    pub fn send_message_to_target(&mut self, recipient: &SocketAddr, msg: Bytes) {
        self.transport
            .send_message_to_targets(slice::from_ref(recipient), 1, msg)
    }

    pub fn send_direct_message(&mut self, recipient: &SocketAddr, variant: Variant) {
        let message =
            match Message::single_src(&self.full_id, DstLocation::Direct, variant, None, None) {
                Ok(message) => message,
                Err(error) => {
                    error!("Failed to create message: {:?}", error);
                    return;
                }
            };

        self.send_message_to_target(recipient, message.to_bytes())
    }

    pub fn handle_unsent_message(
        &mut self,
        addr: SocketAddr,
        msg: Bytes,
        msg_token: Token,
    ) -> PeerStatus {
        self.transport
            .target_failed(msg, msg_token, addr, &self.timer)
    }

    pub fn send_event(&self, event: Event) {
        let _ = self.user_event_tx.send(event);
    }
}

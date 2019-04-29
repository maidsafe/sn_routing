// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::RoutingError;
use crate::id::{FullId, PublicId};
use crate::messages::{DirectMessage, HopMessage, Message, SignedMessage};
use crate::outbox::EventBox;
use crate::routing_table::Authority;
use crate::state_machine::Transition;
use crate::xor_name::XorName;
use crate::CrustBytes;
use crate::Service;
use maidsafe_utilities::serialisation;
use std::collections::BTreeSet;
use std::fmt::Display;

// Trait for all states.
pub trait Base: Display {
    fn crust_service(&self) -> &Service;
    fn full_id(&self) -> &FullId;
    fn in_authority(&self, auth: &Authority<XorName>) -> bool;
    fn min_section_size(&self) -> usize;

    fn handle_lost_peer(&mut self, _pub_id: PublicId, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn id(&self) -> &PublicId {
        self.full_id().public_id()
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn close_group(&self, _name: XorName, _count: usize) -> Option<Vec<XorName>> {
        None
    }

    fn send_direct_message(&mut self, dst_id: PublicId, message: DirectMessage) {
        self.send_message(&dst_id, Message::Direct(message));
    }

    fn send_message(&mut self, dst_id: &PublicId, message: Message) {
        let priority = message.priority();

        match to_crust_bytes(message) {
            Ok(bytes) => {
                self.send_or_drop(dst_id, bytes, priority);
            }
            Err((error, message)) => {
                error!(
                    "{} Failed to serialise message {:?}: {:?}",
                    self, message, error
                );
                // The caller can't do much to handle this except log more messages, so just stop
                // trying to send here and let other mechanisms handle the lost message. If the
                // node drops too many messages, it should fail to join the network anyway.
            }
        };
    }

    // Sends the given `data` to the peer with the given `dst_id`. If that results in an
    // error, it disconnects from the peer.
    fn send_or_drop(&mut self, dst_id: &PublicId, data: CrustBytes, priority: u8) {
        if let Err(err) = self.crust_service().send(dst_id, data, priority) {
            info!("{} Connection to {} failed: {:?}", self, dst_id, err);
            // TODO: Handle lost peer, but avoid a cascade of sending messages and handling more
            //       lost peers: https://maidsafe.atlassian.net/browse/MAID-1924
            // self.crust_service().disconnect(*pub_id);
            // return self.handle_lost_peer(*pub_id).map(|_| Err(err.into()));
        }
    }

    // Serialise HopMessage containing the given signed message.
    fn to_hop_bytes(
        &self,
        signed_msg: SignedMessage,
        route: u8,
        sent_to: BTreeSet<XorName>,
    ) -> Result<CrustBytes, RoutingError> {
        let hop_msg = HopMessage::new(
            signed_msg,
            route,
            sent_to,
            self.full_id().signing_private_key(),
        )?;
        let message = Message::Hop(hop_msg);
        Ok(to_crust_bytes(message).map_err(|(err, _)| err)?)
    }
}

fn to_crust_bytes(
    message: Message,
) -> Result<CrustBytes, (serialisation::SerialisationError, Message)> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::serialise(&message).map_err(|err| (err, message));

    #[cfg(feature = "mock_serialise")]
    let result = Ok(Box::new(message));

    result
}

pub fn from_crust_bytes(data: CrustBytes) -> Result<Message, RoutingError> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::deserialise(&data).map_err(RoutingError::SerialisationError);

    #[cfg(feature = "mock_serialise")]
    let result = Ok(*data);

    result
}

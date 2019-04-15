// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::{FullId, PublicId};
use crate::messages::{DirectMessage, Message};
use crate::outbox::EventBox;
use crate::routing_table::Authority;
use crate::state_machine::Transition;
use crate::xor_name::XorName;
use crate::Service;
use maidsafe_utilities::serialisation;
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

        match serialisation::serialise(&message) {
            Ok(bytes) => {
                self.send_or_drop(dst_id, bytes, priority);
            }
            Err(error) => {
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

    // Sends the given `bytes` to the peer with the given `dst_id`. If that results in an
    // error, it disconnects from the peer.
    fn send_or_drop(&mut self, dst_id: &PublicId, bytes: Vec<u8>, priority: u8) {
        if let Err(err) = self.crust_service().send(dst_id, bytes, priority) {
            info!("{} Connection to {} failed: {:?}", self, dst_id, err);
            // TODO: Handle lost peer, but avoid a cascade of sending messages and handling more
            //       lost peers: https://maidsafe.atlassian.net/browse/MAID-1924
            // self.crust_service().disconnect(*pub_id);
            // return self.handle_lost_peer(*pub_id).map(|_| Err(err.into()));
        }
    }
}

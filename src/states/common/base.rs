// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::{PeerId, Service};

use error::RoutingError;
use event::Event;
use id::FullId;
use maidsafe_utilities::serialisation;
use messages::Message;
use state_machine::Transition;
use stats::Stats;
use std::fmt::Debug;
use xor_name::XorName;

// Trait for all states.
pub trait Base: Debug {
    fn crust_service(&self) -> &Service;
    fn full_id(&self) -> &FullId;
    fn stats(&mut self) -> &mut Stats;
    fn send_event(&self, event: Event);

    fn handle_lost_peer(&mut self, _peer_id: PeerId) -> Transition {
        Transition::Stay
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn send_message(&mut self, peer_id: &PeerId, message: Message) -> Result<(), RoutingError> {
        let priority = message.priority();

        let raw_bytes = match serialisation::serialise(&message) {
            Err(error) => {
                error!("{:?} Failed to serialise message {:?}: {:?}",
                       self,
                       message,
                       error);
                return Err(error.into());
            }
            Ok(bytes) => bytes,
        };

        self.send_or_drop(peer_id, raw_bytes, priority)
    }

    // Sends the given `bytes` to the peer with the given Crust `PeerId`. If that results in an
    // error, it disconnects from the peer.
    fn send_or_drop(&mut self,
                    peer_id: &PeerId,
                    bytes: Vec<u8>,
                    priority: u8)
                    -> Result<(), RoutingError> {
        self.stats().count_bytes(bytes.len());

        if let Err(err) = self.crust_service().send(*peer_id, bytes.clone(), priority) {
            info!("{:?} Connection to {:?} failed. Calling crust::Service::disconnect.",
                  self,
                  peer_id);
            self.crust_service().disconnect(*peer_id);
            let _ = self.handle_lost_peer(*peer_id);
            return Err(err.into());
        }

        Ok(())
    }
}

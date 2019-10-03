// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Bootstrapped;
use crate::{
    error::RoutingError,
    messages::{HopMessage, RoutingMessage},
    routing_message_filter::FilteringResult,
};

pub trait BootstrappedNotEstablished: Bootstrapped {
    fn filter_hop_message(
        &mut self,
        hop_msg: HopMessage,
    ) -> Result<Option<RoutingMessage>, RoutingError> {
        let signed_msg = hop_msg.content;
        let routing_msg = signed_msg.into_routing_message();
        let in_authority = self.in_authority(&routing_msg.dst);

        // Prevents us repeatedly handling identical messages sent by a malicious peer.
        match self.routing_msg_filter().filter_incoming(&routing_msg) {
            FilteringResult::KnownMessage => {
                return Err(RoutingError::FilterCheckFailed);
            }
            FilteringResult::NewMessage => (),
        }

        if !in_authority {
            return Ok(None);
        }

        Ok(Some(routing_msg))
    }
}

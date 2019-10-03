// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Base;
use crate::{
    messages::RoutingMessage,
    routing_message_filter::{FilteringResult, RoutingMessageFilter},
};

// Common functionality for states that are bootstrapped (have established a network
// connection to at least one peer).
pub trait Bootstrapped: Base {
    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter;

    fn filter_incoming_routing_msg(&mut self, msg: &RoutingMessage) -> bool {
        // Prevents us repeatedly handling identical messages sent by a malicious peer.
        match self.routing_msg_filter().filter_incoming(msg) {
            FilteringResult::KnownMessage => {
                debug!("{} Known message: {:?} - not handling further", self, msg);
                false
            }
            FilteringResult::NewMessage => true,
        }
    }
}

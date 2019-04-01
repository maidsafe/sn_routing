// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Base;
use crate::{
    error::Result,
    id::PublicId,
    messages::{MessageContent, RoutingMessage},
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    time::Instant,
    timer::Timer,
    xor_name::XorName,
};

// Common functionality for states that are bootstrapped (have established a network
// connection to at least one peer).
pub trait Bootstrapped: Base {
    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        expires_at: Option<Instant>,
    ) -> Result<()>;

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter;
    fn timer(&mut self) -> &mut Timer;

    /// Adds the outgoing signed message to the statistics and returns `true`
    /// if it should be blocked due to deduplication.
    fn filter_outgoing_routing_msg(&mut self, msg: &RoutingMessage, pub_id: &PublicId) -> bool {
        self.routing_msg_filter().filter_outgoing(msg, pub_id)
    }

    fn send_routing_message_with_expiry(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: MessageContent,
        expires_at: Option<Instant>,
    ) -> Result<()> {
        let routing_msg = RoutingMessage {
            src: src,
            dst: dst,
            content: content,
        };
        self.send_routing_message_impl(routing_msg, expires_at)
    }

    fn send_routing_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: MessageContent,
    ) -> Result<()> {
        self.send_routing_message_with_expiry(src, dst, content, None)
    }
}

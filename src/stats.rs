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

use messages::{DirectMessage, MessageContent, RoutingMessage};

/// The number of messages after which the message statistics should be printed.
const MSG_LOG_COUNT: usize = 500;

/// A collection of counters to gather Routing statistics.
#[derive(Default)]
pub struct Stats {
    // TODO: Make these private and move the logic here.
    pub cur_routing_table_size: usize,
    pub cur_client_num: usize,
    pub cumulative_client_num: usize,
    pub tunnel_client_pairs: usize,
    pub tunnel_connections: usize,

    msg_direct_node_identify: usize,
    msg_direct_new_node: usize,
    msg_direct_connection_unneeded: usize,

    msg_get_close_group: usize,
    msg_get_node_name: usize,
    msg_expect_close_node: usize,
    msg_connection_info: usize,
    msg_get_close_group_rsp: usize,
    msg_get_node_name_rsp: usize,
    msg_ack: usize,
    msg_user: usize,

    msg_other: usize,

    msg_total: usize,
}

impl Stats {
    /// Increments the counter for the given routing message type.
    pub fn count_routing_message(&mut self, msg: &RoutingMessage) {
        match msg.content {
            MessageContent::GetNodeName { .. } => self.msg_get_node_name += 1,
            MessageContent::ExpectCloseNode { .. } => self.msg_expect_close_node += 1,
            MessageContent::GetCloseGroup(..) => self.msg_get_close_group += 1,
            MessageContent::ConnectionInfo { .. } => self.msg_connection_info += 1,
            MessageContent::GetCloseGroupResponse { .. } => self.msg_get_close_group_rsp += 1,
            MessageContent::GetNodeNameResponse { .. } => self.msg_get_node_name_rsp += 1,
            MessageContent::Ack(..) => self.msg_ack += 1,
            MessageContent::UserMessagePart { .. } => self.msg_user += 1,
        }
        self.increment_msg_total();
    }

    /// Increments the counter for the given direct message type.
    pub fn count_direct_message(&mut self, msg: &DirectMessage) {
        match *msg {
            DirectMessage::NodeIdentify { .. } => self.msg_direct_node_identify += 1,
            DirectMessage::NewNode(_) => self.msg_direct_new_node += 1,
            DirectMessage::ConnectionUnneeded(..) => self.msg_direct_connection_unneeded += 1,
            _ => self.msg_other += 1,
        }
        self.increment_msg_total();
    }

    /// Increment the total message count, and if divisible by 100, log a message with the counts.
    fn increment_msg_total(&mut self) {
        self.msg_total += 1;
        if self.msg_total % MSG_LOG_COUNT == 0 {
            info!("Stats - Sent {} messages in total, {} uncategorised",
                  self.msg_total,
                  self.msg_other);
            info!("Stats - Direct - NodeIdentify: {}, NewNode: {}, ConnectionUnneeded: {}",
                  self.msg_direct_node_identify,
                  self.msg_direct_new_node,
                  self.msg_direct_connection_unneeded);
            info!("Stats - Hops - GetNodeName: {}, ExpectCloseNode: {}, GetCloseGroup: {}, \
                   ConnectionInfo: {}, GetCloseGroupResponse: {}, GetNodeNameResponse: {}, \
                   Ack: {}, UserMessagePart: {}",
                  self.msg_get_node_name,
                  self.msg_expect_close_node,
                  self.msg_get_close_group,
                  self.msg_connection_info,
                  self.msg_get_close_group_rsp,
                  self.msg_get_node_name_rsp,
                  self.msg_ack,
                  self.msg_user);
        }
    }
}

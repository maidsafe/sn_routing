// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use messages::{DirectMessage, MessageContent, Request, Response, RoutingMessage, UserMessage};
use peer_manager::MIN_GROUP_SIZE;

/// The number of messages after which the message statistics should be printed.
const MSG_LOG_COUNT: usize = 1000;

/// A collection of counters to gather Routing statistics.
#[derive(Default)]
pub struct Stats {
    // TODO: Make these private and move the logic here.
    pub cur_routing_table_size: usize,
    pub cur_client_num: usize,
    pub cumulative_client_num: usize,
    pub tunnel_client_pairs: usize,
    pub tunnel_connections: usize,

    /// Messages sent by us on different routes.
    routes: [usize; MIN_GROUP_SIZE],
    /// Messages we sent unsuccessfully: unacknowledged on all routes.
    unacked_msgs: usize,

    msg_direct_node_identify: usize,
    msg_direct_new_node: usize,
    msg_direct_sig: usize,

    msg_get: usize,
    msg_put: usize,
    msg_post: usize,
    msg_delete: usize,
    msg_append: usize,
    msg_get_account_info: usize,
    msg_get_close_group: usize,
    msg_get_node_name: usize,
    msg_expect_close_node: usize,
    msg_refresh: usize,
    msg_connection_info: usize,
    msg_get_success: usize,
    msg_get_failure: usize,
    msg_put_success: usize,
    msg_put_failure: usize,
    msg_post_success: usize,
    msg_post_failure: usize,
    msg_delete_success: usize,
    msg_delete_failure: usize,
    msg_append_success: usize,
    msg_append_failure: usize,
    msg_get_account_info_success: usize,
    msg_get_account_info_failure: usize,
    msg_get_close_group_rsp: usize,
    msg_group_split: usize,
    msg_own_group_merge: usize,
    msg_other_group_merge: usize,
    msg_get_node_name_rsp: usize,
    msg_ack: usize,

    msg_other: usize,

    msg_total: usize,
    msg_total_bytes: u64,
}

impl Stats {
    pub fn count_unacked(&mut self) {
        self.unacked_msgs += 1;
    }

    pub fn count_route(&mut self, route: u8) {
        match self.routes.get_mut(route as usize) {
            Some(count) => *count += 1,
            None => error!("Unexpected route number {}", route),
        }
    }

    /// Increments the counter for the given request.
    pub fn count_user_message(&mut self, msg: &UserMessage) {
        match *msg {
            UserMessage::Request(ref request) => {
                match *request {
                    Request::Refresh(..) => self.msg_refresh += 1,
                    Request::Get(..) => self.msg_get += 1,
                    Request::Put(..) => self.msg_put += 1,
                    Request::Post(..) => self.msg_post += 1,
                    Request::Delete(..) => self.msg_delete += 1,
                    Request::Append(..) => self.msg_append += 1,
                    Request::GetAccountInfo(..) => self.msg_get_account_info += 1,
                }
            }
            UserMessage::Response(ref response) => {
                match *response {
                    Response::GetSuccess(..) => self.msg_get_success += 1,
                    Response::GetFailure { .. } => self.msg_get_failure += 1,
                    Response::PutSuccess(..) => self.msg_put_success += 1,
                    Response::PutFailure { .. } => self.msg_put_failure += 1,
                    Response::PostSuccess(..) => self.msg_post_success += 1,
                    Response::PostFailure { .. } => self.msg_post_failure += 1,
                    Response::DeleteSuccess(..) => self.msg_delete_success += 1,
                    Response::DeleteFailure { .. } => self.msg_delete_failure += 1,
                    Response::AppendSuccess(..) => self.msg_append_success += 1,
                    Response::AppendFailure { .. } => self.msg_append_failure += 1,
                    Response::GetAccountInfoSuccess { .. } => {
                        self.msg_get_account_info_success += 1
                    }
                    Response::GetAccountInfoFailure { .. } => {
                        self.msg_get_account_info_failure += 1
                    }
                }
            }
        }
        self.increment_msg_total();
    }

    /// Increments the counter for the given routing message type.
    pub fn count_routing_message(&mut self, msg: &RoutingMessage) {
        match msg.content {
            MessageContent::GetNodeName { .. } => self.msg_get_node_name += 1,
            MessageContent::ExpectCloseNode { .. } => self.msg_expect_close_node += 1,
            MessageContent::GetCloseGroup(..) => self.msg_get_close_group += 1,
            MessageContent::ConnectionInfo(_) => self.msg_connection_info += 1,
            MessageContent::GetCloseGroupResponse { .. } => self.msg_get_close_group_rsp += 1,
            MessageContent::GroupSplit(..) => self.msg_group_split += 1,
            MessageContent::OwnGroupMerge { .. } => self.msg_own_group_merge += 1,
            MessageContent::OtherGroupMerge { .. } => self.msg_other_group_merge += 1,
            MessageContent::GetNodeNameResponse { .. } => self.msg_get_node_name_rsp += 1,
            MessageContent::Ack(..) => self.msg_ack += 1,
            MessageContent::UserMessagePart { .. } => return, // Counted as request/response.
        }
        self.increment_msg_total();
    }

    /// Increments the counter for the given direct message type.
    pub fn count_direct_message(&mut self, msg: &DirectMessage) {
        match *msg {
            DirectMessage::NodeIdentify { .. } => self.msg_direct_node_identify += 1,
            DirectMessage::NewNode(_) => self.msg_direct_new_node += 1,
            DirectMessage::MessageSignature(..) => self.msg_direct_sig += 1,
            _ => self.msg_other += 1,
        }
        self.increment_msg_total();
    }

    pub fn count_bytes(&mut self, len: usize) {
        self.msg_total_bytes += len as u64;
    }

    /// Increments the total message count, and if the count is divisible by
    /// `MSG_LOG_COUNT` logs a message with the counts.
    fn increment_msg_total(&mut self) {
        self.msg_total += 1;
        if self.msg_total % MSG_LOG_COUNT == 0 {
            info!("Stats - Sent {} messages in total, comprising {} bytes, {} uncategorised, \
                  routes/failed: {:?}/{}",
                  self.msg_total,
                  self.msg_total_bytes,
                  self.msg_other,
                  self.routes,
                  self.unacked_msgs);
            info!("Stats - Direct - NodeIdentify: {}, NewNode: {}, MessageSignature: {}",
                  self.msg_direct_node_identify,
                  self.msg_direct_new_node,
                  self.msg_direct_sig);
            info!("Stats - Hops (Request/Response) - GetNodeName: {}/{}, ExpectCloseNode: {}, \
                   GetCloseGroup: {}/{}, GroupSplit: {}, OwnGroupMerge: {}, OtherGroupMerge: {}, \
                   ConnectionInfo: {}, Ack: {}",
                  self.msg_get_node_name,
                  self.msg_get_node_name_rsp,
                  self.msg_expect_close_node,
                  self.msg_get_close_group,
                  self.msg_get_close_group_rsp,
                  self.msg_group_split,
                  self.msg_own_group_merge,
                  self.msg_other_group_merge,
                  self.msg_connection_info,
                  self.msg_ack);
            info!("Stats - User (Request/Success/Failure) - Get: {}/{}/{}, Put: {}/{}/{}, \
                   Post: {}/{}/{}, Delete: {}/{}/{}, Append: {}/{}/{}, GetAccountInfo: {}/{}/{}, \
                   Refresh: {}",
                  self.msg_get,
                  self.msg_get_success,
                  self.msg_get_failure,
                  self.msg_put,
                  self.msg_put_success,
                  self.msg_put_failure,
                  self.msg_post,
                  self.msg_post_success,
                  self.msg_post_failure,
                  self.msg_delete,
                  self.msg_delete_success,
                  self.msg_delete_failure,
                  self.msg_append,
                  self.msg_append_success,
                  self.msg_append_failure,
                  self.msg_get_account_info,
                  self.msg_get_account_info_success,
                  self.msg_get_account_info_failure,
                  self.msg_refresh);
        }
    }
}

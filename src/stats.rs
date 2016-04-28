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

use messages::{DirectMessage, RequestContent, ResponseContent, RoutingMessage};

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
    msg_direct_heartbeat: usize,
    msg_direct_new_node: usize,
    msg_direct_connection_unneeded: usize,

    msg_req_get: usize,
    msg_req_put: usize,
    msg_req_post: usize,
    msg_req_delete: usize,
    msg_req_get_close_group: usize,
    msg_req_refresh: usize,
    msg_req_connect: usize,
    msg_req_connection_info: usize,
    msg_req_get_public_id: usize,
    msg_req_get_public_id_with_connection_info: usize,

    msg_rsp_get_success: usize,
    msg_rsp_get_failure: usize,
    msg_rsp_put_success: usize,
    msg_rsp_put_failure: usize,
    msg_rsp_post_success: usize,
    msg_rsp_post_failure: usize,
    msg_rsp_delete_success: usize,
    msg_rsp_delete_failure: usize,
    msg_rsp_get_close_group: usize,
    msg_rsp_get_public_id: usize,
    msg_rsp_get_public_id_with_connection_info: usize,

    msg_other: usize,

    msg_total: usize,
}

impl Stats {
    /// Increments the counter for the given routing message type.
    pub fn count_routing_message(&mut self, msg: &RoutingMessage) {
        match *msg {
            RoutingMessage::Request(ref request) => {
                match request.content {
                    RequestContent::Get(..) => self.msg_req_get += 1,
                    RequestContent::Put(..) => self.msg_req_put += 1,
                    RequestContent::Post(..) => self.msg_req_post += 1,
                    RequestContent::Delete(..) => self.msg_req_delete += 1,
                    RequestContent::GetCloseGroup(..) => self.msg_req_get_close_group += 1,
                    RequestContent::Refresh(..) => self.msg_req_refresh += 1,
                    RequestContent::Connect => self.msg_req_connect += 1,
                    RequestContent::ConnectionInfo { .. } => self.msg_req_connection_info += 1,
                    RequestContent::GetPublicId => self.msg_req_get_public_id += 1,
                    RequestContent::GetPublicIdWithConnectionInfo { .. } => {
                        self.msg_req_get_public_id_with_connection_info += 1
                    }
                    _ => self.msg_other += 1,
                }
            }
            RoutingMessage::Response(ref response) => {
                match response.content {
                    ResponseContent::GetSuccess(..) => self.msg_rsp_get_success += 1,
                    ResponseContent::GetFailure { .. } => self.msg_rsp_get_failure += 1,
                    ResponseContent::PutSuccess(..) => self.msg_rsp_put_success += 1,
                    ResponseContent::PutFailure { .. } => self.msg_rsp_put_failure += 1,
                    ResponseContent::PostSuccess(..) => self.msg_rsp_post_success += 1,
                    ResponseContent::PostFailure { .. } => self.msg_rsp_post_failure += 1,
                    ResponseContent::DeleteSuccess(..) => self.msg_rsp_delete_success += 1,
                    ResponseContent::DeleteFailure { .. } => self.msg_rsp_delete_failure += 1,
                    ResponseContent::GetCloseGroup { .. } => self.msg_rsp_get_close_group += 1,
                    ResponseContent::GetPublicId { .. } => self.msg_rsp_get_public_id += 1,
                    ResponseContent::GetPublicIdWithConnectionInfo { .. } => {
                        self.msg_rsp_get_public_id_with_connection_info += 1
                    }
                    _ => self.msg_other += 1,
                }
            }
        }
        self.increment_msg_total();
    }

    /// Increments the counter for the given direct message type.
    pub fn count_direct_message(&mut self, msg: &DirectMessage) {
        match *msg {
            DirectMessage::NodeIdentify { .. } => self.msg_direct_node_identify += 1,
            DirectMessage::Heartbeat => self.msg_direct_heartbeat += 1,
            DirectMessage::NewNode(_) => self.msg_direct_new_node += 1,
            DirectMessage::ConnectionUnneeded(..) => self.msg_direct_connection_unneeded += 1,
            _ => self.msg_other += 1,
        }
        self.increment_msg_total();
    }

    /// Increment the total message count, and if divisible by 100, log a message with the counts.
    fn increment_msg_total(&mut self) {
        self.msg_total += 1;
        if self.msg_total % 100 == 0 {
            debug!("Stats - Sent {} messages in total, {} uncategorised",
                   self.msg_total,
                   self.msg_other);
            debug!("Direct - NodeIdentify: {}, Heartbeat: {}, NewNode: {}, ConnectionUnneeded: {}",
                   self.msg_direct_node_identify,
                   self.msg_direct_heartbeat,
                   self.msg_direct_new_node,
                   self.msg_direct_connection_unneeded);
            debug!("Requests - Get: {}, Put: {}, Post: {}, Delete: {}, GetCloseGroup: {}, \
                    Refresh: {}, Connect: {}, ConnectionInfo: {}, GetPublicId: {}, \
                    GetPublicIdWithConnectionInfo: {}",
                   self.msg_req_get,
                   self.msg_req_put,
                   self.msg_req_post,
                   self.msg_req_delete,
                   self.msg_req_get_close_group,
                   self.msg_req_refresh,
                   self.msg_req_connect,
                   self.msg_req_connection_info,
                   self.msg_req_get_public_id,
                   self.msg_req_get_public_id_with_connection_info);
            debug!("Responses - GetSuccess: {}, GetFailure: {}, PutSuccess: {}, PutFailure: {}, \
                    PostSuccess: {}, PostFailure: {}, DeleteSuccess: {}, DeleteFailure: {}, \
                    GetCloseGroup: {}, GetPublicId: {}, GetPublicIdWithConnectionInfo: {}",
                   self.msg_rsp_get_success,
                   self.msg_rsp_get_failure,
                   self.msg_rsp_put_success,
                   self.msg_rsp_put_failure,
                   self.msg_rsp_post_success,
                   self.msg_rsp_post_failure,
                   self.msg_rsp_delete_success,
                   self.msg_rsp_delete_failure,
                   self.msg_rsp_get_close_group,
                   self.msg_rsp_get_public_id,
                   self.msg_rsp_get_public_id_with_connection_info);
        }
    }
}

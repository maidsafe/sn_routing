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

/// The number of messages after which the message statistics should be printed.
const MSG_LOG_COUNT: usize = 5000;

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
    routes: Vec<usize>,
    /// Messages we sent unsuccessfully: unacknowledged on all routes.
    unacked_msgs: usize,

    msg_direct_node_identify: usize,
    msg_direct_candidate_identify: usize,
    msg_direct_sig: usize,
    msg_direct_resource_proof: usize,
    msg_direct_resource_proof_rsp: usize,
    msg_direct_resource_proof_rsp_receipt: usize,
    msg_direct_sls: usize,

    msg_get: usize,
    msg_put: usize,
    msg_post: usize,
    msg_delete: usize,
    msg_append: usize,
    msg_get_account_info: usize,
    msg_get_node_name: usize,
    msg_expect_candidate: usize,
    msg_accept_as_candidate: usize,
    msg_refresh: usize,
    msg_connection_info_req: usize,
    msg_connection_info_rsp: usize,
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
    msg_section_update: usize,
    msg_section_split: usize,
    msg_own_section_merge: usize,
    msg_other_section_merge: usize,
    msg_rt_req: usize,
    msg_rt_rsp: usize,
    msg_get_node_name_rsp: usize,
    msg_candidate_approval: usize,
    msg_node_approval: usize,
    msg_ack: usize,

    msg_other: usize,

    msg_total: usize,
    msg_total_bytes: u64,

    should_log: bool,
}

impl Stats {
    // Create a new instance, with the given number of routes
    pub fn new() -> Self {
        Default::default()
    }

    pub fn count_unacked(&mut self) {
        self.unacked_msgs += 1;
    }

    pub fn count_route(&mut self, route: u8) {
        let route = route as usize;
        if route >= self.routes.len() {
            self.routes.resize(route + 1, 0);
        }
        self.routes[route] += 1;
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
            MessageContent::ExpectCandidate { .. } => self.msg_expect_candidate += 1,
            MessageContent::AcceptAsCandidate { .. } => self.msg_accept_as_candidate += 1,
            MessageContent::ConnectionInfoRequest { .. } => self.msg_connection_info_req += 1,
            MessageContent::ConnectionInfoResponse { .. } => self.msg_connection_info_rsp += 1,
            MessageContent::SectionUpdate { .. } => self.msg_section_update += 1,
            MessageContent::SectionSplit(..) => self.msg_section_split += 1,
            MessageContent::OwnSectionMerge(..) => self.msg_own_section_merge += 1,
            MessageContent::OtherSectionMerge(..) => self.msg_other_section_merge += 1,
            MessageContent::RoutingTableRequest(..) => self.msg_rt_req += 1,
            MessageContent::RoutingTableResponse { .. } => self.msg_rt_rsp += 1,
            MessageContent::GetNodeNameResponse { .. } => self.msg_get_node_name_rsp += 1,
            MessageContent::Ack(..) => self.msg_ack += 1,
            MessageContent::CandidateApproval { .. } => self.msg_candidate_approval += 1,
            MessageContent::NodeApproval { .. } => self.msg_node_approval += 1,
            MessageContent::UserMessagePart { .. } => return, // Counted as request/response.
        }
        self.increment_msg_total();
    }

    /// Increments the counter for the given direct message type.
    pub fn count_direct_message(&mut self, msg: &DirectMessage) {
        use messages::DirectMessage::*;
        match *msg {
            NodeIdentify { .. } => self.msg_direct_node_identify += 1,
            CandidateIdentify { .. } => self.msg_direct_candidate_identify += 1,
            MessageSignature(..) => self.msg_direct_sig += 1,
            SectionListSignature(..) => self.msg_direct_sls += 1,
            ResourceProof { .. } => self.msg_direct_resource_proof += 1,
            ResourceProofResponse { .. } => self.msg_direct_resource_proof_rsp += 1,
            ResourceProofResponseReceipt => self.msg_direct_resource_proof_rsp_receipt += 1,
            BootstrapIdentify { .. } |
            BootstrapDeny |
            ClientIdentify { .. } |
            TunnelRequest(_) |
            TunnelSuccess(_) |
            TunnelClosed(_) |
            TunnelDisconnect(_) => self.msg_other += 1,
        }
        self.increment_msg_total();
    }

    pub fn count_bytes(&mut self, len: usize) {
        self.msg_total_bytes += len as u64;
    }

    pub fn enable_logging(&mut self) {
        self.should_log = true;
    }

    /// Increments the total message count, and if the count is divisible by
    /// `MSG_LOG_COUNT` logs a message with the counts.
    fn increment_msg_total(&mut self) {
        self.msg_total += 1;
        if self.should_log && self.msg_total % MSG_LOG_COUNT == 0 {
            info!(target: "routing_stats",
                  "Stats - Sent {} messages in total, comprising {} bytes, {} uncategorised, \
                   routes/failed: {:?}/{}",
                  self.msg_total,
                  self.msg_total_bytes,
                  self.msg_other,
                  self.routes,
                  self.unacked_msgs);
            info!(target: "routing_stats",
                  "Stats - Direct - NodeIdentify: {}, CandidateIdentify: {}, \
                   MessageSignature: {}, ResourceProof: {}/{}/{}, SectionListSignature: {}",
                  self.msg_direct_node_identify,
                  self.msg_direct_candidate_identify,
                  self.msg_direct_sig,
                  self.msg_direct_resource_proof,
                  self.msg_direct_resource_proof_rsp,
                  self.msg_direct_resource_proof_rsp_receipt,
                  self.msg_direct_sls);
            info!(target: "routing_stats",
                  "Stats - Hops (Request/Response) - GetNodeName: {}/{}, ExpectCandidate: {}, \
                   AcceptAsCandidate: {}, SectionUpdate: {}, SectionSplit: {}, \
                   OwnSectionMerge: {}, OtherSectionMerge: {}, RoutingTable: {}/{}, \
                   ConnectionInfo: {}/{}, CandidateApproval: {}, NodeApproval: {}, Ack: {}",
                  self.msg_get_node_name,
                  self.msg_get_node_name_rsp,
                  self.msg_expect_candidate,
                  self.msg_accept_as_candidate,
                  self.msg_section_update,
                  self.msg_section_split,
                  self.msg_own_section_merge,
                  self.msg_other_section_merge,
                  self.msg_rt_req,
                  self.msg_rt_rsp,
                  self.msg_connection_info_req,
                  self.msg_connection_info_rsp,
                  self.msg_candidate_approval,
                  self.msg_node_approval,
                  self.msg_ack);
            info!(target: "routing_stats",
                  "Stats - User (Request/Success/Failure) - Get: {}/{}/{}, Put: {}/{}/{}, \
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

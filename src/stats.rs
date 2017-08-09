// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use messages::{DirectMessage, MessageContent, Request, Response, RoutingMessage, UserMessage};
use std::fmt::{self, Display, Formatter};

/// The number of messages after which the message statistics should be printed.
const MSG_LOG_COUNT: usize = 5000;

/// A collection of counters to gather Routing statistics.
#[derive(Default, Clone)]
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

    msg_direct_candidate_info: usize,
    msg_direct_sig: usize,
    msg_direct_resource_proof: usize,
    msg_direct_resource_proof_rsp: usize,
    msg_direct_resource_proof_rsp_receipt: usize,
    msg_direct_proxy_rate_limit_exceed: usize,
    msg_direct_sls: usize,

    msg_get: usize,
    msg_put: usize,
    msg_post: usize,
    msg_delete: usize,
    msg_append: usize,
    msg_relocate: usize,
    msg_expect_candidate: usize,
    msg_accept_as_candidate: usize,
    msg_refresh: usize,
    msg_connection_info_req: usize,
    msg_connection_info_rsp: usize,
    msg_section_update: usize,
    msg_section_split: usize,
    msg_own_section_merge: usize,
    msg_other_section_merge: usize,
    msg_relocate_rsp: usize,
    msg_candidate_approval: usize,
    msg_node_approval: usize,
    msg_ack: usize,

    pub msg_user_parts: u64,
    msg_put_idata: UserMessageStats,
    msg_get_idata: UserMessageStats,
    msg_get_mdata: UserMessageStats,
    msg_put_mdata: UserMessageStats,
    msg_get_mdata_version: UserMessageStats,
    msg_get_mdata_shell: UserMessageStats,
    msg_list_mdata_entries: UserMessageStats,
    msg_list_mdata_keys: UserMessageStats,
    msg_list_mdata_values: UserMessageStats,
    msg_get_mdata_value: UserMessageStats,
    msg_mutate_mdata_entries: UserMessageStats,
    msg_list_mdata_permissions: UserMessageStats,
    msg_list_mdata_user_permissions: UserMessageStats,
    msg_set_mdata_user_permissions: UserMessageStats,
    msg_del_mdata_user_permissions: UserMessageStats,
    msg_change_mdata_owner: UserMessageStats,
    msg_list_auth_keys_and_version: UserMessageStats,
    msg_ins_auth_key: UserMessageStats,
    msg_del_auth_key: UserMessageStats,
    msg_get_account_info: UserMessageStats,

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

    pub fn increase_user_msg_part(&mut self) {
        self.msg_user_parts = self.msg_user_parts.wrapping_add(1);
    }

    /// Increments the counter for the given user message.
    pub fn count_user_message(&mut self, msg: &UserMessage) {
        match *msg {
            UserMessage::Request(ref request) => {
                match *request {
                    Request::PutIData { .. } => self.msg_put_idata.inc_request(),
                    Request::GetIData { .. } => self.msg_get_idata.inc_request(),
                    Request::GetMData { .. } => self.msg_get_mdata.inc_request(),
                    Request::PutMData { .. } => self.msg_put_mdata.inc_request(),
                    Request::GetMDataVersion { .. } => self.msg_get_mdata_version.inc_request(),
                    Request::GetMDataShell { .. } => self.msg_get_mdata_shell.inc_request(),
                    Request::ListMDataKeys { .. } => self.msg_list_mdata_keys.inc_request(),
                    Request::ListMDataValues { .. } => self.msg_list_mdata_values.inc_request(),
                    Request::ListMDataEntries { .. } => self.msg_list_mdata_entries.inc_request(),
                    Request::GetMDataValue { .. } => self.msg_get_mdata_value.inc_request(),
                    Request::MutateMDataEntries { .. } => {
                        self.msg_mutate_mdata_entries.inc_request()
                    }
                    Request::ListMDataPermissions { .. } => {
                        self.msg_list_mdata_permissions.inc_request()
                    }
                    Request::ListMDataUserPermissions { .. } => {
                        self.msg_list_mdata_user_permissions.inc_request()
                    }
                    Request::SetMDataUserPermissions { .. } => {
                        self.msg_set_mdata_user_permissions.inc_request()
                    }
                    Request::DelMDataUserPermissions { .. } => {
                        self.msg_del_mdata_user_permissions.inc_request()
                    }
                    Request::ChangeMDataOwner { .. } => self.msg_change_mdata_owner.inc_request(),
                    Request::ListAuthKeysAndVersion { .. } => {
                        self.msg_list_auth_keys_and_version.inc_request()
                    }
                    Request::InsAuthKey { .. } => self.msg_ins_auth_key.inc_request(),
                    Request::DelAuthKey { .. } => self.msg_del_auth_key.inc_request(),
                    Request::GetAccountInfo { .. } => self.msg_get_account_info.inc_request(),
                    Request::Refresh(..) => self.msg_refresh += 1,
                }
            }
            UserMessage::Response(ref response) => {
                match *response {
                    Response::PutIData { ref res, .. } => {
                        self.msg_put_idata.inc_response(res.is_ok())
                    }
                    Response::GetIData { ref res, .. } => {
                        self.msg_get_idata.inc_response(res.is_ok())
                    }
                    Response::PutMData { ref res, .. } => {
                        self.msg_put_mdata.inc_response(res.is_ok())
                    }
                    Response::GetMData { ref res, .. } => {
                        self.msg_get_mdata.inc_response(res.is_ok())
                    }
                    Response::GetMDataVersion { ref res, .. } => {
                        self.msg_get_mdata_version.inc_response(res.is_ok())
                    }
                    Response::GetMDataShell { ref res, .. } => {
                        self.msg_get_mdata_shell.inc_response(res.is_ok())
                    }
                    Response::ListMDataKeys { ref res, .. } => {
                        self.msg_list_mdata_keys.inc_response(res.is_ok())
                    }
                    Response::ListMDataValues { ref res, .. } => {
                        self.msg_list_mdata_values.inc_response(res.is_ok())
                    }
                    Response::ListMDataEntries { ref res, .. } => {
                        self.msg_list_mdata_entries.inc_response(res.is_ok())
                    }
                    Response::GetMDataValue { ref res, .. } => {
                        self.msg_get_mdata_value.inc_response(res.is_ok())
                    }
                    Response::MutateMDataEntries { ref res, .. } => {
                        self.msg_mutate_mdata_entries.inc_response(res.is_ok())
                    }
                    Response::ListMDataPermissions { ref res, .. } => {
                        self.msg_list_mdata_permissions.inc_response(res.is_ok())
                    }
                    Response::ListMDataUserPermissions { ref res, .. } => {
                        self.msg_list_mdata_user_permissions.inc_response(
                            res.is_ok(),
                        )
                    }
                    Response::SetMDataUserPermissions { ref res, .. } => {
                        self.msg_set_mdata_user_permissions.inc_response(
                            res.is_ok(),
                        )
                    }
                    Response::DelMDataUserPermissions { ref res, .. } => {
                        self.msg_del_mdata_user_permissions.inc_response(
                            res.is_ok(),
                        )
                    }
                    Response::ChangeMDataOwner { ref res, .. } => {
                        self.msg_change_mdata_owner.inc_response(res.is_ok())
                    }
                    Response::ListAuthKeysAndVersion { ref res, .. } => {
                        self.msg_list_auth_keys_and_version.inc_response(
                            res.is_ok(),
                        )
                    }
                    Response::InsAuthKey { ref res, .. } => {
                        self.msg_ins_auth_key.inc_response(res.is_ok())
                    }
                    Response::DelAuthKey { ref res, .. } => {
                        self.msg_del_auth_key.inc_response(res.is_ok())
                    }
                    Response::GetAccountInfo { ref res, .. } => {
                        self.msg_get_account_info.inc_response(res.is_ok())
                    }
                }
            }
        }

        self.increment_msg_total();
    }

    /// Increments the counter for the given routing message type.
    pub fn count_routing_message(&mut self, msg: &RoutingMessage) {
        match msg.content {
            MessageContent::Relocate { .. } => self.msg_relocate += 1,
            MessageContent::ExpectCandidate { .. } => self.msg_expect_candidate += 1,
            MessageContent::AcceptAsCandidate { .. } => self.msg_accept_as_candidate += 1,
            MessageContent::ConnectionInfoRequest { .. } => self.msg_connection_info_req += 1,
            MessageContent::ConnectionInfoResponse { .. } => self.msg_connection_info_rsp += 1,
            MessageContent::SectionUpdate { .. } => self.msg_section_update += 1,
            MessageContent::SectionSplit(..) => self.msg_section_split += 1,
            MessageContent::OwnSectionMerge(..) => self.msg_own_section_merge += 1,
            MessageContent::OtherSectionMerge(..) => self.msg_other_section_merge += 1,
            MessageContent::RelocateResponse { .. } => self.msg_relocate_rsp += 1,
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
            CandidateInfo { .. } => self.msg_direct_candidate_info += 1,
            MessageSignature(..) => self.msg_direct_sig += 1,
            SectionListSignature(..) => self.msg_direct_sls += 1,
            ResourceProof { .. } => self.msg_direct_resource_proof += 1,
            ResourceProofResponse { .. } => self.msg_direct_resource_proof_rsp += 1,
            ResourceProofResponseReceipt => self.msg_direct_resource_proof_rsp_receipt += 1,
            ProxyRateLimitExceeded { .. } => self.msg_direct_proxy_rate_limit_exceed += 1,
            BootstrapRequest(_) |
            BootstrapResponse(_) |
            TunnelRequest(_) |
            TunnelSuccess(_) |
            TunnelSelect(_) |
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
                  "Stats - Direct - CandidateInfo: {}, MessageSignature: {}, \
                   ResourceProof: {}/{}/{}, SectionListSignature: {}, ProxyRateLimitExceeded: {}",
                  self.msg_direct_candidate_info,
                  self.msg_direct_sig,
                  self.msg_direct_resource_proof,
                  self.msg_direct_resource_proof_rsp,
                  self.msg_direct_resource_proof_rsp_receipt,
                  self.msg_direct_sls,
                  self.msg_direct_proxy_rate_limit_exceed);
            info!(target: "routing_stats",
                  "Stats - Hops (Request/Response) - Relocate: {}/{}, ExpectCandidate: {}, \
                   AcceptAsCandidate: {}, SectionUpdate: {}, SectionSplit: {}, \
                   OwnSectionMerge: {}, OtherSectionMerge: {}, ConnectionInfo: {}/{}, \
                   CandidateApproval: {}, NodeApproval: {}, Ack: {}",
                  self.msg_relocate,
                  self.msg_relocate_rsp,
                  self.msg_expect_candidate,
                  self.msg_accept_as_candidate,
                  self.msg_section_update,
                  self.msg_section_split,
                  self.msg_own_section_merge,
                  self.msg_other_section_merge,
                  self.msg_connection_info_req,
                  self.msg_connection_info_rsp,
                  self.msg_candidate_approval,
                  self.msg_node_approval,
                  self.msg_ack);
            info!(target: "routing_stats",
                  "Stats - User (total parts: {}) (Request/Success/Failure) - \
                   PutIData: {}, \
                   GetIData: {}, \
                   PutMData: {}, \
                   GetMDataVersion: {}, \
                   GetMDataShell: {}, \
                   ListMDataKeys: {}, \
                   ListMDataValues: {}, \
                   ListMDataEntries: {}, \
                   GetMDataValue: {}, \
                   MutateMDataEntries: {}, \
                   ListMDataPermissions: {}, \
                   ListMDataUserPermissions: {}, \
                   SetMDataUserPermissions: {}, \
                   DelMDataUserPermissions: {}, \
                   ChangeMDataOwner: {}, \
                   ListAuthKeysAndVersion: {}, \
                   InsAuthKey: {}, \
                   DelAuthKey: {}, \
                   GetAccountInfo: {}, \
                   Refresh: {}",
                  self.msg_user_parts,
                  self.msg_put_idata,
                  self.msg_get_idata,
                  self.msg_put_mdata,
                  self.msg_get_mdata_version,
                  self.msg_get_mdata_shell,
                  self.msg_list_mdata_keys,
                  self.msg_list_mdata_values,
                  self.msg_list_mdata_entries,
                  self.msg_get_mdata_value,
                  self.msg_mutate_mdata_entries,
                  self.msg_list_mdata_permissions,
                  self.msg_list_mdata_user_permissions,
                  self.msg_set_mdata_user_permissions,
                  self.msg_del_mdata_user_permissions,
                  self.msg_change_mdata_owner,
                  self.msg_list_auth_keys_and_version,
                  self.msg_ins_auth_key,
                  self.msg_del_auth_key,
                  self.msg_get_account_info,
                  self.msg_refresh);
        }
    }
}

#[derive(Copy, Clone)]
struct UserMessageStats {
    request: usize,
    success: usize,
    failure: usize,
}

impl UserMessageStats {
    fn inc_request(&mut self) {
        self.request += 1;
    }

    fn inc_response(&mut self, success: bool) {
        if success {
            self.success += 1;
        } else {
            self.failure += 1;
        }
    }
}

impl Default for UserMessageStats {
    fn default() -> Self {
        UserMessageStats {
            request: 0,
            success: 0,
            failure: 0,
        }
    }
}

impl Display for UserMessageStats {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}/{}/{}", self.request, self.success, self.failure)
    }
}

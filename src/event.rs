// Copyright 2015 MaidSafe.net limited.
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

use authority::Authority;
use messages::{ExternalRequest, ExternalResponse, SignedToken};
use error::InterfaceError;

/// An Event is received at the effective close group of B of a message flow < A | B >
#[derive(Clone, Eq, PartialEq)]
pub enum Event {
    /// Request.
    Request {
        /// External request.
        request: ExternalRequest,
        /// Our authority.
        our_authority: Authority,
        /// From authority.
        from_authority: Authority,
        /// Not set when the request came from a group.
        response_token: Option<SignedToken>, 
    },
    /// Response.
    Response {
        /// External response.
        response: ExternalResponse,
        /// Our authority.
        our_authority: Authority,
        /// From authority.
        from_authority: Authority,
    },
    /// FailedRequest.
    FailedRequest {
        /// External request.
        request: ExternalRequest,
        /// Our authority.
        our_authority: Option<Authority>,
        /// From authority.
        location: Authority,
        /// Interface error.
        interface_error: InterfaceError,
    },
    /// FailedResponse.
    FailedResponse {
        /// External response.
        response: ExternalResponse,
        /// Our authority.
        our_authority: Option<Authority>,
        /// From authority.
        location: Authority,
        /// Interface error.
        interface_error: InterfaceError,
    },
    /// Refresh reports to the user the collected accounts for a given refresh event,
    /// the arguments are type_tag:u64, authority: Authority, vector_of_bytes: Vec<Vec<u8>>
    Refresh(u64, ::authority::Authority, Vec<Vec<u8>>),
    /// Churn reports whenever our close group is changed, and provides our new close group
    /// as a Vec<NameType> and the name of the node that joined or left our close group
    /// as NameType.  Our close group is sorted from our name and always includes our own name
    /// as the first element.
    Churn(Vec<::NameType>, ::NameType),
    /// DoRefresh reports that a Refresh message is circulating the effective close group
    /// of the given Authority, but that the user is outside of the close group of the churn
    /// that initiated the call for refresh.  To ensure that the account of the current user is
    /// also accumulated a DoRefresh indicates precisely one account routing will expect the
    /// user to do a ::routing::request_refresh for, if a matching account is held by the user.
    DoRefresh(u64, ::authority::Authority, ::NameType),
    /// Bootstrapped.
    Bootstrapped,
    /// Connected.
    Connected,
    /// Disconnected.
    Disconnected,
    /// Event::Terminated is called after RoutingNode::stop() has terminated internal processes
    Terminated,
}

impl ::std::fmt::Debug for Event {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        match self {
            &Event::Request{ ref request, ref our_authority, ref from_authority, ref response_token } => {
                formatter.write_str(&format!("Request(request: {:?} , \
                    our_authority: {:?} , from_authority: {:?}, response_token: {:?})",
                    request, our_authority, from_authority, response_token))
            }
            &Event::Response{ ref response, ref our_authority, ref from_authority } => {
                formatter.write_str(&format!("Response(response: {:?} , \
                    our_authority: {:?} , from_authority: {:?})",
                    response, our_authority, from_authority))
            }
            &Event::FailedRequest{ ref request, ref our_authority, ref location, ref interface_error } => {
                formatter.write_str(&format!("FailedRequest(request: {:?} , \
                    our_authority: {:?} , location: {:?} , interface_error: {:?})",
                    request, our_authority, location, interface_error))
            }
            &Event::FailedResponse{ ref response, ref our_authority, ref location, ref interface_error } => {
                formatter.write_str(&format!("FailedResponse(response: {:?} , \
                    our_authority: {:?} , location: {:?} , interface_error: {:?})",
                    response, our_authority, location, interface_error))
            }
            &Event::Refresh(ref type_tag, ref target, ref payloads) => {
                let _ = formatter.write_str(&format!("Refresh(type_tag: {:?} , target: {:?} , \
                    payloads: (", type_tag, target));
                for payload in payloads.iter() {
                    let _ = formatter.write_str(&format!("{:?} ",
                                                ::utils::get_debug_id(payload.clone())));
                }
                formatter.write_str(&format!("))"))
            }
            &Event::Churn(ref close_group, ref churn_node) => {
                formatter.write_str(&format!("Churn (close_group: {:?} , churn_node: {:?})",
                                             close_group, churn_node))
            }
            &Event::DoRefresh(ref type_tag, ref target, ref churn_node) => {
                formatter.write_str(&format!("DoRefresh(type_tag: {:?} , target: {:?} , \
                    churn_node: {:?})", type_tag, target, churn_node))
            }
            &Event::Bootstrapped => {
                formatter.write_str(&format!("Bootstrapped"))
            }
            &Event::Connected => {
                formatter.write_str(&format!("Connected"))
            }
            &Event::Disconnected => {
                formatter.write_str(&format!("Disconnected"))
            }
            &Event::Terminated => {
                formatter.write_str(&format!("Terminated"))
            }
        }
    }
}
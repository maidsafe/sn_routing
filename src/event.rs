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

use xor_name::XorName;
use authority::Authority;
use messages::{RequestMessage, ResponseMessage};

/// An Event is received at the effective close group of B of a message flow < A | B >
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Event {
    /// Request.
    Request(RequestMessage),
    /// Response.
    Response(ResponseMessage),
    /// Refresh reports to the user the collected accounts for a given refresh event,
    /// the arguments are type_tag:u64, authority: Authority, vector_of_bytes: Vec<Vec<u8>>
    Refresh {
        /// Destination authority from message request, should be identical to source authority.
        dst: Authority,
        /// externally defined value
        raw_bytes: Vec<u8>,
        /// The node that caused the churn event.
        /// Used here (passed up to upper layers in churn event) who must give it back in
        /// which allows filtering of different churn events (used as unique identifier)
        cause: XorName,
        /// The name of the request sender.
        sender: XorName,
    },
    /// Churn reports whenever our close group is changed, and provides our new close group
    /// as a Vec<XorName> and the name of the node that joined or left our close group
    /// as XorName.  Our close group is sorted from our name and always includes our own name
    /// as the first element.
    Churn(Vec<XorName>, XorName),
    /// Current quorum size.
    DynamicQuorum(usize),
    /// Connected.
    Connected,
    /// Disconnected.
    Disconnected,
    /// Event::Terminated is called after RoutingNode::stop() has terminated internal processes
    Terminated,
}

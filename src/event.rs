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
use messages::{RequestMessage, ResponseMessage};

/// An Event raised by a `Node` or `Client` via its event sender.
///
/// These are sent by routing to the library's user. It allows the user to handle requests and
/// responses, and to react to changes in the network.
///
/// `Request` and `Response` events from group authorities are only raised once the quorum has been
/// reached, i. e. enough members of the group have sent the same message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Event {
    /// Request.
    Request(RequestMessage),
    /// Response.
    Response(ResponseMessage),
    /// A new node joined the network and may be a member of group authorities we also belong to.
    NodeAdded(XorName),
    /// A node left the network and may have been a member of group authorities we also belong to.
    NodeLost(XorName),
    /// The client has successfully connected to a proxy node on the network.
    Connected,
}

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

use kademlia_routing_table::RoutingTable;
use xor_name::XorName;

use core::NodeInfo;
use messages::{RequestMessage, ResponseMessage};
use std::fmt::{self, Debug, Formatter};

/// An Event raised by a `Node` or `Client` via its event sender.
///
/// These are sent by routing to the library's user. It allows the user to handle requests and
/// responses, and to react to changes in the network.
///
/// `Request` and `Response` events from group authorities are only raised once the quorum has been
/// reached, i. e. enough members of the group have sent the same message.
#[derive(Clone, Eq, PartialEq)]
pub enum Event {
    /// Request.
    Request(RequestMessage),
    /// Response.
    Response(ResponseMessage),
    /// A new node joined the network and may be a member of group authorities we also belong to.
    NodeAdded(XorName, RoutingTable<NodeInfo>),
    /// A node left the network and may have been a member of group authorities we also belong to.
    NodeLost(XorName, RoutingTable<NodeInfo>),
    /// The client has successfully connected to a proxy node on the network.
    Connected,
    /// We have disconnected from the network.
    Disconnected,
    /// We failed to relocate as a new node in the network.
    GetNetworkNameFailed,
    /// We failed to start listening for incoming connections as the first node.
    NetworkStartupFailed,
    // TODO: Find a better solution for periodic tasks.
    /// This event is sent periodically every time Routing sends the `Heartbeat` messages.
    Tick,
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Event::Request(ref request) => write!(formatter, "Event::Request({:?})", request),
            Event::Response(ref response) => write!(formatter, "Event::Response({:?})", response),
            Event::NodeAdded(ref node_name, _) => {
                write!(formatter,
                       "Event::NodeAdded({:?}, routing_table)",
                       node_name)
            }
            Event::NodeLost(ref node_name, _) => {
                write!(formatter, "Event::NodeLost({:?}, routing_table)", node_name)
            }
            Event::Connected => write!(formatter, "Event::Connected"),
            Event::Disconnected => write!(formatter, "Event::Disconnected"),
            Event::GetNetworkNameFailed => write!(formatter, "Event::GetNetworkNameFailed"),
            Event::NetworkStartupFailed => write!(formatter, "Event::NetworkStartupFailed"),
            Event::Tick => write!(formatter, "Event::Tick"),
        }
    }
}

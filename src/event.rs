// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::messages::{Request, Response};
use crate::routing_table::Authority;
use crate::routing_table::Prefix;
use crate::xor_name::XorName;
use std::fmt::{self, Debug, Formatter};

/// An Event raised by a `Node` or `Client` via its event sender.
///
/// These are sent by routing to the library's user. It allows the user to handle requests and
/// responses, and to react to changes in the network.
///
/// `Request` and `Response` events from section authorities are only raised once the quorum has
/// been reached, i.e. enough members of the section have sent the same message.
#[derive(Clone, Eq, PartialEq)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// Received a request message.
    Request {
        /// The request message.
        request: Request,
        /// The source authority that sent the request.
        src: Authority<XorName>,
        /// The destination authority that receives the request.
        dst: Authority<XorName>,
    },
    /// Received a response message.
    Response {
        /// The response message.
        response: Response,
        /// The source authority that sent the response.
        src: Authority<XorName>,
        /// The destination authority that receives the response.
        dst: Authority<XorName>,
    },
    /// A node has connected to us.
    NodeAdded(XorName),
    /// A node has disconnected from us.
    NodeLost(XorName),
    /// Our own section has been split, resulting in the included `Prefix` for our new section.
    SectionSplit(Prefix<XorName>),
    /// Our own section requires merged with others, resulting in the included `Prefix` for our new
    /// section.
    SectionMerge(Prefix<XorName>),
    /// The client has successfully connected to a proxy node on the network.
    Connected,
    /// Disconnected or failed to connect - restart required.
    RestartRequired,
    /// Startup failed - terminate.
    Terminate,
    // TODO: Find a better solution for periodic tasks.
    /// This event is sent periodically every time Routing sends the `Heartbeat` messages.
    Tick,
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Event::Request {
                ref request,
                ref src,
                ref dst,
            } => write!(
                formatter,
                "Event::Request {{ request: {:?}, src: {:?}, dst: {:?} }}",
                request, src, dst
            ),
            Event::Response {
                ref response,
                ref src,
                ref dst,
            } => write!(
                formatter,
                "Event::Response {{ response: {:?}, src: {:?}, dst: {:?} }}",
                response, src, dst
            ),
            Event::NodeAdded(ref node_name) => {
                write!(formatter, "Event::NodeAdded({:?})", node_name)
            }
            Event::NodeLost(ref node_name) => write!(formatter, "Event::NodeLost({:?})", node_name),
            Event::SectionSplit(ref prefix) => {
                write!(formatter, "Event::SectionSplit({:?})", prefix)
            }
            Event::SectionMerge(ref prefix) => {
                write!(formatter, "Event::SectionMerge({:?})", prefix)
            }
            Event::Connected => write!(formatter, "Event::Connected"),
            Event::RestartRequired => write!(formatter, "Event::RestartRequired"),
            Event::Terminate => write!(formatter, "Event::Terminate"),
            Event::Tick => write!(formatter, "Event::Tick"),
        }
    }
}

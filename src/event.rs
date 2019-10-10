// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::routing_table::Authority;
use crate::routing_table::Prefix;
use crate::xor_name::XorName;
use crate::NetworkBytes;
use hex_fmt::HexFmt;
use quic_p2p::Token;
use std::fmt::{self, Debug, Formatter};
use std::net::SocketAddr;

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
    // =========== Client Events - Routing won't handle these ===========
    /// Inform the user (library) that we are connected to a client
    ConnectedToClient {
        /// Client's endpoint
        peer_addr: SocketAddr,
    },
    /// Inform the user (library) that we are disconnected from a client
    ConnectionFailureToClient {
        /// Client's endpoint
        peer_addr: SocketAddr,
    },
    /// Inform the user (library) that we have a new message from a client
    NewMessageFromClient {
        /// Client's endpoint
        peer_addr: SocketAddr,
        /// Client's message
        msg: NetworkBytes,
    },
    /// Inform the user (library) that we couldn't send this message to a client
    UnsentUserMsgToClient {
        /// Client's endpoint
        peer_addr: SocketAddr,
        /// Message we had tried to send to the client
        msg: NetworkBytes,
        /// Token that we had used to identify this message
        token: Token,
    },
    /// Inform the user (library) that we have successfully sent this message to a client
    SentUserMsgToClient {
        /// Client's endpoint
        peer_addr: SocketAddr,
        /// Message we had tried to send to the client
        msg: NetworkBytes,
        /// Token that we had used to identify this message
        token: Token,
    },
    // ==================================================================
    /// Received a message.
    MessageReceived {
        /// The content of the message.
        content: Vec<u8>,
        /// The source authority that sent the message.
        src: Authority<XorName>,
        /// The destination authority that receives the message.
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
    SectionMerged(Prefix<XorName>),
    /// The client has successfully connected to a proxy node on the network.
    Connected,
    /// Disconnected or failed to connect - restart required.
    RestartRequired,
    /// Startup failed - terminate.
    Terminated,
    // TODO: Find a better solution for periodic tasks.
    /// This event is sent periodically every time Routing sends the `Heartbeat` messages.
    TimerTicked,
    /// Consensus on a custom event.
    Consensus(Vec<u8>),
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Event::ConnectedToClient { peer_addr } => {
                write!(formatter, "Event::ConnectedToClient - {}", peer_addr)
            }
            Event::ConnectionFailureToClient { peer_addr } => {
                write!(formatter, "Event::ConnectionFailureToClient: {}", peer_addr)
            }
            Event::NewMessageFromClient { peer_addr, .. } => {
                write!(formatter, "Event::NewMessageFromClient: {}", peer_addr)
            }
            Event::UnsentUserMsgToClient {
                peer_addr, token, ..
            } => write!(
                formatter,
                "Event::UnsentUserMsgToClient: {} with Token: {}",
                peer_addr, token
            ),
            Event::SentUserMsgToClient {
                peer_addr, token, ..
            } => write!(
                formatter,
                "Event::SentUserMsgToClient: {} with Token: {}",
                peer_addr, token
            ),
            Event::MessageReceived {
                ref content,
                ref src,
                ref dst,
            } => write!(
                formatter,
                "Event::MessageReceived {{ content: \"{:<8}\", src: {:?}, dst: {:?} }}",
                HexFmt(content),
                src,
                dst
            ),
            Event::NodeAdded(ref node_name) => {
                write!(formatter, "Event::NodeAdded({:?})", node_name)
            }
            Event::NodeLost(ref node_name) => write!(formatter, "Event::NodeLost({:?})", node_name),
            Event::SectionSplit(ref prefix) => {
                write!(formatter, "Event::SectionSplit({:?})", prefix)
            }
            Event::SectionMerged(ref prefix) => {
                write!(formatter, "Event::SectionMerged({:?})", prefix)
            }
            Event::Connected => write!(formatter, "Event::Connected"),
            Event::RestartRequired => write!(formatter, "Event::RestartRequired"),
            Event::Terminated => write!(formatter, "Event::Terminated"),
            Event::TimerTicked => write!(formatter, "Event::TimerTicked"),
            Event::Consensus(ref payload) => {
                write!(formatter, "Event::Consensus({:<8})", HexFmt(payload))
            }
        }
    }
}

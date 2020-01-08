// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    authority::Authority,
    xor_space::{Prefix, XorName},
    NetworkBytes,
};
use hex_fmt::HexFmt;
use quic_p2p::Token;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};

/// An Event raised by a `Client`
///
/// These are send transparently to the user library and not handled by routing
#[derive(Clone, Eq, PartialEq)]
pub enum ClientEvent {
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
}

/// An Event raised as node complete joining
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConnectEvent {
    /// Node first joining the network
    First,
    /// Node relocating from one section to another
    Relocate,
}

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
    /// Client events - to be sent to the user library and not handled in the routing library.
    ClientEvent(ClientEvent),
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
    /// The client has successfully connected to a proxy node on the network.
    Connected(ConnectEvent),
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

impl From<ClientEvent> for Event {
    fn from(client_event: ClientEvent) -> Self {
        Self::ClientEvent(client_event)
    }
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::ClientEvent(ref client_event) => {
                write!(formatter, "Event::ClientEvent({:?})", client_event)
            }
            Self::MessageReceived {
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
            Self::NodeAdded(ref node_name) => {
                write!(formatter, "Event::NodeAdded({:?})", node_name)
            }
            Self::NodeLost(ref node_name) => write!(formatter, "Event::NodeLost({:?})", node_name),
            Self::SectionSplit(ref prefix) => {
                write!(formatter, "Event::SectionSplit({:?})", prefix)
            }
            Self::Connected(ref connect_type) => {
                write!(formatter, "Event::Connected({:?})", connect_type)
            }
            Self::RestartRequired => write!(formatter, "Event::RestartRequired"),
            Self::Terminated => write!(formatter, "Event::Terminated"),
            Self::TimerTicked => write!(formatter, "Event::TimerTicked"),
            Self::Consensus(ref payload) => {
                write!(formatter, "Event::Consensus({:<8})", HexFmt(payload))
            }
        }
    }
}

impl Debug for ClientEvent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::ConnectedToClient { peer_addr } => {
                write!(formatter, "ClientEvent::ConnectedToClient - {}", peer_addr)
            }
            Self::ConnectionFailureToClient { peer_addr } => write!(
                formatter,
                "ClientEvent::ConnectionFailureToClient: {}",
                peer_addr
            ),
            Self::NewMessageFromClient { peer_addr, .. } => write!(
                formatter,
                "ClientEvent::NewMessageFromClient: {}",
                peer_addr
            ),
            Self::UnsentUserMsgToClient {
                peer_addr, token, ..
            } => write!(
                formatter,
                "ClientEvent::UnsentUserMsgToClient: {} with Token: {}",
                peer_addr, token
            ),
            Self::SentUserMsgToClient {
                peer_addr, token, ..
            } => write!(
                formatter,
                "ClientEvent::SentUserMsgToClient: {} with Token: {}",
                peer_addr, token
            ),
        }
    }
}

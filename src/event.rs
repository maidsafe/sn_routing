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
};
use bytes::Bytes;
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
pub enum Client {
    /// Inform the user (library) that we are connected to a client
    ConnectedTo {
        /// Client's endpoint
        peer_addr: SocketAddr,
    },
    /// Inform the user (library) that we are disconnected from a client
    ConnectionFailureTo {
        /// Client's endpoint
        peer_addr: SocketAddr,
    },
    /// Inform the user (library) that we have a new message from a client
    NewMessageFrom {
        /// Client's endpoint
        peer_addr: SocketAddr,
        /// Client's message
        msg: Bytes,
    },
    /// Inform the user (library) that we couldn't send this message to a client
    UnsentUserMsg {
        /// Client's endpoint
        peer_addr: SocketAddr,
        /// Message we had tried to send to the client
        msg: Bytes,
        /// Token that we had used to identify this message
        token: Token,
    },
    /// Inform the user (library) that we have successfully sent this message to a client
    SentUserMsg {
        /// Client's endpoint
        peer_addr: SocketAddr,
        /// Message we had tried to send to the client
        msg: Bytes,
        /// Token that we had used to identify this message
        token: Token,
    },
}

/// An Event raised as node complete joining
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Connect {
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
    Client(Client),
    /// Received a message.
    MessageReceived {
        /// The content of the message.
        content: Vec<u8>,
        /// The source authority that sent the message.
        src: Authority<XorName>,
        /// The destination authority that receives the message.
        dst: Authority<XorName>,
    },
    /// Our own section has been split, resulting in the included `Prefix` for our new section.
    SectionSplit(Prefix<XorName>),
    /// The client has successfully connected to a proxy node on the network.
    Connected(Connect),
    /// Disconnected or failed to connect - restart required.
    RestartRequired,
    /// Startup failed - terminate.
    Terminated,
    /// Consensus on a custom event.
    Consensus(Vec<u8>),
}

impl From<Client> for Event {
    fn from(client_event: Client) -> Self {
        Self::Client(client_event)
    }
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::Client(ref client_event) => {
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
            Self::SectionSplit(ref prefix) => {
                write!(formatter, "Event::SectionSplit({:?})", prefix)
            }
            Self::Connected(ref connect_type) => {
                write!(formatter, "Event::Connected({:?})", connect_type)
            }
            Self::RestartRequired => write!(formatter, "Event::RestartRequired"),
            Self::Terminated => write!(formatter, "Event::Terminated"),
            Self::Consensus(ref payload) => {
                write!(formatter, "Event::Consensus({:<8})", HexFmt(payload))
            }
        }
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::ConnectedTo { peer_addr } => {
                write!(formatter, "ClientEvent::ConnectedToClient - {}", peer_addr)
            }
            Self::ConnectionFailureTo { peer_addr } => write!(
                formatter,
                "ClientEvent::ConnectionFailureToClient: {}",
                peer_addr
            ),
            Self::NewMessageFrom { peer_addr, .. } => write!(
                formatter,
                "ClientEvent::NewMessageFromClient: {}",
                peer_addr
            ),
            Self::UnsentUserMsg {
                peer_addr, token, ..
            } => write!(
                formatter,
                "ClientEvent::UnsentUserMsgToClient: {} with Token: {}",
                peer_addr, token
            ),
            Self::SentUserMsg {
                peer_addr, token, ..
            } => write!(
                formatter,
                "ClientEvent::SentUserMsgToClient: {} with Token: {}",
                peer_addr, token
            ),
        }
    }
}

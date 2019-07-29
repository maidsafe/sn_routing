// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::routing_table::Error as RoutingTableError;
use crate::{action::Action, event::Event, id::PublicId, quic_p2p, types::MessageId};
use config_file_handler::Error as ConfigFileHandlerError;
use crossbeam_channel as mpmc;
use maidsafe_utilities::serialisation;
use quick_error::quick_error;
use safe_crypto;
use std::sync::mpsc;

/// The type returned by the routing message handling methods.
pub type Result<T> = ::std::result::Result<T, RoutingError>;

/// The type of errors that can occur if routing is unable to handle a send request.
#[derive(Debug)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum InterfaceError {
    /// We are not connected to the network.
    NotConnected,
    /// We are not in a state to handle the action.
    InvalidState,
    /// Error while trying to receive a message from a multiple-producer-single-consumer channel
    MpscRecvError(mpsc::RecvError),
    /// Error while trying to receive a message from a multiple-producer-multiple-consumer channel
    MpmcRecvError(mpmc::RecvError),
    /// Error while trying to send an event to a multiple-producer-multiple-consumer channel
    MpmcSendEventError(mpmc::SendError<Event>),
    /// Error while trying to send an action to a multiple-producer-multiple-consumer channel
    MpmcSendActionError(mpmc::SendError<Action>),
}

impl From<mpsc::RecvError> for InterfaceError {
    fn from(error: mpsc::RecvError) -> InterfaceError {
        InterfaceError::MpscRecvError(error)
    }
}

impl From<mpmc::RecvError> for InterfaceError {
    fn from(error: mpmc::RecvError) -> InterfaceError {
        InterfaceError::MpmcRecvError(error)
    }
}

impl From<mpmc::SendError<Event>> for InterfaceError {
    fn from(error: mpmc::SendError<Event>) -> InterfaceError {
        InterfaceError::MpmcSendEventError(error)
    }
}

impl From<mpmc::SendError<Action>> for InterfaceError {
    fn from(error: mpmc::SendError<Action>) -> InterfaceError {
        InterfaceError::MpmcSendActionError(error)
    }
}

/// The type of errors that can occur during handling of routing events.
#[derive(Debug)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum RoutingError {
    /// The node/client has not bootstrapped yet
    NotBootstrapped,
    /// Invalid State
    Terminated,
    /// Invalid requester or handler authorities
    BadAuthority,
    /// Failure to connect to an already connected node
    AlreadyConnected,
    /// Failure to connect to a group in handling a joining request
    AlreadyHandlingJoinRequest,
    /// Received message having unknown type
    UnknownMessageType,
    /// Failed signature check
    FailedSignature,
    /// Not Enough signatures
    NotEnoughSignatures,
    /// Duplicate signatures
    DuplicateSignatures,
    /// The list of owner keys is invalid
    InvalidOwners,
    /// Duplicate request received
    FilterCheckFailed,
    /// Failure to bootstrap off the provided endpoints
    FailedToBootstrap,
    /// Node's new name doesn't fall within the specified target address range.
    InvalidRelocationTargetRange,
    /// A client with `client_restriction == true` tried to send a message restricted to nodes.
    RejectedClientMessage,
    /// Routing Table error
    RoutingTable(RoutingTableError),
    /// String errors
    Utf8(::std::str::Utf8Error),
    /// Interface error
    Interface(InterfaceError),
    /// i/o error
    Io(::std::io::Error),
    /// Network layer error
    Network(quic_p2p::Error),
    /// Channel sending error
    MpscSendEventError(mpsc::SendError<Event>),
    /// Current state is invalid for the operation
    InvalidStateForOperation,
    /// Serialisation Error
    SerialisationError(serialisation::SerialisationError),
    /// Unknown Connection
    UnknownConnection(PublicId),
    /// Invalid Destination
    InvalidDestination,
    /// Connection to proxy node does not exist in proxy map
    ProxyConnectionNotFound,
    /// Connection to client does not exist in client map
    ClientConnectionNotFound,
    /// Invalid Source
    InvalidSource,
    /// Decoded a user message with an unexpected hash.
    HashMismatch,
    /// Version check has failed
    InvalidSuccessor,
    /// Candidate is unknown
    UnknownCandidate,
    /// Operation timed out
    TimedOut,
    /// Failed validation of resource proof
    FailedResourceProofValidation,
    /// Content of a received message is inconsistent.
    InvalidMessage,
    /// Invalid Peer
    InvalidPeer,
    /// The client's message indicated by the included message id has been rejected by the
    /// rate-limiter.
    ExceedsRateLimit(MessageId),
    /// Invalid configuration
    ConfigError(ConfigFileHandlerError),
    /// Invalid chain
    Chain,
    /// We received a signed message with a previous hop's section info that we don't know.
    UnknownPrevHop,
    /// A signed message's chain of proving sections is invalid.
    InvalidProvingSection,
    /// A signed message could not be trusted
    UntrustedMessage,
    /// Crypto related error.
    Crypto(safe_crypto::Error),
}

impl From<RoutingTableError> for RoutingError {
    fn from(error: RoutingTableError) -> RoutingError {
        RoutingError::RoutingTable(error)
    }
}

impl From<::std::str::Utf8Error> for RoutingError {
    fn from(error: ::std::str::Utf8Error) -> RoutingError {
        RoutingError::Utf8(error)
    }
}

impl From<::std::io::Error> for RoutingError {
    fn from(error: ::std::io::Error) -> RoutingError {
        RoutingError::Io(error)
    }
}

impl From<InterfaceError> for RoutingError {
    fn from(error: InterfaceError) -> RoutingError {
        RoutingError::Interface(error)
    }
}

impl From<quic_p2p::Error> for RoutingError {
    fn from(error: quic_p2p::Error) -> RoutingError {
        RoutingError::Network(error)
    }
}

impl From<mpsc::SendError<Event>> for RoutingError {
    fn from(error: mpsc::SendError<Event>) -> RoutingError {
        RoutingError::MpscSendEventError(error)
    }
}

impl From<serialisation::SerialisationError> for RoutingError {
    fn from(error: serialisation::SerialisationError) -> RoutingError {
        RoutingError::SerialisationError(error)
    }
}

impl From<ConfigFileHandlerError> for RoutingError {
    fn from(error: ConfigFileHandlerError) -> RoutingError {
        RoutingError::ConfigError(error)
    }
}

impl From<safe_crypto::Error> for RoutingError {
    fn from(error: safe_crypto::Error) -> RoutingError {
        RoutingError::Crypto(error)
    }
}

quick_error! {
    #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub enum BootstrapResponseError {
        NotApproved {
            description("Proxy not approved yet")
            display("The chosen proxy node has not yet been approved by the network.")
        }
        TooFewPeers {
            description("Proxy has too few peers")
            display("The chosen proxy node has too few connections to peers.")
        }
        ClientLimit {
            description("Proxy has max. clients")
            display("The chosen proxy node already has connections to the maximum number of \
                     clients allowed per proxy.")
        }
    }
}

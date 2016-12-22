// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use action::Action;
use crust::{self, PeerId};
use event::Event;
use maidsafe_utilities::event_sender::{EventSenderError, MaidSafeEventCategory};
use maidsafe_utilities::serialisation;
use std::sync::mpsc::{RecvError, SendError};
use super::routing_table::Error as RoutingTableError;

#[derive(Debug)]
/// The type of errors that can occur if routing is unable to handle a send request.
pub enum InterfaceError {
    /// We are not connected to the network.
    NotConnected,
    /// We are not in a state to handle the action.
    InvalidState,
    /// Error while trying to receive a message from a channel
    ChannelRxError(RecvError),
    /// Error while trying to transmit an event via a channel
    EventSenderError(EventSenderError<MaidSafeEventCategory, Action>),
}

impl From<EventSenderError<MaidSafeEventCategory, Action>> for InterfaceError {
    fn from(error: EventSenderError<MaidSafeEventCategory, Action>) -> InterfaceError {
        InterfaceError::EventSenderError(error)
    }
}

impl From<RecvError> for InterfaceError {
    fn from(error: RecvError) -> InterfaceError {
        InterfaceError::ChannelRxError(error)
    }
}

#[derive(Debug)]
/// The type of errors that can occur during handling of routing events.
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
    /// Public id rejected because of disallowed relocated status
    RejectedPublicId,
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
    /// Crust error
    Crust(crust::CrustError),
    /// Channel sending error
    SendEventError(SendError<Event>),
    /// Current state is invalid for the operation
    InvalidStateForOperation,
    /// Serialisation Error
    SerialisationError(serialisation::SerialisationError),
    /// Asymmetric Decryption Failure
    AsymmetricDecryptionFailure,
    /// Unknown Connection
    UnknownConnection(PeerId),
    /// Invalid Destination
    InvalidDestination,
    /// Connection to proxy node does not exist in proxy map
    ProxyConnectionNotFound,
    /// Connection to client does not exist in client map
    ClientConnectionNotFound,
    /// Invalid Source
    InvalidSource,
    /// Attempted to use a node as a tunnel that is not directly connected
    CannotTunnelThroughTunnel,
    /// Decoded a user message with an unexpected hash.
    HashMismatch,
    /// Candidate is unknown
    UnknownCandidate,
    /// Operation timed out
    TimedOut,
    /// Failed validation of resource proof
    FailedResourceProofValidation,
    /// Candidate is connected via a tunnel
    CandidateIsTunnelling,
    /// Could not find a signed section list for some prefix in our cache. This might just be
    /// because we didn't get enough signatures from neighbouring nodes yet.
    NoSectionSigInCache,
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

impl From<crust::CrustError> for RoutingError {
    fn from(error: crust::CrustError) -> RoutingError {
        RoutingError::Crust(error)
    }
}

impl From<SendError<Event>> for RoutingError {
    fn from(error: SendError<Event>) -> RoutingError {
        RoutingError::SendEventError(error)
    }
}

impl From<serialisation::SerialisationError> for RoutingError {
    fn from(error: serialisation::SerialisationError) -> RoutingError {
        RoutingError::SerialisationError(error)
    }
}

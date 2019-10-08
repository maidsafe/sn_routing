// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::routing_table::Error as RoutingTableError;
use crate::{action::Action, event::Event, id::PublicId, quic_p2p};
use crossbeam_channel as mpmc;
use maidsafe_utilities::serialisation;
use quick_error::quick_error;
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
    /// Invalid State
    Terminated,
    /// Invalid requester or handler authorities
    BadAuthority,
    /// Failed signature check
    FailedSignature,
    /// Duplicate request received
    FilterCheckFailed,
    /// Routing Table error
    RoutingTable(RoutingTableError),
    /// Interface error
    Interface(InterfaceError),
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
    /// Invalid Source
    InvalidSource,
    /// Content of a received message is inconsistent.
    InvalidMessage,
    /// A signed message's chain of proving sections is invalid.
    InvalidProvingSection,
    /// A signed message could not be trusted
    UntrustedMessage,
    /// A new SectionInfo is invalid.
    InvalidNewSectionInfo,
}

impl From<RoutingTableError> for RoutingError {
    fn from(error: RoutingTableError) -> RoutingError {
        RoutingError::RoutingTable(error)
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

quick_error! {
    #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub enum BootstrapResponseError {
        NotApproved {
            description("Bootstrap node not approved yet")
            display("The chosen bootstrap node has not yet been approved by the network.")
        }
        TooFewPeers {
            description("Bootstrap node has too few peers")
            display("The chosen bootstrap node has too few connections to peers.")
        }
    }
}

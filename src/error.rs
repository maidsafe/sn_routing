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

use action::Action;
use std::sync::mpsc::RecvError;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, EventSenderError};

// TODO This will be in a crate common to only Vaults and Client
// #[deny(missing_docs)]
// #[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
// /// Represents response errors.
// pub enum ResponseError {
//     /// Abort is for user to indicate that the state can be dropped;
//     /// if received by routing, it will drop the state.
//     Abort,
//     /// On low balance or no account registered
//     LowBalance(::data::Data, u32),
//     /// invalid request
//     InvalidRequest(::data::Data),
//     /// failure to complete request for data
//     FailedRequestForData(::data::Data),
//     /// had to clear Sacrificial Data in order to complete request
//     HadToClearSacrificial(::XorName, u32),
// }
//
// impl From<::cbor::CborError> for ResponseError {
//     fn from(_error: ::cbor::CborError) -> ResponseError {
//         ResponseError::Abort
//     }
// }

#[derive(Debug)]
/// InterfaceError.
pub enum InterfaceError {
    /// NotConnected.
    NotConnected,
    /// Error while listening to a message in a rust channel
    ChannelRxError(RecvError),
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

// ------------------------------------------------------------------------------
#[allow(variant_size_differences)]
#[derive(Debug)]
/// RoutingError.
pub enum RoutingError {
    /// The node/client has not bootstrapped yet
    NotBootstrapped,
    /// Invalid State
    Terminated,
    /// invalid requester or handler authorities
    BadAuthority,
    /// failure to connect to an already connected node
    AlreadyConnected,
    /// received message having unknown type
    UnknownMessageType,
    /// Failed signature check
    FailedSignature,
    /// Not Enough signatures
    NotEnoughSignatures,
    /// Duplicate signatures
    DuplicateSignatures,
    /// duplicate request received
    FilterCheckFailed,
    /// failure to bootstrap off the provided endpoints
    FailedToBootstrap,
    /// unexpected empty routing table
    RoutingTableEmpty,
    /// public id rejected because of unallowed relocated status
    RejectedPublicId,
    /// routing table did not add the node information,
    /// either because it was already added, or because it did not improve the routing table
    RefusedFromRoutingTable,
    /// We received a refresh message but it did not contain group source address
    RefreshNotFromGroup,
    /// String errors
    Utf8(::std::str::Utf8Error),
    /// interface error
    Interface(InterfaceError),
    /// i/o error
    Io(::std::io::Error),
    /// serialisation error
    Cbor(::cbor::CborError),
    /// Current state is invalid for the operation
    InvalidStateForOperation,
    /// Serialisation Error
    SerialisationError(::maidsafe_utilities::serialisation::SerialisationError),
    /// Asymmetric Decryption Failure
    AsymmetricDecryptionFailure,
    /// Unknown Connection
    UnknownConnection,
    /// The message is not getting closer to the target
    DirectionCheckFailed,
    /// Density mismatch
    RoutingTableBucketIndexFailed,
    /// Invalid Destination
    InvalidDestination,
    /// Connection to proxy node does not exist in proxy map
    ProxyConnectionNotFound,
    /// Connection to client does not exist in client map
    ClientConnectionNotFound,
    /// Invalid Source
    InvalidSource,
}

impl From<::std::str::Utf8Error> for RoutingError {
    fn from(error: ::std::str::Utf8Error) -> RoutingError {
        RoutingError::Utf8(error)
    }
}


impl From<::cbor::CborError> for RoutingError {
    fn from(error: ::cbor::CborError) -> RoutingError {
        RoutingError::Cbor(error)
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

impl From<::maidsafe_utilities::serialisation::SerialisationError> for RoutingError {
    fn from(error: ::maidsafe_utilities::serialisation::SerialisationError) -> RoutingError {
        RoutingError::SerialisationError(error)
    }
}

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

use chunk_store;
use mpid_messaging;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::{Authority, InterfaceError, MessageId, RoutingError, RoutingMessage};
use std::io;
use types::Refresh;

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum ClientError {
    NoSuchAccount,
    AccountExists,
    NoSuchData,
    DataExists,
    LowBalance,
}

#[derive(Debug)]
pub enum InternalError {
    FailedToFindCachedRequest(MessageId),
    Client(ClientError),
    UnknownMessageType(RoutingMessage),
    UnknownRefreshType(Authority, Authority, Refresh),
    InvalidResponse,
    NotInCloseGroup,
    UnableToAllocateNewPmidNode,
    ChunkStore(chunk_store::Error),
    MpidMessaging(mpid_messaging::Error),
    Serialisation(SerialisationError),
    Routing(InterfaceError),
    RoutingInternal(RoutingError),
    Io(io::Error),
}

impl From<ClientError> for InternalError {
    fn from(error: ClientError) -> InternalError {
        InternalError::Client(error)
    }
}

impl From<chunk_store::Error> for InternalError {
    fn from(error: chunk_store::Error) -> InternalError {
        InternalError::ChunkStore(error)
    }
}

impl From<mpid_messaging::Error> for InternalError {
    fn from(error: mpid_messaging::Error) -> InternalError {
        InternalError::MpidMessaging(error)
    }
}

impl From<SerialisationError> for InternalError {
    fn from(error: SerialisationError) -> InternalError {
        InternalError::Serialisation(error)
    }
}

impl From<InterfaceError> for InternalError {
    fn from(error: InterfaceError) -> InternalError {
        InternalError::Routing(error)
    }
}

impl From<RoutingError> for InternalError {
    fn from(error: RoutingError) -> InternalError {
        InternalError::RoutingInternal(error)
    }
}

impl From<io::Error> for InternalError {
    fn from(error: io::Error) -> InternalError {
        InternalError::Io(error)
    }
}

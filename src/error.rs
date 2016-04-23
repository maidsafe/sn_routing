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

use config_file_handler;
use chunk_store;
use safe_network_common::messaging;
use safe_network_common::client_errors::{MutationError, GetError};
use maidsafe_utilities::serialisation::SerialisationError;
use routing::{InterfaceError, MessageId, RoutingError, RoutingMessage};
use std::io;

#[derive(Debug)]
pub enum InternalError {
    ChunkStore(chunk_store::Error),
    ClientGet(GetError),
    ClientMutation(MutationError),
    FailedToFindCachedRequest(MessageId),
    FileHandler(config_file_handler::Error),
    Io(io::Error),
    MpidMessaging(messaging::Error),
    Routing(InterfaceError),
    RoutingInternal(RoutingError),
    Serialisation(SerialisationError),
    UnknownMessageType(RoutingMessage),
    InvalidMessage,
}

impl From<MutationError> for InternalError {
    fn from(error: MutationError) -> InternalError {
        InternalError::ClientMutation(error)
    }
}

impl From<GetError> for InternalError {
    fn from(error: GetError) -> InternalError {
        InternalError::ClientGet(error)
    }
}

impl From<config_file_handler::Error> for InternalError {
    fn from(error: config_file_handler::Error) -> InternalError {
        InternalError::FileHandler(error)
    }
}

impl From<chunk_store::Error> for InternalError {
    fn from(error: chunk_store::Error) -> InternalError {
        InternalError::ChunkStore(error)
    }
}

impl From<messaging::Error> for InternalError {
    fn from(error: messaging::Error) -> InternalError {
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

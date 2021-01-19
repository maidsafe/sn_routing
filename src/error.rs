// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{messages, section};
use thiserror::Error;

/// The type returned by the sn_routing message handling methods.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Routing error.
// TODO: consider removing those variants that cannot occur when calling the public API.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("network layer error: {}", .0)]
    Network(#[from] qp2p::Error),
    #[error("node bootstrap was interrupted")]
    BootstrapInterrupted,
    #[error("failed to create genesis section: {}", .0)]
    CreateGenesisSection(#[source] section::CreateError),
    #[error("failed to merge sections: {}", .0)]
    MergeSection(#[from] section::MergeError),
    #[error("failed to create message: {}", .0)]
    CreateMessage(#[from] messages::CreateError),
    #[error("received invalid message: {}", .0)]
    InvalidMessage(#[from] messages::IntegrityError),
    #[error("failed to send a message")]
    SendMessage,
    #[error("failed to create vote proof share: {}", .0)]
    CreateVoteProofShare(#[source] bincode::Error),
    #[error("received invalid vote proof share")]
    InvalidVoteProofShare,
    #[error("failed to create resource challenge: {}", .0)]
    CreateResourceChallenge(#[source] bincode::Error),
    #[error("invalid message source location")]
    InvalidSrcLocation,
    #[error("invalid message destination location")]
    InvalidDstLocation,
    #[error("the secret key share is missing")]
    MissingSecretKeyShare,
    #[error("cannot route")]
    CannotRoute,
}

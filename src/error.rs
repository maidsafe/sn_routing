// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use thiserror::Error;

/// The type returned by the sn_routing message handling methods.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Internal error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Failed signature check.")]
    FailedSignature,
    #[error("Cannot route.")]
    CannotRoute,
    #[error("Network layer error: {0}")]
    Network(#[from] qp2p::Error),
    #[error("The node is not in a state to handle the action.")]
    InvalidState,
    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("Invalid source location.")]
    InvalidSrcLocation,
    #[error("Invalid destination location.")]
    InvalidDstLocation,
    #[error("Content of a received message is inconsistent.")]
    InvalidMessage,
    #[error("A signature share is invalid.")]
    InvalidSignatureShare,
    #[error("The secret key share is missing.")]
    MissingSecretKeyShare,
    #[error("Failed to send a message.")]
    FailedSend,
    #[error("Invalid vote.")]
    InvalidVote,
    #[error("Messaging protocol error: {0}")]
    Messaging(#[from] sn_messaging::Error),
    #[error("Node messaging error: {0}")]
    NodeMessaging(#[from] sn_messaging::node::Error),
}

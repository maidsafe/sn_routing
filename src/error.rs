// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    agreement::ProposalError,
    messages::{CreateError, ExtendProofChainError},
    section::SectionChainError,
};
use std::net::SocketAddr;
use thiserror::Error;
use xor_name::XorName;

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
    #[error("Empty recipient list")]
    EmptyRecipientList,
    #[error("The config is invalid")]
    InvalidConfig,
    #[error("Cannot connect to the endpoint")]
    CannotConnectEndpoint,
    #[error("Address not reachable")]
    AddressNotReachable,
    #[error("Network layer error: {0}")]
    Network(#[from] qp2p::Error),
    #[error("The node is not in a state to handle the action.")]
    InvalidState,
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
    #[error("Failed to send a message to {0}, {1}")]
    FailedSend(SocketAddr, XorName),
    #[error("Connection closed locally")]
    ConnectionClosed,
    #[error("Invalid section chain: {0}")]
    InvalidSectionChain(#[from] SectionChainError),
    #[error("Messaging protocol error: {0}")]
    Messaging(#[from] sn_messaging::Error),
    #[error("proposal error: {0}")]
    ProposalError(#[from] ProposalError),
    #[error("create error: {0}")]
    CreateError(#[from] CreateError),
    #[error("extend proof error: {0}")]
    ExtendProofError(#[from] ExtendProofChainError),
    #[error("invalid payload")]
    InvalidPayload,
    #[error("Routing is set to not allow taking any new node")]
    TryJoinLater,
}

// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::qp2p::Error as QuicP2pError;
use err_derive::Error;

/// The type returned by the sn_routing message handling methods.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Internal error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error(display = "Invalid requester or handler locations.")]
    BadLocation,
    #[error(display = "Failed signature check.")]
    FailedSignature,
    #[error(display = "Cannot route.")]
    CannotRoute,
    #[error(display = "Network layer error: {}", _0)]
    Network(#[error(source)] QuicP2pError),
    #[error(display = "The node is not in a state to handle the action.")]
    InvalidState,
    #[error(display = "Bincode error: {}", _0)]
    Bincode(#[error(source)] bincode::Error),
    #[error(display = "Invalid Source.")]
    InvalidSource,
    #[error(display = "Content of a received message is inconsistent.")]
    InvalidMessage,
    #[error(display = "A signed message could not be trusted.")]
    UntrustedMessage,
    #[error(display = "A signature share is invalid.")]
    InvalidSignatureShare,
    #[error(display = "An Elder DKG result is invalid.")]
    InvalidElderDkgResult,
}

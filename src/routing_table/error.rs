// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use err_derive::Error;

/// Routing table error variants.
#[derive(Debug, PartialEq, Eq, Error, derive_more::From)]
#[allow(missing_docs)]
pub enum RoutingTableError {
    #[error(display = "Our own name is not allowed to be added to the routing table.")]
    OwnNameDisallowed,
    #[error(
        display = "Peer's name can't be added to the routing table as it's outwith all sections."
    )]
    PeerNameUnsuitable,
    #[error(display = "Peer's name has already been added to the routing table.")]
    AlreadyExists,
    #[error(display = "Destination section doesn't have enough members to use requested route.")]
    CannotRoute,
    #[error(display = "Peer doesn't exist on the network.")]
    NoSuchPeer,
    #[error(display = "The routing table state violates the network invariant.")]
    InvariantViolation,
}

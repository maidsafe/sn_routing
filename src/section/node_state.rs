// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{error::Error, peer::PeerUtils};
use sn_messaging::node::{MembershipState, NodeState, Peer};
use xor_name::XorName;

/// The minimum age a node can have. The Infants will start at age 4. This is to prevent frequent
/// relocations during the beginning of a node's lifetime.
pub const MIN_AGE: u8 = 4;

/// The minimum age a node becomes an adult node.
pub const MIN_ADULT_AGE: u8 = MIN_AGE + 1;

/// During the first section, nodes can start at a range of age to avoid too many nodes having the
/// same time get relocated at the same time.
/// Defines the lower bound of this range.
pub const FIRST_SECTION_MIN_AGE: u8 = MIN_ADULT_AGE + 1;
/// Defines the higher bound of this range.
pub const FIRST_SECTION_MAX_AGE: u8 = 100;

/// Information about a member of our section.
pub trait NodeStateUtils {
    // Creates a `NodeState` in the `Joined` state.
    fn joined(peer: Peer) -> NodeState;

    // Is the age > `MIN_AGE`?
    fn is_mature(&self) -> bool;

    fn leave(self) -> Result<NodeState, Error>;

    // Convert this info into one with the state changed to `Relocated`.
    fn relocate(self, destination: XorName) -> NodeState;
}

impl NodeStateUtils for NodeState {
    // Creates a `NodeState` in the `Joined` state.
    fn joined(peer: Peer) -> NodeState {
        NodeState {
            peer,
            state: MembershipState::Joined,
        }
    }

    // Is the age > `MIN_AGE`?
    fn is_mature(&self) -> bool {
        self.peer.age() > MIN_AGE
    }

    fn leave(self) -> Result<NodeState, Error> {
        // Do not allow switching to `Left` when already relocated, to avoid rejoining with the
        // same name.
        if let MembershipState::Relocated(_) = self.state {
            return Err(Error::InvalidState);
        }
        Ok(NodeState {
            state: MembershipState::Left,
            ..self
        })
    }

    // Convert this info into one with the state changed to `Relocated`.
    fn relocate(self, destination: XorName) -> NodeState {
        NodeState {
            state: MembershipState::Relocated(destination),
            ..self
        }
    }
}

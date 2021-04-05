// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{error::Error, peer::Peer};
use serde::{Deserialize, Serialize};
use xor_name::XorName;

/// The minimum age a node can have. The Infants will start at age 4. This is to prevent frequent
/// relocations during the beginning of a node's lifetime.
pub const MIN_AGE: u8 = 4;

/// During the first section, nodes can start at a range of age to avoid too many nodes having the
/// same time get relocated at the same time.
/// Defines the lower bound of this range.
pub const FIRST_SECTION_MIN_AGE: u8 = MIN_AGE + 2;
/// Defines the higher bound of this range.
pub const FIRST_SECTION_MAX_AGE: u8 = 100;

/// Information about a member of our section.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub struct MemberInfo {
    pub peer: Peer,
    pub state: PeerState,
}

impl MemberInfo {
    // Creates a `MemberInfo` in the `Joined` state.
    pub fn joined(peer: Peer) -> Self {
        Self {
            peer,
            state: PeerState::Joined,
        }
    }

    // Is the age > `MIN_AGE`?
    pub fn is_mature(&self) -> bool {
        self.peer.age() > MIN_AGE
    }

    pub fn leave(self) -> Result<Self, Error> {
        // Do not allow switching to `Left` when already relocated, to avoid rejoining with the
        // same name.
        if let PeerState::Relocated(_) = self.state {
            return Err(Error::InvalidState);
        }
        Ok(Self {
            state: PeerState::Left,
            ..self
        })
    }

    // Convert this info into one with the state changed to `Relocated`.
    pub fn relocate(self, destination: XorName) -> Self {
        Self {
            state: PeerState::Relocated(destination),
            ..self
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum PeerState {
    // Node is active member of the section.
    Joined,
    // Node went offline.
    Left,
    // Node was relocated to a different section.
    Relocated(XorName),
}

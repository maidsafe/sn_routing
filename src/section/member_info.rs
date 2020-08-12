// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::P2pNode;

/// The minimum age a node can have. The Infants will start at age 4. This is to prevent frequent
/// relocations during the beginning of a node's lifetime.
pub const MIN_AGE: u8 = 4;

/// Information about a member of our section.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub struct MemberInfo {
    pub p2p_node: P2pNode,
    pub state: MemberState,
    pub age: u8,
}

impl MemberInfo {
    // Creates a `MemberInfo` in the `Joined` state.
    pub fn joined(p2p_node: P2pNode, age: u8) -> Self {
        Self {
            p2p_node,
            state: MemberState::Joined,
            age,
        }
    }

    pub fn is_adult(&self) -> bool {
        self.age > MIN_AGE
    }

    // Converts this info into one with the state changed to `Left`.
    pub fn leave(self) -> Self {
        Self {
            state: MemberState::Left,
            ..self
        }
    }

    // Converts this info into one with the age increased by one.
    pub fn increment_age(self) -> Self {
        Self {
            age: self.age.saturating_add(1),
            ..self
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum MemberState {
    Joined,
    Relocating,
    // TODO: we should track how long the node has been away. If longer than some limit, remove it
    // from the list. Otherwise we allow it to return.
    Left,
}

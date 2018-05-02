// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use public_info::PublicInfo;
use routing_table::Prefix;
use rust_sodium::crypto::sign;
use std::fmt::{self, Debug, Formatter};

/// The state of a node in a given section as voted for by the other elders in that section.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Debug)]
pub enum State {
    /// Node has been accepted to this section as an elder.  May have been relocated here, or may
    /// have come back via a merge or via a promotion from adult.
    ElderLive,
    /// Node has disconnected.  Can rejoin here once in order to be relocated.
    ElderOffline,
    /// Node has been accepted to this new section (indicated by `to`) as a result of a section
    /// splitting.
    ElderSplitTo {
        /// The section prefix after splitting.
        to: Prefix,
    },
    /// Node has been demoted to non-elder due to an older node being made `Live` here and
    /// displacing this one.
    ElderDemoted,
    /// Node has been chosen to be relocated to another section.
    ElderRelocated,
    /// Node was marked as `ElderOffline` and has rejoined here.  Only one rejoin attempt is
    /// allowed.
    ElderRejoined,
    /// Node has been accepted here as a non-elder via a relocation, a merge or a demotion.
    NonElderLive,
    /// Node has disconnected.  Can rejoin here once in order to be relocated.
    NonElderOffline,
    /// Node has been accepted to this new section (indicated by `to`) as a result of a section
    /// splitting.
    NonElderSplitTo {
        /// The section prefix after splitting.
        to: Prefix,
    },
    /// Node has been chosen to be relocated to another section.
    NonElderRelocated,
    /// Node was marked as `NonElderOffline` and has rejoined here.  Only one rejoin attempt is
    /// allowed.
    NonElderRejoined,
}

/// This will be the payload of `Block`s held in the data chain and transient blocks relating to
/// non-elders.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NodeState {
    state: State,
    public_key: sign::PublicKey,
    age: u8,
    section: Prefix,
}

impl NodeState {
    /// Constructor.
    pub fn new(state: State, public_info: &PublicInfo, prefix: Prefix) -> Self {
        NodeState {
            state,
            public_key: *public_info.sign_key(),
            age: public_info.age(),
            section: prefix,
        }
    }

    /// The state the node is transitioning into.
    pub fn state(&self) -> State {
        self.state
    }

    /// The public signing key of the affected node.
    pub fn public_key(&self) -> &sign::PublicKey {
        &self.public_key
    }

    /// The age of the affected node.
    pub fn age(&self) -> u8 {
        self.age
    }

    /// The section to which the affected node belongs.
    pub fn section(&self) -> &Prefix {
        &self.section
    }
}

impl Debug for NodeState {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{:?} for {:02x}{:02x}{:02x}.. age {} in {:?}",
            self.state,
            self.public_key.0[0],
            self.public_key.0[1],
            self.public_key.0[2],
            self.age,
            self.section
        )
    }
}

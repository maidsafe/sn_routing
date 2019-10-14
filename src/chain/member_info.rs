// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// The type for counting the churn events experienced by a node
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub struct AgeCounter(u32);

impl AgeCounter {
    pub fn age(self) -> u8 {
        f64::from(self.0).log2() as u8
    }

    pub fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }
}

impl Default for AgeCounter {
    fn default() -> AgeCounter {
        MIN_AGE_COUNTER
    }
}

/// The minimum allowed value of the Age Counter
/// The Infants will start at age 4, which is equivalent to the age counter value of 16. This is to
/// prevent frequent relocations during the beginning of a node's lifetime.
pub const MIN_AGE_COUNTER: AgeCounter = AgeCounter(16);

const MAX_INFANT_AGE: u32 = 4;

/// Information about a member of our section.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct MemberInfo {
    pub age_counter: AgeCounter,
    pub state: MemberState,
}

impl MemberInfo {
    #[allow(unused)]
    pub fn age(self) -> u8 {
        self.age_counter.age()
    }

    pub fn increase_age(&mut self) {
        self.age_counter.increment();
    }

    pub fn is_mature(self) -> bool {
        self.age_counter > AgeCounter(2u32.pow(MAX_INFANT_AGE))
    }
}

impl Default for MemberInfo {
    fn default() -> Self {
        Self {
            age_counter: MIN_AGE_COUNTER,
            state: MemberState::Joined,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub enum MemberPersona {
    Infant,
    Adult,
    Elder,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub enum MemberState {
    Joined,
    // TODO: we should track how long the node has been away. If longer than some limit, remove it
    // from the list. Otherwise we allow it to return.
    Left,
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::P2pNode;

/// The type for counting the churn events experienced by a node
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub struct AgeCounter(u32);

impl AgeCounter {
    /// Create `AgeCounter` with the given age. Minimal valid age is `MIN_AGE` so if a smaller
    /// value is passed in, it's silently changed to `MIN_AGE`.
    pub fn from_age(age: u8) -> Self {
        Self(2u32.pow(u32::from(age.max(MIN_AGE))))
    }

    pub fn age(self) -> u8 {
        f64::from(self.0).log2() as u8
    }

    /// Increment the counter and return whether the age increased.
    pub fn increment(&mut self) -> bool {
        if let Some(new_value) = self.0.checked_add(1) {
            self.0 = new_value;
            self.0.is_power_of_two()
        } else {
            false
        }
    }
}

impl Default for AgeCounter {
    fn default() -> AgeCounter {
        MIN_AGE_COUNTER
    }
}

/// The minimum allowed value of the Age Counter, equivalent to the minimum age of 4.
pub const MIN_AGE_COUNTER: AgeCounter = AgeCounter(16);
/// The minimum age a node can have. The Infants will start at age 4. This is to prevent frequent
/// relocations during the beginning of a node's lifetime.
pub const MIN_AGE: u8 = 4;

const MAX_INFANT_AGE: u32 = MIN_AGE as u32;

/// Information about a member of our section.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub struct MemberInfo {
    pub age_counter: AgeCounter,
    pub state: MemberState,
    pub p2p_node: P2pNode,
}

impl MemberInfo {
    /// Create new `MemberInfo` in the `Joined` state.
    pub fn new(age: u8, p2p_node: P2pNode) -> Self {
        Self {
            age_counter: AgeCounter::from_age(age),
            state: MemberState::Joined,
            p2p_node,
        }
    }

    pub fn age(&self) -> u8 {
        self.age_counter.age()
    }

    pub fn set_age(&mut self, age: u8) {
        self.age_counter = AgeCounter::from_age(age);
    }

    // Increment the age counter and return whether the age increased.
    pub fn increment_age_counter(&mut self) -> bool {
        self.age_counter.increment()
    }

    // Increment the age.
    pub fn increment_age(&mut self) {
        self.age_counter = AgeCounter::from_age(self.age().saturating_add(1));
    }

    pub fn is_mature(&self) -> bool {
        self.age_counter >= AgeCounter(2u32.pow(MAX_INFANT_AGE + 1))
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
    Relocating {
        // Node knowledge of us
        node_knowledge: u64,
    },
    // TODO: we should track how long the node has been away. If longer than some limit, remove it
    // from the list. Otherwise we allow it to return.
    Left,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_age_counter_agrees_with_min_age() {
        assert_eq!(MIN_AGE_COUNTER.age(), MIN_AGE);
    }

    #[test]
    fn age_counter_to_age() {
        let mut age_counter = AgeCounter::default();

        for age in MIN_AGE..16 {
            for _ in 0..2u32.pow(u32::from(age)) - 1 {
                assert_eq!(age_counter.age(), age);
                assert!(!age_counter.increment());
            }

            assert!(age_counter.increment());
        }
    }
}

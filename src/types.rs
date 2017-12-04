// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#[cfg(any(test, feature = "use-mock-crust"))]
use maidsafe_utilities::SeededRng;
use maidsafe_utilities::event_sender::MaidSafeObserver;
#[cfg(all(not(test), not(feature = "use-mock-crust")))]
use rand;
#[cfg(any(test, feature = "use-mock-crust"))]
use rand::Rng;
use xor_name::XorName;

pub type RoutingActionSender = MaidSafeObserver<::action::Action>;

/// Unique ID for messages
///
/// This is used for deduplication: Since the network sends messages redundantly along different
/// routes, the same message will usually arrive more than once at any given node. A message with
/// an ID that is already in the cache will be ignored.
#[derive(Ord, PartialOrd, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct MessageId(XorName);

impl MessageId {
    /// Generate a new `MessageId` with random content.
    #[cfg(any(test, feature = "use-mock-crust"))]
    pub fn new() -> MessageId {
        let mut rng = SeededRng::thread_rng();
        MessageId(rng.gen())
    }

    /// Generate a new `MessageId` with random content.
    #[cfg(all(not(test), not(feature = "use-mock-crust")))]
    pub fn new() -> MessageId {
        MessageId(rand::random())
    }

    /// Generate a `MessageId` with value 0. This should only be used for messages where there is
    /// no danger of duplication.
    pub fn zero() -> MessageId {
        MessageId(XorName([0; 32]))
    }

    /// Generate a new `MessageId` with contents extracted from lost node.
    pub fn from_lost_node(mut name: XorName) -> MessageId {
        name.0[0] = b'L';
        MessageId(name)
    }

    /// Generate a new `MessageId` with contents extracted from new node.
    pub fn from_added_node(mut name: XorName) -> MessageId {
        name.0[0] = b'A';
        MessageId(name)
    }

    /// Generate the reverse of the given `MessageId`.
    pub fn from_reverse(name: &MessageId) -> MessageId {
        let MessageId(XorName(mut name_mut)) = *name;
        name_mut.reverse();
        MessageId(XorName(name_mut))
    }

    /// Generate the increment (on the MSB only) of the given `MessageId`.
    pub fn increment_first_byte(message_id: &MessageId) -> MessageId {
        let MessageId(XorName(mut vec_mut)) = *message_id;
        vec_mut[0] = vec_mut[0].wrapping_add(1);
        MessageId(XorName(vec_mut))
    }

    /// Generate the decrement (on the MSB only) of the given `MessageId`.
    pub fn decrement_first_byte(message_id: &MessageId) -> MessageId {
        let MessageId(XorName(mut vec_mut)) = *message_id;
        vec_mut[0] = vec_mut[0].wrapping_sub(1);
        MessageId(XorName(vec_mut))
    }
}

impl Default for MessageId {
    fn default() -> MessageId {
        MessageId::zero()
    }
}

#[cfg(test)]
#[cfg_attr(feature = "cargo-clippy", allow(indexing_slicing))]
mod tests {
    use super::MessageId;
    use xor_name::{XOR_NAME_LEN, XorName};

    #[test]
    fn increment() {
        let message_id = MessageId::increment_first_byte(&MessageId(XorName([255; XOR_NAME_LEN])));
        let MessageId(XorName(vec_bytes)) = message_id;
        assert_eq!(vec_bytes[0], 0);
    }

    #[test]
    fn decrement() {
        let message_id = MessageId::decrement_first_byte(&MessageId(XorName([0; XOR_NAME_LEN])));
        let MessageId(XorName(vec_bytes)) = message_id;
        assert_eq!(vec_bytes[0], 255);
    }
}

// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_name::XorName;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

/// Unique ID for messages
///
/// This is used for deduplication: Since the network sends messages redundantly along different
/// routes, the same message will usually arrive more than once at any given node. A message with
/// an ID that is already in the cache will be ignored.
#[derive(Ord, PartialOrd, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct MessageId(XorName);

impl MessageId {
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

impl Distribution<MessageId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MessageId {
        rng.gen()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::MessageId;
    use crate::xor_name::{XorName, XOR_NAME_LEN};

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

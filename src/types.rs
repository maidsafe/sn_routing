// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use rand::random;
use xor_name::XorName;
use rustc_serialize::{Encoder, Decoder};
use maidsafe_utilities::event_sender::MaidSafeObserver;

pub type RoutingActionSender = MaidSafeObserver<::action::Action>;

/// Unique ID for messages
///
/// This is used for deduplication: Since the network sends messages redundantly along different
/// routes, the same message will usually arrive more than once at any given node. A message with
/// an ID that is already in the cache will be ignored.
#[derive(Ord, PartialOrd, Debug, Clone, Eq, PartialEq, RustcEncodable, RustcDecodable, Hash)]
pub struct MessageId(XorName);

impl MessageId {
    /// Generate a new `MessageId` with random content.
    pub fn new() -> MessageId {
        MessageId(random::<XorName>())
    }

    /// Generate a new `MessageId` with contents extracted from lost node.
    pub fn from_lost_node(mut name: XorName) -> MessageId {
        name.0[0] = 'L' as u8;
        MessageId(name)
    }

    /// Generate a new `MessageId` with contents extracted from new node.
    pub fn from_added_node(mut name: XorName) -> MessageId {
        name.0[0] = 'A' as u8;
        MessageId(name)
    }

    /// Generate the reverse of the given `MessageId`.
    pub fn from_reverse(name: &MessageId) -> MessageId {
        let MessageId(XorName(mut name_mut)) = *name;
        name_mut.reverse();
        MessageId(XorName(name_mut))
    }
}

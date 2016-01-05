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

use xor_name::XorName;
use sodiumoxide::crypto::box_;
use rustc_serialize::{Encoder, Decoder};
use maidsafe_utilities::event_sender::MaidSafeObserver;

pub type RoutingActionSender = MaidSafeObserver<::action::Action>;

/// Unique ID for messages
#[derive(Ord, PartialOrd, Debug, Clone, Eq, PartialEq, RustcEncodable, RustcDecodable, Hash)]
pub struct MessageId([u8; box_::NONCEBYTES]);

impl MessageId {
    /// Generate a new MessageId with random content
    pub fn new() -> MessageId {
        MessageId(box_::gen_nonce().0)
    }

    /// Generate a new MessageId with contents extracted from given XorName
    pub fn from_xor_name(name: XorName) -> MessageId {
        MessageId(unwrap_option!(box_::Nonce::from_slice(&name.0[..box_::NONCEBYTES]),
                                 "Failed generating MessageId from XorName")
                      .0)
    }

    /// Generate a new MessageId after reversing self
    pub fn from_reverse(&self) -> MessageId {
        let mut name_mut = self.0;
        name_mut.reverse();
        MessageId(unwrap_option!(box_::Nonce::from_slice(&name_mut),
                                 "Failed generating MessageId from XorName")
                      .0)
    }
}

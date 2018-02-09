// Copyright 2017 MaidSafe.net limited.
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

// FIXME: remove when this module is finished
#![allow(dead_code)]

use rust_sodium::crypto::sign::PublicKey;

/// Public identifier and age of a Peer.
#[derive(Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq, Clone, Hash, Debug)]
pub struct PeerId {
    age: u8, // DO NOT REORDER, this field is the primary sort field to be held in set!
    pub_key: PublicKey,
}

impl PeerId {
    /// Cstr
    pub fn new(age: u8, key: PublicKey) -> PeerId {
        PeerId {
            age: age,
            pub_key: key,
        }
    }
    /// Getter
    pub fn age(&self) -> u8 {
        self.age
    }

    /// Getter
    pub fn pub_key(&self) -> &PublicKey {
        &self.pub_key
    }
}

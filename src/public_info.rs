// Copyright 2018 MaidSafe.net limited.
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

use crust::Uid;
use rust_sodium::crypto::{box_, sign};
use std::fmt::{self, Debug, Display, Formatter};
use xor_name::XorName;

/// Public identifier for a Peer, contains age if peer is a node.
#[derive(Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PublicInfo {
    /// Public identifier for a client
    Client {
        /// Client's public encrypting key
        encrypt_key: box_::PublicKey,
        /// Client's public signing key
        sign_key: sign::PublicKey,
    },
    /// Public identifier for a node
    Node {
        /// Node's age
        age: u8,
        /// Node's public encrypting key
        encrypt_key: box_::PublicKey,
        /// Node's public signing key
        sign_key: sign::PublicKey,
    },
}

impl PublicInfo {
    /// Returning the name of the peer
    pub fn name(&self) -> XorName {
        match *self {
            PublicInfo::Client { sign_key, .. } |
            PublicInfo::Node { sign_key, .. } => XorName(sign_key.0),
        }
    }

    /// Returning peer's public encrypting key
    pub fn encrypt_key(&self) -> &box_::PublicKey {
        match *self {
            PublicInfo::Client { ref encrypt_key, .. } |
            PublicInfo::Node { ref encrypt_key, .. } => encrypt_key,
        }
    }

    /// Returning peer's public signing key
    pub fn sign_key(&self) -> &sign::PublicKey {
        match *self {
            PublicInfo::Client { ref sign_key, .. } |
            PublicInfo::Node { ref sign_key, .. } => sign_key,
        }
    }

    /// Returning peer's age (client always having age of 0)
    pub fn age(&self) -> u8 {
        match *self {
            PublicInfo::Client { .. } => 0,
            PublicInfo::Node { age, .. } => age,
        }
    }

    /// Updating a peer's age (void if peer is client)
    #[cfg(test)]
    pub fn set_age(&mut self, new_age: u8) {
        match *self {
            PublicInfo::Client { .. } => {}
            PublicInfo::Node { ref mut age, .. } => *age = new_age,
        }
    }
}

impl Uid for PublicInfo {}

impl Debug for PublicInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            PublicInfo::Client { .. } => write!(formatter, "PublicInfo(Client: {})", self.name()),
            PublicInfo::Node { age, .. } => {
                write!(formatter, "PublicInfo(Node: {}, age: {})", self.name(), age)
            }
        }
    }
}

impl Display for PublicInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.name())
    }
}

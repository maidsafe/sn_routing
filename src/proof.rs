// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::debug_bytes;
use rust_sodium::crypto::sign::{self, PublicKey, Signature};
use std::fmt::{self, Debug, Formatter};

/// Proof as provided by a close group member
/// This nay be extracted from a `Vote` to be inserted into a `Block`
#[derive(RustcEncodable, RustcDecodable, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub struct Proof {
    key: PublicKey,
    sig: Signature,
}

impl Proof {
    /// cstr
    pub fn new(key: PublicKey, sig: Signature) -> Proof {
        Proof {
            key: key,
            sig: sig,
        }
    }

    /// getter
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// getter
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    /// Validates `data` against this `Proof`'s `key` and `sig`.
    pub fn validate(&self, data: &[u8]) -> bool {
        sign::verify_detached(&self.sig, data, &self.key)
    }
}

impl Debug for Proof {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Proof {{ key: {} }}", debug_bytes(self.key))
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use chain::block_identifier::BlockIdentifier;
    // use rust_sodium::crypto::sign;
    // use sha3::hash;

    // #[test]
    // fn vote_comparisons() {
    //     ::rust_sodium::init();
    //     let keys = sign::gen_keypair();
    //     let test_data1 = BlockIdentifier::Link(hash(b"1"));
    //     let test_data2 = BlockIdentifier::Link(hash(b"1"));
    //     let test_data3 = BlockIdentifier::ImmutableData(hash(b"1"));
    //     let test_node_data_block1 = Vote::new(&keys.0, &keys.1, test_data1).expect("fail1");
    //     let test_node_data_block2 = Vote::new(&keys.0, &keys.1, test_data2).expect("fail2");
    //     let test_node_data_block3 = Vote::new(&keys.0, &keys.1, test_data3).expect("fail3");
    //     assert!(test_node_data_block1.validate());
    //     assert!(test_node_data_block2.validate());
    //     assert!(test_node_data_block3.validate());
    //     assert_eq!(test_node_data_block1.clone(), test_node_data_block2.clone());
    //     assert!(test_node_data_block1 != test_node_data_block3.clone());
    //     assert!(test_node_data_block2 != test_node_data_block3);
    // }
}

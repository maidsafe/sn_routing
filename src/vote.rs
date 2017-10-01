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

use chain::block_identifier::BlockIdentifier;
use chain::proof::Proof;
use error::Error;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey};

/// If data block then this is sent by any group member when data is `Put`, `Post` or `Delete`.
/// If this is a link then it is sent with a `churn` event.
/// A `Link` is a vote that each member must send each other in times of churn.
/// These will not accumulate but be `ManagedNode`  to `ManagedNode` messages in the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct Vote {
    identifier: BlockIdentifier,
    proof: Proof,
}

impl Vote {
    /// Create a Block (used by nodes in network to send to holders of `DataChains`)
    pub fn new(pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: BlockIdentifier)
               -> Result<Vote, Error> {
        let signature = sign::sign_detached(&serialisation::serialise(&data_identifier)?[..],
                                            secret_key);
        Ok(Vote {
            identifier: data_identifier,
            proof: Proof::new(*pub_key, signature),
        })
    }

    /// Getter
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
    /// Getter
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// validate signed correctly
    pub fn validate(&self) -> bool {
        self.validate_detached(&self.identifier)
    }

    /// Check vote is not for self added/removed
    pub fn is_self_vote(&self) -> bool {
        if let Some(name) = self.identifier.name() {
            &self.proof.key().0 == name
        } else {
            false
        }
    }

    /// validate signed correctly
    pub fn validate_detached(&self, identifier: &BlockIdentifier) -> bool {

        match serialisation::serialise(identifier) {
            Ok(data) => self.proof.validate(&data[..]),
            _ => false,
        }
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

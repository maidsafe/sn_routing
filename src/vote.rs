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

use serde::Serialize;
use error::RoutingError;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::sign::{self, Signature, PublicKey, SecretKey};

/// A Vote is a nodes desire to initiate a network action or sub action.
/// If there are Quorum votes the action will happen
/// These are direct messages and therefor do not require the PublicKey
/// Signature is detached and is the signed payload 
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Vote<T> {
    payload: T,
    signature: Signature,
}

impl <T: Serialize>Vote<T> {
    /// Create a Vote
    #[allow(unused)]
    pub fn new(secret_key: &SecretKey,
               payload: T)
               -> Result<Vote<T>, RoutingError> {
        let signature = sign::sign_detached(&serialisation::serialise(&payload)?[..],
                                            secret_key);
        Ok(Vote {
            payload: payload,
            signature: signature,
        })
    }

    /// Getter
        #[allow(unused)]
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Getter
        #[allow(unused)]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// validate signed correctly
        #[allow(unused)]
    pub fn validate(&self, public_key: PublicKey) -> Result<bool, RoutingError> 
    {
        Ok(sign::verify_detached(&self.signature, &serialisation::serialise(&self.payload)?[..], &public_key))
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

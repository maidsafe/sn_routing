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

use block::Block;
// use error::RoutingError;
// use maidsafe_utilities::serialisation;
// use messages::MessageContent;
use network_event::NetworkEvent;
use proof::Proof;
// use rust_sodium::crypto::sign::PublicKey;
use std::collections::{BTreeMap, BTreeSet};
// use std::time::Duration;
// use tiny_keccak::sha3_256;
// use vote::Vote;

#[allow(unused)]
pub struct PeersAndAge {
    peers: usize,
    age: usize,
}

#[allow(unused)]
impl PeersAndAge {
    pub fn new(peers: usize, age: usize) -> PeersAndAge {
        PeersAndAge {
            peers: peers,
            age: age,
        }
    }

    #[allow(unused)]
    pub fn peers(&self) -> usize {
        self.peers
    }

    #[allow(unused)]
    pub fn age(&self) -> usize {
        self.age
    }
}

// Vote -> Quorum Block -> FullBlock (or nearly full Block + Accusation)

/// gives us Blocks and or accusations
/// TODO - We must get told when blocks are not accumuating - can be done later though when we
/// start to penalise and manage false accusations etc.
#[allow(unused)]
struct Accumulator {
    blocks: BTreeMap<NetworkEvent, BTreeSet<Block>>, // Get as many proofs as possibe (union)
    votes: BTreeMap<NetworkEvent, BTreeSet<Proof>>, // Get Quorum proofs and send block,
                                                    // get more and add to this block
}

// impl Accumulator {
// A new `Block` requires a valid vote and the `PublicKey` of the node
//  who sent us this. For this reason
// The `Vote` require a Direct Message from a `Peer` to us.
// #[allow(unused)]
// pub fn add_vote(
//     &mut self,
//     vote: &Vote,
//     pub_key: &PublicKey,
//     age: u8,
// ) -> Result<PeersAndAge, RoutingError> {
//     if !vote.validate_signature(pub_key) {
//         return Err(RoutingError::FailedSignature);
//     }
//     let digest = vote.payload();
//     let proof = Proof::new(&pub_key, age, vote)?;
//
//     if let Some(blk) = self.blocks.get_mut(&digest.clone()) {
//         blk.add_proof(proof);
//         return Ok(PeersAndAge::new(blk.total_proofs(), blk.total_proofs_age()));
//     };
//
//     let mut proofset = BTreeSet::<Proof>::new();
//     if !proofset.insert(proof) {
//         return Err(RoutingError::FailedSignature);
//     }
//     let mut block = Block::new(&vote, &pub_key, age)?;
//     let _fixme = self.blocks.insert(*digest, block.clone());
//     Ok(PeersAndAge::new(
//         block.clone().total_proofs(),
//         block.total_proofs_age(),
//     ))
// }
//
// }

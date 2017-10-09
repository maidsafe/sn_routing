// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This,
// along with the Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use block::Block;
use error::RoutingError;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation;
use messages::MessageContent;
use proof::Proof;
use rust_sodium::crypto::sign::PublicKey;
use sha3::Digest256;
use std::collections::HashSet;
use std::time::Duration;
use tiny_keccak::sha3_256;
use vote::Vote;

#[allow(unused)]
pub struct PeersAndAge {
    peers: usize,
    age: usize,
}

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

/// Contains 2 lru cache types. The notion is that we check the blocks lru
/// to confirm we should store the message. The blocks lru may flush and element
/// whilst the data cache will keep it a little longer.
struct MessageAccumulator {
    blocks: LruCache<[u8; 32], Block>, // TODO impl Hash for Block to only
    // use Digest & then switch here to HashSet
    data: LruCache<[u8; 32], MessageContent>,
}

impl MessageAccumulator {
    #[allow(unused)]
    fn new(keep_alive: Duration) -> MessageAccumulator {
        MessageAccumulator {
            blocks: LruCache::with_expiry_duration(keep_alive),
            data: LruCache::with_expiry_duration(keep_alive),
        }
    }

    /// A new `Block` requires a valid vote and the `PublicKey` of the node
    ///  who sent us this. For this reason
    /// The `Vote` require a Direct Message from a `Peer` to us.
    #[allow(unused)]
    pub fn add_vote(
        &mut self,
        vote: &Vote,
        pub_key: &PublicKey,
        age: u8,
    ) -> Result<PeersAndAge, RoutingError> {
        if !vote.validate_signature(pub_key) {
            return Err(RoutingError::FailedSignature);
        }
        let digest = vote.payload();
        let proof = Proof::new(&pub_key, age, vote)?;

        if let Some(blk) = self.blocks.get_mut(&digest.clone()) {
            blk.add_proof(proof);
            return Ok(PeersAndAge::new(blk.total_proofs(), blk.total_proofs_age()));
        };

        let mut proofset = HashSet::<Proof>::new();
        if !proofset.insert(proof) {
            return Err(RoutingError::FailedSignature);
        }
        let mut block = Block::new(&vote, &pub_key, age)?;
        let _fixme = self.blocks.insert(*digest, block.clone());
        Ok(PeersAndAge::new(
            block.clone().total_proofs(),
            block.total_proofs_age(),
        ))
    }

    /// Confirm we have a `Block` and if so then add the message
    #[allow(unused)]
    pub fn add_message(&mut self, message: MessageContent) -> Result<(), RoutingError> {
        let ref data = serialisation::serialise(&message)?;
        let hash = sha3_256(data);
        if self.blocks.contains_key(&hash) {
        let _ = self.data.insert(hash, message);
        Ok(())
        } else {
            Err(RoutingError::InvalidMessage)
        }
    }

    /// Retreive a message if we have it.
    #[allow(unused)]
    pub fn get_message(&mut self, message_hash: Digest256) -> Option<&MessageContent> {
        self.data.get(&message_hash)
    }
}


 
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
use proof::Proof;
use vote::Vote;
use error::RoutingError;
use rust_sodium::crypto::sign::PublicKey;
use maidsafe_utilities::serialisation;


#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Block<T> {
    payload: T,
    proofs: Vec<Proof>,
    pub valid: bool,
}

impl <T: Serialize + Clone>Block<T> {
    /// new block
    #[allow(unused)]
    pub fn new(vote: &Vote<T>, pub_key: &PublicKey) -> Result<Block<T>, RoutingError> {
        vote.validate(pub_key);
        let proof = Proof::new(&pub_key, vote)?;

        Ok(Block::<T> {
            payload: vote.payload().clone(),
            proofs: vec![proof],
            valid: false,
        })
    }

    /// Add a proof from a peer
    #[allow(unused)]
    pub fn add_proof(&mut self, proof: Proof) -> Result<(), RoutingError> {
        if !self.validate_proof(&proof) {
            return Err(RoutingError::FailedSignature);
        }
        if !self.proofs.iter().any(|x| x.key() == proof.key()) {
            self.proofs.push(proof);
            return Ok(());
        }
        Err(RoutingError::FailedSignature)
    }

    #[allow(unused)]
    /// validate signed correctly
    pub fn validate_proof(&self, proof: &Proof) -> bool {
        match serialisation::serialise(&self.payload) {
            Ok(data) => proof.validate_signature(&data),
            _ => false,
        }
    }

    #[allow(unused)]
    /// validate signed correctly
    pub fn validate_block_signatures(&self) -> bool {
        match serialisation::serialise(&self.payload) {
            Ok(data) => self.proofs.iter().all(|proof| proof.validate_signature(&data)),
            _ => false,
        }
    }

    #[allow(unused)]
    /// Prune any bad signatures.
    pub fn remove_invalid_signatures(&mut self) {
        match serialisation::serialise(&self.payload) {
            Ok(data) => self.proofs.retain(|proof| proof.validate_signature(&data)),
            _ => self.proofs.clear(),
        }
    }

    #[allow(unused)]
    /// getter
    pub fn proofs(&self) -> &Vec<Proof> {
        &self.proofs
    }

    #[allow(unused)]
    /// getter
    pub fn proofs_mut(&mut self) -> &mut Vec<Proof> {
        &mut self.proofs
    }

    #[allow(unused)]
    /// getter
    pub fn identifier(&self) -> &T {
        &self.payload
    }
}

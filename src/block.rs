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
use chain::vote::Vote;
use error::Error;
use maidsafe_utilities::serialisation;

/// Used to validate chain
/// Block can be a data item or
/// a chain link.
#[allow(missing_docs)]
#[derive(Debug, RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub struct Block {
    identifier: BlockIdentifier,
    proofs: Vec<Proof>,
    pub valid: bool,
}

impl Block {
    /// new block
    pub fn new(vote: Vote) -> Result<Block, Error> {
        if !vote.validate() {
            return Err(Error::Signature);
        }
        Ok(Block {
            identifier: vote.identifier().clone(),
            proofs: vec![vote.proof().clone()],
            valid: false,
        })
    }

    /// Add a proof from a peer
    pub fn add_proof(&mut self, proof: Proof) -> Result<(), Error> {
        if !self.validate_proof(&proof) {
            return Err(Error::Signature);
        }
        if !self.proofs.iter().any(|x| x.key() == proof.key()) {
            self.proofs.push(proof);
            return Ok(());
        }
        Err(Error::Validation)
    }

    /// validate signed correctly
    pub fn validate_proof(&self, proof: &Proof) -> bool {
        match serialisation::serialise(&self.identifier) {
            Ok(data) => proof.validate(&data[..]),
            _ => false,
        }
    }

    /// validate signed correctly
    pub fn validate_block_signatures(&self) -> bool {
        match serialisation::serialise(&self.identifier) {
            Ok(data) => self.proofs.iter().all(|proof| proof.validate(&data[..])),
            _ => false,
        }
    }

    /// Prune any bad signatures.
    pub fn remove_invalid_signatures(&mut self) {
        match serialisation::serialise(&self.identifier) {
            Ok(data) => self.proofs.retain(|proof| proof.validate(&data[..])),
            _ => self.proofs.clear(),
        }
    }

    /// getter
    pub fn proofs(&self) -> &Vec<Proof> {
        &self.proofs
    }

    /// getter
    pub fn proofs_mut(&mut self) -> &mut Vec<Proof> {
        &mut self.proofs
    }

    /// getter
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
}

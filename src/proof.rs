// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This,
// along with the
// Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations
// relating to use of the SAFE Network Software.

use super::vote::Vote;
use error::RoutingError;
use maidsafe_utilities::serialisation;
use network_event::NetworkEvent;
use rust_sodium::crypto::sign::{self, PublicKey, Signature};

/// Proof as provided by a close group member
/// This nay be extracted from a `Vote` to be inserted into a `Block`
#[derive(Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq, Clone, Hash, Debug)]
pub struct Proof {
    pub_key: PublicKey,
    age: u8,
    sig: Signature,
}

impl Proof {
    /// Create Proof from Vote and public key
    #[allow(unused)]
    pub fn new(key: &PublicKey, age: u8, vote: &Vote) -> Result<Proof, RoutingError> {
        if !vote.validate_signature(key) {
            return Err(RoutingError::FailedSignature);
        }
        Ok(Proof {
            pub_key: key.clone(),
            age: age,
            sig: vote.signature().clone(),
        })
    }

    /// getter
    #[allow(unused)]
    pub fn key(&self) -> &PublicKey {
        &self.pub_key
    }

    /// getter
    #[allow(unused)]
    pub fn age(&self) -> u8 {
        self.age
    }


    /// getter
    #[allow(unused)]
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    /// Validates `data` against this `Proof`'s `key` and `sig`.
    #[allow(unused)]
    pub fn validate_signature(&self, payload: &NetworkEvent) -> bool {
        match serialisation::serialise(&payload) {
            Ok(data) => sign::verify_detached(&self.sig, &data[..], &self.pub_key),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::SeededRng;
    use rand::random;
    use rust_sodium;
    use tiny_keccak::sha3_256;
    use vote::Vote;

    #[test]
    fn confirm_proof_for_vote() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let keys = sign::gen_keypair();
        let payload = sha3_256(b"1");
        let vote = Vote::new(&keys.1, payload).unwrap();
        assert!(vote.validate_signature(&keys.0));
        let proof = Proof::new(&keys.0, random::<u8>(), &vote).unwrap();
        assert!(proof.validate_signature(&payload));
    }
    #[test]
    fn bad_construction() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let keys = sign::gen_keypair();
        let other_keys = sign::gen_keypair();
        let payload = sha3_256(b"1");
        let vote = Vote::new(&keys.1, payload).unwrap();
        assert!(vote.validate_signature(&keys.0));
        let proof = Proof::new(&keys.0, random::<u8>(), &vote).unwrap();
        assert!(Proof::new(&keys.0, random::<u8>(), &vote).is_ok());
        assert!(Proof::new(&other_keys.0, random::<u8>(), &vote).is_err());
        assert!(proof.validate_signature(&payload));

    }
}

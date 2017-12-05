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

use maidsafe_utilities::serialisation;
use peer_id::PeerId;
use rust_sodium::crypto::sign::{self, Signature};
use serde::Serialize;

/// Proof as provided by a close group member. This may be constructed from a `Vote` to be inserted
/// into a `Block`. This struct is ordered by age then `PublicKey`
#[derive(Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq, Clone, Hash, Debug)]
pub struct Proof {
    pub peer_id: PeerId,
    pub sig: Signature,
}

impl Proof {
    /// getter
    #[allow(unused)]
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// getter
    #[allow(unused)]
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    /// Validates `data` against this `Proof`'s `key` and `sig`.
    #[allow(unused)]
    pub fn validate_signature<T: Serialize>(&self, payload: &T) -> bool {
        match serialisation::serialise(&payload) {
            Ok(data) => sign::verify_detached(&self.sig, &data[..], self.peer_id.pub_key()),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RoutingError;
    use maidsafe_utilities::SeededRng;
    use network_event::SectionState;
    use rand::Rng;
    use rust_sodium;
    use vote::Vote;

    #[test]
    fn confirm_proof_for_vote() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let keys = sign::gen_keypair();
        let peer_id = PeerId::new(rng.gen_range(0, 255), keys.0);
        let payload = SectionState::Live(PeerId::new(rng.gen_range(0, 255), keys.0));
        let vote = unwrap!(Vote::new(&keys.1, payload.clone()));
        assert!(vote.validate_signature(&peer_id));
        let proof = unwrap!(vote.proof(&PeerId::new(rng.gen_range(0, 255), keys.0)));
        assert!(proof.validate_signature(&payload));
    }

    #[test]
    fn bad_construction() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let keys = sign::gen_keypair();
        let peer_id = PeerId::new(rng.gen_range(0, 255), keys.0);
        let other_keys = sign::gen_keypair();
        let payload = SectionState::Live(PeerId::new(rng.gen_range(0, 255), keys.0));
        let vote = unwrap!(Vote::new(&keys.1, payload.clone()));
        assert!(vote.validate_signature(&peer_id));
        let proof = unwrap!(vote.proof(&PeerId::new(rng.gen_range(0, 255), keys.0)));
        assert!(
            vote.proof(&PeerId::new(rng.gen_range(0, 255), keys.0))
                .is_ok()
        );
        if let Err(RoutingError::FailedSignature) =
            vote.proof(&PeerId::new(rng.gen_range(0, 255), other_keys.0))
        {
        } else {
            panic!("Should have failed signature check.");
        }
        assert!(proof.validate_signature(&payload));
    }
}

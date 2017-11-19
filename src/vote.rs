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

use error::RoutingError;
use maidsafe_utilities::serialisation;
use network_event::NetworkEvent;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};

/// A Vote is a peer's desire to initiate a network action or sub action. If there are quorum votes
/// the action will happen. These are DIRECT MESSAGES and therefore do not require the `PubKey`.
/// Signature is detached and is the signed payload.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Vote {
    payload: NetworkEvent,
    signature: Signature,
}

impl Vote {
    /// Create a Vote.
    #[allow(unused)]
    pub fn new(secret_key: &SecretKey, payload: NetworkEvent) -> Result<Vote, RoutingError> {
        let signature = sign::sign_detached(&serialisation::serialise(&payload)?[..], secret_key);
        Ok(Vote {
            payload: payload,
            signature: signature,
        })
    }

    /// Getter
    #[allow(unused)]
    pub fn payload(&self) -> &NetworkEvent {
        &self.payload
    }

    /// Getter
    #[allow(unused)]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Validate signed correctly.
    #[allow(unused)]
    pub fn validate_signature(&self, public_key: &PublicKey) -> bool {
        match serialisation::serialise(&self.payload) {
            Ok(data) => sign::verify_detached(&self.signature, &data[..], public_key),
            Err(_) => false,
        }
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::SeededRng;
    use rust_sodium;

    #[test]
    fn wrong_key() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let keys = sign::gen_keypair();
        let bad_keys = sign::gen_keypair();
        let payload = NetworkEvent::PeerNew(keys.0);
        let vote = Vote::new(&keys.1, payload).unwrap();
        assert!(vote.validate_signature(&keys.0)); // right key
        assert!(!vote.validate_signature(&bad_keys.0)); // wrong key
    }
}

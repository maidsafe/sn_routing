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

// FIXME: remove when this module is finished
#![allow(dead_code)]

use error::RoutingError;
use maidsafe_utilities::serialisation;
use proof::Proof;
use public_info::PublicInfo;
use rust_sodium::crypto::sign::{self, SecretKey, Signature};
use serde::Serialize;

/// A Vote is a peer's desire to initiate a network action or sub action. If there are quorum votes
/// the action will happen. These are DIRECT MESSAGES and therefore do not require the `PubKey`.
/// Signature is detached and is the signed payload.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Vote<T> {
    payload: T,
    signature: Signature,
}

impl<T: Serialize + Clone> Vote<T> {
    /// Create a Vote.
    pub fn new(secret_key: &SecretKey, payload: T) -> Result<Vote<T>, RoutingError> {
        let signature = sign::sign_detached(&serialisation::serialise(&payload)?[..], secret_key);
        Ok(Vote {
            payload: payload,
            signature: signature,
        })
    }

    pub fn proof(&self, peer_info: &PublicInfo) -> Result<Proof, RoutingError> {
        if self.validate_signature(peer_info) {
            return Ok(Proof {
                peer_info: *peer_info,
                sig: self.signature,
            });
        }
        Err(RoutingError::FailedSignature)
    }

    /// Getter
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Getter
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Validate signed correctly.
    pub fn validate_signature(&self, peer_info: &PublicInfo) -> bool {
        match serialisation::serialise(&self.payload) {
            Ok(data) => sign::verify_detached(&self.signature, &data[..], peer_info.sign_key()),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use full_info::FullInfo;
    use maidsafe_utilities::SeededRng;
    use network_event::SectionState;
    use rand::Rng;
    use rust_sodium;

    #[test]
    fn wrong_key() {
        let mut rng = SeededRng::thread_rng();
        unwrap!(rust_sodium::init_with_rng(&mut rng));
        let full_info = FullInfo::node_new(rng.gen_range(0, 255));
        let peer_info = *full_info.public_info();
        let payload = SectionState::Live(peer_info);
        let vote = unwrap!(Vote::new(full_info.secret_sign_key(), payload));
        assert!(vote.validate_signature(&peer_info)); // right key
        let bad_peer_info = *FullInfo::node_new(rng.gen_range(0, 255)).public_info();
        assert!(!vote.validate_signature(&bad_peer_info)); // wrong key
    }
}

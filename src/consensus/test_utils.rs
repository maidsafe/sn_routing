// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Proof, Proven};
use crate::rng::MainRng;
use rand::Rng;
use serde::Serialize;

// Generate random BLS `SecretKey`.
pub fn gen_secret_key(rng: &mut MainRng) -> bls::SecretKey {
    rng.gen()
}

// Create proof for the given payload using the given secret key.
#[cfg_attr(feature = "mock", allow(clippy::trivially_copy_pass_by_ref))]
pub fn prove<T: Serialize>(secret_key: &bls::SecretKey, payload: &T) -> Proof {
    let bytes = bincode::serialize(payload).unwrap();
    Proof {
        public_key: secret_key.public_key(),
        signature: secret_key.sign(&bytes),
    }
}

// Wrap the given payload in `Proven`
pub fn proven<T: Serialize>(secret_key: &bls::SecretKey, payload: T) -> Proven<T> {
    let proof = prove(secret_key, &payload);
    Proven::new(payload, proof)
}

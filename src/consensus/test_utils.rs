// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Proof;
use crate::rng::{MainRng, RngCompat};
use rand_crypto::Rng;
use serde::Serialize;

// Generate random BLS `SecretKey`.
pub fn gen_secret_key(rng: &mut MainRng) -> bls::SecretKey {
    RngCompat(rng).gen()
}

// Create fake proof for the given payload.
#[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
pub fn prove<T: Serialize>(rng: &mut MainRng, payload: &T) -> Proof {
    let secret_key = gen_secret_key(rng);
    let bytes = bincode::serialize(payload).unwrap();
    Proof {
        public_key: secret_key.public_key(),
        signature: secret_key.sign(&bytes),
    }
}

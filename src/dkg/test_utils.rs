// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{ProvenUtils, Signed};
use crate::{Error, Result};
use serde::Serialize;
use sn_messaging::node::Proven;

// Create signed for the given payload using the given secret key.
pub fn prove<T: Serialize>(secret_key: &bls::SecretKey, payload: &T) -> Result<Signed> {
    let bytes = bincode::serialize(payload).map_err(|_| Error::InvalidPayload)?;
    Ok(Signed {
        public_key: secret_key.public_key(),
        signature: secret_key.sign(&bytes),
    })
}

// Wrap the given payload in `Proven`
pub fn proven<T: Serialize>(secret_key: &bls::SecretKey, payload: T) -> Result<Proven<T>> {
    let signed = prove(secret_key, &payload)?;
    Ok(Proven::new(payload, signed))
}

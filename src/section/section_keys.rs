// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};

/// All the key material needed to sign or combine signature for our section key.
#[derive(Debug)]
pub struct SectionKeyShare {
    /// Public key set to verify threshold signatures and combine shares.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the owner of this key share within the set of all section elders.
    pub index: usize,
    /// Secret Key share.
    pub secret_key_share: bls::SecretKeyShare,
}

/// Struct that holds the current section keys and helps with new key generation.
#[derive(Debug)]
pub struct SectionKeysProvider {
    /// Our current section BLS keys.
    current: Option<SectionKeyShare>,
    /// The new keys to use when section update completes.
    pending: Option<SectionKeyShare>,
}

impl SectionKeysProvider {
    pub fn new(current: Option<SectionKeyShare>) -> Self {
        Self {
            current,
            pending: None,
        }
    }

    pub fn key_share(&self) -> Result<&SectionKeyShare> {
        self.current.as_ref().ok_or(Error::MissingSecretKeyShare)
    }

    pub fn has_key_share(&self) -> bool {
        self.current.is_some()
    }

    pub fn insert_dkg_outcome(&mut self, share: SectionKeyShare) {
        self.pending = Some(share);
    }

    pub fn finalise_dkg(&mut self, public_key: &bls::PublicKey) {
        if let Some(share) = &self.pending {
            let pending_public_key = share.public_key_set.public_key();

            if pending_public_key == *public_key {
                trace!("finalise DKG: {:?}", pending_public_key);
                self.current = self.pending.take();
            }
        }
    }
}

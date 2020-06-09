// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::elders_info::EldersInfo;
use crate::{
    consensus::{DkgResult, DkgResultWrapper},
    error::{Result, RoutingError},
    id::PublicId,
    xor_space::XorName,
};
use std::collections::{BTreeMap, BTreeSet};

/// Secret key share with its index.
#[derive(Clone)]
pub struct IndexedSecretKeyShare {
    /// Index used to combine signature share and get PublicKeyShare from PublicKeySet.
    pub index: usize,
    /// Secret Key share
    pub key: bls::SecretKeyShare,
}

impl IndexedSecretKeyShare {
    /// Create a new share finding the index within the elders.
    pub fn new(
        key: bls::SecretKeyShare,
        our_name: &XorName,
        elders_info: &EldersInfo,
    ) -> Option<Self> {
        let index = elders_info.position(our_name)?;
        Some(Self { index, key })
    }

    /// Extracts the `index`-th share from `secret_key_set`.
    #[cfg(any(test, feature = "mock_base"))]
    pub fn from_set(secret_key_set: &bls::SecretKeySet, index: usize) -> Self {
        Self {
            index,
            key: secret_key_set.secret_key_share(index),
        }
    }
}

/// All the key material needed to sign or combine signature for our section key.
#[derive(Clone)]
pub struct SectionKeyShare {
    /// Public key set to verify threshold signatures and combine shares.
    pub public_key_set: bls::PublicKeySet,
    /// Secret Key share and index.
    pub secret_key_share: IndexedSecretKeyShare,
}

impl SectionKeyShare {
    pub fn new(public_key_set: bls::PublicKeySet, secret_key_share: IndexedSecretKeyShare) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }
}

/// Struct that holds the current section keys and helps with new key generation.
pub struct SectionKeysProvider {
    /// Our current section BLS keys.
    current: Option<SectionKeyShare>,
    /// The new dkg key to use when SectionInfo completes. For lookup, use the XorName of the
    /// first member in DKG participants and new ElderInfo. We only store 2 items during split, and
    /// then members are disjoint. We are working around not having access to the prefix for the
    /// DkgResult but only the list of participants.
    new: BTreeMap<XorName, DkgResult>,
}

impl SectionKeysProvider {
    pub fn new(current: Option<SectionKeyShare>) -> Self {
        Self {
            current,
            new: Default::default(),
        }
    }

    pub fn key_share(&self) -> Result<&SectionKeyShare> {
        self.current
            .as_ref()
            .ok_or(RoutingError::InvalidElderDkgResult)
    }

    /// Handles a completed parsec DKG Observation.
    pub fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        dkg_result: &DkgResultWrapper,
    ) -> Result<()> {
        if let Some(first) = participants.iter().next() {
            if self
                .new
                .insert(*first.name(), dkg_result.0.clone())
                .is_some()
            {
                log_or_panic!(log::Level::Error, "Ejected previous DKG result");
            }
        }

        Ok(())
    }

    pub fn finalise_dkg(&mut self, our_name: &XorName, elders_info: &EldersInfo) -> Result<()> {
        let first_name = elders_info
            .elders
            .keys()
            .next()
            .ok_or(RoutingError::InvalidElderDkgResult)?;
        let dkg_result = self
            .new
            .remove(first_name)
            .ok_or(RoutingError::InvalidElderDkgResult)?;
        let public_key_set = dkg_result.public_key_set;

        self.current = dkg_result
            .secret_key_share
            .and_then(|key| IndexedSecretKeyShare::new(key, our_name, elders_info))
            .map(|secret_key_share| SectionKeyShare::new(public_key_set, secret_key_share));
        self.new.clear();

        Ok(())
    }
}

// Generate random BLS `SecretKey`. For tests only.
#[cfg(test)]
pub fn gen_secret_key(rng: &mut crate::rng::MainRng) -> bls::SecretKey {
    use crate::rng::RngCompat;
    use rand_crypto::Rng;

    RngCompat(rng).gen()
}

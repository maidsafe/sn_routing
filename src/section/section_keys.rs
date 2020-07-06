// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::elders_info::EldersInfo;
use crate::{
    consensus::DkgResult,
    error::{Result, RoutingError},
    id::PublicId,
};
use std::collections::{BTreeMap, BTreeSet};
use xor_name::XorName;

/// All the key material needed to sign or combine signature for our section key.
#[derive(Clone)]
pub struct SectionKeyShare {
    /// Public key set to verify threshold signatures and combine shares.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the owner of this key share within the set of all section elders.
    pub index: usize,
    /// Secret Key share.
    pub secret_key_share: bls::SecretKeyShare,
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
        dkg_result: &DkgResult,
    ) -> Result<()> {
        if let Some(first) = participants.iter().next() {
            if self.new.insert(*first.name(), dkg_result.clone()).is_some() {
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
            .and_then(|secret_key_share| {
                elders_info
                    .position(our_name)
                    .map(|index| (index, secret_key_share))
            })
            .map(|(index, secret_key_share)| SectionKeyShare {
                public_key_set,
                index,
                secret_key_share,
            });
        self.new.clear();

        Ok(())
    }
}

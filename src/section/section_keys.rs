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
};
use std::{collections::BTreeMap, mem};
use xor_name::XorName;

/// All the key material needed to sign or combine signature for our section key.
#[derive(Clone, Debug)]
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
    pending: BTreeMap<u64, DkgResult>,
}

impl SectionKeysProvider {
    pub fn new(current: Option<SectionKeyShare>) -> Self {
        Self {
            current,
            pending: Default::default(),
        }
    }

    pub fn public_key(&self) -> Option<bls::PublicKey> {
        if let Some(current) = &self.current {
            Some(current.public_key_set.public_key())
        } else {
            None
        }
    }

    pub fn key_share(&self) -> Result<&SectionKeyShare> {
        self.current
            .as_ref()
            .ok_or(RoutingError::InvalidElderDkgResult)
    }

    /// Handles a completed DKG
    pub fn handle_dkg_result_event(&mut self, section_key_index: u64, dkg_result: DkgResult) {
        let _ = self.pending.entry(section_key_index).or_insert_with(|| {
            trace!(
                "insert pending DKG result #{}: {:?}",
                section_key_index,
                dkg_result.public_key_set.public_key()
            );
            dkg_result
        });
    }

    pub fn finalise_dkg(
        &mut self,
        section_key_index: u64,
        our_name: &XorName,
        elders_info: &EldersInfo,
    ) {
        let dkg_result = if let Some(result) = self.pending.remove(&section_key_index) {
            result
        } else {
            trace!("missing pending DKG result #{}", section_key_index);
            return;
        };

        let public_key_set = dkg_result.public_key_set;

        trace!(
            "finalise DKG result #{}: {:?}",
            section_key_index,
            public_key_set.public_key()
        );

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

        self.pending = mem::take(&mut self.pending)
            .into_iter()
            .filter(|(index, _)| *index > section_key_index)
            .collect();
    }

    pub fn has_pending(&self, section_key_index: u64) -> bool {
        self.pending.contains_key(&section_key_index)
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{elders_info::EldersInfo, section_proof_chain::SectionProofBlock};
use crate::{
    consensus::{AccumulatingProof, DkgResult, DkgResultWrapper},
    error::{Result, RoutingError},
    id::PublicId,
    xor_space::XorName,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

/// The secret share of the section key.
#[derive(Clone)]
pub struct SectionKeyShare {
    /// Index used to combine signature share and get PublicKeyShare from PublicKeySet.
    pub index: usize,
    /// Secret Key share
    pub key: bls::SecretKeyShare,
}

impl SectionKeyShare {
    /// Create a new share with associated share index.
    #[cfg(any(test, feature = "mock_base"))]
    pub const fn new_with_position(index: usize, key: bls::SecretKeyShare) -> Self {
        Self { index, key }
    }

    /// create a new share finding the position wihtin the elders.
    pub fn new(
        key: Option<bls::SecretKeyShare>,
        our_id: &PublicId,
        new_elders_info: &EldersInfo,
    ) -> Option<Self> {
        let key = key?;
        let index = new_elders_info.elder_ids().position(|id| id == our_id)?;

        Some(Self { index, key })
    }
}

/// All the key material needed to sign or combine signature for our section key.
#[derive(Clone)]
pub struct SectionKeys {
    /// Public key set to verify threshold signatures and combine shares.
    pub public_key_set: bls::PublicKeySet,
    /// Secret Key share and index. None if the node was not participating in the DKG.
    pub secret_key_share: Option<SectionKeyShare>,
}

impl SectionKeys {
    pub fn new(
        public_key_set: bls::PublicKeySet,
        secret_key_share: Option<SectionKeyShare>,
    ) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }
}

/// Struct that holds the current section keys and helps with new key generation.
pub struct SectionKeysProvider {
    /// Our current section BLS keys.
    keys: SectionKeys,
    /// The new dkg key to use when SectionInfo completes. For lookup, use the XorName of the
    /// first member in DKG participants and new ElderInfo. We only store 2 items during split, and
    /// then members are disjoint. We are working around not having access to the prefix for the
    /// DkgResult but only the list of participants.
    new_keys: BTreeMap<XorName, DkgResult>,
}

impl SectionKeysProvider {
    pub fn new(
        public_key_set: bls::PublicKeySet,
        secret_key_share: Option<SectionKeyShare>,
    ) -> Self {
        Self {
            keys: SectionKeys::new(public_key_set, secret_key_share),
            new_keys: Default::default(),
        }
    }

    pub fn public_key_set(&self) -> &bls::PublicKeySet {
        &self.keys.public_key_set
    }

    pub fn secret_key_share(&self) -> Result<&SectionKeyShare> {
        self.keys
            .secret_key_share
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
                .new_keys
                .insert(*first.name(), dkg_result.0.clone())
                .is_some()
            {
                log_or_panic!(log::Level::Error, "Ejected previous DKG result");
            }
        }

        Ok(())
    }

    pub fn finalise_dkg(&mut self, our_id: &PublicId, elders_info: &EldersInfo) -> Result<()> {
        let first_name = elders_info
            .elders
            .keys()
            .next()
            .ok_or(RoutingError::InvalidElderDkgResult)?;
        let dkg_result = self
            .new_keys
            .remove(first_name)
            .ok_or(RoutingError::InvalidElderDkgResult)?;
        let secret_key_share =
            SectionKeyShare::new(dkg_result.secret_key_share, our_id, elders_info);

        self.keys = SectionKeys::new(dkg_result.public_key_set, secret_key_share);
        self.new_keys.clear();

        Ok(())
    }

    pub fn combine_signatures_for_section_proof_block(
        &self,
        our_elders: &EldersInfo,
        key: bls::PublicKey,
        proofs: AccumulatingProof,
    ) -> Result<SectionProofBlock, RoutingError> {
        let signature = self
            .check_and_combine_signatures(our_elders, &key, proofs)
            .ok_or(RoutingError::InvalidNewSectionInfo)?;
        Ok(SectionProofBlock { key, signature })
    }

    pub fn check_and_combine_signatures<S: Serialize + Debug>(
        &self,
        our_elders: &EldersInfo,
        signed_payload: &S,
        proofs: AccumulatingProof,
    ) -> Option<bls::Signature> {
        let signed_bytes = bincode::serialize(signed_payload)
            .map_err(|err| {
                log_or_panic!(
                    log::Level::Error,
                    "Failed to serialise accumulated event: {:?} for {:?}",
                    err,
                    signed_payload
                );
                err
            })
            .ok()?;

        proofs
            .check_and_combine_signatures(our_elders, self.public_key_set(), &signed_bytes)
            .or_else(|| {
                log_or_panic!(
                    log::Level::Error,
                    "Failed to combine signatures for accumulated event: {:?}",
                    signed_payload
                );
                None
            })
    }
}

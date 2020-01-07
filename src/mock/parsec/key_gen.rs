// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Fake DKG (distributed key generation). Does not perform actual DKG, uses a trusted dealer
//! instead.

use super::{DkgResult, PublicId};
use crate::rng::RngCompat;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct KeyGen<P: PublicId> {
    instances: BTreeMap<BTreeSet<P>, bls::SecretKeySet>,
}

impl<P: PublicId> KeyGen<P> {
    pub fn new() -> Self {
        Self {
            instances: BTreeMap::new(),
        }
    }

    pub fn get_or_generate(
        &mut self,
        rng: &mut impl Rng,
        our_id: &P,
        participants: BTreeSet<P>,
    ) -> DkgResult {
        let index = participants.iter().position(|id| id == our_id);
        let threshold = participants.len().saturating_sub(1) / 3;
        let secret_key_set = self
            .instances
            .entry(participants)
            .or_insert_with(|| bls::SecretKeySet::random(threshold, &mut RngCompat(rng)));

        let secret_key_share = index.map(|index| secret_key_set.secret_key_share(index));
        DkgResult::new(secret_key_set.public_keys(), secret_key_share)
    }

    pub fn contains_participant(&self, our_id: &P) -> bool {
        self.instances
            .keys()
            .any(|participants| participants.contains(our_id))
    }
}

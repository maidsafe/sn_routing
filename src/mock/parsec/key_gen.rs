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
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use threshold_crypto::SecretKeySet;

pub(super) struct KeyGen<P: PublicId> {
    instances: BTreeMap<BTreeSet<P>, SecretKeySet>,
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
            .or_insert_with(|| SecretKeySet::random(threshold, &mut RngAdapter(rng)));

        let secret_key_share = index.map(|index| secret_key_set.secret_key_share(index));
        DkgResult::new(secret_key_set.public_keys(), secret_key_share)
    }
}

// Note: routing uses different version of the rand crate than threshold_crypto. This is a
// compatibility adapter between the two.
struct RngAdapter<R>(R);

impl<R: Rng> rand_threshold_crypto::RngCore for RngAdapter<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_threshold_crypto::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

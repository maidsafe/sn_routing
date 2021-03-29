// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::mem;

use crate::{
    consensus::{Proof, Proven},
    section::EldersInfo,
};
use xor_name::Prefix;

type Entry = (Proven<EldersInfo>, Proof);

// Helper structure to make sure we process a split by updating info about both our section and the
// sibling section at the same time.
pub(crate) struct SplitBarrier(Vec<Entry>);

impl SplitBarrier {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    // Pass an aggreed-on vote for `OurElders` through this function. If there is no split, it
    // returns it unchanged. If there is a split and we've seen the aggreement for only one
    // subsection so far, it caches it and returns nothing. Otherwise it returns both votes.
    //
    // Note: in case of a fork, it can return more than two votes. In that case one of the votes
    // will be for one subsection and all the others for the other subsection.
    pub fn process(
        &mut self,
        our_prefix: &Prefix,
        elders_info: Proven<EldersInfo>,
        key_proof: Proof,
    ) -> Vec<Entry> {
        if !elders_info.value.prefix.is_extension_of(our_prefix) {
            // Not a split, no need to cache.
            return vec![(elders_info, key_proof)];
        }

        // Split detected. Find all cached siblings.
        let (mut give, keep) =
            mem::take(&mut self.0)
                .into_iter()
                .partition(|(cached_elders_info, _)| {
                    cached_elders_info.value.prefix == elders_info.value.prefix.sibling()
                });
        self.0 = keep;

        if give.is_empty() {
            // No sibling found. Cache this update until we see the sibling update.
            self.0.push((elders_info, key_proof));
            vec![]
        } else {
            // Sibling found. We can proceed with the update.
            give.push((elders_info, key_proof));
            give
        }
    }
}

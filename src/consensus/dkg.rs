// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{network_event::AccumulatingEvent, proof::Proof};
use crate::{
    id::{FullId, PublicId},
    rng::{MainRng, RngCompat},
    section::EldersInfo,
    QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
};
use bls::{PublicKeySet, SecretKeyShare};
use bls_dkg::key_gen::{message::Message as DkgMessage, KeyGen};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::{self, Debug, Formatter},
    mem,
};

/// Generate a BLS SecretKeySet for the given number of participants.
/// Used for generating first node, or for test.
pub fn generate_secret_key_set(rng: &mut MainRng, participants: usize) -> bls::SecretKeySet {
    // The BLS scheme will require more than `participants / 3`
    // shares in order to construct a full key or signature.
    let threshold = participants.saturating_sub(1) / 3;

    bls::SecretKeySet::random(threshold, &mut RngCompat(rng))
}

#[derive(Clone)]
/// DKG result
pub struct DkgResult {
    /// Public key set to verify threshold signatures
    pub public_key_set: PublicKeySet,
    /// Secret Key share: None if the node was not participating in the DKG and did not receive
    /// encrypted shares.
    pub secret_key_share: Option<SecretKeyShare>,
}

impl DkgResult {
    /// Create DkgResult from components
    pub fn new(public_key_set: PublicKeySet, secret_key_share: Option<SecretKeyShare>) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }
}

impl Debug for DkgResult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "DkgResult({:?}, {})",
            self.public_key_set,
            self.secret_key_share.is_some()
        )
    }
}

/// Returns the number of minumn responsive participants expected for the DKG process
#[inline]
pub const fn threshold_count(elder_size: usize) -> usize {
    // TODO: allow threshold to be configurable.
    elder_size * QUORUM_NUMERATOR / QUORUM_DENOMINATOR
}

pub type DkgKey = (BTreeSet<PublicId>, u64);

#[derive(Default)]
pub struct DkgVoter {
    dkg_cache: BTreeMap<DkgKey, EldersInfo>,
    key_gen_map: BTreeMap<DkgKey, KeyGen<FullId>>,
    pending_accumulated_events: VecDeque<(AccumulatingEvent, Proof)>,
    completed_dkg: BTreeSet<DkgKey>,
    sibling_dkg_result_cache: BTreeMap<DkgKey, DkgResult>,
    timer_token: u64,
}

impl DkgVoter {
    pub fn check_dkg(
        &mut self,
    ) -> (
        BTreeMap<DkgKey, DkgResult>,
        VecDeque<(AccumulatingEvent, Proof)>,
    ) {
        let mut completed = BTreeMap::new();
        for (key, key_gen) in self.key_gen_map.iter_mut() {
            if key_gen.is_finalized() {
                let dkg_key = (key.0.clone(), key.1);
                if let Some((_participants, dkg_outcome)) = key_gen.generate_keys() {
                    let dkg_result = DkgResult::new(
                        dkg_outcome.public_key_set,
                        Some(dkg_outcome.secret_key_share),
                    );
                    let _ = completed.insert(dkg_key.clone(), dkg_result);
                }
                let _ = self.completed_dkg.insert(dkg_key);
            }
        }

        // Only handle cached accumulated events after DKG completion, if has.
        let backlog_events = if !completed.is_empty() {
            mem::replace(&mut self.pending_accumulated_events, VecDeque::new())
        } else {
            VecDeque::new()
        };

        (completed, backlog_events)
    }

    pub fn remove_voter(&mut self, dkg_key: &DkgKey) {
        let _ = self.key_gen_map.remove(dkg_key);
    }

    pub fn progress_dkg(&mut self, rng: &mut MainRng) -> Vec<(DkgKey, DkgMessage<PublicId>)> {
        let mut broadcast = Vec::new();
        for (key, key_gen) in self.key_gen_map.iter_mut() {
            debug!("Progressing DKG {:?}", key);
            if let Ok(messages) = key_gen.timed_phase_transition(rng) {
                for message in messages {
                    broadcast.push((key.clone(), message));
                }
            }
        }

        broadcast
    }

    pub fn process_dkg_message(
        &mut self,
        rng: &mut MainRng,
        dkg_key: &DkgKey,
        message: DkgMessage<PublicId>,
    ) -> Vec<DkgMessage<PublicId>> {
        let mut messages = Vec::new();

        if let Some(mut key_gen) = self.key_gen_map.remove(dkg_key) {
            if let Ok(responses) = key_gen.handle_message(rng, message) {
                messages = responses;
            }

            let _ = self.key_gen_map.insert(dkg_key.clone(), key_gen);
        }
        messages
    }

    pub fn init_dkg_gen(
        &mut self,
        full_id: &FullId,
        dkg_key: &DkgKey,
    ) -> Vec<DkgMessage<PublicId>> {
        if self.key_gen_map.contains_key(dkg_key) || self.completed_dkg.contains(dkg_key) {
            trace!("already have key_gen of {:?}", dkg_key);
            return vec![];
        }

        let threshold = threshold_count(dkg_key.0.len());

        if let Ok((key_gen, message)) = KeyGen::initialize(full_id, threshold, dkg_key.0.clone()) {
            debug!("started key_gen of {:?}", dkg_key);

            let _ = self.key_gen_map.insert(dkg_key.clone(), key_gen);
            vec![message]
        } else {
            vec![]
        }
    }

    pub fn has_info(&mut self, dkg_key: &DkgKey, dkg_result: &DkgResult) -> bool {
        if self.dkg_cache.contains_key(dkg_key) {
            true
        } else {
            // During split, sibling DKG got completed before this elder notice the churn.
            // In this case, as this elder is responsible for voting SectionInfo and Key for the
            // sibling DKG, the notified result has to be cached.
            if !self.completed_dkg.contains(dkg_key) {
                let _ = self
                    .sibling_dkg_result_cache
                    .insert(dkg_key.clone(), dkg_result.clone());
            }
            false
        }
    }

    pub fn push_info(&mut self, dkg_key: &DkgKey, info: EldersInfo) -> Option<DkgResult> {
        let _ = self.dkg_cache.insert(dkg_key.clone(), info);

        if let Some(dkg_result) = self.sibling_dkg_result_cache.remove(dkg_key) {
            Some(dkg_result)
        } else {
            None
        }
    }

    pub fn take_info(&mut self, dkg_key: &DkgKey) -> Option<EldersInfo> {
        self.dkg_cache.remove(dkg_key)
    }

    pub fn info_keys(&self) -> impl Iterator<Item = &DkgKey> {
        self.dkg_cache.keys()
    }

    pub fn insert_dkg_result(&mut self, dkg_key: DkgKey, dkg_result: DkgResult) {
        let _ = self.sibling_dkg_result_cache.insert(dkg_key, dkg_result);
    }

    pub fn timer_token(&self) -> u64 {
        self.timer_token
    }

    pub fn set_timer_token(&mut self, token: u64) {
        self.timer_token = token;
    }

    pub fn push_event(&mut self, event: AccumulatingEvent, proof: Proof) {
        self.pending_accumulated_events.push_front((event, proof));
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{vote::Vote, Proof};
use crate::{
    id::{FullId, PublicId},
    rng::MainRng,
    section::EldersInfo,
    QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
};
use bls::{PublicKeySet, SecretKeyShare};
use bls_dkg::key_gen::{message::Message as DkgMessage, KeyGen};
use lru_time_cache::LruCache;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fmt::{self, Debug, Formatter},
    mem,
    time::Duration,
};

const OLD_ELDERS_EXPIRY_DURATION: Duration = Duration::from_secs(2 * 60);

/// Returns the number of minumn responsive participants expected for the DKG process
#[inline]
pub const fn threshold_count(elder_size: usize) -> usize {
    // TODO: allow threshold to be configurable.
    elder_size * QUORUM_NUMERATOR / QUORUM_DENOMINATOR
}

pub type DkgKey = (BTreeSet<PublicId>, u64);

/// Generate a BLS SecretKeySet for the given number of participants.
/// Used for generating first node, or for test.
pub fn generate_secret_key_set(rng: &mut MainRng, participants: usize) -> bls::SecretKeySet {
    let threshold = threshold_count(participants);
    bls::SecretKeySet::random(threshold, rng)
}

#[derive(Clone)]
/// DKG result
pub struct DkgResult {
    /// Actual participants of the DKG. Excludes the non-participating nodes.
    pub participants: BTreeSet<PublicId>,
    /// Public key set to verify threshold signatures
    pub public_key_set: PublicKeySet,
    /// Secret Key share: None if the node was not participating in the DKG and did not receive
    /// encrypted shares.
    pub secret_key_share: Option<SecretKeyShare>,
}

impl Debug for DkgResult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("DkgResult")
            .field("participants", &self.participants)
            .field("public_key", &self.public_key_set.public_key())
            .field("secret_key_share", &self.secret_key_share.is_some())
            .finish()
    }
}

/// DKG voter carries out the work of voting for a DKG. Also contains the facility caches that
/// allows routing utilize the result properly within its churning process.
pub struct DkgVoter {
    // Holds the info of the expected new elders.
    dkg_cache: BTreeMap<DkgKey, EldersInfo>,
    // Holds the key generator that carries out the DKG voting procedure.
    key_gen_map: HashMap<DkgKey, KeyGen<FullId>>,
    // Holds the accumulated votes that sent to us BEFORE the completion of the DKG process.
    pending_accumulated_votes: VecDeque<(Vote, Proof)>,
    // Cache of notified dkg_result. During split or demote,
    // old elders will be notified by the new elders.
    dkg_result_cache: BTreeMap<DkgKey, DkgResult>,
    // section_key_index of the latest completed DKG.
    current_section_key_index: u64,
    // Cache of DKGOldElders notifications.
    old_elders_notifications: LruCache<BTreeSet<PublicId>, BTreeSet<PublicId>>,
    timer_token: u64,
}

impl Default for DkgVoter {
    fn default() -> Self {
        Self {
            dkg_cache: Default::default(),
            key_gen_map: Default::default(),
            pending_accumulated_votes: Default::default(),
            dkg_result_cache: Default::default(),
            current_section_key_index: 0,
            old_elders_notifications: LruCache::with_expiry_duration(OLD_ELDERS_EXPIRY_DURATION),
            timer_token: 0,
        }
    }
}

impl DkgVoter {
    // Check whether a key generator is finalized to give a DKG. Once a DKG is generated, the cached
    // accumulated events shall be taken for routing (updated with new DKG) to process.
    pub fn check_dkg(&mut self) -> (BTreeMap<DkgKey, DkgResult>, VecDeque<(Vote, Proof)>) {
        let mut completed = BTreeMap::new();
        for (key, key_gen) in self.key_gen_map.iter_mut() {
            if key_gen.is_finalized() {
                let dkg_key = (key.0.clone(), key.1);
                if let Some((participants, dkg_outcome)) = key_gen.generate_keys() {
                    let dkg_result = DkgResult {
                        participants,
                        public_key_set: dkg_outcome.public_key_set,
                        secret_key_share: Some(dkg_outcome.secret_key_share),
                    };
                    let _ = completed.insert(dkg_key.clone(), dkg_result);
                }
            }
        }

        // Only handle cached accumulated votes after DKG completion, if has.
        let backlog_votes = if !completed.is_empty() {
            mem::replace(&mut self.pending_accumulated_votes, VecDeque::new())
        } else {
            VecDeque::new()
        };

        (completed, backlog_votes)
    }

    // Free key generators not newer than the current one.
    // After a DKG completion, routing will carry out votes of OurKey and SectionInfo.
    // Only after these votes got consensused, will then the section_key_index got updated.
    // So, a routing level check of section_index will not be enough within the gap.
    // i.e. any DKG message received during the gap will cause a new round of DKG for the same.
    // Hence here the info of completed highest section_key_index shall be recorded and checked
    // against to cover the gap.
    pub fn remove_voter(&mut self, current_section_key_index: u64) {
        self.key_gen_map
            .retain(|key, _| key.1 > current_section_key_index);
        self.current_section_key_index =
            std::cmp::max(self.current_section_key_index, current_section_key_index);
    }

    // Make key generator progress with timed phase. Returns with DkgMessages to broadcast if any.
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

    // Handle a received DkgMessage. Returns with DkgMessages to broadcast if any.
    pub fn process_dkg_message(
        &mut self,
        rng: &mut MainRng,
        dkg_key: &DkgKey,
        message: DkgMessage<PublicId>,
    ) -> Vec<DkgMessage<PublicId>> {
        if let Some(key_gen) = self.key_gen_map.get_mut(dkg_key) {
            if let Ok(responses) = key_gen.handle_message(rng, message) {
                return responses;
            }
        }
        vec![]
    }

    // Startup a key generator.
    pub fn init_dkg_gen(
        &mut self,
        full_id: &FullId,
        dkg_key: &DkgKey,
    ) -> Vec<DkgMessage<PublicId>> {
        if (self.current_section_key_index > 0 && self.current_section_key_index >= dkg_key.1)
            || self.key_gen_map.iter().any(|(key, _)| key.1 == dkg_key.1)
        {
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

    // Check whether we have the EldersInfo for the DkgResult that sent to us.
    // In case we don't have, indicates we don't notice the churn yet,
    // the dkg_result shall be cached.
    pub fn has_info(
        &mut self,
        dkg_key: &DkgKey,
        dkg_result: &DkgResult,
        current_section_key_index: u64,
    ) -> bool {
        if self.dkg_cache.contains_key(dkg_key) {
            true
        } else {
            // During split or demote, DKG got completed before this elder notice the churn.
            // In this case, as this elder is responsible for voting SectionInfo and Key,
            // the notified result has to be cached.
            if current_section_key_index <= dkg_key.1 {
                let _ = self
                    .dkg_result_cache
                    .insert(dkg_key.clone(), dkg_result.clone());
            }
            false
        }
    }

    // When a churn is noticed, the new EdlersInfo that calculated shall be recorded.
    // In case we already have the correspondent DkgResult, the dkg_result shall be returned for
    // routing to carry out further process.
    pub fn push_info(&mut self, dkg_key: &DkgKey, info: EldersInfo) -> Option<DkgResult> {
        let _ = self.dkg_cache.insert(dkg_key.clone(), info);

        if let Some(dkg_result) = self.dkg_result_cache.remove(dkg_key) {
            Some(dkg_result)
        } else {
            None
        }
    }

    // Give the cached new EldersInfo to routing for its further process.
    pub fn take_info(&mut self, dkg_key: &DkgKey) -> Option<EldersInfo> {
        self.dkg_cache.remove(dkg_key)
    }

    // Give the keys of cached new EldersInfo.
    pub fn info_keys(&self) -> impl Iterator<Item = &DkgKey> {
        self.dkg_cache.keys()
    }

    // Cache the dkg result that we got notified, indicates we are an old elder.
    pub fn insert_old_elders_dkg_result(&mut self, dkg_key: DkgKey, dkg_result: DkgResult) {
        let _ = self.dkg_result_cache.insert(dkg_key, dkg_result);
    }

    pub fn timer_token(&self) -> u64 {
        self.timer_token
    }

    pub fn set_timer_token(&mut self, token: u64) {
        self.timer_token = token;
    }

    // Cache the accumulated vote that currently cannot be handled properly, mainly due to the DKG
    // process is not completed yet.
    pub fn push_vote(&mut self, vote: Vote, proof: Proof) {
        self.pending_accumulated_votes.push_front((vote, proof));
    }

    // Return with true only when accumulated quorum valid notifications first time.
    pub fn add_old_elders_notification(
        &mut self,
        participants: &BTreeSet<PublicId>,
        src_id: &PublicId,
    ) -> bool {
        if !participants.contains(src_id) {
            return false;
        }

        let senders = self
            .old_elders_notifications
            .entry(participants.clone())
            .or_insert(BTreeSet::new());
        let _ = senders.insert(*src_id);
        senders.len() == threshold_count(participants.len())
    }
}

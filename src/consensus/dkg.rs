// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::Digest256,
    id::{FullId, P2pNode, PublicId},
    rng::MainRng,
    section::{quorum_count, EldersInfo},
};
use bls_dkg::key_gen::{message::Message as DkgMessage, outcome::Outcome, KeyGen};
use hex_fmt::HexFmt;
use itertools::Itertools;
use lru_time_cache::LruCache;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Debug, Formatter},
};

// Maximum number of DKG sessions we can observe at the same time. Normally there should be no
// more than two DKG sessions at the time (one during normal section update, two during split), but
// in the case of heavy churn there can be more. Note also that this applies to DKG observers only.
// A DKG participant has always at most one active session.
const MAX_OBSERVERS: usize = 10;

/// Generate a BLS SecretKeySet for the given number of participants.
/// Used for generating first node, or for test.
pub fn generate_secret_key_set(rng: &mut MainRng, participants: usize) -> bls::SecretKeySet {
    let threshold = quorum_count(participants) - 1;
    bls::SecretKeySet::random(threshold, rng)
}

/// Unique identified of a DKG session.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DkgKey(Digest256);

impl DkgKey {
    pub fn new(elders_info: &EldersInfo) -> Self {
        Self(elders_info.hash())
    }
}

impl Debug for DkgKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DkgKey({:10})", HexFmt(&self.0))
    }
}

pub type DkgStatus<T> = Option<Result<T, EldersInfo>>;

/// DKG voter carries out the work of participating and/or observing a DKG.
///
/// # Usage
///
/// 1. First the current elders propose the new elder candidates in the form of `EldersInfo`
///    structure.
/// 2. They send an accumulating message `DKGStart` containing this proposed `EldersInfo` to the
///    other elders (DKG observers) and also to the candidates (DKG participants).
/// 3. When it accumulates, a participant calls `start_participating`. An observer calls
///    `start_observing`. Note a node can sometimes be both participant and observer at the same
///    time.
/// 4. The participants keep exchanging the DKG messages and calling `process_dkg_message`.
/// 5. The participants call `check_dkg` to check whether the DKG session completed or failed.
/// 6. They should also run a timer in case of inactivity and call `progress_dkg` when it fires.
/// 7. On DKG completion or failure, the participants send `DKGResult` message to the current
///    elders (observers)
/// 8. The observers observer the result by calling `observe_result`.
/// 9. When it returns success, that means we accumulated at least quorum of successful DKG results
///    and can proceed with voting for the section update.
/// 10. When it fails, the observers restart the process from step 1.
///
/// Note: in case of heavy churn, it can happen that more than one DKG session completes
/// successfully. Some kind of disambiguation strategy needs to be employed in that case, but that
/// is currently not a responsibility of this module.
pub struct DkgVoter {
    participant: Option<Participant>,
    observers: LruCache<EldersInfo, Observer>,
}

impl Default for DkgVoter {
    fn default() -> Self {
        Self {
            participant: None,
            observers: LruCache::with_capacity(MAX_OBSERVERS),
        }
    }
}

impl DkgVoter {
    // Starts a new DKG session as a participant. The caller should broadcast the returned messages
    // to the other DKG participants.
    pub fn start_participating(
        &mut self,
        full_id: &FullId,
        elders_info: EldersInfo,
    ) -> Option<(DkgKey, DkgMessage<PublicId>)> {
        if let Some(current_elders_info) = self
            .participant
            .as_ref()
            .and_then(|session| session.elders_info.as_ref())
        {
            if *current_elders_info == elders_info {
                trace!("DKG for {} already in progress", elders_info);
                return None;
            }
        }

        let threshold = quorum_count(elders_info.elders.len()) - 1;
        let participants = elders_info
            .elders
            .values()
            .map(P2pNode::public_id)
            .copied()
            .collect();

        match KeyGen::initialize(full_id, threshold, participants) {
            Ok((key_gen, message)) => {
                trace!("DKG for {} starting", elders_info);

                let dkg_key = DkgKey::new(&elders_info);

                self.participant = Some(Participant {
                    dkg_key,
                    key_gen,
                    elders_info: Some(elders_info),
                    timer_token: 0,
                });

                Some((dkg_key, message))
            }
            Err(error) => {
                debug!("DKG for {} failed to start: {}", elders_info, error);

                None
            }
        }
    }

    // Start a new DKG session as an observer.
    pub fn start_observing(&mut self, elders_info: EldersInfo) {
        let _ = self
            .observers
            .entry(elders_info)
            .or_insert_with(Default::default);
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    //
    // Returns:
    // - `Some(Ok((elders_info, outcome)))` if the DKG successfully completed
    // - `Some(Err(elders_info))` if the DKG failed
    // - `None` if the DKG is still in progress or if there is no active DKG session.
    //
    // A returned `Some` should be sent to the DKG observers for accumulation.
    pub fn check_dkg(&mut self) -> DkgStatus<(EldersInfo, Outcome)> {
        let session = self.participant.as_mut()?;
        let _ = session.elders_info.as_ref()?;

        if !session.key_gen.is_finalized() {
            return None;
        }

        let (participants, outcome) = session.key_gen.generate_keys()?;

        // This is OK to `unwrap` because we already checked it is `Some`.
        let elders_info = session.elders_info.take().unwrap();

        if participants
            .iter()
            .eq(elders_info.elders.values().map(P2pNode::public_id))
        {
            trace!(
                "DKG for {} complete: {:?}",
                elders_info,
                outcome.public_key_set.public_key()
            );

            // Note: we keep `self.participant` set because other nodes might still need to receive
            // DKG messages from us for them to complete.

            Some(Ok((elders_info, outcome)))
        } else {
            trace!(
                "DKG for {} failed: unexpected participants: {:?}",
                elders_info,
                participants.iter().map(PublicId::name).format(", ")
            );

            self.participant = None;

            Some(Err(elders_info))
        }
    }

    // Make key generator progress with timed phase.
    //
    // Returns:
    // - `Some(Ok((dkg_key, messages)))` if the DKG is still in progress. The returned messages
    //   should be broadcast to the other participants.
    // - `Some(Err(elders_info))` if the DKG failed. The result should be sent to the DKG observers
    //   for accumulation.
    // - `None` if there is no active DKG session.
    pub fn progress_dkg(
        &mut self,
        rng: &mut MainRng,
    ) -> DkgStatus<(DkgKey, Vec<DkgMessage<PublicId>>)> {
        let session = self.participant.as_mut()?;
        let elders_info = session.elders_info.as_ref()?;

        trace!("DKG for {} progressing", elders_info);

        match session.key_gen.timed_phase_transition(rng) {
            Ok(messages) => Some(Ok((session.dkg_key, messages))),
            Err(error) => {
                trace!("DKG for {} failed: {}", elders_info, error);

                // This is OK to `unwrap` because we already checked it is `Some`.
                let elders_info = session.elders_info.take().unwrap();

                self.participant = None;

                Some(Err(elders_info))
            }
        }
    }

    /// Returns the participants of the DKG session, if there is one.
    pub fn participants(&self) -> impl Iterator<Item = &P2pNode> {
        self.participant
            .as_ref()
            .and_then(|session| session.elders_info.as_ref())
            .into_iter()
            .flat_map(|elders_info| elders_info.elders.values())
    }

    // Handle a received DkgMessage. Returns with DkgMessages to broadcast to the other
    // participants, if any.
    pub fn process_dkg_message(
        &mut self,
        rng: &mut MainRng,
        dkg_key: &DkgKey,
        message: DkgMessage<PublicId>,
    ) -> Vec<DkgMessage<PublicId>> {
        let session = if let Some(session) = &mut self.participant {
            session
        } else {
            return vec![];
        };

        if session.dkg_key != *dkg_key {
            return vec![];
        }

        session
            .key_gen
            .handle_message(rng, message)
            .unwrap_or_default()
    }

    // Observer and accumulate a DKG result (either success or failure).
    //
    // Returns:
    // - `Some(Result)` if the results accumulated
    // - `None` if more results are still needed
    pub fn observe_result(
        &mut self,
        elders_info: &EldersInfo,
        result: Result<bls::PublicKey, ()>,
        sender: PublicId,
    ) -> Option<Result<bls::PublicKey, ()>> {
        if !elders_info.elders.contains_key(sender.name()) {
            return None;
        }

        // Avoid updating the LRU list if the entry already exists.
        if self
            .observers
            .peek(elders_info)
            .and_then(|session| session.accumulator.get(&result))
            .map(|ids| ids.contains(&sender))
            .unwrap_or(false)
        {
            return None;
        }

        let session = self.observers.get_mut(elders_info)?;

        let _ = session
            .accumulator
            .entry(result)
            .or_default()
            .insert(sender);

        let total: usize = session.accumulator.values().map(|ids| ids.len()).sum();
        let missing = elders_info.elders.len() - total;
        let quorum = quorum_count(elders_info.elders.len());

        let output = if let Some((public_key, count)) = session
            .accumulator
            .iter()
            .filter_map(|(result, ids)| result.ok().map(|key| (key, ids.len())))
            .max_by_key(|(_, count)| *count)
        {
            // At least one successful result

            if count >= quorum {
                // Successful quorum reached
                Some(Ok(public_key))
            } else if count + missing >= quorum {
                // Successful quorum is still possible
                None
            } else {
                // Successful quorum is no longer possible
                Some(Err(()))
            }
        } else {
            // No successful results yet

            if missing >= quorum {
                // Successful quorum is still possible
                None
            } else {
                // Successful quorum is no longer possible
                Some(Err(()))
            }
        };

        if output.is_some() {
            let _ = self.observers.remove(elders_info);
        }

        output
    }

    // Returns the timer token of the active DKG session if there is one. If this timer fires, we
    // should call `progress_dkg`.
    pub fn timer_token(&self) -> Option<u64> {
        self.participant.as_ref().map(|session| session.timer_token)
    }

    // Sets the timer token for the active DKG session. This should be set after a successful DKG
    // initialization, or after handling a DKG message that produced at least one response.
    pub fn set_timer_token(&mut self, token: u64) {
        if let Some(session) = &mut self.participant {
            session.timer_token = token;
        }
    }
}

// Data for a DKG participant.
struct Participant {
    // `None` means the session is completed.
    elders_info: Option<EldersInfo>,
    dkg_key: DkgKey,
    key_gen: KeyGen<FullId>,
    timer_token: u64,
}

// Data for a DKG observer.
#[derive(Default)]
struct Observer {
    accumulator: HashMap<Result<bls::PublicKey, ()>, HashSet<PublicId>>,
}

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
use bls_dkg::key_gen::{outcome::Outcome, KeyGen};
use hex_fmt::HexFmt;
use itertools::Itertools;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Debug, Formatter},
};

pub type DkgMessage = bls_dkg::key_gen::message::Message<PublicId>;

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
        use tiny_keccak::{Hasher, Sha3};

        // Calculate the hash without involving serialization to avoid having to return `Result`.
        let mut hasher = Sha3::v256();

        for name in elders_info.elders.keys() {
            hasher.update(&name.0);
        }

        hasher.update(&elders_info.prefix.name().0);
        hasher.update(&elders_info.prefix.bit_count().to_le_bytes());

        let mut output = Digest256::default();
        hasher.finalize(&mut output);

        Self(output)
    }
}

impl Debug for DkgKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DkgKey({:10})", HexFmt(&self.0))
    }
}

/// DKG voter carries out the work of participating and/or observing a DKG.
///
/// # Usage
///
/// 1. First the current elders propose the new elder candidates in the form of `EldersInfo`
///    structure.
/// 2. They send an accumulating message `DKGStart` containing this proposed `EldersInfo` to the
///    new elders candidates (DKG participants) and also call `start_observing` to initialize the
///    DKG result accumulator.
/// 3. When the `DKGStart` message accumulates, the participants call `start_participating`.
/// 4. The participants keep exchanging the DKG messages and calling `process_dkg_message`.
/// 5. The participants call `check_dkg` to check whether the DKG session completed or failed.
/// 6. They should also run a timer in case of inactivity and call `progress_dkg` when it fires.
/// 7. On DKG completion or failure, the participants send `DKGResult` message to the current
///    elders (observers)
/// 8. The observers call `observe_result` with each received `DKGResult`.
/// 9. When it returns success, that means we accumulated at least quorum of successful DKG results
///    and can proceed with voting for the section update.
/// 10. When it fails, the observers restart the process from step 1.
///
/// Note: in case of heavy churn, it can happen that more than one DKG session completes
/// successfully. Some kind of disambiguation strategy needs to be employed in that case, but that
/// is currently not a responsibility of this module.
pub struct DkgVoter {
    participant: Option<Participant>,
    observers: HashMap<DkgKey, Observer>,
}

impl Default for DkgVoter {
    fn default() -> Self {
        Self {
            participant: None,
            observers: HashMap::new(),
        }
    }
}

impl DkgVoter {
    // Starts a new DKG session as a participant. The caller should broadcast the returned messages
    // to the other DKG participants.
    pub fn start_participating(
        &mut self,
        full_id: &FullId,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
    ) -> Option<DkgMessage> {
        if let Some(session) = &self.participant {
            if session.dkg_key == dkg_key && session.elders_info.is_some() {
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

                self.participant = Some(Participant {
                    dkg_key,
                    key_gen,
                    elders_info: Some(elders_info),
                    // TODO: review if we still need this
                    //timer_token: 0,
                });

                Some(message)
            }
            Err(error) => {
                debug!("DKG for {} failed to start: {}", elders_info, error);

                None
            }
        }
    }

    // Start a new DKG session as an observer.
    pub fn start_observing(
        &mut self,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
        section_key_index: u64,
    ) {
        trace!("DKG for {} observing", elders_info);

        let _ = self.observers.entry(dkg_key).or_insert_with(|| Observer {
            elders_info,
            section_key_index,
            accumulator: Default::default(),
        });
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    //
    // Returns:
    // - `Some(Ok((elders_info, outcome)))` if the DKG successfully completed
    // - `Some(Err(elders_info))` if the DKG failed
    // - `None` if the DKG is still in progress or if there is no active DKG session.
    //
    // A returned `Some` should be sent to the DKG observers for accumulation.
    pub fn check_dkg(&mut self) -> Option<Result<(EldersInfo, Outcome), ()>> {
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

            Some(Err(()))
        }
    }

    // Make key generator progress with timed phase.
    //
    // Returns:
    // - `Some((dkg_key, Ok(messages)))` if the DKG is still in progress. The returned messages
    //   should be broadcast to the other participants.
    // - `Some((dkg_key, Err(())))` if the DKG failed. The result should be sent to the DKG observers
    //   for accumulation.
    // - `None` if there is no active DKG session.
    // TODO: review if we still need this function
    /*
    pub fn progress_dkg(
        &mut self,
        rng: &mut MainRng,
    ) -> Option<(DkgKey, Result<Vec<DkgMessage>, ()>)> {
        let session = self.participant.as_mut()?;
        let elders_info = session.elders_info.as_ref()?;

        trace!("DKG for {} progressing", elders_info);

        match session.key_gen.timed_phase_transition(rng) {
            Ok(messages) => Some((session.dkg_key, Ok(messages))),
            Err(error) => {
                trace!("DKG for {} failed: {}", elders_info, error);

                let dkg_key = session.dkg_key;
                self.participant = None;

                Some((dkg_key, Err(())))
            }
        }
    }
    */

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
        message: DkgMessage,
    ) -> Vec<DkgMessage> {
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
    // - `Some((EldersInfo, Result))` if the results accumulated
    // - `None` if more results are still needed
    pub fn observe_result(
        &mut self,
        dkg_key: &DkgKey,
        result: Result<bls::PublicKey, ()>,
        sender: PublicId,
    ) -> Option<(EldersInfo, Result<bls::PublicKey, ()>)> {
        let session = self.observers.get_mut(dkg_key)?;

        if !session.elders_info.elders.contains_key(sender.name()) {
            return None;
        }

        if !session
            .accumulator
            .entry(result)
            .or_default()
            .insert(sender)
        {
            return None;
        }

        let total: usize = session.accumulator.values().map(|ids| ids.len()).sum();
        let missing = session.elders_info.elders.len() - total;
        let quorum = quorum_count(session.elders_info.elders.len());

        let result = if let Some((public_key, count)) = session
            .accumulator
            .iter()
            .filter_map(|(result, ids)| result.ok().map(|key| (key, ids.len())))
            .max_by_key(|(_, count)| *count)
        {
            // At least one successful result

            if count >= quorum {
                // Successful quorum reached
                Ok(public_key)
            } else if count + missing >= quorum {
                // Successful quorum is still possible
                return None;
            } else {
                // Successful quorum is no longer possible
                Err(())
            }
        } else {
            // No successful results yet

            if missing >= quorum {
                // Successful quorum is still possible
                return None;
            } else {
                // Successful quorum is no longer possible
                Err(())
            }
        };

        let elders_info = if result.is_ok() {
            // On success, remove the sesssion because we don't need it anymore.
            self.observers.remove(dkg_key).unwrap().elders_info
        } else {
            // On failure, only clear the accumulator to allow new votes from restarted DKG
            session.accumulator.clear();
            session.elders_info.clone()
        };

        Some((elders_info, result))
    }

    pub fn stop_observing(&mut self, section_key_index: u64) {
        self.observers
            .retain(|_, session| session.section_key_index >= section_key_index);
    }

    // Returns the timer token of the active DKG session if there is one. If this timer fires, we
    // should call `progress_dkg`.
    // TODO: review if we still need this function
    /*
    pub fn timer_token(&self) -> Option<u64> {
        self.participant.as_ref().map(|session| session.timer_token)
    }
    */

    // Sets the timer token for the active DKG session. This should be set after a successful DKG
    // initialization, or after handling a DKG message that produced at least one response.
    // TODO: review if we still need this function
    /*
    pub fn set_timer_token(&mut self, token: u64) {
        if let Some(session) = &mut self.participant {
            session.timer_token = token;
        }
    }
    */
}

// Data for a DKG participant.
struct Participant {
    // `None` means the session is completed.
    elders_info: Option<EldersInfo>,
    dkg_key: DkgKey,
    key_gen: KeyGen<FullId>,
    // TODO: review if we still need this
    //timer_token: u64,
}

// Data for a DKG observer.
#[derive(Default)]
struct Observer {
    elders_info: EldersInfo,
    section_key_index: u64,
    accumulator: HashMap<Result<bls::PublicKey, ()>, HashSet<PublicId>>,
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::Digest256,
    error::Result,
    majority,
    messages::Message,
    messages::Variant,
    node::Node,
    peer::Peer,
    routing::command::{self, Command},
    section::EldersInfo,
    DstLocation,
};
use bls_dkg::key_gen::{message::Message as DkgMessage, KeyGen};
use hex_fmt::HexFmt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Debug, Formatter},
    time::Duration,
};
use xor_name::XorName;

// Interval to progress DKG timed phase
const DKG_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

/// Unique identified of a DKG session.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DkgKey(Digest256);

impl DkgKey {
    pub fn new(elders_info: &EldersInfo) -> Self {
        use tiny_keccak::{Hasher, Sha3};

        // Calculate the hash without involving serialization to avoid having to return `Result`.
        let mut hasher = Sha3::v256();

        for peer in elders_info.elders.values() {
            hasher.update(&peer.name().0);
            hasher.update(&[peer.age()]);
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
/// 4. The participants keep exchanging the DKG messages and calling `process_message`.
/// 7. On DKG completion or failure, the participants send `DKGResult` message to the current
///    elders (observers)
/// 8. The observers call `observe_result` with each received `DKGResult`.
/// 9. When it returns success, that means we accumulated majority of successful DKG results
///    and can proceed with voting for the section update.
/// 10. When it fails, the observers restart the process from step 1.
///
/// Note: in case of heavy churn, it can happen that more than one DKG session completes
/// successfully. Some kind of disambiguation strategy needs to be employed in that case, but that
/// is currently not a responsibility of this module.
pub(crate) struct DkgVoter {
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
    // Starts a new DKG session as a participant.
    pub fn start_participating(
        &mut self,
        node: &Node,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
    ) -> Result<Vec<Command>> {
        if let Some(session) = &self.participant {
            if session.dkg_key == dkg_key && session.elders_info.is_some() {
                trace!("DKG for {} already in progress", elders_info);
                return Ok(vec![]);
            }
        }

        let threshold = majority(elders_info.elders.len()) - 1;
        let participants = elders_info
            .elders
            .values()
            .map(Peer::name)
            .copied()
            .collect();

        match KeyGen::initialize(node.name(), threshold, participants) {
            Ok((key_gen, message)) => {
                trace!("DKG for {} starting", elders_info);

                let mut session = Participant {
                    dkg_key,
                    key_gen,
                    elders_info: Some(elders_info),
                    timer_token: 0,
                };

                let mut commands = session.broadcast(node, dkg_key, message)?;

                if let Some(command) = session.check() {
                    // Already completed.
                    commands.push(command)
                } else {
                    commands.push(session.reset_timer());
                    self.participant = Some(session);
                }

                Ok(commands)
            }
            Err(error) => {
                // TODO: return error here
                error!("DKG for {} failed to start: {}", elders_info, error);
                Ok(vec![])
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

    // Make key generator progress with timed phase.
    pub fn handle_timeout(&mut self, node: &Node, timer_token: u64) -> Result<Vec<Command>> {
        let session = if let Some(session) = self.participant.as_mut() {
            session
        } else {
            return Ok(vec![]);
        };

        if session.timer_token != timer_token {
            return Ok(vec![]);
        }

        let elders_info = if let Some(elders_info) = session.elders_info.as_ref() {
            elders_info
        } else {
            return Ok(vec![]);
        };

        let dkg_key = session.dkg_key;

        trace!("DKG for {} progressing", elders_info);

        match session
            .key_gen
            .timed_phase_transition(&mut rand::thread_rng())
        {
            Ok(messages) => {
                let mut commands = vec![];

                for message in messages {
                    commands.extend(session.broadcast(node, dkg_key, message)?);
                }
                commands.push(session.reset_timer());
                commands.extend(self.check());

                Ok(commands)
            }
            Err(error) => {
                trace!("DKG for {} failed: {}", elders_info, error);

                let elders_info = session.elders_info.take().unwrap();

                self.participant = None;

                Ok(vec![Command::HandleDkgParticipationResult {
                    dkg_key,
                    elders_info,
                    result: Err(()),
                }])
            }
        }
    }

    // Handle a received DkgMessage.
    pub fn process_message(
        &mut self,
        node: &Node,
        dkg_key: DkgKey,
        message: DkgMessage,
    ) -> Result<Vec<Command>> {
        let session = if let Some(session) = &mut self.participant {
            session
        } else {
            return Ok(vec![]);
        };

        let mut commands = session.process_message(node, dkg_key, message)?;

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        if !commands.is_empty() {
            commands.push(session.reset_timer());
        }

        commands.extend(self.check());

        Ok(commands)
    }

    // Observe and accumulate a DKG result (either success or failure).
    pub fn observe_result(
        &mut self,
        dkg_key: &DkgKey,
        result: Result<bls::PublicKey, ()>,
        sender: XorName,
    ) -> Option<Command> {
        let session = self.observers.get_mut(dkg_key)?;

        if !session.elders_info.elders.contains_key(&sender) {
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
        let majority = majority(session.elders_info.elders.len());

        let result = if let Some((public_key, count)) = session
            .accumulator
            .iter()
            .filter_map(|(result, ids)| result.ok().map(|key| (key, ids.len())))
            .max_by_key(|(_, count)| *count)
        {
            // At least one successful result

            if count >= majority {
                // Successful majority reached
                Ok(public_key)
            } else if count + missing >= majority {
                // Successful majority is still possible
                return None;
            } else {
                // Successful majority is no longer possible
                Err(())
            }
        } else {
            // No successful results yet

            if missing >= majority {
                // Successful majority is still possible
                return None;
            } else {
                // Successful majority is no longer possible
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

        Some(Command::HandleDkgObservationResult {
            elders_info,
            result,
        })
    }

    pub fn stop_observing(&mut self, section_key_index: u64) {
        self.observers
            .retain(|_, session| session.section_key_index >= section_key_index);
    }

    // Is this node participating in any DKG session?
    pub fn is_participating(&self) -> bool {
        self.participant.is_some()
    }

    pub fn observing_elders_info(&self, dkg_key: &DkgKey) -> Option<&EldersInfo> {
        self.observers
            .get(dkg_key)
            .map(|session| &session.elders_info)
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    fn check(&mut self) -> Option<Command> {
        let session = self.participant.as_mut()?;
        let command = session.check()?;

        // NOTE: Only reset `self.participant` on failed completion, because on success other nodes
        // might still need to receive DKG messages from us.
        if matches!(command, Command::HandleDkgParticipationResult { result: Err(()), .. }) {
            self.participant = None
        }

        Some(command)
    }
}

// Data for a DKG participant.
struct Participant {
    // `None` means the session is completed.
    elders_info: Option<EldersInfo>,
    dkg_key: DkgKey,
    key_gen: KeyGen,
    timer_token: u64,
}

impl Participant {
    fn process_message(
        &mut self,
        node: &Node,
        dkg_key: DkgKey,
        message: DkgMessage,
    ) -> Result<Vec<Command>> {
        if self.dkg_key != dkg_key {
            return Ok(vec![]);
        }

        let responses = self
            .key_gen
            .handle_message(&mut rand::thread_rng(), message)
            .unwrap_or_default();

        let mut commands = vec![];
        for response in responses {
            commands.extend(self.broadcast(node, dkg_key, response)?);
        }

        Ok(commands)
    }

    fn broadcast(
        &mut self,
        node: &Node,
        dkg_key: DkgKey,
        dkg_message: DkgMessage,
    ) -> Result<Vec<Command>> {
        let recipients: Vec<_> = self
            .elders_info
            .as_ref()
            .into_iter()
            .flat_map(EldersInfo::peers)
            .filter(|peer| *peer.name() != node.name())
            .map(Peer::addr)
            .copied()
            .collect();

        trace!(
            "broadcasting DKG message {:?} to {:?}",
            dkg_message,
            recipients
        );

        let variant = Variant::DKGMessage {
            dkg_key,
            message: bincode::serialize(&dkg_message)?.into(),
        };
        let message = Message::single_src(node, DstLocation::Direct, variant, None, None)?;

        let mut commands = vec![];
        commands.push(Command::send_message_to_targets(
            &recipients,
            recipients.len(),
            message.to_bytes(),
        ));
        commands.extend(self.process_message(node, dkg_key, dkg_message)?);

        Ok(commands)
    }

    fn check(&mut self) -> Option<Command> {
        let _ = self.elders_info.as_ref()?;

        if !self.key_gen.is_finalized() {
            return None;
        }

        let (participants, outcome) = self.key_gen.generate_keys()?;

        // This is OK to `unwrap` because we already checked it is `Some`.
        let elders_info = self.elders_info.take().unwrap();

        if participants.iter().eq(elders_info.elders.keys()) {
            trace!(
                "DKG for {} complete: {:?}",
                elders_info,
                outcome.public_key_set.public_key()
            );

            Some(Command::HandleDkgParticipationResult {
                dkg_key: self.dkg_key,
                elders_info,
                result: Ok(outcome),
            })
        } else {
            trace!(
                "DKG for {} failed: unexpected participants: {:?}",
                elders_info,
                participants.iter().format(", ")
            );

            Some(Command::HandleDkgParticipationResult {
                dkg_key: self.dkg_key,
                elders_info,
                result: Err(()),
            })
        }
    }

    fn reset_timer(&mut self) -> Command {
        self.timer_token = command::next_timer_token();
        Command::ScheduleTimeout {
            duration: DKG_PROGRESS_INTERVAL,
            token: self.timer_token,
        }
    }
}

// Data for a DKG observer.
#[derive(Default)]
struct Observer {
    elders_info: EldersInfo,
    section_key_index: u64,
    accumulator: HashMap<Result<bls::PublicKey, ()>, HashSet<XorName>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{section::test_utils::gen_addr, MIN_AGE};
    use std::iter;
    use xor_name::Prefix;

    #[test]
    fn dkg_key_is_affected_by_ages() {
        let name = rand::random();
        let addr = gen_addr();

        let peer0 = Peer::new(name, addr, MIN_AGE);
        let peer1 = Peer::new(name, addr, MIN_AGE + 1);

        let elders_info0 = EldersInfo::new(iter::once(peer0), Prefix::default());
        let elders_info1 = EldersInfo::new(iter::once(peer1), Prefix::default());

        let key0 = DkgKey::new(&elders_info0);
        let key1 = DkgKey::new(&elders_info1);

        assert_ne!(key0, key1);
    }
}

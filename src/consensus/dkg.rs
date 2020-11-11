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
    messages::{Message, Variant},
    node::Node,
    peer::Peer,
    routing::command::{self, Command},
    section::EldersInfo,
    DstLocation,
};
use bls_dkg::key_gen::{message::Message as DkgMessage, outcome::Outcome as DkgOutcome, KeyGen};
use hex_fmt::HexFmt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    time::Duration,
};
use xor_name::XorName;

// Interval to progress DKG timed phase
const DKG_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

const BACKLOG_CAPACITY: usize = 100;

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

    // Due to the asyncronous nature of the network we might sometimes receive a DKG message before
    // we created the corresponding `Participant` session. To avoid losing those messages, we store
    // them in this backlog and replay them once we create the session.
    backlog: Backlog,
}

impl Default for DkgVoter {
    fn default() -> Self {
        Self {
            participant: None,
            observers: HashMap::new(),
            backlog: Backlog::new(),
        }
    }
}

impl DkgVoter {
    // Starts a new DKG session as a participant.
    pub fn start_participating(
        &mut self,
        our_name: XorName,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
    ) -> Vec<DkgCommand> {
        if let Some(session) = &self.participant {
            if session.dkg_key == dkg_key && session.elders_info.is_some() {
                trace!("DKG for {} already in progress", elders_info);
                return vec![];
            }
        }

        // Special case: only one participant.
        if elders_info.elders.len() == 1 {
            let secret_key_set = bls::SecretKeySet::random(0, &mut rand::thread_rng());

            return vec![DkgCommand::HandleParticipationResult {
                dkg_key,
                elders_info,
                result: Ok(DkgOutcome {
                    public_key_set: secret_key_set.public_keys(),
                    secret_key_share: secret_key_set.secret_key_share(0),
                }),
            }];
        }

        let threshold = majority(elders_info.elders.len()) - 1;
        let participants = elders_info
            .elders
            .values()
            .map(Peer::name)
            .copied()
            .collect();

        match KeyGen::initialize(our_name, threshold, participants) {
            Ok((key_gen, message)) => {
                trace!("DKG for {} starting", elders_info);

                let mut session = Participant {
                    dkg_key,
                    key_gen,
                    elders_info: Some(elders_info),
                    timer_token: 0,
                };

                let mut commands = session.broadcast(&our_name, dkg_key, message);

                commands.extend(
                    self.backlog
                        .take(&dkg_key)
                        .into_iter()
                        .flat_map(|message| session.process_message(&our_name, dkg_key, message)),
                );

                if let Some(command) = session.check() {
                    // Already completed.
                    commands.push(command)
                } else {
                    commands.push(session.reset_timer());
                    self.participant = Some(session);
                }

                commands
            }
            Err(error) => {
                // TODO: return error here
                error!("DKG for {} failed to start: {}", elders_info, error);
                vec![]
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
    pub fn handle_timeout(&mut self, our_name: &XorName, timer_token: u64) -> Vec<DkgCommand> {
        let session = if let Some(session) = self.participant.as_mut() {
            session
        } else {
            return vec![];
        };

        if session.timer_token != timer_token {
            return vec![];
        }

        let elders_info = if let Some(elders_info) = session.elders_info.as_ref() {
            elders_info
        } else {
            return vec![];
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
                    commands.extend(session.broadcast(our_name, dkg_key, message));
                }
                commands.push(session.reset_timer());
                commands.extend(self.check());
                commands
            }
            Err(error) => {
                trace!("DKG for {} failed: {}", elders_info, error);

                let elders_info = session.elders_info.take().unwrap();

                self.participant = None;

                vec![DkgCommand::HandleParticipationResult {
                    dkg_key,
                    elders_info,
                    result: Err(()),
                }]
            }
        }
    }

    // Handle a received DkgMessage.
    pub fn process_message(
        &mut self,
        our_name: &XorName,
        dkg_key: DkgKey,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        let session = if let Some(session) = self
            .participant
            .as_mut()
            .filter(|session| session.dkg_key == dkg_key)
        {
            session
        } else {
            self.backlog.push(dkg_key, message);
            return vec![];
        };

        let mut commands = session.process_message(our_name, dkg_key, message);

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        if !commands.is_empty() {
            commands.push(session.reset_timer());
        }

        commands.extend(self.check());
        commands
    }

    // Observe and accumulate a DKG result (either success or failure).
    pub fn observe_result(
        &mut self,
        dkg_key: &DkgKey,
        result: Result<bls::PublicKey, ()>,
        sender: XorName,
    ) -> Option<DkgCommand> {
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
            self.observers.remove(dkg_key)?.elders_info
        } else {
            // On failure, only clear the accumulator to allow new votes from restarted DKG
            session.accumulator.clear();
            session.elders_info.clone()
        };

        Some(DkgCommand::HandleObservationResult {
            elders_info,
            result,
        })
    }

    pub fn stop_observing(&mut self, section_key_index: u64) {
        self.observers
            .retain(|_, session| session.section_key_index >= section_key_index);
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    fn check(&mut self) -> Option<DkgCommand> {
        let session = self.participant.as_mut()?;
        let command = session.check()?;

        // NOTE: Only reset `self.participant` on failed completion, because on success other nodes
        // might still need to receive DKG messages from us.
        if matches!(command, DkgCommand::HandleParticipationResult { result: Err(()), .. }) {
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
        our_name: &XorName,
        dkg_key: DkgKey,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        trace!("process DKG message {:?}", message);
        let responses = self
            .key_gen
            .handle_message(&mut rand::thread_rng(), message)
            .unwrap_or_default();

        responses
            .into_iter()
            .flat_map(|response| self.broadcast(our_name, dkg_key, response))
            .collect()
    }

    fn broadcast(
        &mut self,
        our_name: &XorName,
        dkg_key: DkgKey,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        let mut commands = vec![];

        let recipients: Vec<_> = self
            .elders_info
            .as_ref()
            .into_iter()
            .flat_map(EldersInfo::peers)
            .filter(|peer| peer.name() != our_name)
            .map(Peer::addr)
            .copied()
            .collect();

        if !recipients.is_empty() {
            trace!("broadcasting DKG message {:?} to {:?}", message, recipients);
            commands.push(DkgCommand::SendMessage {
                recipients,
                dkg_key,
                message: message.clone(),
            });
        }

        commands.extend(self.process_message(our_name, dkg_key, message));
        commands
    }

    fn check(&mut self) -> Option<DkgCommand> {
        if !self.key_gen.is_finalized() {
            return None;
        }

        let (participants, outcome) = self.key_gen.generate_keys()?;
        let elders_info = self.elders_info.take()?;

        if participants.iter().eq(elders_info.elders.keys()) {
            trace!(
                "DKG for {} complete: {:?}",
                elders_info,
                outcome.public_key_set.public_key()
            );

            Some(DkgCommand::HandleParticipationResult {
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

            Some(DkgCommand::HandleParticipationResult {
                dkg_key: self.dkg_key,
                elders_info,
                result: Err(()),
            })
        }
    }

    fn reset_timer(&mut self) -> DkgCommand {
        self.timer_token = command::next_timer_token();
        DkgCommand::ScheduleTimeout {
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

struct Backlog(VecDeque<(DkgKey, DkgMessage)>);

impl Backlog {
    fn new() -> Self {
        Self(VecDeque::with_capacity(BACKLOG_CAPACITY))
    }

    fn push(&mut self, dkg_key: DkgKey, message: DkgMessage) {
        if self.0.len() == self.0.capacity() {
            let _ = self.0.pop_front();
        }

        self.0.push_back((dkg_key, message))
    }

    fn take(&mut self, dkg_key: &DkgKey) -> Vec<DkgMessage> {
        let mut output = Vec::new();
        let max = self.0.len();

        for _ in 0..max {
            if let Some((message_dkg_key, message)) = self.0.pop_front() {
                if &message_dkg_key == dkg_key {
                    output.push(message)
                } else {
                    self.0.push_back((message_dkg_key, message))
                }
            }
        }

        output
    }
}

#[derive(Debug)]
pub(crate) enum DkgCommand {
    SendMessage {
        recipients: Vec<SocketAddr>,
        dkg_key: DkgKey,
        message: DkgMessage,
    },
    ScheduleTimeout {
        duration: Duration,
        token: u64,
    },
    HandleParticipationResult {
        dkg_key: DkgKey,
        elders_info: EldersInfo,
        result: Result<DkgOutcome, ()>,
    },
    HandleObservationResult {
        elders_info: EldersInfo,
        result: Result<bls::PublicKey, ()>,
    },
}

impl DkgCommand {
    fn into_command(self, node: &Node) -> Result<Command> {
        match self {
            Self::SendMessage {
                recipients,
                dkg_key,
                message,
            } => {
                let variant = Variant::DKGMessage {
                    dkg_key,
                    message: bincode::serialize(&message)?.into(),
                };
                let message = Message::single_src(node, DstLocation::Direct, variant, None, None)?;

                Ok(Command::send_message_to_targets(
                    &recipients,
                    recipients.len(),
                    message.to_bytes(),
                ))
            }
            Self::ScheduleTimeout { duration, token } => {
                Ok(Command::ScheduleTimeout { duration, token })
            }
            Self::HandleParticipationResult {
                dkg_key,
                elders_info,
                result,
            } => Ok(Command::HandleDkgParticipationResult {
                dkg_key,
                elders_info,
                result,
            }),
            Self::HandleObservationResult {
                elders_info,
                result,
            } => Ok(Command::HandleDkgObservationResult {
                elders_info,
                result,
            }),
        }
    }
}

pub(crate) trait DkgCommands {
    fn into_commands(self, node: &Node) -> Result<Vec<Command>>;
}

impl DkgCommands for Vec<DkgCommand> {
    fn into_commands(self, node: &Node) -> Result<Vec<Command>> {
        self.into_iter()
            .map(|command| command.into_command(node))
            .collect()
    }
}

impl DkgCommands for Option<DkgCommand> {
    fn into_commands(self, node: &Node) -> Result<Vec<Command>> {
        self.into_iter()
            .map(|command| command.into_command(node))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        peer::test_utils::arbitrary_unique_peers,
        section::test_utils::{gen_addr, gen_elders_info},
        ELDER_SIZE, MIN_AGE,
    };
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rand::{rngs::SmallRng, SeedableRng};
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

    #[test]
    fn accumulate_results() {
        let mut voter = DkgVoter::default();

        let (elders_info, nodes) = gen_elders_info(Prefix::default(), ELDER_SIZE);
        let dkg_key = DkgKey::new(&elders_info);
        let majority = majority(elders_info.elders.len());

        voter.start_observing(dkg_key, elders_info, 0);

        let pk = bls::SecretKey::random().public_key();

        for sender in &nodes[..majority - 1] {
            assert!(voter
                .observe_result(&dkg_key, Ok(pk), sender.name())
                .is_none());
        }

        assert!(voter
            .observe_result(&dkg_key, Ok(pk), nodes[majority - 1].name())
            .is_some());
    }

    #[test]
    fn result_is_ignored_if_observation_not_started() {
        let mut voter = DkgVoter::default();

        let (elders_info, _) = gen_elders_info(Prefix::default(), ELDER_SIZE);
        let dkg_key = DkgKey::new(&elders_info);
        let pk = bls::SecretKey::random().public_key();

        for sender in elders_info.elders.keys() {
            assert!(voter.observe_result(&dkg_key, Ok(pk), *sender).is_none());
        }
    }

    #[test]
    fn result_is_ignored_if_not_from_participant() {
        let mut voter = DkgVoter::default();

        let (elders_info, nodes) = gen_elders_info(Prefix::default(), ELDER_SIZE);
        let dkg_key = DkgKey::new(&elders_info);
        let majority = majority(elders_info.elders.len());

        voter.start_observing(dkg_key, elders_info, 0);

        let pk = bls::SecretKey::random().public_key();

        for sender in &nodes[..majority - 1] {
            assert!(voter
                .observe_result(&dkg_key, Ok(pk), sender.name())
                .is_none());
        }

        let invalid_peer: XorName = rand::random();
        assert!(voter
            .observe_result(&dkg_key, Ok(pk), invalid_peer)
            .is_none());
    }

    #[test]
    fn unequal_results_do_not_accumulate() {
        let mut voter = DkgVoter::default();

        let (elders_info, nodes) = gen_elders_info(Prefix::default(), ELDER_SIZE);
        let dkg_key = DkgKey::new(&elders_info);
        let majority = majority(elders_info.elders.len());

        voter.start_observing(dkg_key, elders_info, 0);

        let pk0 = bls::SecretKey::random().public_key();
        let pk1 = bls::SecretKey::random().public_key();

        for sender in &nodes[..majority - 1] {
            assert!(voter
                .observe_result(&dkg_key, Ok(pk0), sender.name())
                .is_none());
        }

        assert!(voter
            .observe_result(&dkg_key, Ok(pk1), nodes[majority - 1].name())
            .is_none());
    }

    #[test]
    fn single_participant() {
        // If there is only one participant, the DKG should complete immediately.

        let mut voter = DkgVoter::default();

        let peer = Peer::new(rand::random(), gen_addr(), MIN_AGE);
        let elders_info = EldersInfo::new(iter::once(peer), Prefix::default());
        let dkg_key = DkgKey::new(&elders_info);

        let commands = voter.start_participating(*peer.name(), dkg_key, elders_info);
        assert_matches!(
            &commands[..],
            &[DkgCommand::HandleParticipationResult { result: Ok(_), .. }]
        );
    }

    proptest! {
        // Run a DKG session where every participant handles every message sent to them.
        // Expect the session to successfully complete without timed transitions.
        // NOTE: `seed` is for seeding the rng that randomizes the message order.
        #[test]
        fn proptest_full_participation(peers in arbitrary_elder_peers(), seed in any::<u64>()) {
            proptest_full_participation_impl(peers, seed)
        }
    }

    fn proptest_full_participation_impl(peers: Vec<Peer>, seed: u64) {
        // Rng used to randomize the message order.
        let mut rng = SmallRng::seed_from_u64(seed);
        let mut messages = Vec::new();

        let mut actors: HashMap<_, _> = peers
            .iter()
            .map(|peer| (*peer.addr(), Actor::new(*peer.name())))
            .collect();

        let elders_info = EldersInfo::new(peers, Prefix::default());
        let dkg_key = DkgKey::new(&elders_info);

        for actor in actors.values_mut() {
            let commands =
                actor
                    .voter
                    .start_participating(actor.name, dkg_key, elders_info.clone());

            for command in commands {
                messages.extend(actor.handle(command, &dkg_key))
            }
        }

        loop {
            match actors
                .values()
                .filter_map(|actor| actor.outcome.as_ref())
                .unique()
                .count()
            {
                0 => {}
                1 => return,
                _ => panic!("inconsistent DKG outcomes"),
            }

            // NOTE: this panics if `messages` is empty, but that's OK because it would mean
            // failure anyway.
            let index = rng.gen_range(0, messages.len());
            let (addr, message) = messages.swap_remove(index);

            let actor = actors.get_mut(&addr).expect("unknown message recipient");
            let commands = actor.voter.process_message(&actor.name, dkg_key, message);

            for command in commands {
                messages.extend(actor.handle(command, &dkg_key))
            }
        }
    }

    struct Actor {
        name: XorName,
        voter: DkgVoter,
        outcome: Option<bls::PublicKey>,
    }

    impl Actor {
        fn new(name: XorName) -> Self {
            Self {
                name,
                voter: DkgVoter::default(),
                outcome: None,
            }
        }

        fn handle(
            &mut self,
            command: DkgCommand,
            expected_dkg_key: &DkgKey,
        ) -> Vec<(SocketAddr, DkgMessage)> {
            match command {
                DkgCommand::SendMessage {
                    recipients,
                    dkg_key,
                    message,
                    ..
                } => {
                    assert_eq!(dkg_key, *expected_dkg_key);
                    recipients
                        .into_iter()
                        .map(|addr| (addr, message.clone()))
                        .collect()
                }
                DkgCommand::HandleParticipationResult {
                    result: Ok(outcome),
                    ..
                } => {
                    self.outcome = Some(outcome.public_key_set.public_key());
                    vec![]
                }
                DkgCommand::HandleParticipationResult {
                    result: Err(()), ..
                } => panic!("DKG failed"),
                DkgCommand::HandleObservationResult { .. } | DkgCommand::ScheduleTimeout { .. } => {
                    vec![]
                }
            }
        }
    }

    fn arbitrary_elder_peers() -> impl Strategy<Value = Vec<Peer>> {
        arbitrary_unique_peers(2..=ELDER_SIZE, MIN_AGE..)
    }
}

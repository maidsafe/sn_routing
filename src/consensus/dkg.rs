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
    section::{EldersInfo, SectionKeyShare},
    DstLocation,
};
use bls_dkg::key_gen::{message::Message as DkgMessage, KeyGen};
use hex_fmt::HexFmt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
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
        let mut output = Digest256::default();

        for peer in elders_info.elders.values() {
            hasher.update(&peer.name().0);
            hasher.update(&[peer.age()]);
        }

        hasher.update(&elders_info.prefix.name().0);
        hasher.update(&elders_info.prefix.bit_count().to_le_bytes());
        hasher.finalize(&mut output);

        Self(output)
    }

    pub fn retry(&self) -> Self {
        use tiny_keccak::{Hasher, Sha3};

        let mut hasher = Sha3::v256();
        let mut output = Digest256::default();

        hasher.update(&self.0);
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
///    new elders candidates (DKG participants).
/// 3. When the `DKGStart` message accumulates, the participants call `start`.
/// 4. The participants keep exchanging the DKG messages and calling `process_message`.
/// 5. On DKG completion, the participants send `DKGResult` vote to the current elders (observers)
/// 6. When the observers accumulate the votesm the can proceed with voting for the section update.
///
/// Note: in case of heavy churn, it can happen that more than one DKG session completes
/// successfully. Some kind of disambiguation strategy needs to be employed in that case, but that
/// is currently not a responsibility of this module.
pub(crate) struct DkgVoter {
    session: Option<Session>,

    // Due to the asyncronous nature of the network we might sometimes receive a DKG message before
    // we created the corresponding session. To avoid losing those messages, we store them in this
    // backlog and replay them once we create the session.
    backlog: Backlog,
}

impl Default for DkgVoter {
    fn default() -> Self {
        Self {
            session: None,
            backlog: Backlog::new(),
        }
    }
}

impl DkgVoter {
    // Starts a new DKG session.
    pub fn start(
        &mut self,
        our_name: XorName,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
    ) -> Vec<DkgCommand> {
        if let Some(session) = &self.session {
            if session.dkg_key == dkg_key && session.elders_info.is_some() {
                trace!("DKG for {} already in progress", elders_info);
                return vec![];
            }
        }

        let index = if let Some(index) = elders_info.position(&our_name) {
            index
        } else {
            error!(
                "DKG for {} failed to start: {} is not a participant",
                elders_info, our_name
            );
            return vec![];
        };

        // Special case: only one participant.
        if elders_info.elders.len() == 1 {
            let secret_key_set = bls::SecretKeySet::random(0, &mut rand::thread_rng());

            return vec![DkgCommand::HandleOutcome {
                elders_info,
                outcome: SectionKeyShare {
                    public_key_set: secret_key_set.public_keys(),
                    index,
                    secret_key_share: secret_key_set.secret_key_share(0),
                },
            }];
        }

        // Keep trying to initialize until we succeed. This should always terminate in a finite
        // number of iterations (usually small).
        let mut next_dkg_key = dkg_key;
        let mut next_elders_info = elders_info;

        loop {
            match self.try_initialize(our_name, next_dkg_key, next_elders_info, index) {
                Ok(commands) => break commands,
                Err(elders_info) => {
                    next_dkg_key = next_dkg_key.retry();
                    next_elders_info = elders_info;
                }
            }
        }
    }

    fn try_initialize(
        &mut self,
        our_name: XorName,
        dkg_key: DkgKey,
        elders_info: EldersInfo,
        index: usize,
    ) -> Result<Vec<DkgCommand>, EldersInfo> {
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

                let mut session = Session {
                    dkg_key,
                    key_gen,
                    elders_info: Some(elders_info),
                    index,
                    timer_token: 0,
                };

                let mut commands = vec![];
                commands.extend(session.broadcast(dkg_key, message));
                commands.extend(
                    self.backlog
                        .take(&dkg_key)
                        .into_iter()
                        .flat_map(|message| session.process_message(dkg_key, message)),
                );

                match session.check() {
                    None => {
                        commands.push(session.reset_timer());
                        self.session = Some(session);
                        Ok(commands)
                    }
                    Some(Status::Success {
                        elders_info,
                        outcome,
                    }) => {
                        // Already completed.
                        commands.push(DkgCommand::HandleOutcome {
                            elders_info,
                            outcome,
                        });
                        Ok(commands)
                    }
                    Some(Status::Failure { elders_info, .. }) => {
                        // This might happen if processing the backlogged messages causes failure.
                        // We retry the initialization when this happens, but using a different DKG
                        // key so we won't process the same backlog again. Thus the process should
                        // eventually terminate.
                        Err(elders_info)
                    }
                }
            }
            Err(error) => {
                // TODO: return a separate error here.
                error!("DKG for {} failed to start: {}", elders_info, error);
                Ok(vec![])
            }
        }
    }

    // Make key generator progress with timed phase.
    pub fn handle_timeout(&mut self, our_name: XorName, timer_token: u64) -> Vec<DkgCommand> {
        let session = if let Some(session) = self.session.as_mut() {
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
                    commands.extend(session.broadcast(dkg_key, message));
                }
                commands.push(session.reset_timer());
                commands.extend(self.check(our_name));
                commands
            }
            Err(error) => {
                trace!("DKG for {} failed: {}", elders_info, error);

                let elders_info = session.elders_info.take().unwrap();

                // Restart on failure.
                self.start(our_name, dkg_key.retry(), elders_info)
            }
        }
    }

    // Handle a received DkgMessage.
    pub fn process_message(
        &mut self,
        our_name: XorName,
        dkg_key: DkgKey,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        let session = if let Some(session) = self
            .session
            .as_mut()
            .filter(|session| session.dkg_key == dkg_key)
        {
            session
        } else {
            self.backlog.push(dkg_key, message);
            return vec![];
        };

        let mut commands = session.process_message(dkg_key, message);

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        if !commands.is_empty() {
            commands.push(session.reset_timer());
        }

        commands.extend(self.check(our_name));
        commands
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    fn check(&mut self, our_name: XorName) -> Vec<DkgCommand> {
        match self.session.as_mut().and_then(|session| session.check()) {
            Some(Status::Success {
                elders_info,
                outcome,
            }) => vec![DkgCommand::HandleOutcome {
                elders_info,
                outcome,
            }],
            Some(Status::Failure {
                dkg_key,
                elders_info,
            }) => {
                // Restart on failure.
                self.start(our_name, dkg_key.retry(), elders_info)
            }
            None => vec![],
        }
    }
}

// Data for a DKG participant.
struct Session {
    // `None` means the session is completed.
    elders_info: Option<EldersInfo>,
    // Our participant index.
    index: usize,
    dkg_key: DkgKey,
    key_gen: KeyGen,
    timer_token: u64,
}

impl Session {
    fn process_message(&mut self, dkg_key: DkgKey, message: DkgMessage) -> Vec<DkgCommand> {
        trace!("process DKG message {:?}", message);
        let responses = self
            .key_gen
            .handle_message(&mut rand::thread_rng(), message)
            .unwrap_or_default();

        responses
            .into_iter()
            .flat_map(|response| self.broadcast(dkg_key, response))
            .collect()
    }

    fn broadcast(&mut self, dkg_key: DkgKey, message: DkgMessage) -> Vec<DkgCommand> {
        let mut commands = vec![];

        let recipients: Vec<_> = self
            .elders_info
            .as_ref()
            .into_iter()
            .flat_map(EldersInfo::peers)
            .enumerate()
            .filter(|(index, _)| *index != self.index)
            .map(|(_, peer)| peer.addr())
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

        commands.extend(self.process_message(dkg_key, message));
        commands
    }

    fn reset_timer(&mut self) -> DkgCommand {
        self.timer_token = command::next_timer_token();
        DkgCommand::ScheduleTimeout {
            duration: DKG_PROGRESS_INTERVAL,
            token: self.timer_token,
        }
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    fn check(&mut self) -> Option<Status> {
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

            let outcome = SectionKeyShare {
                public_key_set: outcome.public_key_set,
                index: self.index,
                secret_key_share: outcome.secret_key_share,
            };

            Some(Status::Success {
                elders_info,
                outcome,
            })
        } else {
            trace!(
                "DKG for {} failed: unexpected participants: {:?}",
                elders_info,
                participants.iter().format(", ")
            );

            Some(Status::Failure {
                dkg_key: self.dkg_key,
                elders_info,
            })
        }
    }
}

enum Status {
    Success {
        elders_info: EldersInfo,
        outcome: SectionKeyShare,
    },
    Failure {
        dkg_key: DkgKey,
        elders_info: EldersInfo,
    },
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
    HandleOutcome {
        elders_info: EldersInfo,
        outcome: SectionKeyShare,
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
                let variant = Variant::DKGMessage { dkg_key, message };
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
            Self::HandleOutcome {
                elders_info,
                outcome,
            } => Ok(Command::HandleDkgOutcome {
                elders_info,
                outcome,
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
        peer::test_utils::arbitrary_unique_peers, section::test_utils::gen_addr, ELDER_SIZE,
        MIN_AGE,
    };
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rand::{rngs::SmallRng, SeedableRng};
    use std::{collections::HashMap, iter};
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
    fn single_participant() {
        // If there is only one participant, the DKG should complete immediately.

        let mut voter = DkgVoter::default();

        let peer = Peer::new(rand::random(), gen_addr(), MIN_AGE);
        let elders_info = EldersInfo::new(iter::once(peer), Prefix::default());
        let dkg_key = DkgKey::new(&elders_info);

        let commands = voter.start(*peer.name(), dkg_key, elders_info);
        assert_matches!(&commands[..], &[DkgCommand::HandleOutcome { .. }]);
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
            let commands = actor.voter.start(actor.name, dkg_key, elders_info.clone());

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
            let commands = actor.voter.process_message(actor.name, dkg_key, message);

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
                DkgCommand::HandleOutcome { outcome, .. } => {
                    self.outcome = Some(outcome.public_key_set.public_key());
                    vec![]
                }
                DkgCommand::ScheduleTimeout { .. } => {
                    vec![]
                }
            }
        }
    }

    fn arbitrary_elder_peers() -> impl Strategy<Value = Vec<Peer>> {
        arbitrary_unique_peers(2..=ELDER_SIZE, MIN_AGE..)
    }
}

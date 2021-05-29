// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DkgFailureProofSetUtils, DkgFailureProofUtils};
use crate::{
    crypto::{self, Keypair},
    error::Result,
    messages::RoutingMsgUtils,
    node::Node,
    routing::command::{self, Command},
    section::{ElderCandidatesUtils, SectionAuthorityProviderUtils, SectionKeyShare},
    supermajority,
};
use bls_dkg::key_gen::{message::Message as DkgMessage, KeyGen};
use itertools::Itertools;
use sn_messaging::{
    node::{
        DkgFailureProof, DkgFailureProofSet, DkgKey, ElderCandidates, RoutingMsg,
        SectionAuthorityProvider, Variant,
    },
    DestInfo, DstLocation,
};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fmt::Debug,
    iter, mem,
    net::SocketAddr,
    time::Duration,
};
use xor_name::XorName;

// Interval to progress DKG timed phase
const DKG_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

const BACKLOG_CAPACITY: usize = 100;

/// DKG voter carries out the work of participating and/or observing a DKG.
///
/// # Usage
///
/// 1. First the current elders propose the new elder candidates in the form of
///    `SectionAuthorityProvider`structure.
/// 2. They send an accumulating message `DkgStart` containing this proposed
///    `SectionAuthorityProvider` to the new elders candidates (DKG participants).
/// 3. When the `DkgStart` message accumulates, the participants call `start`.
/// 4. The participants keep exchanging the DKG messages and calling `process_message`.
/// 5. On DKG completion, the participants send `DkgResult` vote to the current elders (observers)
/// 6. When the observers accumulate the votes, they can proceed with voting for the section update.
///
/// Note: in case of heavy churn, it can happen that more than one DKG session completes
/// successfully. Some kind of disambiguation strategy needs to be employed in that case, but that
/// is currently not a responsibility of this module.
pub(crate) struct DkgVoter {
    sessions: HashMap<DkgKey, Session>,

    // Due to the asyncronous nature of the network we might sometimes receive a DKG message before
    // we created the corresponding session. To avoid losing those messages, we store them in this
    // backlog and replay them once we create the session.
    backlog: Backlog,
}

impl Default for DkgVoter {
    fn default() -> Self {
        Self {
            sessions: HashMap::default(),
            backlog: Backlog::new(),
        }
    }
}

impl DkgVoter {
    // Starts a new DKG session.
    pub fn start(
        &mut self,
        keypair: &Keypair,
        dkg_key: DkgKey,
        elder_candidates: ElderCandidates,
    ) -> Vec<DkgCommand> {
        if self.sessions.contains_key(&dkg_key) {
            trace!("DKG for {:?} already in progress", elder_candidates);
            return vec![];
        }

        let name = crypto::name(&keypair.public);
        let participant_index = if let Some(index) = elder_candidates.position(&name) {
            index
        } else {
            error!(
                "DKG for {:?} failed to start: {} is not a participant",
                elder_candidates, name
            );
            return vec![];
        };

        // Special case: only one participant.
        if elder_candidates.elders.len() == 1 {
            let secret_key_set = bls::SecretKeySet::random(0, &mut rand::thread_rng());
            let section_auth = SectionAuthorityProvider::from_elder_candidates(
                elder_candidates,
                secret_key_set.public_keys(),
            );
            return vec![DkgCommand::HandleOutcome {
                section_auth,
                outcome: SectionKeyShare {
                    public_key_set: secret_key_set.public_keys(),
                    index: participant_index,
                    secret_key_share: secret_key_set.secret_key_share(0),
                },
            }];
        }

        let threshold = supermajority(elder_candidates.elders.len()) - 1;
        let participants = elder_candidates.elders.keys().copied().collect();

        match KeyGen::initialize(name, threshold, participants) {
            Ok((key_gen, message)) => {
                trace!("DKG for {:?} starting", elder_candidates);

                let mut session = Session {
                    key_gen,
                    elder_candidates,
                    participant_index,
                    timer_token: 0,
                    failures: DkgFailureProofSet::default(),
                    complete: false,
                };

                let mut commands = vec![];
                commands.extend(session.broadcast(&dkg_key, keypair, message));
                commands.extend(
                    self.backlog
                        .take(&dkg_key)
                        .into_iter()
                        .flat_map(|message| session.process_message(&dkg_key, keypair, message)),
                );

                let _ = self.sessions.insert(dkg_key, session);

                // Remove uneeded old sessions.
                self.sessions.retain(|existing_dkg_key, _| {
                    existing_dkg_key.generation >= dkg_key.generation
                });
                self.backlog.prune(&dkg_key);

                commands
            }
            Err(error) => {
                // TODO: return a separate error here.
                error!("DKG for {:?} failed to start: {}", elder_candidates, error);
                vec![]
            }
        }
    }

    // Make key generator progress with timed phase.
    pub fn handle_timeout(&mut self, keypair: &Keypair, timer_token: u64) -> Vec<DkgCommand> {
        if let Some((dkg_key, session)) = self
            .sessions
            .iter_mut()
            .find(|(_, session)| session.timer_token == timer_token)
        {
            session.handle_timeout(dkg_key, keypair)
        } else {
            vec![]
        }
    }

    // Handle a received DkgMessage.
    pub fn process_message(
        &mut self,
        keypair: &Keypair,
        dkg_key: &DkgKey,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        if let Some(session) = self.sessions.get_mut(dkg_key) {
            session.process_message(dkg_key, keypair, message)
        } else {
            self.backlog.push(*dkg_key, message);
            vec![]
        }
    }

    pub fn process_failure(
        &mut self,
        dkg_key: &DkgKey,
        non_participants: &BTreeSet<XorName>,
        proof: DkgFailureProof,
    ) -> Option<DkgCommand> {
        self.sessions
            .get_mut(dkg_key)?
            .process_failure(dkg_key, non_participants, proof)
    }
}

// Data for a DKG participant.
struct Session {
    elder_candidates: ElderCandidates,
    participant_index: usize,
    key_gen: KeyGen,
    timer_token: u64,
    failures: DkgFailureProofSet,
    // Flag to track whether this session has completed (either with success or failure). We don't
    // remove complete sessions because the other participants might still need us to respond to
    // their messages.
    complete: bool,
}

impl Session {
    fn process_message(
        &mut self,
        dkg_key: &DkgKey,
        keypair: &Keypair,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        trace!("process DKG message {:?}", message);
        let responses = self
            .key_gen
            .handle_message(&mut rand::thread_rng(), message)
            .unwrap_or_default();

        // Only a valid DkgMessage, which results in some responses, shall reset the ticker.
        let reset_timer = if responses.is_empty() {
            None
        } else {
            Some(self.reset_timer())
        };

        let mut commands: Vec<_> = responses
            .into_iter()
            .flat_map(|response| self.broadcast(dkg_key, keypair, response))
            .chain(reset_timer)
            .collect();
        commands.extend(self.check(dkg_key, keypair));
        commands
    }

    fn recipients(&self) -> Vec<(XorName, SocketAddr)> {
        self.elder_candidates
            .elders
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != self.participant_index)
            .map(|(_, (name, addr))| (*name, *addr))
            .collect()
    }

    fn broadcast(
        &mut self,
        dkg_key: &DkgKey,
        keypair: &Keypair,
        message: DkgMessage,
    ) -> Vec<DkgCommand> {
        let mut commands = vec![];

        let recipients = self.recipients();
        if !recipients.is_empty() {
            trace!("broadcasting DKG message {:?} to {:?}", message, recipients);
            commands.push(DkgCommand::SendMessage {
                recipients,
                dkg_key: *dkg_key,
                message: message.clone(),
            });
        }

        commands.extend(self.process_message(dkg_key, keypair, message));
        commands
    }

    fn handle_timeout(&mut self, dkg_key: &DkgKey, keypair: &Keypair) -> Vec<DkgCommand> {
        if self.complete {
            return vec![];
        }

        trace!("DKG for {:?} progressing", self.elder_candidates);

        match self.key_gen.timed_phase_transition(&mut rand::thread_rng()) {
            Ok(messages) => {
                let mut commands: Vec<_> = messages
                    .into_iter()
                    .flat_map(|message| self.broadcast(dkg_key, keypair, message))
                    .collect();
                commands.push(self.reset_timer());
                commands.extend(self.check(dkg_key, keypair));
                commands
            }
            Err(error) => {
                trace!("DKG for {:?} failed: {}", self.elder_candidates, error);
                self.report_failure(dkg_key, BTreeSet::new(), keypair)
            }
        }
    }

    // Check whether a key generator is finalized to give a DKG outcome.
    fn check(&mut self, dkg_key: &DkgKey, keypair: &Keypair) -> Vec<DkgCommand> {
        if self.complete {
            return vec![];
        }

        if !self.key_gen.is_finalized() {
            return vec![];
        }

        let (participants, outcome) = if let Some(tuple) = self.key_gen.generate_keys() {
            tuple
        } else {
            return vec![];
        };

        // Less than 100% participation
        if !participants.iter().eq(self.elder_candidates.elders.keys()) {
            trace!(
                "DKG for {:?} failed: unexpected participants: {:?}",
                self.elder_candidates,
                participants.iter().format(", ")
            );

            let non_participants: BTreeSet<_> = self
                .elder_candidates
                .elders
                .keys()
                .filter_map(|elder| {
                    if !participants.contains(elder) {
                        Some(*elder)
                    } else {
                        None
                    }
                })
                .collect();

            return self.report_failure(dkg_key, non_participants, keypair);
        }

        // Corrupted DKG outcome. This can happen when a DKG session is restarted using the same set
        // of participants and the same generation, but some of the participants are unaware of the
        // restart (due to lag, etc...) and keep sending messages for the original session which
        // then get mixed with the messages of the restarted session.
        if outcome
            .public_key_set
            .public_key_share(self.participant_index)
            != outcome.secret_key_share.public_key_share()
        {
            trace!(
                "DKG for {:?} failed: corrupted outcome",
                self.elder_candidates
            );
            return self.report_failure(dkg_key, BTreeSet::new(), keypair);
        }

        trace!(
            "DKG for {:?} complete: {:?}",
            self.elder_candidates,
            outcome.public_key_set.public_key()
        );

        self.complete = true;
        let section_auth = SectionAuthorityProvider::from_elder_candidates(
            self.elder_candidates.clone(),
            outcome.public_key_set.clone(),
        );

        let outcome = SectionKeyShare {
            public_key_set: outcome.public_key_set,
            index: self.participant_index,
            secret_key_share: outcome.secret_key_share,
        };

        vec![DkgCommand::HandleOutcome {
            section_auth,
            outcome,
        }]
    }

    fn report_failure(
        &mut self,
        dkg_key: &DkgKey,
        non_participants: BTreeSet<XorName>,
        keypair: &Keypair,
    ) -> Vec<DkgCommand> {
        let proof = DkgFailureProof::new(keypair, &non_participants, dkg_key);

        if !self.failures.insert(proof, &non_participants) {
            return vec![];
        }

        self.check_failure_agreement()
            .into_iter()
            .chain(iter::once(DkgCommand::SendFailureObservation {
                recipients: self.recipients(),
                dkg_key: *dkg_key,
                proof,
                non_participants,
            }))
            .collect()
    }

    fn process_failure(
        &mut self,
        dkg_key: &DkgKey,
        non_participants: &BTreeSet<XorName>,
        proof: DkgFailureProof,
    ) -> Option<DkgCommand> {
        if !self
            .elder_candidates
            .elders
            .contains_key(&crypto::name(&proof.public_key))
        {
            return None;
        }

        if !proof.verify(dkg_key, non_participants) {
            return None;
        }

        if !self.failures.insert(proof, non_participants) {
            return None;
        }

        self.check_failure_agreement()
    }

    fn check_failure_agreement(&mut self) -> Option<DkgCommand> {
        if self.failures.has_agreement(&self.elder_candidates) {
            self.complete = true;

            Some(DkgCommand::HandleFailureAgreement(mem::take(
                &mut self.failures,
            )))
        } else {
            None
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

    fn prune(&mut self, dkg_key: &DkgKey) {
        self.0
            .retain(|(old_dkg_key, _)| old_dkg_key.generation >= dkg_key.generation)
    }
}

#[derive(Debug)]
pub(crate) enum DkgCommand {
    SendMessage {
        recipients: Vec<(XorName, SocketAddr)>,
        dkg_key: DkgKey,
        message: DkgMessage,
    },
    ScheduleTimeout {
        duration: Duration,
        token: u64,
    },
    HandleOutcome {
        section_auth: SectionAuthorityProvider,
        outcome: SectionKeyShare,
    },
    SendFailureObservation {
        recipients: Vec<(XorName, SocketAddr)>,
        dkg_key: DkgKey,
        proof: DkgFailureProof,
        non_participants: BTreeSet<XorName>,
    },
    HandleFailureAgreement(DkgFailureProofSet),
}

impl DkgCommand {
    fn into_command(self, node: &Node, key: bls::PublicKey) -> Result<Command> {
        match self {
            Self::SendMessage {
                recipients,
                dkg_key,
                message,
            } => {
                let variant = Variant::DkgMessage { dkg_key, message };
                let message =
                    RoutingMsg::single_src(node, DstLocation::DirectAndUnrouted, variant, None)?;

                Ok(Command::send_message_to_nodes(
                    recipients.clone(),
                    recipients.len(),
                    message,
                    DestInfo {
                        dest: XorName::random(),
                        dest_section_pk: key,
                    },
                ))
            }
            Self::ScheduleTimeout { duration, token } => {
                Ok(Command::ScheduleTimeout { duration, token })
            }
            Self::HandleOutcome {
                section_auth,
                outcome,
            } => Ok(Command::HandleDkgOutcome {
                section_auth,
                outcome,
            }),
            Self::SendFailureObservation {
                recipients,
                dkg_key,
                proof,
                non_participants,
            } => {
                let variant = Variant::DkgFailureObservation {
                    dkg_key,
                    proof,
                    non_participants,
                };
                let message =
                    RoutingMsg::single_src(node, DstLocation::DirectAndUnrouted, variant, None)?;

                Ok(Command::send_message_to_nodes(
                    recipients.clone(),
                    recipients.len(),
                    message,
                    DestInfo {
                        dest: XorName::random(),
                        dest_section_pk: key,
                    },
                ))
            }
            Self::HandleFailureAgreement(proofs) => Ok(Command::HandleDkgFailure(proofs)),
        }
    }
}

pub(crate) trait DkgCommands {
    fn into_commands(self, node: &Node, key: bls::PublicKey) -> Result<Vec<Command>>;
}

impl DkgCommands for Vec<DkgCommand> {
    fn into_commands(self, node: &Node, key: bls::PublicKey) -> Result<Vec<Command>> {
        self.into_iter()
            .map(|command| command.into_command(node, key))
            .collect()
    }
}

impl DkgCommands for Option<DkgCommand> {
    fn into_commands(self, node: &Node, key: bls::PublicKey) -> Result<Vec<Command>> {
        self.into_iter()
            .map(|command| command.into_command(node, key))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::DkgKeyUtils, crypto, node::test_utils::arbitrary_unique_nodes,
        section::test_utils::gen_addr, ELDER_SIZE, MIN_ADULT_AGE,
    };
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rand::{rngs::SmallRng, SeedableRng};
    use std::{collections::HashMap, iter};
    use xor_name::Prefix;

    #[test]
    fn single_participant() {
        // If there is only one participant, the DKG should complete immediately.

        let mut voter = DkgVoter::default();

        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let elder_candidates = ElderCandidates::new(iter::once(node.peer()), Prefix::default());
        let dkg_key = DkgKey::new(&elder_candidates, 0);

        let commands = voter.start(&node.keypair, dkg_key, elder_candidates);
        assert_matches!(&commands[..], &[DkgCommand::HandleOutcome { .. }]);
    }

    proptest! {
        // Run a DKG session where every participant handles every message sent to them.
        // Expect the session to successfully complete without timed transitions.
        // NOTE: `seed` is for seeding the rng that randomizes the message order.
        #[test]
        fn proptest_full_participation(nodes in arbitrary_elder_nodes(), seed in any::<u64>()) {
            proptest_full_participation_impl(nodes, seed)
        }
    }

    fn proptest_full_participation_impl(nodes: Vec<Node>, seed: u64) {
        // Rng used to randomize the message order.
        let mut rng = SmallRng::seed_from_u64(seed);
        let mut messages = Vec::new();

        let elder_candidates =
            ElderCandidates::new(nodes.iter().map(Node::peer), Prefix::default());
        let dkg_key = DkgKey::new(&elder_candidates, 0);

        let mut actors: HashMap<_, _> = nodes
            .into_iter()
            .map(|node| (node.addr, Actor::new(node)))
            .collect();

        for actor in actors.values_mut() {
            let commands =
                actor
                    .voter
                    .start(&actor.node.keypair, dkg_key, elder_candidates.clone());

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
            let commands = actor
                .voter
                .process_message(&actor.node.keypair, &dkg_key, message);

            for command in commands {
                messages.extend(actor.handle(command, &dkg_key))
            }
        }
    }

    struct Actor {
        node: Node,
        voter: DkgVoter,
        outcome: Option<bls::PublicKey>,
    }

    impl Actor {
        fn new(node: Node) -> Self {
            Self {
                node,
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
                        .map(|addr| (addr.1, message.clone()))
                        .collect()
                }
                DkgCommand::HandleOutcome { outcome, .. } => {
                    self.outcome = Some(outcome.public_key_set.public_key());
                    vec![]
                }
                DkgCommand::ScheduleTimeout { .. } => vec![],
                DkgCommand::SendFailureObservation { .. }
                | DkgCommand::HandleFailureAgreement { .. } => {
                    panic!("unexpected command: {:?}", command)
                }
            }
        }
    }

    fn arbitrary_elder_nodes() -> impl Strategy<Value = Vec<Node>> {
        arbitrary_unique_nodes(2..=ELDER_SIZE)
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// This is used two ways: inline tests, and integration tests (with mock).
// There's no point configuring each item which is only used in one of these.

use crate::state::{State, TryRelocatingState};
use crate::utilities::{Candidate, Event, LocalEvent, ParsecVote, Rpc, SectionInfo};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct TopLevelSrc(pub State);

impl TopLevelSrc {
    pub fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(local_event) => self.try_local_event(local_event),
        }
        .map(|state| state.0)
    }

    fn try_rpc(&self, rpc: Rpc) -> Option<Self> {
        match rpc {
            Rpc::RefuseCandidate(candidate) => Some(self.vote_parsec_refuse_candidate(candidate)),
            Rpc::RelocateResponse(candidate, section) => {
                Some(self.vote_parsec_relocation_response(candidate, section))
            }
            _ => None,
        }
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        match vote {
            ParsecVote::RelocationTrigger => self.try_consensused_relocation_trigger(),

            // Delegate to other event loops
            _ => None,
        }
    }

    fn try_local_event(&self, local_event: LocalEvent) -> Option<Self> {
        match local_event {
            LocalEvent::RelocationTrigger => Some(self.vote_parsec_relocation_trigger()),
            _ => None,
        }
    }

    fn try_consensused_relocation_trigger(&self) -> Option<Self> {
        match self.0.src_routine.relocating_candidate {
            Some(_) => Some(self.discard()),
            None => Some(
                self.set_relocating_candidate(Some(self.0.action.get_relocating_candidate()))
                    .set_candidate_relocating_state_if_needed()
                    .check_if_relocating_elder(),
            ),
        }
    }

    fn check_if_relocating_elder(&self) -> Self {
        if self
            .0
            .action
            .is_elder_state(self.0.src_routine.relocating_candidate.unwrap())
        {
            self.set_relocating_candidate(None)
        } else {
            self.concurrent_transition_to_try_relocating()
        }
    }

    fn concurrent_transition_to_try_relocating(&self) -> Self {
        self.0
            .as_try_relocating()
            .start_event_loop(self.0.src_routine.relocating_candidate.unwrap())
            .0
            .as_top_level_src()
    }

    fn transition_exit_try_relocating(&self) -> Self {
        self.set_relocating_candidate(None)
    }

    fn discard(&self) -> Self {
        self.clone()
    }

    fn vote_parsec_relocation_trigger(&self) -> Self {
        self.0.action.vote_parsec(ParsecVote::RelocationTrigger);
        self.clone()
    }

    fn set_relocating_candidate(&self, candidate: Option<Candidate>) -> Self {
        let mut state = self.clone();
        state.0.src_routine.relocating_candidate = candidate;
        state
    }

    fn set_candidate_relocating_state_if_needed(&self) -> Self {
        let candidate = self.0.src_routine.relocating_candidate.unwrap();
        if !self.0.action.is_candidate_relocating_state(candidate) {
            self.0.action.set_candidate_relocating_state(candidate);
        }
        self.clone()
    }

    fn vote_parsec_refuse_candidate(&self, candiddate: Candidate) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::RefuseCandidate(candiddate));
        self.clone()
    }

    fn vote_parsec_relocation_response(&self, candiddate: Candidate, section: SectionInfo) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::RelocateResponse(candiddate, section));
        self.clone()
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct TryRelocating(pub State);

// TryRelocating Sub Routine
impl TryRelocating {
    fn start_event_loop(&self, candidate: Candidate) -> Self {
        self.0
            .with_src_sub_routine_try_relocating(Some(TryRelocatingState { candidate }))
            .as_try_relocating()
            .send_expect_candidate_rpc()
    }

    fn exit_event_loop(&self) -> Self {
        self.0
            .with_src_sub_routine_try_relocating(None)
            .as_top_level_src()
            .transition_exit_try_relocating()
            .0
            .as_try_relocating()
    }

    pub fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        if vote.candidate() != Some(self.candidate()) {
            return None;
        }

        match vote {
            ParsecVote::RefuseCandidate(_) => Some(self.exit_event_loop()),
            ParsecVote::RelocateResponse(_, section) => Some(self.remove_node(section)),
            // Delegate to other event loops
            _ => None,
        }
    }

    fn routine_state(&self) -> &TryRelocatingState {
        match &self.0.src_routine.sub_routine_try_relocating {
            Some(state) => state,
            _ => panic!("Expect AcceptAsCandidate {:?}", &self),
        }
    }

    fn mut_routine_state(&mut self) -> &mut TryRelocatingState {
        let clone = self.clone();
        match &mut self.0.src_routine.sub_routine_try_relocating {
            Some(state) => state,
            _ => panic!("Expect AcceptAsCandidate {:?}", &clone),
        }
    }

    fn send_expect_candidate_rpc(&self) -> Self {
        self.0
            .action
            .send_rpc(Rpc::ExpectCandidate(self.candidate()));
        self.clone()
    }

    fn remove_node(&self, section: SectionInfo) -> Self {
        self.0
            .action
            .send_candidate_relocated_info(self.candidate(), section);
        self.0.action.remove_node(self.candidate());
        self.exit_event_loop()
    }

    fn candidate(&self) -> Candidate {
        self.routine_state().candidate
    }
}

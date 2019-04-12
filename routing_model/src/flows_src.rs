// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::state::{MemberState, TryRelocatingState};
use crate::utilities::{Candidate, Event, LocalEvent, ParsecVote, Rpc, SectionInfo};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct TopLevelSrc(pub MemberState);

impl TopLevelSrc {
    fn start_event_loop(&self) -> Self {
        self.start_work_unit_timeout()
    }

    pub fn try_next(&self, event: Event) -> Option<MemberState> {
        match event {
            Event::Rpc(_) => None,
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(local_event) => self.try_local_event(local_event),
        }
        .map(|state| state.0)
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        match vote {
            ParsecVote::WorkUnitIncrement => Some(
                self.increment_nodes_work_units()
                    .check_get_node_to_relocate(),
            ),

            // Delegate to other event loops
            _ => None,
        }
    }

    fn try_local_event(&self, local_event: LocalEvent) -> Option<Self> {
        match local_event {
            LocalEvent::TimeoutWorkUnit => Some(
                self.vote_parsec_work_unit_increment()
                    .start_work_unit_timeout(),
            ),
            _ => None,
        }
    }

    fn increment_nodes_work_units(&self) -> Self {
        self.0.action.increment_nodes_work_units();
        self.clone()
    }

    fn check_get_node_to_relocate(&self) -> Self {
        match (self.0.action.get_node_to_relocate(), false) {
            (Some(candidate), false) => self.set_relocating_candidate(candidate),
            _ => self.clone(),
        }
    }

    fn set_relocating_candidate(&self, candidate: Candidate) -> Self {
        self.0.action.set_candidate_relocating_state(candidate);
        self.clone()
    }

    fn vote_parsec_work_unit_increment(&self) -> Self {
        self.0.action.vote_parsec(ParsecVote::WorkUnitIncrement);
        self.clone()
    }

    fn start_work_unit_timeout(&self) -> Self {
        self.0.action.schedule_event(LocalEvent::TimeoutWorkUnit);
        self.clone()
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct StartRelocateSrc(pub MemberState);

// StartRelocateSrc Sub Routine
impl StartRelocateSrc {
    fn start_event_loop(&self) -> Self {
        self.start_check_relocate_timeout()
    }

    pub fn try_next(&self, event: Event) -> Option<MemberState> {
        match event {
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(local_event) => self.try_local_event(local_event),
        }
        .map(|state| state.0)
    }

    fn try_local_event(&self, local_event: LocalEvent) -> Option<Self> {
        match local_event {
            LocalEvent::TimeoutCheckRelocate => Some(
                self.vote_parsec_check_relocate()
                    .start_check_relocate_timeout(),
            ),
            _ => None,
        }
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
        let is_our_relocating_node =
            |candidate: Candidate| self.0.action.is_our_relocating_node(candidate);

        match vote {
            ParsecVote::CheckRelocate => Some(self.relocate_as_needed()),
            ParsecVote::RefuseCandidate(candidate) if is_our_relocating_node(candidate) => {
                Some(self.discard())
            }
            ParsecVote::RelocateResponse(candidate, section)
                if is_our_relocating_node(candidate) =>
            {
                Some(self.remove_node(candidate, section))
            }
            ParsecVote::RefuseCandidate(_) | ParsecVote::RelocateResponse(_, _) => {
                Some(self.discard())
            }
            // Delegate to other event loops
            _ => None,
        }
    }

    fn relocate_as_needed(&self) -> Self {
        if let Some((candidate, _)) = self.0.action.get_best_relocating_node_and_target() {
            self.send_expect_candidate_rpc(candidate);
        }
        self.clone()
    }

    fn vote_parsec_check_relocate(&self) -> Self {
        self.0.action.vote_parsec(ParsecVote::CheckRelocate);
        self.clone()
    }

    fn start_check_relocate_timeout(&self) -> Self {
        self.0
            .action
            .schedule_event(LocalEvent::TimeoutCheckRelocate);
        self.clone()
    }

    fn send_expect_candidate_rpc(&self, candidate: Candidate) -> Self {
        self.0.action.send_rpc(Rpc::ExpectCandidate(candidate));
        self.clone()
    }

    fn remove_node(&self, candidate: Candidate, section: SectionInfo) -> Self {
        self.0
            .action
            .send_candidate_relocated_info(candidate, section);
        self.0.action.remove_node(candidate);
        self.clone()
    }

    fn discard(&self) -> Self {
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

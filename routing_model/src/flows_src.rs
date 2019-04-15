// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::state::{MemberState, StartRelocateSrcState};
use crate::utilities::{Candidate, Event, LocalEvent, ParsecVote, RelocatedInfo, Rpc, SectionInfo};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct TopLevelSrc(pub MemberState);

impl TopLevelSrc {
    fn start_event_loop(&self) -> Self {
        self.start_work_unit_timeout()
    }

    pub fn try_next(&self, event: Event) -> Option<MemberState> {
        match event {
            Event::LocalEvent(local_event) => self.try_local_event(local_event),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),

            Event::Rpc(_) => None,
        }
        .map(|state| state.0)
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

    fn check_get_node_to_relocate(&self) -> Self {
        match (self.0.action.get_node_to_relocate(), false) {
            (Some(candidate), false) => self.set_relocating_candidate(candidate),
            _ => self.clone(),
        }
    }

    //
    // Actions
    //
    fn increment_nodes_work_units(&self) -> Self {
        self.0.action.increment_nodes_work_units();
        self.clone()
    }

    fn set_relocating_candidate(&self, candidate: Candidate) -> Self {
        self.0.action.set_candidate_relocating_state(candidate);
        self.clone()
    }

    fn start_work_unit_timeout(&self) -> Self {
        self.0.action.schedule_event(LocalEvent::TimeoutWorkUnit);
        self.clone()
    }

    //
    // Votes
    //

    fn vote_parsec_work_unit_increment(&self) -> Self {
        self.0.action.vote_parsec(ParsecVote::WorkUnitIncrement);
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
            Event::LocalEvent(local_event) => self.try_local_event(local_event),
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
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
        match vote {
            ParsecVote::CheckRelocate => {
                Some(self.check_need_relocate().update_wait_and_allow_resend())
            }
            ParsecVote::RefuseCandidate(candidate) | ParsecVote::RelocateResponse(candidate, _) => {
                Some(self.check_is_our_relocating_node(vote, candidate))
            }
            ParsecVote::RelocatedInfo(info) => Some(
                self.send_candidate_relocated_info_rpc(info)
                    .purge_node_info(info.candidate),
            ),
            // Delegate to other event loops
            _ => None,
        }
    }

    fn check_need_relocate(&self) -> Self {
        let mut state = self.clone();
        if let Some((candidate, _)) = self
            .0
            .action
            .get_best_relocating_node_and_target(&state.routine_state().already_relocating)
        {
            state.0.action.send_rpc(Rpc::ExpectCandidate(candidate));
            state
                .mut_routine_state()
                .already_relocating
                .insert(candidate, 0);
        }
        state
    }

    fn update_wait_and_allow_resend(&self) -> Self {
        let mut state = self.clone();
        let new_already_relocating = state
            .routine_state()
            .already_relocating
            .iter()
            .map(|(node, count)| (*node, *count + 1))
            .filter(|(_, count)| *count < 3)
            .collect();
        state.mut_routine_state().already_relocating = new_already_relocating;
        state
    }

    fn check_is_our_relocating_node(&self, vote: ParsecVote, candidate: Candidate) -> Self {
        if self.0.action.is_our_relocating_node(candidate) {
            match vote {
                ParsecVote::RefuseCandidate(candidate) => self.allow_resend(candidate),
                ParsecVote::RelocateResponse(candidate, section) => {
                    self.set_relocated_and_prepare_info(candidate, section)
                }
                _ => panic!("Unepected vote"),
            }
        } else {
            self.discard()
        }
    }

    fn allow_resend(&self, candidate: Candidate) -> Self {
        let mut state = self.clone();
        state
            .mut_routine_state()
            .already_relocating
            .remove(&candidate);
        state
    }

    fn set_relocated_and_prepare_info(
        &self,
        candidate: Candidate,
        section_info: SectionInfo,
    ) -> Self {
        let relocated_info = RelocatedInfo {
            candidate,
            section_info,
        };
        self.0
            .action
            .set_candidate_relocated_state(candidate, relocated_info);
        self.0
            .action
            .vote_parsec(ParsecVote::RelocatedInfo(relocated_info));
        self.clone()
    }

    //
    // Routine state
    //

    fn routine_state(&self) -> &StartRelocateSrcState {
        &self.0.start_relocate_src
    }

    fn mut_routine_state(&mut self) -> &mut StartRelocateSrcState {
        &mut self.0.start_relocate_src
    }

    //
    // Actions
    //

    fn start_check_relocate_timeout(&self) -> Self {
        self.0
            .action
            .schedule_event(LocalEvent::TimeoutCheckRelocate);
        self.clone()
    }

    fn purge_node_info(&self, candidate: Candidate) -> Self {
        self.0.action.remove_node(candidate);
        self.clone()
    }

    fn discard(&self) -> Self {
        self.clone()
    }

    //
    // RPCs
    //

    fn send_expect_candidate_rpc(&self, candidate: Candidate) -> Self {
        self.0.action.send_rpc(Rpc::ExpectCandidate(candidate));
        self.clone()
    }

    fn send_candidate_relocated_info_rpc(&self, info: RelocatedInfo) -> Self {
        self.0
            .action
            .send_rpc(Rpc::RelocatedInfo(info.candidate, info.section_info));
        self.clone()
    }

    //
    // Votes
    //

    fn vote_parsec_check_relocate(&self) -> Self {
        self.0.action.vote_parsec(ParsecVote::CheckRelocate);
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

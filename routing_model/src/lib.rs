// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// This is used two ways: inline tests, and integration tests (with mock).
// There's no point configuring each item which is only used in one of these.

#![allow(dead_code)]
#![allow(unused_imports)]

mod actions;
mod utilities;
mod scenario_tests;

use itertools::Itertools;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display, Formatter};
use std::rc::Rc;

use crate::actions::{Action, InnerAction};
use crate::utilities::{
    Age, Attributes, Candidate, ChangeElder, Event, GenesisPfxInfo, LocalEvent, Name, Node,
    NodeChange, NodeState, ParsecVote, Proof, ProofRequest, ProofSource, Rpc, Section, SectionInfo,
};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate unwrap;

//////////////////
/// Dst
//////////////////

#[derive(Debug, PartialEq, Default, Clone)]
struct TopLevelDst(State);

impl TopLevelDst {
    fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(LocalEvent::TimeoutAccept) => {
                return Some(self.0.failure_event(event));
            }
            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_rpc(&self, rpc: Rpc) -> Option<Self> {
        match rpc {
            Rpc::ExpectCandidate(candidate) => Some(self.vote_parsec_expect_candidate(candidate)),
            Rpc::ResourceProofResponse { .. } | Rpc::CandidateInfo { .. } => Some(self.discard()),
            _ => None,
        }
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        match vote {
            ParsecVote::ExpectCandidate(candidate) => {
                self.try_consensused_expect_candidate(candidate)
            }
            ParsecVote::Online(_) | ParsecVote::PurgeCandidate(_) => Some(self.discard()),

            // Delegate to other event loops
            _ => None,
        }
    }

    fn try_consensused_expect_candidate(&self, candidate: Candidate) -> Option<Self> {
        match (
            self.0.dst_routine.is_processing_candidate,
            self.0.action.check_shortest_prefix(),
        ) {
            (_, Some(section)) => Some(self.resend_expect_candidate_rpc(candidate, section)),
            (true, None) => Some(self.send_refuse_candidate_rpc(candidate)),
            (false, None) => Some(self.concurrent_transition_to_accept_as_candidate(candidate)),
        }
    }

    fn concurrent_transition_to_accept_as_candidate(&self, candidate: Candidate) -> Self {
        self.set_is_processing_candidate(true)
            .0
            .as_accept_as_candidate()
            .start_event_loop(candidate)
            .0
            .as_top_level_dst()
    }

    fn transition_exit_accept_as_candidate(&self) -> Self {
        self.set_is_processing_candidate(false)
    }

    fn set_is_processing_candidate(&self, value: bool) -> Self {
        let mut state = self.clone();
        state.0.dst_routine.is_processing_candidate = value;
        state
    }

    fn discard(&self) -> Self {
        self.clone()
    }

    fn vote_parsec_expect_candidate(&self, candidate: Candidate) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::ExpectCandidate(candidate));
        self.clone()
    }

    fn send_refuse_candidate_rpc(&self, candidate: Candidate) -> Self {
        self.0.action.send_rpc(Rpc::RefuseCandidate(candidate));
        self.clone()
    }

    fn resend_expect_candidate_rpc(&self, candidate: Candidate, section: Section) -> Self {
        self.0
            .action
            .send_rpc(Rpc::ResendExpectCandidate(section, candidate));
        self.clone()
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
struct AcceptAsCandidate(State);

// AcceptAsCandidate Sub Routine
impl AcceptAsCandidate {
    fn start_event_loop(&self, candidate: Candidate) -> Self {
        self.0
            .with_dst_sub_routine_accept_as_candidate(Some(AcceptAsCandidateState::new(candidate)))
            .as_accept_as_candidate()
            .add_node_ressource_proofing()
            .send_relocate_response_rpc()
    }

    fn exit_event_loop(&self) -> Self {
        self.0
            .with_dst_sub_routine_accept_as_candidate(None)
            .as_top_level_dst()
            .transition_exit_accept_as_candidate()
            .0
            .as_accept_as_candidate()
    }

    fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::Rpc(Rpc::CandidateInfo {
                candidate, valid, ..
            }) => self.try_rpc_info(candidate, valid),
            Event::Rpc(Rpc::ResourceProofResponse {
                candidate, proof, ..
            }) => self.try_rpc_proof(candidate, proof),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(LocalEvent::TimeoutAccept) => {
                Some(self.vote_parsec_purge_candidate())
            }
            // Delegate to other event loops
            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_rpc_info(&self, candidate: Candidate, valid: bool) -> Option<Self> {
        if candidate != self.candidate() || self.routine_state().got_candidate_info {
            return None;
        }

        Some(match valid {
            true => self.set_got_candidate_info(true).send_resource_proof_rpc(),
            false => self.vote_parsec_purge_candidate(),
        })
    }

    fn try_rpc_proof(&self, candidate: Candidate, proof: Proof) -> Option<Self> {
        if candidate != self.candidate() || self.routine_state().voted_online || !proof.is_valid() {
            return None;
        }

        Some(match proof {
            Proof::ValidPart => self.send_resource_proof_receipt_rpc(),
            Proof::ValidEnd => self.set_voted_online(true).vote_parsec_online_candidate(),
            Proof::Invalid => panic!("Only valid proof"),
        })
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        if vote.candidate() != Some(self.candidate()) {
            return None;
        }

        match vote {
            ParsecVote::Online(_) => Some(self.make_node_online()),
            ParsecVote::PurgeCandidate(_) => Some(self.remove_node()),

            // Delegate to other event loops
            _ => None,
        }
    }

    fn routine_state(&self) -> &AcceptAsCandidateState {
        match &self.0.dst_routine.sub_routine_accept_as_candidate {
            Some(state) => state,
            _ => panic!("Expect AcceptAsCandidate {:?}", &self),
        }
    }

    fn mut_routine_state(&mut self) -> &mut AcceptAsCandidateState {
        let clone = self.clone();
        match &mut self.0.dst_routine.sub_routine_accept_as_candidate {
            Some(state) => state,
            _ => panic!("Expect AcceptAsCandidate {:?}", &clone),
        }
    }

    fn set_got_candidate_info(&self, value: bool) -> Self {
        let mut state = self.clone();
        state.mut_routine_state().got_candidate_info = value;
        state
    }

    fn set_voted_online(&self, value: bool) -> Self {
        let mut state = self.clone();
        state.mut_routine_state().voted_online = value;
        state
    }

    fn vote_parsec_purge_candidate(&self) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::PurgeCandidate(self.candidate()));
        self.clone()
    }

    fn vote_parsec_online_candidate(&self) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::Online(self.candidate()));
        self.clone()
    }

    fn add_node_ressource_proofing(&self) -> Self {
        self.0.action.add_node_ressource_proofing(self.candidate());
        self.clone()
    }

    fn make_node_online(&self) -> Self {
        self.0.action.set_candidate_online_state(self.candidate());
        self.0.action.send_node_approval_rpc(self.candidate());
        self.exit_event_loop()
    }

    fn remove_node(&self) -> Self {
        self.0.action.remove_node(self.candidate());
        self.exit_event_loop()
    }

    fn send_relocate_response_rpc(&self) -> Self {
        self.0.action.send_relocate_response_rpc(self.candidate());
        self.clone()
    }

    fn send_resource_proof_rpc(&self) -> Self {
        self.0.action.send_candidate_proof_request(self.candidate());
        self.clone()
    }

    fn send_resource_proof_receipt_rpc(&self) -> Self {
        self.0.action.send_candidate_proof_receipt(self.candidate());
        self.clone()
    }

    fn candidate(&self) -> Candidate {
        self.routine_state().candidate
    }
}

#[derive(Debug, PartialEq, Clone)]
struct CheckAndProcessElderChange(State);

// CheckAndProcessElderChange Sub Routine
impl CheckAndProcessElderChange {
    fn start_event_loop(&self) -> Self {
        self.start_check_elder_timeout()
    }

    fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::ParsecConsensus(vote) => self.try_consensus(&vote),
            Event::LocalEvent(LocalEvent::TimeoutCheckElder) => {
                Some(self.vote_parsec_check_elder())
            }
            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_consensus(&self, vote: &ParsecVote) -> Option<Self> {
        if ParsecVote::CheckElder == *vote {
            return Some(self.check_elder());
        }

        if !self.routine_state().wait_votes.contains(&vote) {
            return None;
        }

        let mut state = self.clone();
        let wait_votes = &mut state.mut_routine_state().wait_votes;
        wait_votes.retain(|wait_vote| wait_vote != vote);

        if wait_votes.is_empty() {
            Some(state.mark_elder_change().start_check_elder_timeout())
        } else {
            Some(state)
        }
    }

    fn routine_state(&self) -> &CheckAndProcessElderChangeState {
        &self.0.check_and_process_elder_change_routine
    }

    fn mut_routine_state(&mut self) -> &mut CheckAndProcessElderChangeState {
        &mut self.0.check_and_process_elder_change_routine
    }

    fn check_elder(&self) -> Self {
        match self.0.action.check_elder() {
            Some(change_elder) => self.start_vote_elder_change(change_elder),
            None => self.start_check_elder_timeout(),
        }
    }

    fn start_vote_elder_change(&self, change_elder: ChangeElder) -> Self {
        let mut state = self.clone();

        let votes = state.0.action.get_elder_change_votes(&change_elder);
        state.mut_routine_state().change_elder = Some(change_elder);
        state.mut_routine_state().wait_votes = votes;

        for vote in &state.routine_state().wait_votes {
            state.0.action.vote_parsec(*vote);
        }

        state
    }

    fn mark_elder_change(&self) -> Self {
        let mut state = self.clone();

        let change_elder = state.mut_routine_state().change_elder.take().unwrap();
        state.0.action.mark_elder_change(change_elder);

        state
    }

    fn vote_parsec_check_elder(&self) -> Self {
        self.0.action.vote_parsec(ParsecVote::CheckElder);
        self.clone()
    }

    fn start_check_elder_timeout(&self) -> Self {
        self.0.action.schedule_event(LocalEvent::TimeoutCheckElder);
        self.clone()
    }
}

//////////////////
/// Scr
//////////////////

#[derive(Debug, PartialEq, Default, Clone)]
struct TopLevelSrc(State);

impl TopLevelSrc {
    fn try_next(&self, event: Event) -> Option<State> {
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
struct TryRelocating(State);

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

    fn try_next(&self, event: Event) -> Option<State> {
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

//////////////////
/// Joining Single Node
//////////////////

#[derive(Debug, PartialEq, Default, Clone)]
struct JoiningRelocateCandidate(JoiningState);

impl JoiningRelocateCandidate {
    fn start_event_loop(&self, new_section: &SectionInfo) -> Self {
        self.store_destination_members(new_section)
            .send_connection_info_requests()
            .start_resend_info_timeout()
            .start_refused_timeout()
    }

    fn try_next(&self, event: Event) -> Option<JoiningState> {
        match event {
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::LocalEvent(local_event) => self.try_local_event(local_event),
            _ => None,
        }
        .or_else(|| Some(self.discard()))
        .map(|state| state.0)
    }

    fn try_rpc(&self, rpc: Rpc) -> Option<Self> {
        if let Rpc::NodeApproval(candidate, info) = &rpc {
            if self.0.action.is_our_name(Name(candidate.0.name)) {
                return Some(self.exit(*info));
            } else {
                return None;
            }
        }

        if !rpc
            .destination()
            .map(|name| self.0.action.is_our_name(name))
            .unwrap_or(false)
        {
            return None;
        }

        match rpc {
            Rpc::ConnectionInfoResponse {
                source,
                connection_info,
                ..
            } => Some(self.connect_and_send_candidate_info(source, connection_info)),
            Rpc::ResourceProof { proof, source, .. } => {
                Some(self.start_compute_resource_proof(source, proof))
            }
            Rpc::ResourceProofReceipt { source, .. } => Some(self.send_next_proof_response(source)),
            _ => None,
        }
    }

    fn try_local_event(&self, local_event: LocalEvent) -> Option<Self> {
        match local_event {
            LocalEvent::ComputeResourceProofForElder(source, proof) => {
                Some(self.send_first_proof_response(source, proof))
            }
            LocalEvent::JoiningTimeoutResendCandidateInfo => Some(
                self.send_connection_info_requests()
                    .start_resend_info_timeout(),
            ),
            _ => None,
        }
    }

    fn exit(&self, info: GenesisPfxInfo) -> Self {
        let mut state = self.clone();
        state.0.join_routine.has_resource_proofs.clear();
        state.0.join_routine.routine_complete = Some(info);
        state
    }

    fn discard(&self) -> Self {
        self.clone()
    }

    fn store_destination_members(&self, section: &SectionInfo) -> Self {
        let mut state = self.clone();

        let members = state.0.action.get_section_members(section);
        state.0.join_routine.has_resource_proofs = members
            .iter()
            .map(|node| (Name(node.0.name), (false, None)))
            .collect();
        state
    }

    fn send_connection_info_requests(&self) -> Self {
        let has_resource_proofs = &self.0.join_routine.has_resource_proofs;
        for (name, _) in has_resource_proofs.iter().filter(|(_, value)| !value.0) {
            self.0.action.send_connection_info_request(*name);
        }

        self.clone()
    }

    fn send_first_proof_response(&self, source: Name, mut proof_source: ProofSource) -> Self {
        let mut state = self.clone();
        let proof = state
            .0
            .join_routine
            .has_resource_proofs
            .get_mut(&source)
            .unwrap();

        let next_part = proof_source.next_part();
        proof.1 = Some(proof_source);

        state
            .0
            .action
            .send_resource_proof_response(source, next_part);
        state
    }

    fn send_next_proof_response(&self, source: Name) -> Self {
        let mut state = self.clone();
        let proof_source = &mut state
            .0
            .join_routine
            .has_resource_proofs
            .get_mut(&source)
            .unwrap()
            .1
            .as_mut()
            .unwrap();

        let next_part = proof_source.next_part();
        state
            .0
            .action
            .send_resource_proof_response(source, next_part);
        state
    }

    fn connect_and_send_candidate_info(&self, source: Name, connect_info: i32) -> Self {
        self.0.action.send_candidate_info(source);
        self.clone()
    }

    fn start_resend_info_timeout(&self) -> Self {
        self.0
            .action
            .schedule_event(LocalEvent::JoiningTimeoutResendCandidateInfo);
        self.clone()
    }

    fn start_refused_timeout(&self) -> Self {
        self.0
            .action
            .schedule_event(LocalEvent::JoiningTimeoutRefused);
        self.clone()
    }

    fn start_compute_resource_proof(&self, source: Name, proof: ProofRequest) -> Self {
        let mut state = self.clone();
        state.0.action.start_compute_resource_proof(source, proof);
        let proof = state
            .0
            .join_routine
            .has_resource_proofs
            .get_mut(&source)
            .unwrap();
        if !proof.0 {
            *proof = (true, None);
        }
        state
    }
}

//////////////////
/// Utilities
//////////////////

#[derive(Debug, PartialEq, Default, Clone)]
struct CheckAndProcessElderChangeState {
    wait_votes: Vec<ParsecVote>,
    change_elder: Option<ChangeElder>,
}

#[derive(Debug, PartialEq, Clone)]
struct AcceptAsCandidateState {
    candidate: Candidate,
    got_candidate_info: bool,
    voted_online: bool,
}

impl AcceptAsCandidateState {
    fn new(candidate: Candidate) -> Self {
        Self {
            candidate,
            got_candidate_info: false,
            voted_online: false,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
struct TryRelocatingState {
    candidate: Candidate,
}

#[derive(Debug, PartialEq, Default, Clone)]
struct DstRoutineState {
    is_processing_candidate: bool,
    sub_routine_accept_as_candidate: Option<AcceptAsCandidateState>,
}

#[derive(Debug, PartialEq, Default, Clone)]
struct SrcRoutineState {
    relocating_candidate: Option<Candidate>,
    sub_routine_try_relocating: Option<TryRelocatingState>,
}

// The very top level event loop deciding how the sub event loops are processed
#[derive(Debug, PartialEq, Default, Clone)]
struct State {
    action: Action,
    failure: Option<Event>,
    dst_routine: DstRoutineState,
    src_routine: SrcRoutineState,
    check_and_process_elder_change_routine: CheckAndProcessElderChangeState,
}

impl State {
    fn try_next(&self, event: Event) -> Option<Self> {
        let dst = &self.dst_routine;
        let src = &self.src_routine;

        if let Some(next) = self.as_check_and_process_elder_change().try_next(event) {
            return Some(next);
        }

        if src.sub_routine_try_relocating.is_some() {
            if let Some(next) = self.as_try_relocating().try_next(event) {
                return Some(next);
            }
        }

        if let Some(next) = self.as_top_level_src().try_next(event) {
            return Some(next);
        }

        if dst.sub_routine_accept_as_candidate.is_some() {
            if let Some(next) = self.as_accept_as_candidate().try_next(event) {
                return Some(next);
            }
        }

        if let Some(next) = self.as_top_level_dst().try_next(event) {
            return Some(next);
        }

        match event {
            // These should only happen if a routine started them, so it should have
            // handled them too, but other routine are not there yet and we want to test
            // these do not fail.
            Event::ParsecConsensus(ParsecVote::RemoveElderNode(_))
            | Event::ParsecConsensus(ParsecVote::AddElderNode(_))
            | Event::ParsecConsensus(ParsecVote::NewSectionInfo(_)) => Some(self.clone()),

            _ => None,
        }
    }

    fn as_top_level_dst(&self) -> TopLevelDst {
        TopLevelDst(self.clone())
    }

    fn as_accept_as_candidate(&self) -> AcceptAsCandidate {
        AcceptAsCandidate(self.clone())
    }

    fn as_check_and_process_elder_change(&self) -> CheckAndProcessElderChange {
        CheckAndProcessElderChange(self.clone())
    }

    fn as_top_level_src(&self) -> TopLevelSrc {
        TopLevelSrc(self.clone())
    }

    fn as_try_relocating(&self) -> TryRelocating {
        TryRelocating(self.clone())
    }

    fn failure_event(&self, event: Event) -> Self {
        Self {
            failure: Some(event),
            ..self.clone()
        }
    }

    fn with_dst_sub_routine_accept_as_candidate(
        &self,
        sub_routine_accept_as_candidate: Option<AcceptAsCandidateState>,
    ) -> Self {
        Self {
            dst_routine: DstRoutineState {
                sub_routine_accept_as_candidate,
                ..self.dst_routine.clone()
            },
            ..self.clone()
        }
    }

    fn with_src_sub_routine_try_relocating(
        &self,
        sub_routine_try_relocating: Option<TryRelocatingState>,
    ) -> Self {
        Self {
            src_routine: SrcRoutineState {
                sub_routine_try_relocating,
                ..self.src_routine.clone()
            },
            ..self.clone()
        }
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
struct JoiningRelocateCandidateState {
    has_resource_proofs: BTreeMap<Name, (bool, Option<ProofSource>)>,
    routine_complete: Option<GenesisPfxInfo /*output*/>,
}

// The very top level event loop deciding how the sub event loops are processed
#[derive(Debug, PartialEq, Default, Clone)]
struct JoiningState {
    action: Action,
    failure: Option<Event>,
    join_routine: JoiningRelocateCandidateState,
}

impl JoiningState {
    fn start(&self, new_section: &SectionInfo) -> Self {
        self.as_joining_relocate_candidate()
            .start_event_loop(new_section)
            .0
    }

    fn try_next(&self, event: Event) -> Option<Self> {
        if let Some(next) = self.as_joining_relocate_candidate().try_next(event) {
            return Some(next);
        }

        None
    }

    fn as_joining_relocate_candidate(&self) -> JoiningRelocateCandidate {
        JoiningRelocateCandidate(self.clone())
    }

    fn failure_event(&self, event: Event) -> Self {
        Self {
            failure: Some(event),
            ..self.clone()
        }
    }
}


// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::state::*;
use crate::utilities::{
    Event, GenesisPfxInfo, LocalEvent, Name, ProofRequest, ProofSource, Rpc, SectionInfo,
};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct JoiningRelocateCandidate(pub JoiningState);

impl JoiningRelocateCandidate {
    pub fn start_event_loop(&self, new_section: SectionInfo) -> Self {
        self.store_destination_members(new_section)
            .send_connection_info_requests()
            .start_resend_info_timeout()
            .start_refused_timeout()
    }

    pub fn try_next(&self, event: Event) -> Option<JoiningState> {
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

    fn store_destination_members(&self, section: SectionInfo) -> Self {
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

    fn connect_and_send_candidate_info(&self, source: Name, _connect_info: i32) -> Self {
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

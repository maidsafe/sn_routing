// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// This is used two ways: inline tests, and integration tests (with mock).
// There's no point configuring each item which is only used in one of these.

use itertools::Itertools;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::rc::Rc;

use crate::utilities::{
    Attributes, Candidate, ChangeElder, GenesisPfxInfo, LocalEvent, Name, Node, NodeChange,
    NodeState, ParsecVote, Proof, ProofRequest, ProofSource, Rpc, Section, SectionInfo,
};

#[derive(Debug, PartialEq, Clone)]
pub struct InnerAction {
    pub our_attributes: Attributes,
    pub our_section: SectionInfo,
    pub our_current_nodes: BTreeMap<Name, NodeState>,

    pub our_votes: Vec<ParsecVote>,
    pub our_rpc: Vec<Rpc>,
    pub our_events: Vec<LocalEvent>,
    pub our_nodes: Vec<NodeChange>,

    pub shortest_prefix: Option<Section>,
    pub node_to_relocate: Option<Node>,
    pub section_members: BTreeMap<SectionInfo, Vec<Node>>,
}

impl InnerAction {
    pub fn new_with_our_attributes(name: Attributes) -> Self {
        Self {
            our_attributes: name,
            our_section: Default::default(),
            our_current_nodes: Default::default(),

            our_votes: Default::default(),
            our_rpc: Default::default(),
            our_events: Default::default(),
            our_nodes: Default::default(),

            shortest_prefix: Default::default(),
            node_to_relocate: Default::default(),
            section_members: Default::default(),
        }
    }

    fn extend_current_nodes(mut self, nodes: &[NodeState]) -> Self {
        self.our_current_nodes.extend(
            nodes
                .iter()
                .map(|state| (Name(state.node.0.name), state.clone())),
        );
        self
    }

    pub fn extend_current_nodes_with(self, value: &NodeState, nodes: &[Node]) -> Self {
        let node_states = nodes
            .iter()
            .map(|node| NodeState {
                node: node.clone(),
                ..value.clone()
            })
            .collect_vec();
        self.extend_current_nodes(&node_states)
    }

    pub fn with_section_members(mut self, section: &SectionInfo, nodes: &[Node]) -> Self {
        self.section_members
            .insert(*section, nodes.iter().cloned().collect());
        self
    }

    fn add_node(&mut self, node_state: NodeState) {
        self.our_nodes
            .push(NodeChange::AddResourceProofing(node_state.node));
        self.our_current_nodes
            .insert(Name(node_state.node.0.name), node_state);
    }

    fn remove_node(&mut self, node: Node) {
        self.our_nodes.push(NodeChange::Remove(node));
        self.our_current_nodes.remove(&Name(node.0.name));
    }

    fn set_relocating_state(&mut self, name: &Name) {
        let node = &mut self.our_current_nodes.get_mut(name).unwrap();

        node.is_relocating = true;
        self.our_nodes.push(NodeChange::Relocating(node.node));
    }

    fn set_online_state(&mut self, name: &Name) {
        let node = &mut self.our_current_nodes.get_mut(name).unwrap();

        node.is_resource_proofing = false;
        self.our_nodes.push(NodeChange::Online(node.node));
    }

    fn set_elder_state(&mut self, name: &Name, value: bool) {
        let node = &mut self.our_current_nodes.get_mut(name).unwrap();

        node.is_elder = value;
        self.our_nodes.push(NodeChange::Elder(node.node, value));
    }

    fn set_section_info(&mut self, section: SectionInfo) {
        self.our_section = section;
    }
}

#[derive(Clone)]
pub struct Action(Rc<RefCell<InnerAction>>);

impl Action {
    pub fn new(inner: InnerAction) -> Self {
        Action(Rc::new(RefCell::new(inner)))
    }

    pub fn inner(&self) -> InnerAction {
        (*self.0.borrow()).clone()
    }

    pub fn remove_processed_state(&self) {
        let inner = &mut self.0.borrow_mut();

        inner.our_votes.clear();
        inner.our_rpc.clear();
        inner.our_nodes.clear();
        inner.our_events.clear();
    }

    pub fn vote_parsec(&self, vote: ParsecVote) {
        self.0.borrow_mut().our_votes.push(vote);
    }

    pub fn send_rpc(&self, rpc: Rpc) {
        self.0.borrow_mut().our_rpc.push(rpc);
    }

    pub fn schedule_event(&self, event: LocalEvent) {
        self.0.borrow_mut().our_events.push(event);
    }

    pub fn add_node_ressource_proofing(&self, candidate: Candidate) {
        let state = NodeState {
            node: Node(candidate.0),
            is_resource_proofing: true,
            ..NodeState::default()
        };
        self.0.borrow_mut().add_node(state);
    }

    pub fn set_candidate_online_state(&self, candidate: Candidate) {
        self.0
            .borrow_mut()
            .set_online_state(&Name(candidate.0.name));
    }

    pub fn remove_node(&self, candidate: Candidate) {
        self.0.borrow_mut().remove_node(Node(candidate.0));
    }

    pub fn check_shortest_prefix(&self) -> Option<Section> {
        self.0.borrow().shortest_prefix
    }

    pub fn check_elder(&self) -> Option<ChangeElder> {
        let inner = &self.0.borrow();
        let our_current_nodes = &inner.our_current_nodes;

        let (new_elders, ex_elders, _elders) = {
            let mut sorted_values = our_current_nodes
                .values()
                .cloned()
                .sorted_by(|left, right| {
                    left.is_relocating
                        .cmp(&right.is_relocating)
                        .then(left.node.0.age.cmp(&right.node.0.age).reverse())
                        .then(left.node.0.name.cmp(&right.node.0.name))
                })
                .collect_vec();
            let elder_size = std::cmp::min(3, sorted_values.len());
            let adults = sorted_values.split_off(elder_size);

            let new_elders = sorted_values
                .iter()
                .filter(|elder| !elder.is_elder)
                .cloned()
                .collect_vec();
            let ex_elders = adults
                .iter()
                .filter(|elder| elder.is_elder)
                .cloned()
                .collect_vec();

            (new_elders, ex_elders, sorted_values)
        };

        let changes = new_elders
            .iter()
            .map(|elder| (elder, true))
            .chain(ex_elders.iter().map(|elder| (elder, false)))
            .map(|(elder, new_is_elder)| (elder.node, new_is_elder))
            .collect_vec();

        if changes.is_empty() {
            None
        } else {
            Some(ChangeElder {
                changes,
                new_section: SectionInfo(inner.our_section.0, inner.our_section.1 + 1),
            })
        }
    }

    pub fn get_elder_change_votes(&self, change_elder: &ChangeElder) -> Vec<ParsecVote> {
        change_elder
            .changes
            .iter()
            .map(|(node, new_is_elder)| match new_is_elder {
                true => ParsecVote::AddElderNode(*node),
                false => ParsecVote::RemoveElderNode(*node),
            })
            .chain(std::iter::once(ParsecVote::NewSectionInfo(
                change_elder.new_section,
            )))
            .collect_vec()
    }

    pub fn mark_elder_change(&self, change_elder: ChangeElder) {
        for (node, new_is_elder) in &change_elder.changes {
            self.0
                .borrow_mut()
                .set_elder_state(&Name(node.0.name), *new_is_elder);
        }
        self.0
            .borrow_mut()
            .set_section_info(change_elder.new_section);
    }

    pub fn get_relocating_candidate(&self) -> Candidate {
        let inner = &self.0.borrow();

        if let Some(relocating) = inner
            .our_current_nodes
            .values()
            .find(|state| state.is_relocating)
        {
            return Candidate(relocating.node.0);
        }

        match &inner.node_to_relocate {
            Some(Node(val)) => Candidate(*val),
            None => panic!("node_to_relocate not setup"),
        }
    }

    pub fn is_elder_state(&self, candidate: Candidate) -> bool {
        self.0
            .borrow()
            .our_current_nodes
            .get(&Name(candidate.0.name))
            .unwrap()
            .is_elder
    }

    pub fn is_candidate_relocating_state(&self, candidate: Candidate) -> bool {
        self.0
            .borrow()
            .our_current_nodes
            .get(&Name(candidate.0.name))
            .unwrap()
            .is_relocating
    }

    pub fn is_our_name(&self, name: Name) -> bool {
        self.our_name() == name
    }

    pub fn our_name(&self) -> Name {
        Name(self.0.borrow().our_attributes.name)
    }

    pub fn send_node_approval_rpc(&self, candidate: Candidate) {
        let section = GenesisPfxInfo(self.0.borrow().our_section);
        self.send_rpc(Rpc::NodeApproval(candidate, section));
    }

    pub fn set_candidate_relocating_state(&self, candidate: Candidate) {
        self.0
            .borrow_mut()
            .set_relocating_state(&Name(candidate.0.name));
    }

    pub fn send_relocate_response_rpc(&self, candidate: Candidate) {
        let section = self.0.borrow().our_section;
        self.send_rpc(Rpc::RelocateResponse(candidate, section));
    }

    pub fn send_candidate_relocated_info(&self, candidate: Candidate, section: SectionInfo) {
        self.send_rpc(Rpc::RelocatedInfo(candidate, section));
    }

    pub fn send_candidate_proof_request(&self, candidate: Candidate) {
        let source = self.our_name();
        let proof = ProofRequest { value: source.0 };
        self.send_rpc(Rpc::ResourceProof {
            candidate,
            proof,
            source,
        });
    }

    pub fn send_candidate_proof_receipt(&self, candidate: Candidate) {
        let source = self.our_name();
        self.send_rpc(Rpc::ResourceProofReceipt { candidate, source });
    }

    pub fn start_compute_resource_proof(&self, source: Name, _proof: ProofRequest) {
        self.schedule_event(LocalEvent::ComputeResourceProofForElder(
            source,
            ProofSource(2),
        ));
    }

    pub fn get_section_members(&self, section_info: &SectionInfo) -> Vec<Node> {
        self.0
            .borrow()
            .section_members
            .get(section_info)
            .unwrap()
            .clone()
    }

    pub fn send_connection_info_request(&self, destination: Name) {
        let source = self.our_name();
        self.send_rpc(Rpc::ConnectionInfoRequest {
            source,
            destination,
            connection_info: source.0,
        });
    }

    pub fn send_candidate_info(&self, destination: Name) {
        let candidate = Candidate(self.0.borrow().our_attributes);
        self.send_rpc(Rpc::CandidateInfo {
            candidate,
            destination,
            valid: true,
        });
    }

    pub fn send_resource_proof_response(&self, destination: Name, proof: Proof) {
        let candidate = Candidate(self.0.borrow().our_attributes);
        self.send_rpc(Rpc::ResourceProofResponse {
            candidate,
            destination,
            proof,
        });
    }
}

impl Default for Action {
    fn default() -> Action {
        Action::new(InnerAction::new_with_our_attributes(Attributes::default()))
    }
}

impl Debug for Action {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.0.borrow().fmt(formatter)
    }
}

impl PartialEq for Action {
    fn eq(&self, other: &Self) -> bool {
        self.0.borrow().eq(&*other.0.borrow())
    }
}

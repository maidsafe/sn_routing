use itertools::Itertools;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display, Formatter};
use std::rc::Rc;

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
        self.0
            .as_check_and_process_elder_change(&CheckAndProcessElderChangeCaller::TopLevelDst)
            .start_event_loop()
            .0
            .as_top_level_dst()
    }

    fn transition_exit_check_and_process_elder_change(&self) -> Self {
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
            Event::Rpc(Rpc::CandidateInfo { candidate, valid }) => {
                self.try_rpc_info(candidate, valid)
            }
            Event::Rpc(Rpc::ResourceProofResponse { candidate, proof }) => {
                self.try_rpc_proof(candidate, proof)
            }
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
        self.exit_event_loop()
    }

    fn remove_node(&self) -> Self {
        self.0.action.remove_node(self.candidate());
        self.exit_event_loop()
    }

    fn send_relocate_response_rpc(&self) -> Self {
        self.0
            .action
            .send_rpc(Rpc::RelocateResponse(self.candidate()));
        self.clone()
    }

    fn send_resource_proof_rpc(&self) -> Self {
        self.0.action.send_rpc(Rpc::ResourceProof(self.candidate()));
        self.clone()
    }

    fn send_resource_proof_receipt_rpc(&self) -> Self {
        self.0
            .action
            .send_rpc(Rpc::ResourceProofReceipt(self.candidate()));
        self.clone()
    }

    fn candidate(&self) -> Candidate {
        self.routine_state().candidate
    }
}

#[derive(Debug, PartialEq, Clone)]
struct CheckAndProcessElderChange(State, CheckAndProcessElderChangeCaller);

// CheckAndProcessElderChange Sub Routine
impl CheckAndProcessElderChange {
    fn start_event_loop(&self) -> Self {
        self.0
            .with_sub_routine_check_and_process_elder_change(
                &self.1,
                Some(CheckAndProcessElderChangeState {
                    wait_votes: Default::default(),
                }),
            )
            .as_check_and_process_elder_change(&self.1)
            .check_elder()
    }

    fn exit_event_loop(&self) -> Self {
        self.0
            .with_sub_routine_check_and_process_elder_change(&self.1, None)
            .transition_exit_check_and_process_elder_change(&self.1)
            .as_check_and_process_elder_change(&self.1)
    }

    fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::ParsecConsensus(vote) => self.try_consensus_elder(&vote),
            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_consensus_elder(&self, vote: &ParsecVote) -> Option<Self> {
        if !self.routine_state().wait_votes.contains(&vote) {
            return None;
        }

        let mut state = self.clone();
        let wait_votes = &mut state.mut_routine_state().wait_votes;
        wait_votes.retain(|wait_vote| wait_vote != vote);

        Some(match wait_votes.is_empty() {
            true => state.exit_event_loop(),
            false => state,
        })
    }

    fn routine_state(&self) -> &CheckAndProcessElderChangeState {
        match self
            .0
            .sub_routine_check_and_process_elder_change(&self.1)
        {
            Some(state) => state,
            _ => panic!("Expect CheckAndProcessElderChange {:?}", &self),
        }
    }

    fn mut_routine_state(&mut self) -> &mut CheckAndProcessElderChangeState {
        let clone = self.clone();
        match self
            .0
            .mut_sub_routine_check_and_process_elder_change(&self.1)
        {
            Some(state) => state,
            _ => panic!("Expect CheckAndProcessElderChange {:?}", &clone),
        }
    }

    fn check_elder(&self) -> Self {
        match self.0.action.check_elder() {
            Some(change_elder) => self.mark_and_vote_elder_change(change_elder),
            None => self.exit_event_loop(),
        }
    }

    fn mark_and_vote_elder_change(&self, change_elder: ChangeElder) -> Self {
        let mut state = self.clone();

        let votes = state.0.action.mark_and_vote_elder_change(change_elder);
        state.mut_routine_state().wait_votes.extend(votes.iter());

        state
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
            Rpc::RefuseCandidate(_) | Rpc::RelocateResponse(_) => Some(self.discard()),
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
            None => Some(self.concurrent_transition_to_check_and_process_elder_change()),
        }
    }

    fn concurrent_transition_to_check_and_process_elder_change(&self) -> Self {
        self.set_relocating_candidate(Some(self.0.action.get_relocating_candidate()))
            .set_candidate_relocating_state_if_needed()
            .0
            .as_check_and_process_elder_change(&CheckAndProcessElderChangeCaller::TopLevelSrc)
            .start_event_loop()
            .0
            .as_top_level_src()
    }

    fn transition_exit_check_and_process_elder_change(&self) -> Self {
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
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),

            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_rpc(&self, rpc: Rpc) -> Option<Self> {
        if rpc.candidate() != Some(self.candidate()) {
            return None;
        }

        match rpc {
            Rpc::RefuseCandidate(_) => Some(self.vote_parsec_refuse_candidate()),
            Rpc::RelocateResponse(_) => Some(self.vote_parsec_relocation_response()),
            _ => None,
        }
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        if vote.candidate() != Some(self.candidate()) {
            return None;
        }

        match vote {
            ParsecVote::RefuseCandidate(_) => Some(self.exit_event_loop()),
            ParsecVote::RelocateResponse(_) => Some(self.remove_node()),
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

    fn vote_parsec_refuse_candidate(&self) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::RefuseCandidate(self.candidate()));
        self.clone()
    }

    fn vote_parsec_relocation_response(&self) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::RelocateResponse(self.candidate()));
        self.clone()
    }

    fn send_expect_candidate_rpc(&self) -> Self {
        self.0
            .action
            .send_rpc(Rpc::ExpectCandidate(self.candidate()));
        self.clone()
    }

    fn remove_node(&self) -> Self {
        self.0.action.remove_node(self.candidate());
        self.exit_event_loop()
    }

    fn candidate(&self) -> Candidate {
        self.routine_state().candidate
    }
}

//////////////////
/// Utilities
//////////////////

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
struct Name(i32);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
struct Age(i32);

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Attributes {
    age: i32,
    name: i32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Candidate(Attributes);

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Node(Attributes);

#[derive(Debug, Clone, Copy, PartialEq)]
enum NodeChange {
    AddResourceProofing(Node),
    Online(Node),
    Relocating(Node),
    Remove(Node),
}

impl NodeChange {
    fn node(&self) -> Node {
        match &self {
            NodeChange::AddResourceProofing(node)
            | NodeChange::Online(node)
            | NodeChange::Relocating(node)
            | NodeChange::Remove(node) => *node,
        }
    }

    fn relocating(&self) -> bool {
        match &self {
            NodeChange::Relocating(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct NodeState {
    node: Node,
    is_elder: bool,
    is_relocating: bool,
    need_relocate: bool,
    is_resource_proofing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Section(i32);

#[derive(Debug, Clone, Copy, PartialEq)]
struct SectionInfo(i32);

#[derive(Debug, Clone, PartialEq)]
struct ChangeElder(Vec<(Node, bool)>);

#[derive(Debug, Clone, Copy, PartialEq)]
enum Proof {
    ValidPart,
    ValidEnd,
    Invalid,
}

impl Proof {
    fn is_valid(&self) -> bool {
        match self {
            Proof::ValidPart | Proof::ValidEnd => true,
            Proof::Invalid => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Event {
    Rpc(Rpc),
    ParsecConsensus(ParsecVote),
    LocalEvent(LocalEvent),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Rpc {
    RefuseCandidate(Candidate),
    RelocateResponse(Candidate),

    ExpectCandidate(Candidate),
    ResendExpectCandidate(Section, Candidate),

    ResourceProof(Candidate),
    ResourceProofReceipt(Candidate),
    ResourceProofResponse { candidate: Candidate, proof: Proof },
    CandidateInfo { candidate: Candidate, valid: bool },
}

impl Rpc {
    fn to_event(&self) -> Event {
        Event::Rpc(*self)
    }

    fn candidate(&self) -> Option<Candidate> {
        match self {
            Rpc::RefuseCandidate(candidate)
            | Rpc::RelocateResponse(candidate)
            | Rpc::ExpectCandidate(candidate)
            | Rpc::ResendExpectCandidate(_, candidate)
            | Rpc::ResourceProof(candidate)
            | Rpc::ResourceProofReceipt(candidate)
            | Rpc::ResourceProofResponse { candidate, .. }
            | Rpc::CandidateInfo { candidate, .. } => Some(*candidate),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ParsecVote {
    ExpectCandidate(Candidate),
    Online(Candidate),
    PurgeCandidate(Candidate),
    AddElderNode(Node),
    RemoveElderNode(Node),
    NewSectionInfo(SectionInfo),

    RelocationTrigger,
    RefuseCandidate(Candidate),
    RelocateResponse(Candidate),
}

impl ParsecVote {
    fn to_event(&self) -> Event {
        Event::ParsecConsensus(*self)
    }

    fn candidate(&self) -> Option<Candidate> {
        match self {
            ParsecVote::ExpectCandidate(candidate)
            | ParsecVote::Online(candidate)
            | ParsecVote::PurgeCandidate(candidate)
            | ParsecVote::RefuseCandidate(candidate)
            | ParsecVote::RelocateResponse(candidate) => Some(*candidate),

            ParsecVote::AddElderNode(_)
            | ParsecVote::RemoveElderNode(_)
            | ParsecVote::NewSectionInfo(_)
            | ParsecVote::RelocationTrigger => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum LocalEvent {
    TimeoutAccept,
    RelocationTrigger,
}

impl LocalEvent {
    fn to_event(&self) -> Event {
        Event::LocalEvent(*self)
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
struct InnerAction {
    our_current_nodes: BTreeMap<Name, NodeState>,

    our_votes: Vec<ParsecVote>,
    our_rpc: Vec<Rpc>,
    our_nodes: Vec<NodeChange>,

    shortest_prefix: Option<Section>,
    node_to_relocate: Option<Node>,
}

impl InnerAction {
    fn extend_current_nodes(mut self, nodes: &[NodeState]) -> Self {
        self.our_current_nodes.extend(
            nodes
                .iter()
                .map(|state| (Name(state.node.0.name), state.clone())),
        );
        self
    }

    fn extend_current_nodes_with(mut self, value: &NodeState, nodes: &[Node]) -> Self {
        let node_states = nodes
            .iter()
            .map(|node| NodeState {
                node: node.clone(),
                ..value.clone()
            })
            .collect_vec();
        self.extend_current_nodes(&node_states)
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
}

#[derive(Clone)]
struct Action(Rc<RefCell<InnerAction>>);

impl Action {
    fn new(inner: InnerAction) -> Self {
        Action(Rc::new(RefCell::new(inner)))
    }

    fn inner(&self) -> InnerAction {
        (*self.0.borrow()).clone()
    }

    fn remove_processed_state(&self) {
        let inner = &mut self.0.borrow_mut();
        let our_nodes_len = inner.our_nodes.len();

        inner.our_votes.clear();
        inner.our_rpc.clear();
        inner.our_nodes.clear();
    }

    fn vote_parsec(&self, vote: ParsecVote) {
        self.0.borrow_mut().our_votes.push(vote);
    }

    fn send_rpc(&self, rpc: Rpc) {
        self.0.borrow_mut().our_rpc.push(rpc);
    }

    fn add_node_ressource_proofing(&self, candidate: Candidate) {
        let state = NodeState {
            node: Node(candidate.0),
            is_resource_proofing: true,
            ..NodeState::default()
        };
        self.0.borrow_mut().add_node(state);
    }

    fn set_candidate_online_state(&self, candidate: Candidate) {
        self.0
            .borrow_mut()
            .set_online_state(&Name(candidate.0.name));
    }

    fn remove_node(&self, candidate: Candidate) {
        self.0.borrow_mut().remove_node(Node(candidate.0));
    }

    fn check_shortest_prefix(&self) -> Option<Section> {
        self.0.borrow().shortest_prefix
    }

    fn check_elder(&self) -> Option<ChangeElder> {
        let inner = &self.0.borrow();
        let our_current_nodes = &inner.our_current_nodes;

        let (new_elders, ex_elders, elders) = {
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
            Some(ChangeElder(changes))
        }
    }

    fn mark_and_vote_elder_change(&self, change_elder: ChangeElder) -> Vec<ParsecVote> {
        let votes = {
            let inner = &mut self.0.borrow_mut();
            let our_current_nodes = &mut inner.our_current_nodes;

            for (node, new_is_elder) in &change_elder.0 {
                let node_state = our_current_nodes.get_mut(&Name(node.0.name)).unwrap();
                node_state.is_elder = *new_is_elder;
            }

            change_elder
                .0
                .iter()
                .map(|(node, new_is_elder)| match new_is_elder {
                    true => ParsecVote::AddElderNode(*node),
                    false => ParsecVote::RemoveElderNode(*node),
                })
                .chain(std::iter::once(ParsecVote::NewSectionInfo(SectionInfo(1))))
                .collect_vec()
        };

        for vote in &votes {
            self.vote_parsec(*vote);
        }
        votes
    }

    fn get_relocating_candidate(&self) -> Candidate {
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

    fn is_candidate_relocating_state(&self, candidate: Candidate) -> bool {
        self.0
            .borrow()
            .our_current_nodes
            .get(&Name(candidate.0.name))
            .unwrap()
            .is_relocating
    }

    fn set_candidate_relocating_state(&self, candidate: Candidate) {
        self.0
            .borrow_mut()
            .set_relocating_state(&Name(candidate.0.name));
    }
}

impl Default for Action {
    fn default() -> Action {
        Action::new(InnerAction::default())
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

#[derive(Debug, PartialEq, Clone, Copy)]
enum CheckAndProcessElderChangeCaller {
    TopLevelDst,
    TopLevelSrc,
}

#[derive(Debug, PartialEq, Clone)]
struct CheckAndProcessElderChangeState {
    wait_votes: Vec<ParsecVote>,
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
    sub_routine_check_and_process_elder_change: Option<CheckAndProcessElderChangeState>,
}

#[derive(Debug, PartialEq, Default, Clone)]
struct SrcRoutineState {
    relocating_candidate: Option<Candidate>,
    sub_routine_check_and_process_elder_change: Option<CheckAndProcessElderChangeState>,
    sub_routine_try_relocating: Option<TryRelocatingState>,
}

// The very top level event loop deciding how the sub event loops are processed
#[derive(Debug, PartialEq, Default, Clone)]
struct State {
    action: Action,
    failure: Option<Event>,
    dst_routine: DstRoutineState,
    src_routine: SrcRoutineState,
}

impl State {
    fn try_next(&self, event: Event) -> Option<Self> {
        let dst = &self.dst_routine;
        let src = &self.src_routine;

        if dst.sub_routine_accept_as_candidate.is_some() {
            if let Some(next) = self.as_accept_as_candidate().try_next(event) {
                return Some(next);
            }
        }
        if dst.sub_routine_check_and_process_elder_change.is_some() {
            if let Some(next) = self
                .as_check_and_process_elder_change(&CheckAndProcessElderChangeCaller::TopLevelDst)
                .try_next(event)
            {
                return Some(next);
            }
        }

        if let Some(next) = self.as_top_level_dst().try_next(event) {
            return Some(next);
        }

        if src.sub_routine_check_and_process_elder_change.is_some() {
            if let Some(next) = self
                .as_check_and_process_elder_change(&CheckAndProcessElderChangeCaller::TopLevelSrc)
                .try_next(event)
            {
                return Some(next);
            }
        }

        if src.sub_routine_try_relocating.is_some() {
            if let Some(next) = self.as_try_relocating().try_next(event) {
                return Some(next);
            }
        }

        if let Some(next) = self.as_top_level_src().try_next(event) {
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

    fn as_check_and_process_elder_change(
        &self,
        caller: &CheckAndProcessElderChangeCaller,
    ) -> CheckAndProcessElderChange {
        CheckAndProcessElderChange(self.clone(), *caller)
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

    fn sub_routine_check_and_process_elder_change(
        &self,
        caller: &CheckAndProcessElderChangeCaller
    ) -> &Option<CheckAndProcessElderChangeState> {
        match caller {
            CheckAndProcessElderChangeCaller::TopLevelDst =>
                &self.dst_routine.sub_routine_check_and_process_elder_change,
            CheckAndProcessElderChangeCaller::TopLevelSrc =>
                &self.src_routine.sub_routine_check_and_process_elder_change,
        }
    }

    fn mut_sub_routine_check_and_process_elder_change(
        &mut self,
        caller: &CheckAndProcessElderChangeCaller,
    ) -> &mut Option<CheckAndProcessElderChangeState> {
        match caller {
            CheckAndProcessElderChangeCaller::TopLevelDst =>
                &mut self.dst_routine.sub_routine_check_and_process_elder_change,
            CheckAndProcessElderChangeCaller::TopLevelSrc =>
                &mut self.src_routine.sub_routine_check_and_process_elder_change,
        }
    }

    fn with_sub_routine_check_and_process_elder_change(
        &self,
        caller: &CheckAndProcessElderChangeCaller,
        sub_routine_check_and_process_elder_change: Option<CheckAndProcessElderChangeState>,
    ) -> Self {
        let mut state = self.clone();
        *state.mut_sub_routine_check_and_process_elder_change(caller) = sub_routine_check_and_process_elder_change;
        state
    }

    fn transition_exit_check_and_process_elder_change(
        &self,
        caller: &CheckAndProcessElderChangeCaller,
    ) -> State {
        match caller {
            CheckAndProcessElderChangeCaller::TopLevelDst => {
                self.as_top_level_dst()
                    .transition_exit_check_and_process_elder_change()
                    .0
            }
            CheckAndProcessElderChangeCaller::TopLevelSrc => {
                self.as_top_level_src()
                    .transition_exit_check_and_process_elder_change()
                    .0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE_1: Candidate = Candidate(Attributes { name: 1, age: 10 });
    const CANDIDATE_2: Candidate = Candidate(Attributes { name: 2, age: 10 });
    const CANDIDATE_130: Candidate = Candidate(Attributes { name: 130, age: 30 });
    const CANDIDATE_205: Candidate = Candidate(Attributes { name: 205, age: 5 });
    const SECTION_1: Section = Section(1);

    const NODE_1: Node = Node(Attributes { name: 1, age: 10 });
    const ADD_PROOFING_NODE_1: NodeChange =
        NodeChange::AddResourceProofing(Node(Attributes { name: 1, age: 10 }));
    const SET_ONLINE_NODE_1: NodeChange = NodeChange::Online(Node(Attributes { name: 1, age: 10 }));
    const REMOVE_NODE_1: NodeChange = NodeChange::Remove(Node(Attributes { name: 1, age: 10 }));

    const ADD_PROOFING_NODE_2: NodeChange =
        NodeChange::AddResourceProofing(Node(Attributes { name: 2, age: 10 }));

    const NODE_ELDER_109: Node = Node(Attributes { name: 109, age: 9 });
    const NODE_ELDER_110: Node = Node(Attributes { name: 110, age: 10 });
    const NODE_ELDER_111: Node = Node(Attributes { name: 111, age: 11 });
    const NODE_ELDER_130: Node = Node(Attributes { name: 130, age: 30 });
    const NODE_ELDER_131: Node = Node(Attributes { name: 131, age: 31 });
    const NODE_ELDER_132: Node = Node(Attributes { name: 132, age: 32 });
    const YOUNG_ADULT_205: Node = Node(Attributes { name: 205, age: 5 });
    const SECTION_INFO_1: SectionInfo = SectionInfo(1);
    const SECTION_INFO_2: SectionInfo = SectionInfo(2);

    const CANDIDATE_INFO_VALID_RPC_1: Rpc = Rpc::CandidateInfo {
        candidate: CANDIDATE_1,
        valid: true,
    };

    lazy_static! {
        static ref INNER_ACTION_YOUNG_ELDERS: InnerAction = InnerAction::default()
            .extend_current_nodes_with(
                &NodeState {
                    is_elder: true,
                    ..NodeState::default()
                },
                &[NODE_ELDER_109, NODE_ELDER_110, NODE_ELDER_111]
            )
            .extend_current_nodes_with(&NodeState::default(), &[YOUNG_ADULT_205]);
        static ref INNER_ACTION_OLD_ELDERS: InnerAction = InnerAction::default()
            .extend_current_nodes_with(
                &NodeState {
                    is_elder: true,
                    ..NodeState::default()
                },
                &[NODE_ELDER_130, NODE_ELDER_131, NODE_ELDER_132]
            )
            .extend_current_nodes_with(&NodeState::default(), &[YOUNG_ADULT_205]);
        static ref PARSEC_VOTES_SWAP_ELDER_109_NODE_1_SECTION_INFO_1: Vec<ParsecVote> = vec![
            ParsecVote::AddElderNode(NODE_1),
            ParsecVote::RemoveElderNode(NODE_ELDER_109),
            ParsecVote::NewSectionInfo(SECTION_INFO_1),
        ];
        static ref PARSEC_VOTES_SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1: Vec<ParsecVote> = vec![
            ParsecVote::AddElderNode(YOUNG_ADULT_205),
            ParsecVote::RemoveElderNode(NODE_ELDER_130),
            ParsecVote::NewSectionInfo(SECTION_INFO_1),
        ];
    }

    #[derive(Debug, PartialEq, Default, Clone)]
    struct AssertState {
        action_our_votes: Vec<ParsecVote>,
        action_our_rpcs: Vec<Rpc>,
        action_our_nodes: Vec<NodeChange>,
        dst_routine: DstRoutineState,
        src_routine: SrcRoutineState,
    }

    fn process_events(mut state: State, events: &[Event]) -> State {
        for event in events.iter().cloned() {
            state = match state.try_next(event) {
                Some(next_state) => next_state,
                None => state.failure_event(event),
            };

            if state.failure.is_some() {
                break;
            }
        }

        state
    }

    fn run_test(
        test_name: &str,
        start_state: &State,
        events: &[Event],
        expected_state: &AssertState,
    ) {
        let final_state = process_events(start_state.clone(), &events);
        let action = final_state.action.inner();

        let final_state = (
            AssertState {
                action_our_rpcs: action.our_rpc,
                action_our_votes: action.our_votes,
                action_our_nodes: action.our_nodes,
                dst_routine: final_state.dst_routine,
                src_routine: final_state.src_routine,
            },
            final_state.failure,
        );
        let expected_state = (expected_state.clone(), None);

        assert_eq!(expected_state, final_state, "{}", test_name);
    }

    fn arrange_initial_state(state: &State, events: &[Event]) -> State {
        let state = process_events(state.clone(), events);
        state.action.remove_processed_state();
        state
    }

    fn intial_state_young_elders() -> State {
        State {
            action: Action::new(INNER_ACTION_YOUNG_ELDERS.clone()),
            ..State::default()
        }
    }

    fn intial_state_old_elders() -> State {
        State {
            action: Action::new(INNER_ACTION_OLD_ELDERS.clone()),
            ..State::default()
        }
    }

    fn routine_state_accept_as_candidate(
        accept_as_candidate: AcceptAsCandidateState,
    ) -> DstRoutineState {
        DstRoutineState {
            is_processing_candidate: true,
            sub_routine_accept_as_candidate: Some(accept_as_candidate),
            ..Default::default()
        }
    }

    //////////////////
    /// Dst
    //////////////////

    #[test]
    fn test_rpc_expect_candidate() {
        run_test(
            "Get RPC ExpectCandidate",
            &intial_state_old_elders(),
            &[Rpc::ExpectCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::ExpectCandidate(CANDIDATE_1)],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate() {
        run_test(
            "Get Parsec ExpectCandidate",
            &intial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_nodes: vec![ADD_PROOFING_NODE_1],
                action_our_rpcs: vec![Rpc::RelocateResponse(CANDIDATE_1)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![CANDIDATE_INFO_VALID_RPC_1.to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ResourceProof(CANDIDATE_1)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info_twice() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![CANDIDATE_INFO_VALID_RPC_1.to_event()],
            &AssertState {
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_invalid_candidate_info() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![Rpc::CandidateInfo {
                candidate: CANDIDATE_1,
                valid: false,
            }
            .to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::PurgeCandidate(CANDIDATE_1)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_time_out() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![LocalEvent::TimeoutAccept.to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::PurgeCandidate(CANDIDATE_1)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_wrong_candidate_info() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![Rpc::CandidateInfo {
                candidate: CANDIDATE_2,
                valid: true,
            }
            .to_event()],
            &AssertState {
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info_then_part_proof() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::ResourceProofResponse {
                candidate: CANDIDATE_1,
                proof: Proof::ValidPart,
            }
            .to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ResourceProofReceipt(CANDIDATE_1)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info_then_end_proof() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::ResourceProofResponse {
                candidate: CANDIDATE_1,
                proof: Proof::ValidEnd,
            }
            .to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::Online(CANDIDATE_1)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: true,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info_then_end_proof_twice() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
                Rpc::ResourceProofResponse {
                    candidate: CANDIDATE_1,
                    proof: Proof::ValidEnd,
                }
                .to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::ResourceProofResponse {
                candidate: CANDIDATE_1,
                proof: Proof::ValidEnd,
            }
            .to_event()],
            &AssertState {
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: true,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info_then_invalid_proof() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::ResourceProofResponse {
                candidate: CANDIDATE_1,
                proof: Proof::Invalid,
            }
            .to_event()],
            &AssertState {
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_candidate_info_then_end_proof_wrong_candidate() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::ResourceProofResponse {
                candidate: CANDIDATE_2,
                proof: Proof::ValidEnd,
            }
            .to_event()],
            &AssertState {
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: true,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_purge_and_online_for_wrong_candidate() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![
                ParsecVote::Online(CANDIDATE_2).to_event(),
                ParsecVote::PurgeCandidate(CANDIDATE_2).to_event(),
            ],
            &AssertState {
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_no_elder_change() {
        let initial_state = arrange_initial_state(
            &intial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (No Elder Change)",
            &initial_state,
            &[ParsecVote::Online(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_nodes: vec![SET_ONLINE_NODE_1],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &vec![ParsecVote::Online(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_votes: PARSEC_VOTES_SWAP_ELDER_109_NODE_1_SECTION_INFO_1.clone(),
                action_our_nodes: vec![SET_ONLINE_NODE_1],
                dst_routine: DstRoutineState {
                    is_processing_candidate: true,
                    sub_routine_check_and_process_elder_change: Some(
                        CheckAndProcessElderChangeState {
                            wait_votes: PARSEC_VOTES_SWAP_ELDER_109_NODE_1_SECTION_INFO_1.clone(),
                        },
                    ),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_get_wrong_votes() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change) RemoveElderNode for wrong elder,\
            AddElderNode for wrong node, NewSectionInfo for wrong section",
            &initial_state,
            &vec![
                ParsecVote::RemoveElderNode(NODE_1).to_event(),
                ParsecVote::AddElderNode(NODE_ELDER_109).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_2).to_event(),
            ],
            &AssertState {
                dst_routine: DstRoutineState {
                    is_processing_candidate: true,
                    sub_routine_check_and_process_elder_change: Some(
                        CheckAndProcessElderChangeState {
                            wait_votes: PARSEC_VOTES_SWAP_ELDER_109_NODE_1_SECTION_INFO_1.clone(),
                        },
                    ),
            ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_remove_elder() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change) then RemoveElderNode",
            &initial_state,
            &vec![ParsecVote::RemoveElderNode(NODE_ELDER_109).to_event()],
            &AssertState {
                dst_routine: DstRoutineState {
                    is_processing_candidate: true,
                    sub_routine_check_and_process_elder_change: Some(
                        CheckAndProcessElderChangeState {
                            wait_votes: vec![
                                ParsecVote::AddElderNode(NODE_1),
                                ParsecVote::NewSectionInfo(SECTION_INFO_1),
                            ],
                        },
                    ),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_complete_elder() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::RemoveElderNode(NODE_ELDER_109).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change) then \
             RemoveElderNode, AddElderNode, NewSectionInfo",
            &initial_state,
            &[
                ParsecVote::AddElderNode(NODE_1).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_1).to_event(),
            ],
            &AssertState::default(),
        );
    }

    #[test]
    fn test_parsec_expect_candidate_when_candidate_completed_with_elder_change() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::RemoveElderNode(NODE_ELDER_109).to_event(),
                ParsecVote::AddElderNode(NODE_1).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_1).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate after first candidate completed \
             with elder change",
            &initial_state,
            &[ParsecVote::ExpectCandidate(CANDIDATE_2).to_event()],
            &&AssertState {
                action_our_nodes: vec![ADD_PROOFING_NODE_2],
                action_our_rpcs: vec![Rpc::RelocateResponse(CANDIDATE_2)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_2,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_purge() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![ParsecVote::PurgeCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_nodes: vec![REMOVE_NODE_1],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_twice() {
        let initial_state = arrange_initial_state(
            &intial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            &"Get Parsec 2 ExpectCandidate",
            &initial_state,
            &vec![ParsecVote::ExpectCandidate(CANDIDATE_2).to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::RefuseCandidate(CANDIDATE_2)],
                dst_routine: routine_state_accept_as_candidate(AcceptAsCandidateState {
                    candidate: CANDIDATE_1,
                    got_candidate_info: false,
                    voted_online: false,
                }),
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_with_shorter_known_section() {
        let initial_state = State {
            action: Action::new(InnerAction {
                shortest_prefix: Some(SECTION_1),
                ..INNER_ACTION_OLD_ELDERS.clone()
            }),
            ..State::default()
        };

        run_test(
            &"Get Parsec ExpectCandidate with a shorter known section",
            &initial_state,
            &vec![ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ResendExpectCandidate(SECTION_1, CANDIDATE_1)],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_unexpected_purge_online() {
        run_test(
            "Get unexpected Parsec consensus Online and PurgeCandidate. \
             Candidate may have trigger both vote: only consider the first",
            &intial_state_old_elders(),
            &[
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::PurgeCandidate(CANDIDATE_1).to_event(),
            ],
            &AssertState::default(),
        );
    }

    #[test]
    fn test_rpc_unexpected_candidate_info_resource_proof_response() {
        run_test(
            "Get unexpected RPC CandidateInfo and ResourceProofResponse. \
             Candidate RPC may arrive after candidate was pured or accepted",
            &intial_state_old_elders(),
            &[
                Rpc::CandidateInfo {
                    candidate: CANDIDATE_1,
                    valid: true,
                }
                .to_event(),
                Rpc::ResourceProofResponse {
                    candidate: CANDIDATE_1,
                    proof: Proof::ValidEnd,
                }
                .to_event(),
            ],
            &AssertState::default(),
        );
    }

    //////////////////
    /// Scr
    //////////////////
    #[test]
    fn test_local_event_relocation_trigger() {
        run_test(
            "Get RPC ExpectCandidate",
            &intial_state_old_elders(),
            &[LocalEvent::RelocationTrigger.to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RelocationTrigger],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger() {
        let initial_state = State {
            action: Action::new(InnerAction {
                node_to_relocate: Some(YOUNG_ADULT_205),
                ..INNER_ACTION_OLD_ELDERS.clone()
            }),
            ..State::default()
        };

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocationTrigger.to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_205.clone())],
                action_our_nodes: vec![NodeChange::Relocating(YOUNG_ADULT_205.clone())],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205.clone()),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocate_trigger_elder_change() {
        let initial_state = State {
            action: Action::new(InnerAction {
                node_to_relocate: Some(NODE_ELDER_130),
                ..INNER_ACTION_OLD_ELDERS.clone()
            }),
            ..State::default()
        };

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &vec![ParsecVote::RelocationTrigger.to_event()],
            &AssertState {
                action_our_nodes: vec![NodeChange::Relocating(NODE_ELDER_130.clone())],
                action_our_votes: PARSEC_VOTES_SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.clone(),
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_130.clone()),
                    sub_routine_check_and_process_elder_change: Some(
                        CheckAndProcessElderChangeState {
                            wait_votes: PARSEC_VOTES_SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1
                                .clone(),
                        },
                    ),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocate_trigger_elder_change_complete() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(NODE_ELDER_130),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &vec![
                ParsecVote::RemoveElderNode(NODE_ELDER_130).to_event(),
                ParsecVote::AddElderNode(YOUNG_ADULT_205).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_1).to_event(),
            ],
            &AssertState {
                //action_our_nodes: vec![ADD_PROOFING_NODE_1],
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_130.clone())],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(Candidate(NODE_ELDER_130.0)),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_130.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_refuse_candidate_rpc() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(YOUNG_ADULT_205),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[Rpc::RefuseCandidate(CANDIDATE_205.clone()).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RefuseCandidate(CANDIDATE_205.clone())],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205.clone()),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_relocate_response_rpc() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(YOUNG_ADULT_205),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[Rpc::RelocateResponse(CANDIDATE_205).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RelocateResponse(CANDIDATE_205.clone())],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205.clone()),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_accept() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(YOUNG_ADULT_205),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocateResponse(CANDIDATE_205).to_event()],
            &AssertState {
                action_our_nodes: vec![NodeChange::Remove(YOUNG_ADULT_205.clone())],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_refuse() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(YOUNG_ADULT_205),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RefuseCandidate(CANDIDATE_205).to_event()],
            &AssertState::default(),
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_refuse_trigger_again() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(YOUNG_ADULT_205),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[
                ParsecVote::RelocationTrigger.to_event(),
                ParsecVote::RefuseCandidate(CANDIDATE_205).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocationTrigger.to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_205.clone())],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205.clone()),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_elder_change_refuse_trigger_again() {
        let initial_state = arrange_initial_state(
            &State {
                action: Action::new(InnerAction {
                    node_to_relocate: Some(NODE_ELDER_130),
                    ..INNER_ACTION_OLD_ELDERS.clone()
                }),
                ..State::default()
            },
            &[
                ParsecVote::RelocationTrigger.to_event(),
                ParsecVote::RemoveElderNode(NODE_ELDER_130).to_event(),
                ParsecVote::AddElderNode(YOUNG_ADULT_205).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_1).to_event(),
                ParsecVote::RefuseCandidate(CANDIDATE_130).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocationTrigger.to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_130.clone())],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_130.clone()),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_130.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_unexpected_refuse_candidate() {
        run_test(
            "Get RPC ExpectCandidate",
            &intial_state_old_elders(),
            &[Rpc::RefuseCandidate(CANDIDATE_205.clone()).to_event()],
            &AssertState::default(),
        );
    }

    #[test]
    fn test_unexpected_relocate_response() {
        run_test(
            "Get RPC ExpectCandidate",
            &intial_state_old_elders(),
            &[Rpc::RefuseCandidate(CANDIDATE_205.clone()).to_event()],
            &AssertState::default(),
        );
    }
}

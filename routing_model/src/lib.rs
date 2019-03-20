use std::cell::RefCell;
use std::fmt::{self, Debug, Display, Formatter};
use std::rc::Rc;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate unwrap;

#[derive(Debug, PartialEq, Default, Clone)]
struct TopLevelDst(State);

impl TopLevelDst {
    fn try_next(&self, event: Event) -> Option<State> {
        match event {
            Event::Rpc(rpc) => self.try_rpc(rpc),
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(_) => return Some(self.0.failure_event(event)),
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
            .as_accept_ass_candidate()
            .start_event_loop(candidate)
            .0
            .as_top_level_dst()
    }

    fn transition_exit_accept_as_candidate(&self, vote: ParsecVote) -> Self {
        self.0
            .as_process_candidate_consensus()
            .start_event_loop(vote)
            .0
            .as_top_level_dst()
    }

    fn transition_exit_process_candidate_consensus(&self) -> Self {
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
            .as_accept_ass_candidate()
            .send_relocate_response_rpc(candidate)
    }

    fn exit_event_loop(&self, vote: ParsecVote) -> Self {
        self.0
            .with_dst_sub_routine_accept_as_candidate(None)
            .as_top_level_dst()
            .transition_exit_accept_as_candidate(vote)
            .0
            .as_accept_ass_candidate()
    }

    fn try_next(&self, event: Event) -> Option<State> {
        let routine_state = self.routine_state();
        match event {
            Event::Rpc(Rpc::CandidateInfo { candidate, valid }) => {
                self.try_rpc_info(candidate, valid)
            }
            Event::Rpc(Rpc::ResourceProofResponse { candidate, proof }) => {
                self.try_rpc_proof(candidate, proof)
            }
            Event::ParsecConsensus(vote) => self.try_consensus(vote),
            Event::LocalEvent(LocalEvent::TimeoutAccept) => {
                Some(self.vote_parsec_purge_candidate(routine_state.candidate))
            }
            // Delegate to other event loops
            _ => None,
        }
        .map(|state| state.0)
    }

    fn try_rpc_info(&self, candidate: Candidate, valid: bool) -> Option<Self> {
        let routine_state = self.routine_state();
        if candidate != routine_state.candidate || routine_state.got_candidate_info {
            return None;
        }

        Some(match valid {
            true => self
                .set_got_candidate_info(true)
                .send_resource_proof_rpc(candidate),
            false => self.vote_parsec_purge_candidate(candidate),
        })
    }

    fn try_rpc_proof(&self, candidate: Candidate, proof: Proof) -> Option<Self> {
        let routine_state = self.routine_state();
        if candidate != routine_state.candidate || routine_state.voted_online || !proof.is_valid() {
            return None;
        }

        Some(match proof {
            Proof::ValidPart => self.send_resource_proof_receipt_rpc(candidate),
            Proof::ValidEnd => self
                .set_voted_online(true)
                .vote_parsec_online_candidate(candidate),
            Proof::Invalid => panic!("Only valid proof"),
        })
    }

    fn try_consensus(&self, vote: ParsecVote) -> Option<Self> {
        let routine_state = self.routine_state();
        if vote.candidate() != Some(routine_state.candidate) {
            return None;
        }

        match vote {
            ParsecVote::Online(_) | ParsecVote::PurgeCandidate(_) => {
                Some(self.exit_event_loop(vote))
            }
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

    fn vote_parsec_purge_candidate(&self, candidate: Candidate) -> Self {
        self.0
            .action
            .vote_parsec(ParsecVote::PurgeCandidate(candidate));
        self.clone()
    }

    fn vote_parsec_online_candidate(&self, candidate: Candidate) -> Self {
        self.0.action.vote_parsec(ParsecVote::Online(candidate));
        self.clone()
    }

    fn send_relocate_response_rpc(&self, candidate: Candidate) -> Self {
        self.0.action.send_rpc(Rpc::RelocateResponse(candidate));
        self.clone()
    }

    fn send_resource_proof_rpc(&self, candidate: Candidate) -> Self {
        self.0.action.send_rpc(Rpc::ResourceProof(candidate));
        self.clone()
    }

    fn send_resource_proof_receipt_rpc(&self, candidate: Candidate) -> Self {
        self.0.action.send_rpc(Rpc::ResourceProofReceipt(candidate));
        self.clone()
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
struct ProcessCandidateConsensus(State);

// ProcessCandidateConsensus Sub Routine
impl ProcessCandidateConsensus {
    fn start_event_loop(&self, vote: ParsecVote) -> Self {
        self.0
            .with_dst_sub_routine_process_candidate_consensus(Some(
                ProcessCandidateConsensusState::default(),
            ))
            .as_process_candidate_consensus()
            .check_consensus(vote)
    }

    fn exit_event_loop(&self) -> Self {
        self.0
            .with_dst_sub_routine_process_candidate_consensus(None)
            .as_top_level_dst()
            .transition_exit_process_candidate_consensus()
            .0
            .as_process_candidate_consensus()
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

    fn routine_state(&self) -> &ProcessCandidateConsensusState {
        match &self.0.dst_routine.sub_routine_process_candidate_consensus {
            Some(state) => state,
            _ => panic!("Expect ProcessCandidateConsensus {:?}", &self),
        }
    }

    fn mut_routine_state(&mut self) -> &mut ProcessCandidateConsensusState {
        let clone = self.clone();
        match &mut self.0.dst_routine.sub_routine_process_candidate_consensus {
            Some(state) => state,
            _ => panic!("Expect ProcessCandidateConsensus {:?}", &clone),
        }
    }

    fn check_consensus(&self, vote: ParsecVote) -> Self {
        match vote {
            ParsecVote::Online(candidate) => self.add_node(candidate),
            ParsecVote::PurgeCandidate(_) => self.exit_event_loop(),
            vote => panic!("Only expect Online and purge{:?}", vote),
        }
    }

    fn add_node(&self, candidate: Candidate) -> Self {
        self.0.action.add_node(candidate);
        self.check_elder()
    }

    fn check_elder(&self) -> Self {
        match self.0.action.check_elder() {
            Some(votes) => self.vote_swap_new_elder(votes),
            None => self.exit_event_loop(),
        }
    }

    fn vote_swap_new_elder(&self, votes: Vec<ParsecVote>) -> Self {
        let mut state = self.clone();

        votes
            .iter()
            .for_each(|vote| state.0.action.vote_parsec(*vote));
        state.mut_routine_state().wait_votes.extend(votes.iter());

        state
    }
}

//////////////////
/// Utilities
//////////////////
#[derive(Debug, Clone, Copy, PartialEq)]
struct Candidate(i32);

#[derive(Debug, Clone, Copy, PartialEq)]
struct Node(i32);

#[derive(Debug, Clone, Copy, PartialEq)]
struct Section(i32);

#[derive(Debug, Clone, Copy, PartialEq)]
struct SectionInfo(i32);

#[derive(Debug, Clone, Copy, PartialEq)]
struct ChangeElder {
    add: ParsecVote,
    remove: ParsecVote,
    new_section: ParsecVote,
}

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
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ParsecVote {
    ExpectCandidate(Candidate),
    Online(Candidate),
    PurgeCandidate(Candidate),
    AddElderNode(Node),
    RemoveElderNode(Node),
    NewSectionInfo(SectionInfo),
}

impl ParsecVote {
    fn to_event(&self) -> Event {
        Event::ParsecConsensus(*self)
    }

    fn candidate(&self) -> Option<Candidate> {
        match self {
            ParsecVote::ExpectCandidate(candidate)
            | ParsecVote::Online(candidate)
            | ParsecVote::PurgeCandidate(candidate) => Some(*candidate),

            ParsecVote::AddElderNode(_)
            | ParsecVote::RemoveElderNode(_)
            | ParsecVote::NewSectionInfo(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum LocalEvent {
    TimeoutAccept,
}

impl LocalEvent {
    fn to_event(&self) -> Event {
        Event::LocalEvent(*self)
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
struct InnerAction {
    our_votes: Vec<ParsecVote>,
    our_rpc: Vec<Rpc>,
    our_nodes: Vec<Node>,

    shortest_prefix: Option<Section>,
    elder_to_replace: Vec<(Node, SectionInfo)>,
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

        inner.elder_to_replace.drain(0..our_nodes_len);
    }

    fn vote_parsec(&self, vote: ParsecVote) {
        self.0.borrow_mut().our_votes.push(vote);
    }

    fn send_rpc(&self, rpc: Rpc) {
        self.0.borrow_mut().our_rpc.push(rpc);
    }

    fn add_node(&self, candidate: Candidate) {
        let new_node = Node(candidate.0);
        self.0.borrow_mut().our_nodes.push(new_node);
    }

    fn check_shortest_prefix(&self) -> Option<Section> {
        self.0.borrow().shortest_prefix
    }

    fn check_elder(&self) -> Option<Vec<ParsecVote>> {
        let elder_to_replace = &self.0.borrow().elder_to_replace;
        let our_nodes = &self.0.borrow().our_nodes;

        if let Some(add) = our_nodes.last() {
            if let Some((remove, new_section)) = elder_to_replace.get(our_nodes.len() - 1) {
                return Some(vec![
                    ParsecVote::AddElderNode(*add),
                    ParsecVote::RemoveElderNode(*remove),
                    ParsecVote::NewSectionInfo(*new_section),
                ]);
            }
        }
        None
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

#[derive(Debug, PartialEq, Default, Clone)]
struct ProcessCandidateConsensusState {
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

#[derive(Debug, PartialEq, Default, Clone)]
struct RoutineState {
    is_processing_candidate: bool,
    sub_routine_accept_as_candidate: Option<AcceptAsCandidateState>,
    sub_routine_process_candidate_consensus: Option<ProcessCandidateConsensusState>,
}

// The very top level event loop deciding how the sub event loops are processed
#[derive(Debug, PartialEq, Default, Clone)]
struct State {
    action: Action,
    failure: Option<Event>,
    dst_routine: RoutineState,
}

impl State {
    fn try_next(&self, event: Event) -> Option<Self> {
        let dst = &self.dst_routine;

        if dst.sub_routine_accept_as_candidate.is_some() {
            if let Some(next) = self.as_accept_ass_candidate().try_next(event) {
                return Some(next);
            }
        }
        if dst.sub_routine_process_candidate_consensus.is_some() {
            if let Some(next) = self.as_process_candidate_consensus().try_next(event) {
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

    fn as_accept_ass_candidate(&self) -> AcceptAsCandidate {
        AcceptAsCandidate(self.clone())
    }

    fn as_process_candidate_consensus(&self) -> ProcessCandidateConsensus {
        ProcessCandidateConsensus(self.clone())
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
            dst_routine: RoutineState {
                sub_routine_accept_as_candidate,
                ..self.dst_routine.clone()
            },
            ..self.clone()
        }
    }

    fn with_dst_sub_routine_process_candidate_consensus(
        &self,
        sub_routine_process_candidate_consensus: Option<ProcessCandidateConsensusState>,
    ) -> Self {
        Self {
            dst_routine: RoutineState {
                sub_routine_process_candidate_consensus,
                ..self.dst_routine.clone()
            },
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE_1: Candidate = Candidate(1);
    const CANDIDATE_2: Candidate = Candidate(2);
    const SECTION_1: Section = Section(1);
    const NODE_1: Node = Node(1);
    const NODE_ELDER_100: Node = Node(100);
    const SECTION_INFO_1: SectionInfo = SectionInfo(1);
    const SECTION_INFO_2: SectionInfo = SectionInfo(2);

    const CANDIDATE_INFO_VALID_RPC_1: Rpc = Rpc::CandidateInfo {
        candidate: CANDIDATE_1,
        valid: true,
    };

    lazy_static! {
        static ref INNER_ACTION_SWAP_FIRST_WITH_ELDER_100_SECTION_INFO_1: InnerAction =
            InnerAction {
                elder_to_replace: vec![(NODE_ELDER_100, SECTION_INFO_1)],
                ..InnerAction::default()
            };
        static ref PARSEC_VOTES_SWAP_ELDER_100_NODE_1_SECTION_INFO_1: Vec<ParsecVote> = vec![
            ParsecVote::AddElderNode(NODE_1),
            ParsecVote::RemoveElderNode(NODE_ELDER_100),
            ParsecVote::NewSectionInfo(SECTION_INFO_1),
        ];
    }

    #[derive(Debug, PartialEq, Default, Clone)]
    struct AssertState {
        action_our_votes: Vec<ParsecVote>,
        action_our_rpcs: Vec<Rpc>,
        action_our_nodes: Vec<Node>,
        dst_routine: RoutineState,
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

    fn intial_state_elder_100_to_swap() -> State {
        State {
            action: Action::new(INNER_ACTION_SWAP_FIRST_WITH_ELDER_100_SECTION_INFO_1.clone()),
            ..State::default()
        }
    }

    fn routine_state_accept_as_candidate(
        accept_as_candidate: AcceptAsCandidateState,
    ) -> RoutineState {
        RoutineState {
            is_processing_candidate: true,
            sub_routine_accept_as_candidate: Some(accept_as_candidate),
            ..Default::default()
        }
    }

    #[test]
    fn test_rpc_expect_candidate() {
        run_test(
            "Get RPC ExpectCandidate",
            &State::default(),
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
            &State::default(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
            &AssertState {
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &intial_state_elder_100_to_swap(),
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
            &State::default(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (No Elder Change)",
            &initial_state,
            &[ParsecVote::Online(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_nodes: vec![NODE_1],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change() {
        let initial_state = arrange_initial_state(
            &intial_state_elder_100_to_swap(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &vec![ParsecVote::Online(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_votes: PARSEC_VOTES_SWAP_ELDER_100_NODE_1_SECTION_INFO_1.clone(),
                action_our_nodes: vec![NODE_1],
                dst_routine: RoutineState {
                    is_processing_candidate: true,
                    sub_routine_process_candidate_consensus: Some(ProcessCandidateConsensusState {
                        wait_votes: PARSEC_VOTES_SWAP_ELDER_100_NODE_1_SECTION_INFO_1.clone(),
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_get_wrong_votes() {
        let initial_state = arrange_initial_state(
            &intial_state_elder_100_to_swap(),
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
                ParsecVote::AddElderNode(NODE_ELDER_100).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_2).to_event(),
            ],
            &AssertState {
                dst_routine: RoutineState {
                    is_processing_candidate: true,
                    sub_routine_process_candidate_consensus: Some(
                        ProcessCandidateConsensusState {
                            wait_votes: PARSEC_VOTES_SWAP_ELDER_100_NODE_1_SECTION_INFO_1.clone(),
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
            &intial_state_elder_100_to_swap(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change) then RemoveElderNode",
            &initial_state,
            &vec![ParsecVote::RemoveElderNode(NODE_ELDER_100).to_event()],
            &AssertState {
                dst_routine: RoutineState {
                    is_processing_candidate: true,
                    sub_routine_process_candidate_consensus: Some(ProcessCandidateConsensusState {
                        wait_votes: vec![
                            ParsecVote::AddElderNode(NODE_1),
                            ParsecVote::NewSectionInfo(SECTION_INFO_1),
                        ],
                    }),
                    ..Default::default()
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_complete_elder() {
        let initial_state = arrange_initial_state(
            &intial_state_elder_100_to_swap(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::RemoveElderNode(NODE_ELDER_100).to_event(),
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
            &intial_state_elder_100_to_swap(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::RemoveElderNode(NODE_ELDER_100).to_event(),
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
            &intial_state_elder_100_to_swap(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &vec![ParsecVote::PurgeCandidate(CANDIDATE_1).to_event()],
            &AssertState::default(),
        );
    }

    #[test]
    fn test_parsec_expect_candidate_twice() {
        let initial_state = arrange_initial_state(
            &intial_state_elder_100_to_swap(),
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
                ..InnerAction::default()
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
            &State::default(),
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
            &State::default(),
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

}

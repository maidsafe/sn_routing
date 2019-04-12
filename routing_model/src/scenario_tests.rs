// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::actions::*;
use crate::state::*;

use crate::utilities::{
    Attributes, Candidate, ChangeElder, Event, GenesisPfxInfo, LocalEvent, Name, Node, NodeChange,
    NodeState, ParsecVote, Proof, ProofRequest, ProofSource, Rpc, Section, SectionInfo,
};

macro_rules! to_collect {
    ($($item:expr),*) => {{
        let mut val = Vec::new();
        $(
            let _ = val.push($item.clone());
        )*
        val.into_iter().collect()
    }}
}

const CANDIDATE_1: Candidate = Candidate(Attributes { name: 1, age: 10 });
const CANDIDATE_2: Candidate = Candidate(Attributes { name: 2, age: 10 });
const CANDIDATE_130: Candidate = Candidate(Attributes { name: 130, age: 30 });
const CANDIDATE_205: Candidate = Candidate(Attributes { name: 205, age: 5 });
const OTHER_SECTION_1: Section = Section(1);
const DST_SECTION_200: Section = Section(200);

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

const NAME_109: Name = Name(NODE_ELDER_109.0.name);
const NAME_110: Name = Name(NODE_ELDER_110.0.name);
const NAME_111: Name = Name(NODE_ELDER_111.0.name);

const YOUNG_ADULT_205: Node = Node(Attributes { name: 205, age: 5 });
const SECTION_INFO_1: SectionInfo = SectionInfo(OUR_SECTION, 1);
const SECTION_INFO_2: SectionInfo = SectionInfo(OUR_SECTION, 2);
const DST_SECTION_INFO_200: SectionInfo = SectionInfo(DST_SECTION_200, 0);

const CANDIDATE_INFO_VALID_RPC_1: Rpc = Rpc::CandidateInfo {
    candidate: CANDIDATE_1,
    destination: OUR_NAME,
    valid: true,
};
const OUR_SECTION: Section = Section(0);
const OUR_NODE: Node = NODE_ELDER_132;
const OUR_NAME: Name = Name(OUR_NODE.0.name);
const OUR_NODE_CANDIDATE: Candidate = Candidate(NODE_ELDER_132.0);
const OUR_PROOF_REQUEST: ProofRequest = ProofRequest { value: OUR_NAME.0 };
const OUR_INITIAL_SECTION_INFO: SectionInfo = SectionInfo(OUR_SECTION, 0);
const OUR_GENESIS_INFO: GenesisPfxInfo = GenesisPfxInfo(OUR_INITIAL_SECTION_INFO);

lazy_static! {
    static ref INNER_ACTION_132: InnerAction = InnerAction::new_with_our_attributes(OUR_NODE.0);
    static ref INNER_ACTION_YOUNG_ELDERS: InnerAction = INNER_ACTION_132
        .clone()
        .extend_current_nodes_with(
            &NodeState {
                is_elder: true,
                ..NodeState::default()
            },
            &[NODE_ELDER_109, NODE_ELDER_110, NODE_ELDER_132]
        )
        .extend_current_nodes_with(&NodeState::default(), &[YOUNG_ADULT_205]);
    static ref INNER_ACTION_OLD_ELDERS: InnerAction = INNER_ACTION_132
        .clone()
        .extend_current_nodes_with(
            &NodeState {
                is_elder: true,
                ..NodeState::default()
            },
            &[NODE_ELDER_130, NODE_ELDER_131, NODE_ELDER_132]
        )
        .extend_current_nodes_with(&NodeState::default(), &[YOUNG_ADULT_205]);
    static ref INNER_ACTION_YOUNG_ELDERS_WITH_WAITING_ELDER: InnerAction = INNER_ACTION_132
        .clone()
        .extend_current_nodes_with(
            &NodeState {
                is_elder: true,
                ..NodeState::default()
            },
            &[NODE_ELDER_109, NODE_ELDER_110, NODE_ELDER_111]
        )
        .extend_current_nodes_with(&NodeState::default(), &[NODE_ELDER_130]);
    static ref INNER_ACTION_WITH_DST_SECTION_200: InnerAction =
        INNER_ACTION_132.clone().with_section_members(
            DST_SECTION_INFO_200,
            &[NODE_ELDER_109, NODE_ELDER_110, NODE_ELDER_111]
        );
    static ref SWAP_ELDER_109_NODE_1_SECTION_INFO_1: (ChangeElder, Vec<ParsecVote>) = (
        ChangeElder {
            changes: vec![(NODE_1, true), (NODE_ELDER_109, false),],
            new_section: SECTION_INFO_1,
        },
        vec![
            ParsecVote::AddElderNode(NODE_1),
            ParsecVote::RemoveElderNode(NODE_ELDER_109),
            ParsecVote::NewSectionInfo(SECTION_INFO_1),
        ]
    );
    static ref SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1: (ChangeElder, Vec<ParsecVote>) = (
        ChangeElder {
            changes: vec![(YOUNG_ADULT_205, true), (NODE_ELDER_130, false),],
            new_section: SECTION_INFO_1,
        },
        vec![
            ParsecVote::AddElderNode(YOUNG_ADULT_205),
            ParsecVote::RemoveElderNode(NODE_ELDER_130),
            ParsecVote::NewSectionInfo(SECTION_INFO_1),
        ]
    );
}

#[derive(Debug, PartialEq, Default, Clone)]
struct AssertState {
    action_our_votes: Vec<ParsecVote>,
    action_our_rpcs: Vec<Rpc>,
    action_our_nodes: Vec<NodeChange>,
    action_our_events: Vec<LocalEvent>,
    action_our_section: SectionInfo,
    dst_routine: DstRoutineState,
    src_routine: SrcRoutineState,
    check_and_process_elder_change_routine: CheckAndProcessElderChangeState,
}

fn process_events(mut state: MemberState, events: &[Event]) -> MemberState {
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

fn run_test(test_name: &str, start_state: &MemberState, events: &[Event], expected_state: &AssertState) {
    let final_state = process_events(start_state.clone(), &events);
    let action = final_state.action.inner();

    let final_state = (
        AssertState {
            action_our_rpcs: action.our_rpc,
            action_our_votes: action.our_votes,
            action_our_nodes: action.our_nodes,
            action_our_events: action.our_events,
            action_our_section: action.our_section,
            dst_routine: final_state.dst_routine,
            src_routine: final_state.src_routine,
            check_and_process_elder_change_routine: final_state
                .check_and_process_elder_change_routine,
        },
        final_state.failure,
    );
    let expected_state = (expected_state.clone(), None);

    assert_eq!(expected_state, final_state, "{}", test_name);
}

fn arrange_initial_state(state: &MemberState, events: &[Event]) -> MemberState {
    let state = process_events(state.clone(), events);
    state.action.remove_processed_state();
    state
}

fn initial_state_young_elders() -> MemberState {
    MemberState {
        action: Action::new(INNER_ACTION_YOUNG_ELDERS.clone()),
        ..Default::default()
    }
}

fn initial_state_old_elders() -> MemberState {
    MemberState {
        action: Action::new(INNER_ACTION_OLD_ELDERS.clone()),
        ..Default::default()
    }
}

fn routine_state_accept_as_candidate(
    accept_as_candidate: AcceptAsCandidateState,
) -> DstRoutineState {
    DstRoutineState {
        is_processing_candidate: true,
        sub_routine_accept_as_candidate: Some(accept_as_candidate),
    }
}

//////////////////
/// Dst
//////////////////

mod dst_tests {
    use super::*;

    #[test]
    fn test_rpc_expect_candidate() {
        run_test(
            "Get RPC ExpectCandidate",
            &initial_state_old_elders(),
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
            &initial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_nodes: vec![ADD_PROOFING_NODE_1],
                action_our_rpcs: vec![Rpc::RelocateResponse(CANDIDATE_1, OUR_INITIAL_SECTION_INFO)],
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
            &initial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[CANDIDATE_INFO_VALID_RPC_1.to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ResourceProof {
                    candidate: CANDIDATE_1,
                    source: OUR_NAME,
                    proof: OUR_PROOF_REQUEST,
                }],
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
            &initial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[CANDIDATE_INFO_VALID_RPC_1.to_event()],
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
            &initial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::CandidateInfo {
                candidate: CANDIDATE_1,
                destination: OUR_NAME,
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
            &initial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[LocalEvent::TimeoutAccept.to_event()],
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
            &initial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[Rpc::CandidateInfo {
                candidate: CANDIDATE_2,
                destination: OUR_NAME,
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
            &initial_state_old_elders(),
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
                destination: OUR_NAME,
                proof: Proof::ValidPart,
            }
            .to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ResourceProofReceipt {
                    candidate: CANDIDATE_1,
                    source: OUR_NAME,
                }],
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
            &initial_state_old_elders(),
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
                destination: OUR_NAME,
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
            &initial_state_old_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                CANDIDATE_INFO_VALID_RPC_1.to_event(),
                Rpc::ResourceProofResponse {
                    candidate: CANDIDATE_1,
                    destination: OUR_NAME,
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
                destination: OUR_NAME,
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
            &initial_state_old_elders(),
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
                destination: OUR_NAME,
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
            &initial_state_old_elders(),
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
                destination: OUR_NAME,
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
            &initial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[
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
            &initial_state_old_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (No Elder Change)",
            &initial_state,
            &[ParsecVote::Online(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::NodeApproval(CANDIDATE_1, OUR_GENESIS_INFO)],
                action_our_nodes: vec![SET_ONLINE_NODE_1],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change() {
        let initial_state = arrange_initial_state(
            &initial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &[
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::CheckElder.to_event(),
            ],
            &AssertState {
                action_our_rpcs: vec![Rpc::NodeApproval(CANDIDATE_1, OUR_GENESIS_INFO)],
                action_our_votes: SWAP_ELDER_109_NODE_1_SECTION_INFO_1.1.clone(),
                action_our_nodes: vec![SET_ONLINE_NODE_1],
                check_and_process_elder_change_routine: CheckAndProcessElderChangeState {
                    change_elder: Some(SWAP_ELDER_109_NODE_1_SECTION_INFO_1.0.clone()),
                    wait_votes: SWAP_ELDER_109_NODE_1_SECTION_INFO_1.1.clone(),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_get_wrong_votes() {
        let initial_state = arrange_initial_state(
            &initial_state_young_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::CheckElder.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change) RemoveElderNode for wrong elder,\
            AddElderNode for wrong node, NewSectionInfo for wrong section",
            &initial_state,
            &[
                ParsecVote::RemoveElderNode(NODE_1).to_event(),
                ParsecVote::AddElderNode(NODE_ELDER_109).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_2).to_event(),
            ],
            &AssertState {
                check_and_process_elder_change_routine: CheckAndProcessElderChangeState {
                    change_elder: Some(SWAP_ELDER_109_NODE_1_SECTION_INFO_1.0.clone()),
                    wait_votes: SWAP_ELDER_109_NODE_1_SECTION_INFO_1.1.clone(),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_remove_elder() {
        let initial_state = arrange_initial_state(
            &initial_state_young_elders(),
            &[
                ParsecVote::ExpectCandidate(CANDIDATE_1).to_event(),
                ParsecVote::Online(CANDIDATE_1).to_event(),
                ParsecVote::CheckElder.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change) then RemoveElderNode",
            &initial_state,
            &[ParsecVote::RemoveElderNode(NODE_ELDER_109).to_event()],
            &AssertState {
                check_and_process_elder_change_routine: CheckAndProcessElderChangeState {
                    change_elder: Some(SWAP_ELDER_109_NODE_1_SECTION_INFO_1.0.clone()),
                    wait_votes: vec![
                        ParsecVote::AddElderNode(NODE_1),
                        ParsecVote::NewSectionInfo(SECTION_INFO_1),
                    ],
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_then_online_elder_change_complete_elder() {
        let initial_state = arrange_initial_state(
            &initial_state_young_elders(),
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
            &initial_state_young_elders(),
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
                action_our_rpcs: vec![Rpc::RelocateResponse(CANDIDATE_2, OUR_INITIAL_SECTION_INFO)],
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
            &initial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate then Purge",
            &initial_state,
            &[ParsecVote::PurgeCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_nodes: vec![REMOVE_NODE_1],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_expect_candidate_twice() {
        let initial_state = arrange_initial_state(
            &initial_state_young_elders(),
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
        );

        run_test(
            &"Get Parsec 2 ExpectCandidate",
            &initial_state,
            &[ParsecVote::ExpectCandidate(CANDIDATE_2).to_event()],
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
        let initial_state = MemberState {
            action: Action::new(InnerAction {
                shortest_prefix: Some(OTHER_SECTION_1),
                ..INNER_ACTION_OLD_ELDERS.clone()
            }),
            ..MemberState::default()
        };

        run_test(
            &"Get Parsec ExpectCandidate with a shorter known section",
            &initial_state,
            &[ParsecVote::ExpectCandidate(CANDIDATE_1).to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ResendExpectCandidate(OTHER_SECTION_1, CANDIDATE_1)],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_unexpected_purge_online() {
        run_test(
            "Get unexpected Parsec consensus Online and PurgeCandidate. \
             Candidate may have trigger both vote: only consider the first",
            &initial_state_old_elders(),
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
            &initial_state_old_elders(),
            &[
                Rpc::CandidateInfo {
                    candidate: CANDIDATE_1,
                    destination: OUR_NAME,
                    valid: true,
                }
                .to_event(),
                Rpc::ResourceProofResponse {
                    candidate: CANDIDATE_1,
                    destination: OUR_NAME,
                    proof: Proof::ValidEnd,
                }
                .to_event(),
            ],
            &AssertState::default(),
        );
    }

    #[test]
    fn test_local_events_offline_online_again_for_different_nodes() {
        run_test(
            "Get local event node detected offline online again different nodes",
            &initial_state_old_elders(),
            &[
                LocalEvent::NodeDetectedOffline(NODE_ELDER_130).to_event(),
                LocalEvent::NodeDetectedBackOnline(NODE_ELDER_131).to_event(),
            ],
            &AssertState {
                action_our_votes: vec![
                    ParsecVote::Offline(NODE_ELDER_130),
                    ParsecVote::BackOnline(NODE_ELDER_131),
                ],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_offline() {
        run_test(
            "Get parsec consensus offline",
            &initial_state_old_elders(),
            &[ParsecVote::Offline(NODE_ELDER_130).to_event()],
            &AssertState {
                action_our_nodes: vec![NodeChange::Offline(NODE_ELDER_130)],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_offline_then_check_elder() {
        let initial_state = arrange_initial_state(
            &initial_state_old_elders(),
            &[ParsecVote::Offline(NODE_ELDER_130).to_event()],
        );
        run_test(
            "Get parsec consensus offline then check elder",
            &initial_state,
            &[ParsecVote::CheckElder.to_event()],
            &AssertState {
                action_our_votes: SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.1.clone(),
                check_and_process_elder_change_routine: CheckAndProcessElderChangeState {
                    change_elder: Some(SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.0.clone()),
                    wait_votes: SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.1.clone(),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_offline_then_parsec_online() {
        let initial_state = arrange_initial_state(
            &initial_state_old_elders(),
            &[ParsecVote::Offline(NODE_ELDER_130).to_event()],
        );
        run_test(
            "Get parsec consensus offline then parsec online",
            &initial_state,
            &[ParsecVote::BackOnline(NODE_ELDER_130).to_event()],
            &AssertState {
                action_our_nodes: vec![NodeChange::Relocating(NODE_ELDER_130)],
                ..AssertState::default()
            },
        );
    }
}

mod src_tests {
    use super::*;

    #[test]
    fn test_local_event_relocation_trigger() {
        run_test(
            "Get RPC ExpectCandidate",
            &initial_state_old_elders(),
            &[LocalEvent::RelocationTrigger.to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RelocationTrigger],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger() {
        let initial_state = MemberState {
            action: Action::new(
                INNER_ACTION_OLD_ELDERS
                    .clone()
                    .with_enough_work_to_relocate(&[YOUNG_ADULT_205]),
            ),
            ..MemberState::default()
        };

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocationTrigger.to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_205)],
                action_our_nodes: vec![NodeChange::Relocating(YOUNG_ADULT_205)],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205,
                    }),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocate_trigger_elder_change() {
        let initial_state = MemberState {
            action: Action::new(
                INNER_ACTION_OLD_ELDERS
                    .clone()
                    .with_enough_work_to_relocate(&[NODE_ELDER_130]),
            ),
            ..MemberState::default()
        };

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &[
                ParsecVote::RelocationTrigger.to_event(),
                ParsecVote::CheckElder.to_event(),
            ],
            &AssertState {
                action_our_nodes: vec![NodeChange::Relocating(NODE_ELDER_130)],
                action_our_votes: SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.1.clone(),
                check_and_process_elder_change_routine: CheckAndProcessElderChangeState {
                    change_elder: Some(SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.0.clone()),
                    wait_votes: SWAP_ELDER_130_YOUNG_205_SECTION_INFO_1.1.clone(),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocate_trigger_elder_change_complete() {
        let initial_state = arrange_initial_state(
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[NODE_ELDER_130]),
                ),
                ..MemberState::default()
            },
            &[
                ParsecVote::RelocationTrigger.to_event(),
                ParsecVote::CheckElder.to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate then Online (Elder Change)",
            &initial_state,
            &[
                ParsecVote::RemoveElderNode(NODE_ELDER_130).to_event(),
                ParsecVote::AddElderNode(YOUNG_ADULT_205).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_1).to_event(),
                ParsecVote::RelocationTrigger.to_event(),
            ],
            &AssertState {
                action_our_section: SECTION_INFO_1,
                action_our_nodes: vec![
                    NodeChange::Elder(YOUNG_ADULT_205, true),
                    NodeChange::Elder(NODE_ELDER_130, false),
                ],
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_130)],
                action_our_events: vec![LocalEvent::TimeoutCheckElder],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(Candidate(NODE_ELDER_130.0)),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_130,
                    }),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_refuse_candidate_rpc() {
        let initial_state = arrange_initial_state(
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[YOUNG_ADULT_205]),
                ),
                ..MemberState::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[Rpc::RefuseCandidate(CANDIDATE_205).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RefuseCandidate(CANDIDATE_205)],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205,
                    }),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_relocate_response_rpc() {
        let initial_state = arrange_initial_state(
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[YOUNG_ADULT_205]),
                ),
                ..MemberState::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[Rpc::RelocateResponse(CANDIDATE_205, DST_SECTION_INFO_200).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RelocateResponse(
                    CANDIDATE_205,
                    DST_SECTION_INFO_200,
                )],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205,
                    }),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_accept() {
        let initial_state = arrange_initial_state(
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[YOUNG_ADULT_205]),
                ),
                ..MemberState::default()
            },
            &[ParsecVote::RelocationTrigger.to_event()],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocateResponse(CANDIDATE_205, DST_SECTION_INFO_200).to_event()],
            &AssertState {
                action_our_rpcs: vec![Rpc::RelocatedInfo(
                    Candidate(YOUNG_ADULT_205.0),
                    DST_SECTION_INFO_200,
                )],
                action_our_nodes: vec![NodeChange::Remove(YOUNG_ADULT_205)],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_refuse() {
        let initial_state = arrange_initial_state(
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[YOUNG_ADULT_205]),
                ),
                ..MemberState::default()
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
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[YOUNG_ADULT_205]),
                ),
                ..MemberState::default()
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
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_205)],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_205),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_205,
                    }),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_parsec_relocation_trigger_elder_change_refuse_trigger_again() {
        let initial_state = arrange_initial_state(
            &MemberState {
                action: Action::new(
                    INNER_ACTION_OLD_ELDERS
                        .clone()
                        .with_enough_work_to_relocate(&[NODE_ELDER_130]),
                ),
                ..MemberState::default()
            },
            &[
                ParsecVote::RelocationTrigger.to_event(),
                ParsecVote::CheckElder.to_event(),
                ParsecVote::RemoveElderNode(NODE_ELDER_130).to_event(),
                ParsecVote::AddElderNode(YOUNG_ADULT_205).to_event(),
                ParsecVote::NewSectionInfo(SECTION_INFO_1).to_event(),
                ParsecVote::RelocationTrigger.to_event(),
                ParsecVote::RefuseCandidate(CANDIDATE_130).to_event(),
            ],
        );

        run_test(
            "Get Parsec ExpectCandidate",
            &initial_state,
            &[ParsecVote::RelocationTrigger.to_event()],
            &AssertState {
                action_our_section: SECTION_INFO_1,
                action_our_rpcs: vec![Rpc::ExpectCandidate(CANDIDATE_130)],
                src_routine: SrcRoutineState {
                    relocating_candidate: Some(CANDIDATE_130),
                    sub_routine_try_relocating: Some(TryRelocatingState {
                        candidate: CANDIDATE_130,
                    }),
                },
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_unexpected_refuse_candidate() {
        run_test(
            "Get RPC ExpectCandidate",
            &initial_state_old_elders(),
            &[Rpc::RefuseCandidate(CANDIDATE_205).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RefuseCandidate(CANDIDATE_205)],
                ..AssertState::default()
            },
        );
    }

    #[test]
    fn test_unexpected_relocate_response() {
        run_test(
            "Get RPC ExpectCandidate",
            &initial_state_old_elders(),
            &[Rpc::RelocateResponse(CANDIDATE_205, DST_SECTION_INFO_200).to_event()],
            &AssertState {
                action_our_votes: vec![ParsecVote::RelocateResponse(
                    CANDIDATE_205,
                    DST_SECTION_INFO_200,
                )],
                ..AssertState::default()
            },
        );
    }
}

mod node_tests {
    use super::*;
    use crate::state::JoiningRelocateCandidateState;

    #[derive(Debug, PartialEq, Default, Clone)]
    struct AssertJoiningState {
        action_our_votes: Vec<ParsecVote>,
        action_our_rpcs: Vec<Rpc>,
        action_our_nodes: Vec<NodeChange>,
        action_our_events: Vec<LocalEvent>,
        action_our_section: SectionInfo,
        join_routine: JoiningRelocateCandidateState,
    }

    fn run_joining_test(
        test_name: &str,
        start_state: &JoiningState,
        events: &[Event],
        expected_state: &AssertJoiningState,
    ) {
        let final_state = process_joining_events(start_state.clone(), &events);
        let action = final_state.action.inner();

        let final_state = (
            AssertJoiningState {
                action_our_rpcs: action.our_rpc,
                action_our_votes: action.our_votes,
                action_our_nodes: action.our_nodes,
                action_our_events: action.our_events,
                action_our_section: action.our_section,
                join_routine: final_state.join_routine,
            },
            final_state.failure,
        );
        let expected_state = (expected_state.clone(), None);

        assert_eq!(expected_state, final_state, "{}", test_name);
    }

    fn process_joining_events(mut state: JoiningState, events: &[Event]) -> JoiningState {
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

    fn arrange_initial_joining_state(state: &JoiningState, events: &[Event]) -> JoiningState {
        let state = process_joining_events(state.clone(), events);
        state.action.remove_processed_state();
        state
    }

    fn initial_joining_state_with_dst_200() -> JoiningState {
        JoiningState {
            action: Action::new(INNER_ACTION_WITH_DST_SECTION_200.clone()),
            ..Default::default()
        }
    }

    //////////////////
    /// Joining Relocate Node
    //////////////////

    #[test]
    fn test_joining_start() {
        run_joining_test(
            "",
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[],
            &AssertJoiningState {
                action_our_rpcs: vec![
                    Rpc::ConnectionInfoRequest {
                        source: OUR_NAME,
                        destination: NAME_109,
                        connection_info: OUR_NAME.0,
                    },
                    Rpc::ConnectionInfoRequest {
                        source: OUR_NAME,
                        destination: NAME_110,
                        connection_info: OUR_NAME.0,
                    },
                    Rpc::ConnectionInfoRequest {
                        source: OUR_NAME,
                        destination: NAME_111,
                        connection_info: OUR_NAME.0,
                    },
                ],
                action_our_events: vec![
                    LocalEvent::JoiningTimeoutResendCandidateInfo,
                    LocalEvent::JoiningTimeoutRefused,
                ],
                join_routine: JoiningRelocateCandidateState {
                    has_resource_proofs: to_collect![
                        (NAME_109, (false, None)),
                        (NAME_110, (false, None)),
                        (NAME_111, (false, None))
                    ],
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }

    #[test]
    fn test_joining_receive_two_connection_info() {
        let initial_state = arrange_initial_joining_state(
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[],
        );

        run_joining_test(
            "",
            &initial_state,
            &[
                Rpc::ConnectionInfoResponse {
                    source: NAME_110,
                    destination: OUR_NAME,
                    connection_info: NAME_110.0,
                }
                .to_event(),
                Rpc::ConnectionInfoResponse {
                    source: NAME_111,
                    destination: OUR_NAME,
                    connection_info: NAME_111.0,
                }
                .to_event(),
            ],
            &AssertJoiningState {
                action_our_rpcs: vec![
                    Rpc::CandidateInfo {
                        candidate: OUR_NODE_CANDIDATE,
                        destination: NAME_110,
                        valid: true,
                    },
                    Rpc::CandidateInfo {
                        candidate: OUR_NODE_CANDIDATE,
                        destination: NAME_111,
                        valid: true,
                    },
                ],
                join_routine: JoiningRelocateCandidateState {
                    has_resource_proofs: to_collect![
                        (NAME_109, (false, None)),
                        (NAME_110, (false, None)),
                        (NAME_111, (false, None))
                    ],
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }

    #[test]
    fn test_joining_receive_one_resource_proof() {
        let initial_state = arrange_initial_joining_state(
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[
                Rpc::ConnectionInfoResponse {
                    source: NAME_110,
                    destination: OUR_NAME,
                    connection_info: NAME_110.0,
                }
                .to_event(),
                Rpc::ConnectionInfoResponse {
                    source: NAME_111,
                    destination: OUR_NAME,
                    connection_info: NAME_111.0,
                }
                .to_event(),
            ],
        );

        run_joining_test(
            "",
            &initial_state,
            &[Rpc::ResourceProof {
                candidate: OUR_NODE_CANDIDATE,
                source: NAME_111,
                proof: ProofRequest { value: NAME_111.0 },
            }
            .to_event()],
            &AssertJoiningState {
                action_our_events: vec![LocalEvent::ComputeResourceProofForElder(
                    NAME_111,
                    ProofSource(2),
                )],
                join_routine: JoiningRelocateCandidateState {
                    has_resource_proofs: to_collect![
                        (NAME_109, (false, None)),
                        (NAME_110, (false, None)),
                        (NAME_111, (true, None))
                    ],
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }

    #[test]
    fn test_joining_computed_one_proof_one_proof() {
        let initial_state = arrange_initial_joining_state(
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[
                Rpc::ConnectionInfoResponse {
                    source: NAME_111,
                    destination: OUR_NAME,
                    connection_info: NAME_111.0,
                }
                .to_event(),
                Rpc::ResourceProof {
                    candidate: OUR_NODE_CANDIDATE,
                    source: NAME_111,
                    proof: ProofRequest { value: NAME_111.0 },
                }
                .to_event(),
            ],
        );

        run_joining_test(
            "",
            &initial_state,
            &[LocalEvent::ComputeResourceProofForElder(NAME_111, ProofSource(2)).to_event()],
            &AssertJoiningState {
                action_our_rpcs: vec![Rpc::ResourceProofResponse {
                    candidate: OUR_NODE_CANDIDATE,
                    destination: NAME_111,
                    proof: Proof::ValidPart,
                }],
                join_routine: JoiningRelocateCandidateState {
                    has_resource_proofs: to_collect![
                        (NAME_109, (false, None)),
                        (NAME_110, (false, None)),
                        (NAME_111, (true, Some(ProofSource(1))))
                    ],
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }

    #[test]
    fn test_joining_got_one_proof_receipt() {
        let initial_state = arrange_initial_joining_state(
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[
                Rpc::ConnectionInfoResponse {
                    source: NAME_111,
                    destination: OUR_NAME,
                    connection_info: NAME_111.0,
                }
                .to_event(),
                Rpc::ResourceProof {
                    candidate: OUR_NODE_CANDIDATE,
                    source: NAME_111,
                    proof: ProofRequest { value: NAME_111.0 },
                }
                .to_event(),
                LocalEvent::ComputeResourceProofForElder(NAME_111, ProofSource(2)).to_event(),
            ],
        );

        run_joining_test(
            "",
            &initial_state,
            &[Rpc::ResourceProofReceipt {
                candidate: OUR_NODE_CANDIDATE,
                source: NAME_111,
            }
            .to_event()],
            &AssertJoiningState {
                action_our_rpcs: vec![Rpc::ResourceProofResponse {
                    candidate: OUR_NODE_CANDIDATE,
                    destination: NAME_111,
                    proof: Proof::ValidEnd,
                }],
                join_routine: JoiningRelocateCandidateState {
                    has_resource_proofs: to_collect![
                        (NAME_109, (false, None)),
                        (NAME_110, (false, None)),
                        (NAME_111, (true, Some(ProofSource(0))))
                    ],
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }

    #[test]
    fn test_joining_resend_timeout_after_one_proof() {
        let initial_state = arrange_initial_joining_state(
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[
                Rpc::ConnectionInfoResponse {
                    source: NAME_110,
                    destination: OUR_NAME,
                    connection_info: NAME_110.0,
                }
                .to_event(),
                Rpc::ConnectionInfoResponse {
                    source: NAME_111,
                    destination: OUR_NAME,
                    connection_info: NAME_111.0,
                }
                .to_event(),
                Rpc::ResourceProof {
                    candidate: OUR_NODE_CANDIDATE,
                    source: NAME_111,
                    proof: ProofRequest { value: NAME_111.0 },
                }
                .to_event(),
            ],
        );

        run_joining_test(
            "",
            &initial_state,
            &[LocalEvent::JoiningTimeoutResendCandidateInfo.to_event()],
            &AssertJoiningState {
                action_our_rpcs: vec![
                    Rpc::ConnectionInfoRequest {
                        source: OUR_NAME,
                        destination: NAME_109,
                        connection_info: OUR_NAME.0,
                    },
                    Rpc::ConnectionInfoRequest {
                        source: OUR_NAME,
                        destination: NAME_110,
                        connection_info: OUR_NAME.0,
                    },
                ],
                action_our_events: vec![LocalEvent::JoiningTimeoutResendCandidateInfo],
                join_routine: JoiningRelocateCandidateState {
                    has_resource_proofs: to_collect![
                        (NAME_109, (false, None)),
                        (NAME_110, (false, None)),
                        (NAME_111, (true, None))
                    ],
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }

    #[test]
    fn test_joining_approved() {
        let initial_state = arrange_initial_joining_state(
            &initial_joining_state_with_dst_200().start(DST_SECTION_INFO_200),
            &[],
        );

        run_joining_test(
            "",
            &initial_state,
            &[
                Rpc::NodeApproval(OUR_NODE_CANDIDATE, GenesisPfxInfo(DST_SECTION_INFO_200))
                    .to_event(),
            ],
            &AssertJoiningState {
                join_routine: JoiningRelocateCandidateState {
                    routine_complete: Some(GenesisPfxInfo(DST_SECTION_INFO_200)),
                    ..JoiningRelocateCandidateState::default()
                },
                ..AssertJoiningState::default()
            },
        );
    }
}

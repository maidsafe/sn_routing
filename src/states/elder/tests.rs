// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::*;
use crate::{
    messages::DirectMessage,
    mock::Network,
    outbox::{EventBox, EventBuf},
    state_machine::{State, StateMachine, Transition},
    utils::XorTargetInterval,
    xor_name::XOR_NAME_LEN,
    NetworkConfig, NetworkService,
};
use maidsafe_utilities::serialisation;
use std::net::SocketAddr;
use unwrap::unwrap;
use utils::LogIdent;

const DEFAULT_MIN_SECTION_SIZE: usize = 4;
// Accumulate even if 1 old node and an additional new node do not vote.
const NO_SINGLE_VETO_VOTE_COUNT: usize = 7;
const ACCUMULATE_VOTE_COUNT: usize = 6;
const NOT_ACCUMULATE_ALONE_VOTE_COUNT: usize = 5;

struct CandidateInfo {
    old_full_id: FullId,
    old_proxy_id: FullId,
    new_full_id: FullId,
    new_proxy_id: FullId,
    message_id: MessageId,
}

impl CandidateInfo {
    fn new() -> Self {
        Self {
            old_full_id: FullId::new(),
            old_proxy_id: FullId::new(),
            new_full_id: FullId::new(),
            new_proxy_id: FullId::new(),
            message_id: MessageId::new(),
        }
    }
}

struct ClientInfo {
    full_id: FullId,
    addr: SocketAddr,
}

impl ClientInfo {
    fn with_addr(addr: &str) -> Self {
        Self {
            full_id: FullId::new(),
            addr: unwrap!(addr.parse()),
        }
    }

    fn public_id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo::Client {
            peer_addr: self.addr,
        }
    }
}

struct ElderUnderTest {
    pub machine: StateMachine,
    pub full_id: FullId,
    pub other_full_ids: Vec<FullId>,
    pub other_parsec_map: Vec<ParsecMap>,
    pub ev_buffer: EventBuf,
    pub elders_info: EldersInfo,
    pub candidate_info: CandidateInfo,
}

impl ElderUnderTest {
    fn new() -> Self {
        Self::with_min_section_size(DEFAULT_MIN_SECTION_SIZE)
    }

    fn with_min_section_size(min_section_size: usize) -> Self {
        let full_ids = (0..NO_SINGLE_VETO_VOTE_COUNT)
            .map(|_| FullId::new())
            .collect_vec();
        let mut ev_buffer = EventBuf::new();

        let prefix = Prefix::<XorName>::default();
        let elders_info = unwrap!(EldersInfo::new(
            full_ids.iter().map(|id| *id.public_id()).collect(),
            prefix,
            iter::empty()
        ));

        let gen_pfx_info = GenesisPfxInfo {
            first_info: elders_info.clone(),
            first_state_serialized: Vec::new(),
            latest_info: EldersInfo::default(),
        };

        let full_id = full_ids[0].clone();
        let machine = make_state_machine(&full_id, &gen_pfx_info, min_section_size, &mut ev_buffer);

        let other_full_ids = full_ids[1..].iter().cloned().collect_vec();
        let other_parsec_map = other_full_ids
            .iter()
            .map(|full_id| ParsecMap::new(full_id.clone(), &gen_pfx_info))
            .collect_vec();

        let mut elder_test = Self {
            machine,
            full_id,
            other_full_ids,
            other_parsec_map,
            ev_buffer,
            elders_info,
            candidate_info: CandidateInfo::new(),
        };

        // Process initial unpolled event
        let _ = elder_test.create_gossip();
        elder_test
    }

    fn elder_state(&self) -> &Elder {
        unwrap!(self.machine.current().elder_state())
    }

    fn n_vote_for(&mut self, count: usize, events: &[&AccumulatingEvent]) {
        for event in events {
            self.other_parsec_map
                .iter_mut()
                .zip(self.other_full_ids.iter())
                .take(count)
                .for_each(|(parsec, full_id)| {
                    let sig_event = event
                        .elders_info()
                        .map(|info| unwrap!(SectionInfoSigPayload::new(info, &full_id)));
                    parsec.vote_for(
                        (*event).clone().into_network_event_with(sig_event),
                        &LogIdent::new(&0),
                    )
                });
        }
    }

    fn create_gossip(&mut self) -> Result<(), RoutingError> {
        let other_pub_id = *self.other_full_ids[0].public_id();
        let message = unwrap!(self.other_parsec_map[0].create_gossip(0, self.full_id.public_id()));
        self.handle_direct_message((message, other_pub_id))
    }

    fn n_vote_for_gossipped(
        &mut self,
        count: usize,
        events: &[&AccumulatingEvent],
    ) -> Result<(), RoutingError> {
        self.n_vote_for(count, events);
        self.create_gossip()
    }

    fn set_interval_to_match_candidate(&mut self, match_candidate: bool) {
        let name = if match_candidate {
            *self.candidate_info.new_full_id.public_id().name()
        } else {
            *self.full_id.public_id().name()
        };

        self.machine
            .elder_state_mut()
            .set_next_relocation_interval(Some(XorTargetInterval(name, name)));
    }

    fn accumulate_expect_candidate(&mut self, payload_expect: ExpectCandidatePayload) {
        self.n_accumulate_expect_candidate(ACCUMULATE_VOTE_COUNT, payload_expect)
    }

    fn accumulate_expect_candidate_if_vote(&mut self, payload_expect: ExpectCandidatePayload) {
        self.n_accumulate_expect_candidate(NOT_ACCUMULATE_ALONE_VOTE_COUNT, payload_expect)
    }

    fn n_accumulate_expect_candidate(
        &mut self,
        count: usize,
        payload_expect: ExpectCandidatePayload,
    ) {
        let _ = self.n_vote_for_gossipped(
            count,
            &[&AccumulatingEvent::ExpectCandidate(payload_expect.clone())],
        );
    }

    fn accumulate_purge_candidate(&mut self, purge_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&AccumulatingEvent::PurgeCandidate(purge_payload)],
        );
    }

    fn accumulate_online(&mut self, online_payload: OnlinePayload) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&AccumulatingEvent::Online(online_payload)],
        );
    }

    fn accumulate_add_elder_if_vote(&mut self, online_payload: OnlinePayload) {
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            &[&AccumulatingEvent::AddElder(
                online_payload.new_public_id,
                online_payload.client_auth,
            )],
        );
    }

    fn accumulate_section_info_if_vote(&mut self, section_info_payload: EldersInfo) {
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            &[&AccumulatingEvent::SectionInfo(section_info_payload)],
        );
    }

    fn accumulate_offline(&mut self, offline_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&AccumulatingEvent::Offline(offline_payload)],
        );
    }

    fn accumulate_remove_elder_if_vote(&mut self, offline_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            &[&AccumulatingEvent::RemoveElder(offline_payload)],
        );
    }

    fn new_elders_info_with_candidate(&self) -> EldersInfo {
        unwrap!(EldersInfo::new(
            self.elders_info
                .members()
                .iter()
                .chain(Some(self.candidate_info.new_full_id.public_id()))
                .cloned()
                .collect(),
            *self.elders_info.prefix(),
            Some(&self.elders_info)
        ))
    }

    fn new_elders_info_without_candidate(&self) -> EldersInfo {
        let old_info = self.new_elders_info_with_candidate();
        unwrap!(EldersInfo::new(
            self.elders_info.members().clone(),
            *old_info.prefix(),
            Some(&old_info)
        ))
    }

    fn has_unpolled_observations(&self) -> bool {
        self.elder_state().has_unpolled_observations()
    }

    fn has_candidate(&self) -> bool {
        self.elder_state().has_candidate()
    }

    fn is_candidate_a_valid_peer(&self) -> bool {
        self.elder_state()
            .chain()
            .is_peer_valid(self.candidate_info.new_full_id.public_id())
    }

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
    ) -> Result<(), RoutingError> {
        unwrap!(self.machine.current_mut().elder_state_mut())
            .dispatch_routing_message(routing_msg, &mut self.ev_buffer)
    }

    fn handle_direct_message(
        &mut self,
        msg: (DirectMessage, PublicId),
    ) -> Result<(), RoutingError> {
        let _ = self.machine.elder_state_mut().handle_direct_message(
            msg.0,
            msg.1,
            &mut self.ev_buffer,
        )?;
        Ok(())
    }

    fn handle_connected_to(&mut self, conn_info: ConnectionInfo) {
        match self
            .machine
            .elder_state_mut()
            .handle_connected_to(conn_info, &mut self.ev_buffer)
        {
            Transition::Stay => (),
            _ => panic!("Unexpected transition"),
        }
    }

    fn handle_connected_to_candidate(&mut self) {
        let conn_info = ConnectionInfo::Node {
            node_info: self.candidate_node_info(),
        };
        self.handle_connected_to(conn_info)
    }

    fn expect_candidate_payload(&self) -> ExpectCandidatePayload {
        ExpectCandidatePayload {
            old_public_id: *self.candidate_info.old_full_id.public_id(),
            old_client_auth: Authority::Client {
                client_id: *self.candidate_info.old_full_id.public_id(),
                proxy_node_name: *self.candidate_info.old_proxy_id.public_id().name(),
            },
            message_id: self.candidate_info.message_id,
            dst_name: XorName([0; XOR_NAME_LEN]),
        }
    }

    fn online_payload(&self) -> OnlinePayload {
        let client_auth = Authority::Client {
            client_id: *self.candidate_info.new_full_id.public_id(),
            proxy_node_name: *self.candidate_info.new_proxy_id.public_id().name(),
        };
        OnlinePayload {
            new_public_id: *self.candidate_info.new_full_id.public_id(),
            client_auth,
            old_public_id: *self.candidate_info.old_full_id.public_id(),
        }
    }

    fn offline_payload(&self) -> PublicId {
        *self.candidate_info.new_full_id.public_id()
    }

    fn purge_payload(&self) -> PublicId {
        *self.candidate_info.old_full_id.public_id()
    }

    fn expect_candidate_message(&self) -> RoutingMessage {
        let payload = self.expect_candidate_payload();

        RoutingMessage {
            src: Authority::Section(*payload.old_public_id.name()),
            dst: Authority::Section(payload.dst_name),
            content: MessageContent::ExpectCandidate {
                old_public_id: payload.old_public_id,
                old_client_auth: payload.old_client_auth,
                message_id: payload.message_id,
            },
        }
    }

    fn connection_request_message(&self) -> RoutingMessage {
        let new_full_id = &self.candidate_info.new_full_id;
        let their_pub_id = self.full_id.public_id();

        let src = Authority::Client {
            client_id: *new_full_id.public_id(),
            proxy_node_name: *self.candidate_info.new_proxy_id.public_id().name(),
        };
        let dst = Authority::ManagedNode(*their_pub_id.name());

        let content = {
            let conn_info = self.candidate_node_info();
            let conn_info = unwrap!(serialisation::serialise(&conn_info));

            MessageContent::ConnectionRequest {
                conn_info,
                pub_id: *new_full_id.public_id(),
                msg_id: MessageId::new(),
            }
        };

        RoutingMessage { src, dst, content }
    }

    fn candidate_info_message(&self) -> (DirectMessage, PublicId) {
        self.candidate_info_message_use_wrong_old_signature(false)
    }

    fn candidate_info_message_use_wrong_old_signature(
        &self,
        use_bad_sig: bool,
    ) -> (DirectMessage, PublicId) {
        let old_full_id = &self.candidate_info.old_full_id;
        let new_full_id = &self.candidate_info.new_full_id;

        let both_ids = (old_full_id.public_id(), new_full_id.public_id());

        let old_signing_id = if use_bad_sig {
            new_full_id
        } else {
            old_full_id
        };

        let to_sign = unwrap!(serialisation::serialise(&both_ids));
        let signature_using_old = old_signing_id.sign(&to_sign);

        (
            DirectMessage::CandidateInfo {
                old_public_id: *old_full_id.public_id(),
                signature_using_old,
                new_client_auth: Authority::Client {
                    client_id: *new_full_id.public_id(),
                    proxy_node_name: *self.candidate_info.new_proxy_id.public_id().name(),
                },
            },
            *new_full_id.public_id(),
        )
    }

    fn candidate_node_info(&self) -> NodeInfo {
        let peer_addr = unwrap!("198.51.100.0:5555".parse());
        NodeInfo {
            peer_addr,
            peer_cert_der: vec![],
        }
    }

    fn handle_bootstrap_request(&mut self, pub_id: PublicId, conn_info: ConnectionInfo) {
        let peer_addr = conn_info.peer_addr();

        self.handle_connected_to(conn_info);
        self.machine
            .elder_state_mut()
            .identify_connection(pub_id, peer_addr);
        unwrap!(self
            .machine
            .elder_state_mut()
            .handle_bootstrap_request(pub_id));
    }

    fn has_client(&self, pub_id: &PublicId) -> bool {
        match self.elder_state().get_peer(pub_id).map(Peer::state) {
            Some(PeerState::Client { .. }) => true,
            Some(state) => panic!("Unexpected peer state: expected Client, got {:?}", state),
            None => false,
        }
    }
}

fn new_elder_state(
    full_id: &FullId,
    gen_pfx_info: &GenesisPfxInfo,
    min_section_size: usize,
    network_service: NetworkService,
    timer: Timer,
    outbox: &mut dyn EventBox,
) -> State {
    let public_id = *full_id.public_id();

    let parsec_map = ParsecMap::new(full_id.clone(), gen_pfx_info);
    let chain = Chain::new(min_section_size, public_id, gen_pfx_info.clone());
    let peer_map = PeerMap::new();
    let peer_mgr = PeerManager::new(false);

    let details = ElderDetails {
        chain,
        network_service,
        event_backlog: Default::default(),
        full_id: full_id.clone(),
        gen_pfx_info: gen_pfx_info.clone(),
        msg_queue: Default::default(),
        parsec_map,
        peer_map,
        peer_mgr,
        routing_msg_filter: RoutingMessageFilter::new(),
        timer,
    };

    let section_info = gen_pfx_info.first_info.clone();
    let prefix = *section_info.prefix();
    Elder::from_adult(details, section_info, prefix, outbox)
        .map(State::Elder)
        .unwrap_or(State::Terminated)
}

fn make_state_machine(
    full_id: &FullId,
    gen_pfx_info: &GenesisPfxInfo,
    min_section_size: usize,
    outbox: &mut dyn EventBox,
) -> StateMachine {
    let network = Network::new(min_section_size, None);

    let endpoint = network.gen_addr();
    let config = NetworkConfig::node().with_hard_coded_contact(endpoint);

    let _ = network.gen_next_addr();

    StateMachine::new(
        move |network_service, timer, outbox2| {
            new_elder_state(
                full_id,
                gen_pfx_info,
                min_section_size,
                network_service,
                timer,
                outbox2,
            )
        },
        config,
        outbox,
    )
    .1
}

trait StateMachineExt {
    fn elder_state_mut(&mut self) -> &mut Elder;
}

impl StateMachineExt for StateMachine {
    fn elder_state_mut(&mut self) -> &mut Elder {
        unwrap!(self.current_mut().elder_state_mut())
    }
}

#[test]
fn construct() {
    let elder_test = ElderUnderTest::new();

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// ExpectCandidate is consensused: candidate is added
fn accumulate_expect_candidate() {
    let mut elder_test = ElderUnderTest::new();

    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// ExpectCandidate not consensused but node received Message: candidate is not added
fn not_accumulate_expect_candidate_with_message() {
    let mut elder_test = ElderUnderTest::new();

    let _ = elder_test.dispatch_routing_message(elder_test.expect_candidate_message());
    let _ = elder_test.create_gossip();

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// ExpectCandidate is consensused with the vote of node under test: candidate is added
fn accumulate_expect_candidate_with_message() {
    let mut elder_test = ElderUnderTest::new();
    let _ = elder_test.dispatch_routing_message(elder_test.expect_candidate_message());
    let _ = elder_test.create_gossip();

    elder_test.accumulate_expect_candidate_if_vote(elder_test.expect_candidate_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// PurgeCandidate is consensused first: candidate is removed
fn accumulate_purge_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());

    // Should probably add a test that the vote occured on timeout
    elder_test.accumulate_purge_candidate(elder_test.purge_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate is only removed as candidate when its EldersInfo is consensused
fn accumulate_online_candidate_only_do_not_remove_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());

    elder_test.accumulate_online(elder_test.online_payload());

    assert!(elder_test.has_unpolled_observations());
    assert!(elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate is only removed as candidate when its EldersInfo is consensused
// Vote for `Online` trigger immediate vote for AddElder
fn accumulate_online_candidate_then_add_elder_only_do_not_remove_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());

    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.has_candidate());
    assert!(elder_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate is only removed as candidate when its EldersInfo is consensused
fn accumulate_online_candidate_then_add_elder_then_section_info_remove_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());

    let new_elders_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_section_info_if_vote(new_elders_info);

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.has_candidate());
    assert!(elder_test.is_candidate_a_valid_peer());
}

#[test]
// When Online consensused first, PurgeCandidate has no effect
fn accumulate_online_then_purge_then_add_elder_for_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());

    elder_test.accumulate_purge_candidate(elder_test.purge_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.has_candidate());
    assert!(elder_test.is_candidate_a_valid_peer());
}

#[test]
// When Online consensused first, PurgeCandidate has no effect
fn accumulate_online_then_purge_then_add_elder_then_section_info_for_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());
    elder_test.accumulate_purge_candidate(elder_test.purge_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());

    let new_elders_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_section_info_if_vote(new_elders_info);

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.has_candidate());
    assert!(elder_test.is_candidate_a_valid_peer());
}

#[test]
// When PurgeCandidate consensused first, When Online consensused AddElder is not voted
// and the peer is not added.
fn accumulate_purge_then_online_for_candidate() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_purge_candidate(elder_test.purge_payload());

    elder_test.accumulate_online(elder_test.online_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// When Offline consensused, RemoveElder is voted.
fn accumulate_offline_for_node() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());
    elder_test.accumulate_section_info_if_vote(elder_test.new_elders_info_with_candidate());

    elder_test.accumulate_offline(elder_test.offline_payload());

    assert!(elder_test.has_unpolled_observations());
    assert!(elder_test.is_candidate_a_valid_peer());
}

#[test]
// When Offline consensused, RemoveElder is voted. The peer only become invalid once
// EldersInfo is consensused
fn accumulate_offline_then_remove_elder_for_node() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());
    elder_test.accumulate_section_info_if_vote(elder_test.new_elders_info_with_candidate());
    elder_test.accumulate_offline(elder_test.offline_payload());

    elder_test.accumulate_remove_elder_if_vote(elder_test.offline_payload());

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.is_candidate_a_valid_peer());
}

#[test]
// When Offline consensused, RemoveElder is voted. The peer only become invalid once
// EldersInfo is consensused
fn accumulate_offline_then_remove_elder_then_section_info_for_node() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());
    elder_test.accumulate_section_info_if_vote(elder_test.new_elders_info_with_candidate());
    elder_test.accumulate_offline(elder_test.offline_payload());
    elder_test.accumulate_remove_elder_if_vote(elder_test.offline_payload());

    elder_test.accumulate_section_info_if_vote(elder_test.new_elders_info_without_candidate());

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate now show info
fn candidate_info_message_in_interval() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.set_interval_to_match_candidate(true);
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());

    let _ = elder_test.dispatch_routing_message(elder_test.connection_request_message());
    elder_test.handle_connected_to_candidate();
    let _ = elder_test.handle_direct_message(elder_test.candidate_info_message());

    assert!(elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate info in wrong interval: Candidate not modifed - require purge event to remove
fn candidate_info_message_not_in_interval() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.set_interval_to_match_candidate(false);
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());

    let _ = elder_test.dispatch_routing_message(elder_test.connection_request_message());
    elder_test.handle_connected_to_candidate();
    let _ = elder_test.handle_direct_message(elder_test.candidate_info_message());

    assert!(elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate info that is not trustworthy is not trusted.
fn candidate_info_message_bad_signature() {
    let mut elder_test = ElderUnderTest::new();
    elder_test.set_interval_to_match_candidate(true);
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());

    let _ = elder_test.dispatch_routing_message(elder_test.connection_request_message());
    elder_test.handle_connected_to_candidate();
    let _ = elder_test
        .handle_direct_message(elder_test.candidate_info_message_use_wrong_old_signature(true));

    assert!(elder_test.has_candidate());
    assert!(!elder_test.is_candidate_a_valid_peer());
}

#[test]
fn allow_only_one_client_per_ip() {
    // Create two clients on the same IP.
    let client0 = ClientInfo::with_addr("198.51.100.0:5000");
    let client1 = ClientInfo::with_addr("198.51.100.0:5001");

    let mut elder_test = ElderUnderTest::new();
    elder_test.handle_bootstrap_request(*client0.public_id(), client0.connection_info());
    elder_test.handle_bootstrap_request(*client1.public_id(), client1.connection_info());

    assert!(elder_test.has_client(client0.public_id()));
    assert!(!elder_test.has_client(client1.public_id()));
}

#[test]
fn accept_previously_rejected_client_after_reaching_min_section_size() {
    // Set min_section_size to one more than the initial size of the section. This makes us reject
    // any bootstrapping clients.
    let mut elder_test = ElderUnderTest::with_min_section_size(NO_SINGLE_VETO_VOTE_COUNT + 1);
    let client = ClientInfo::with_addr("198.51.100.0:5000");

    // Bootstrap fails for insufficient section size.
    elder_test.handle_bootstrap_request(*client.public_id(), client.connection_info());
    assert!(!elder_test.has_client(client.public_id()));

    // Add new section member to reach min_section_size.
    elder_test.accumulate_expect_candidate(elder_test.expect_candidate_payload());
    elder_test.accumulate_online(elder_test.online_payload());
    elder_test.accumulate_add_elder_if_vote(elder_test.online_payload());
    elder_test.accumulate_section_info_if_vote(elder_test.new_elders_info_with_candidate());

    // Re-bootstrap now succeeds.
    elder_test.handle_bootstrap_request(*client.public_id(), client.connection_info());
    assert!(elder_test.has_client(client.public_id()));
}

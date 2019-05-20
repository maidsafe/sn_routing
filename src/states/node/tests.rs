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
use crate::cache::NullCache;
use crate::messages::Message;
use crate::mock_crust::crust::Config;
use crate::mock_crust::{self, Network};
use crate::outbox::{EventBox, EventBuf};
use crate::state_machine::{State, StateMachine};
use crate::xor_name::XOR_NAME_LEN;
use utils::LogIdent;

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

struct NoteUnderTest {
    pub machine: StateMachine,
    pub full_id: FullId,
    pub other_full_ids: Vec<FullId>,
    pub other_parsec_map: Vec<ParsecMap>,
    pub ev_buffer: EventBuf,
    pub section_info: SectionInfo,
    pub candidate_info: CandidateInfo,
}

impl NoteUnderTest {
    fn new() -> Self {
        let full_ids = (0..NO_SINGLE_VETO_VOTE_COUNT)
            .map(|_| FullId::new())
            .collect_vec();
        let mut ev_buffer = EventBuf::new();

        let prefix = Prefix::<XorName>::default();
        let section_info = unwrap!(SectionInfo::new(
            full_ids.iter().map(|id| *id.public_id()).collect(),
            prefix,
            iter::empty()
        ));

        let gen_pfx_info = GenesisPfxInfo {
            first_info: section_info.clone(),
            latest_info: SectionInfo::default(),
        };

        let full_id = full_ids[0].clone();
        let machine = make_state_machine(&full_id, &gen_pfx_info, &mut ev_buffer);

        let other_full_ids = full_ids[1..].iter().cloned().collect_vec();
        let other_parsec_map = other_full_ids
            .iter()
            .map(|full_id| ParsecMap::new(full_id.clone(), &gen_pfx_info))
            .collect_vec();

        let mut node_test = Self {
            machine,
            full_id,
            other_full_ids,
            other_parsec_map,
            ev_buffer,
            section_info,
            candidate_info: CandidateInfo::new(),
        };

        // Process initial unpolled event
        let _ = node_test.create_gossip();
        node_test
    }

    fn node_state(&self) -> &Node {
        unwrap!(self.machine.current().node_state())
    }

    fn n_vote_for(&mut self, count: usize, events: &[&NetworkEvent]) {
        for event in events {
            self.other_parsec_map
                .iter_mut()
                .take(count)
                .for_each(|parsec| parsec.vote_for((*event).clone(), &LogIdent::new(&0)));
        }
    }

    fn create_gossip(&mut self) -> Result<(), RoutingError> {
        let other_pub_id = *self.other_full_ids[0].public_id();
        match self.other_parsec_map[0].create_gossip(0, self.full_id.public_id()) {
            Some(Message::Direct(message)) => {
                self.handle_direct_message((message, other_pub_id))?
            }
            _ => panic!("create_gossip unexpected message"),
        };
        Ok(())
    }

    fn n_vote_for_gossipped(
        &mut self,
        count: usize,
        events: &[&NetworkEvent],
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

        unwrap!(self.machine.current_mut().node_state_mut())
            .set_next_relocation_interval(Some((name, name)));
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
            &[&NetworkEvent::ExpectCandidate(payload_expect.clone())],
        );
    }

    fn accumulate_purge_candidate(&mut self, purge_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&NetworkEvent::PurgeCandidate(purge_payload)],
        );
    }

    fn accumulate_online(&mut self, online_payload: OnlinePayload) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&NetworkEvent::Online(online_payload)],
        );
    }

    fn accumulate_add_elder_if_vote(&mut self, online_payload: OnlinePayload) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&NetworkEvent::AddElder(
                online_payload.new_public_id,
                online_payload.client_auth,
            )],
        );
    }

    fn accumulate_section_info_if_vote(&mut self, section_info_payload: SectionInfo) {
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            &[&NetworkEvent::SectionInfo(section_info_payload)],
        );
    }

    fn accumulate_offline(&mut self, offline_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            &[&NetworkEvent::Offline(offline_payload)],
        );
    }

    fn accumulate_remove_elder_if_vote(&mut self, offline_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            &[&NetworkEvent::RemoveElder(offline_payload)],
        );
    }

    fn new_section_info_with_candidate(&self) -> SectionInfo {
        unwrap!(SectionInfo::new(
            self.section_info
                .members()
                .iter()
                .chain(Some(self.candidate_info.new_full_id.public_id()))
                .cloned()
                .collect(),
            *self.section_info.prefix(),
            Some(&self.section_info)
        ))
    }

    fn new_section_info_without_candidate(&self) -> SectionInfo {
        let old_info = self.new_section_info_with_candidate();
        unwrap!(SectionInfo::new(
            self.section_info.members().clone(),
            *old_info.prefix(),
            Some(&old_info)
        ))
    }

    fn has_unpolled_observations(&self) -> bool {
        self.node_state().has_unpolled_observations(false)
    }

    fn has_resource_proof_candidate(&self) -> bool {
        self.node_state().has_resource_proof_candidate()
    }

    fn has_candidate_info(&self) -> bool {
        self.node_state().peer_mgr().has_candidate_info()
    }

    fn is_candidate_a_valid_peer(&self) -> bool {
        self.node_state()
            .chain()
            .is_peer_valid(self.candidate_info.new_full_id.public_id())
    }

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
    ) -> Result<(), RoutingError> {
        unwrap!(self.machine.current_mut().node_state_mut())
            .dispatch_routing_message(routing_msg, &mut self.ev_buffer)
    }

    fn handle_direct_message(
        &mut self,
        msg: (DirectMessage, PublicId),
    ) -> Result<(), RoutingError> {
        let _ = unwrap!(self.machine.current_mut().node_state_mut()).handle_direct_message(
            msg.0,
            msg.1,
            &mut self.ev_buffer,
        )?;
        Ok(())
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

    fn connection_info_request_message(&self) -> RoutingMessage {
        use crate::mock_crust::Endpoint;
        use crate::PubConnectionInfo;

        let new_full_id = &self.candidate_info.new_full_id;
        let their_pub_id = self.full_id.public_id();

        let src = Authority::Client {
            client_id: *new_full_id.public_id(),
            proxy_node_name: *self.candidate_info.new_proxy_id.public_id().name(),
        };
        let dst = Authority::ManagedNode(*their_pub_id.name());

        let content = {
            let shared_secret = new_full_id
                .encrypting_private_key()
                .shared_secret(their_pub_id.encrypting_public_key());

            let our_pub_info = PubConnectionInfo {
                id: *new_full_id.public_id(),
                endpoint: Endpoint(333),
            };
            let encrypted_conn_info = unwrap!(shared_secret.encrypt(&our_pub_info));

            MessageContent::ConnectionInfoRequest {
                encrypted_conn_info,
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

        let old_and_new_pub_ids = (old_full_id.public_id(), new_full_id.public_id());

        let old_signing_id = if use_bad_sig {
            new_full_id
        } else {
            old_full_id
        };

        let mut to_sign = unwrap!(serialisation::serialise(&old_and_new_pub_ids));
        let signature_using_old = old_signing_id.signing_private_key().sign_detached(&to_sign);

        to_sign.extend_from_slice(&signature_using_old.into_bytes());
        let signature_using_new = new_full_id.signing_private_key().sign_detached(&to_sign);

        (
            DirectMessage::CandidateInfo {
                old_public_id: *old_full_id.public_id(),
                new_public_id: *new_full_id.public_id(),
                signature_using_old,
                signature_using_new,
                new_client_auth: Authority::Client {
                    client_id: *new_full_id.public_id(),
                    proxy_node_name: *self.candidate_info.new_proxy_id.public_id().name(),
                },
            },
            *new_full_id.public_id(),
        )
    }
}

fn new_node_state(
    full_id: &FullId,
    gen_pfx_info: &GenesisPfxInfo,
    min_section_size: usize,
    crust_service: Service,
    timer: Timer,
    outbox: &mut EventBox,
) -> State {
    let public_id = *full_id.public_id();

    let parsec_map = ParsecMap::new(full_id.clone(), gen_pfx_info);
    let chain = Chain::new(min_section_size, public_id, gen_pfx_info.clone());
    let peer_mgr = PeerManager::new(public_id, true);
    let cache = Box::new(NullCache);

    let details = NodeDetails {
        ack_mgr: AckManager::new(),
        cache,
        chain,
        crust_service,
        event_backlog: Vec::new(),
        full_id: full_id.clone(),
        gen_pfx_info: gen_pfx_info.clone(),
        msg_backlog: Vec::new(),
        parsec_map,
        peer_mgr,
        routing_msg_filter: RoutingMessageFilter::new(),
        timer,
    };

    let section_info = gen_pfx_info.first_info.clone();
    let prefix = *section_info.prefix();
    Node::from_establishing_node(details, section_info, prefix, outbox)
        .map(State::Node)
        .unwrap_or(State::Terminated)
}

fn make_state_machine(
    full_id: &FullId,
    gen_pfx_info: &GenesisPfxInfo,
    outbox: &mut EventBox,
) -> StateMachine {
    let min_section_size = 4;
    let network = Network::new(min_section_size, None);
    let public_id = *full_id.public_id();

    let handle0 = network.new_service_handle(None, None);
    let config = Config::with_contacts(&[handle0.endpoint()]);

    let handle1 = network.new_service_handle(Some(config.clone()), None);
    mock_crust::make_current(&handle1, || {
        StateMachine::new(
            move |_action_sender, crust_service, timer, outbox2| {
                new_node_state(
                    full_id,
                    gen_pfx_info,
                    min_section_size,
                    crust_service,
                    timer,
                    outbox2,
                )
            },
            public_id,
            None,
            outbox,
        )
        .1
    })
}

#[test]
fn construct() {
    let node_test = NoteUnderTest::new();

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// ExpectCandidate is consensused: candidate is added
fn accumulate_expect_candidate() {
    let mut node_test = NoteUnderTest::new();

    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// ExpectCandidate not consensused but node received Message: candidate is not added
fn not_accumulate_expect_candidate_with_message() {
    let mut node_test = NoteUnderTest::new();

    let _ = node_test.dispatch_routing_message(node_test.expect_candidate_message());
    let _ = node_test.create_gossip();

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// ExpectCandidate is consensused with the vote of node under test: candidate is added
fn accumulate_expect_candidate_with_message() {
    let mut node_test = NoteUnderTest::new();
    let _ = node_test.dispatch_routing_message(node_test.expect_candidate_message());
    let _ = node_test.create_gossip();

    node_test.accumulate_expect_candidate_if_vote(node_test.expect_candidate_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// PurgeCandidate is consensused first: candidate is removed
fn accumulate_purge_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());

    // Should probably add a test that the vote occured on timeout
    node_test.accumulate_purge_candidate(node_test.purge_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate is only removed as candidate when its SectionInfo is consensused
fn accumulate_online_candidate_only_do_not_remove_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());

    node_test.accumulate_online(node_test.online_payload());

    assert!(node_test.has_unpolled_observations());
    assert!(node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate is only removed as candidate when its SectionInfo is consensused
// Vote for `Online` trigger immediate vote for AddElder
fn accumulate_online_candidate_then_add_elder_only_do_not_remove_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());

    node_test.accumulate_add_elder_if_vote(node_test.online_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(node_test.has_resource_proof_candidate());
    assert!(node_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate is only removed as candidate when its SectionInfo is consensused
fn accumulate_online_candidate_then_add_elder_then_section_info_remove_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());
    node_test.accumulate_add_elder_if_vote(node_test.online_payload());

    let new_section_info = node_test.new_section_info_with_candidate();
    node_test.accumulate_section_info_if_vote(new_section_info);

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.has_resource_proof_candidate());
    assert!(node_test.is_candidate_a_valid_peer());
}

#[test]
// When Online consensused first, PurgeCandidate has no effect
fn accumulate_online_then_purge_then_add_elder_for_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());

    node_test.accumulate_purge_candidate(node_test.purge_payload());
    node_test.accumulate_add_elder_if_vote(node_test.online_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(node_test.has_resource_proof_candidate());
    assert!(node_test.is_candidate_a_valid_peer());
}

#[test]
// When Online consensused first, PurgeCandidate has no effect
fn accumulate_online_then_purge_then_add_elder_then_section_info_for_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());
    node_test.accumulate_purge_candidate(node_test.purge_payload());
    node_test.accumulate_add_elder_if_vote(node_test.online_payload());

    let new_section_info = node_test.new_section_info_with_candidate();
    node_test.accumulate_section_info_if_vote(new_section_info);

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.has_resource_proof_candidate());
    assert!(node_test.is_candidate_a_valid_peer());
}

#[test]
// When PurgeCandidate consensused first, When Online consensused AddElder is not voted
// and the peer is not added.
fn accumulate_purge_then_online_for_candidate() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_purge_candidate(node_test.purge_payload());

    node_test.accumulate_online(node_test.online_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// When Offline consensused, RemoveElder is voted.
fn accumulate_offline_for_node() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());
    node_test.accumulate_add_elder_if_vote(node_test.online_payload());
    node_test.accumulate_section_info_if_vote(node_test.new_section_info_with_candidate());

    node_test.accumulate_offline(node_test.offline_payload());

    assert!(node_test.has_unpolled_observations());
    assert!(node_test.is_candidate_a_valid_peer());
}

#[test]
// When Offline consensused, RemoveElder is voted. The peer only become invalid once
// SectionInfo is consensused
fn accumulate_offline_then_remove_elder_for_node() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());
    node_test.accumulate_add_elder_if_vote(node_test.online_payload());
    node_test.accumulate_section_info_if_vote(node_test.new_section_info_with_candidate());
    node_test.accumulate_offline(node_test.offline_payload());

    node_test.accumulate_remove_elder_if_vote(node_test.offline_payload());

    assert!(!node_test.has_unpolled_observations());
    assert!(node_test.is_candidate_a_valid_peer());
}

#[test]
// When Offline consensused, RemoveElder is voted. The peer only become invalid once
// SectionInfo is consensused
fn accumulate_offline_then_remove_elder_then_section_info_for_node() {
    let mut node_test = NoteUnderTest::new();
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());
    node_test.accumulate_online(node_test.online_payload());
    node_test.accumulate_add_elder_if_vote(node_test.online_payload());
    node_test.accumulate_section_info_if_vote(node_test.new_section_info_with_candidate());
    node_test.accumulate_offline(node_test.offline_payload());
    node_test.accumulate_remove_elder_if_vote(node_test.offline_payload());

    node_test.accumulate_section_info_if_vote(node_test.new_section_info_without_candidate());

    assert!(!node_test.has_unpolled_observations());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate now show info
fn candidate_info_message_in_interval() {
    let mut node_test = NoteUnderTest::new();
    node_test.set_interval_to_match_candidate(true);
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());

    let _ = node_test.dispatch_routing_message(node_test.connection_info_request_message());
    let _ = node_test.handle_direct_message(node_test.candidate_info_message());

    assert!(node_test.has_candidate_info());
    assert!(node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate info in wrong interval: Candidate not modifed - require purge event to remove
fn candidate_info_message_not_in_interval() {
    let mut node_test = NoteUnderTest::new();
    node_test.set_interval_to_match_candidate(false);
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());

    let _ = node_test.dispatch_routing_message(node_test.connection_info_request_message());
    let _ = node_test.handle_direct_message(node_test.candidate_info_message());

    assert!(!node_test.has_candidate_info());
    assert!(node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

#[test]
// Candidate info that is not trustworthy is not trusted.
fn candidate_info_message_bad_signature() {
    let mut node_test = NoteUnderTest::new();
    node_test.set_interval_to_match_candidate(true);
    node_test.accumulate_expect_candidate(node_test.expect_candidate_payload());

    let _ = node_test.dispatch_routing_message(node_test.connection_info_request_message());
    let _ = node_test
        .handle_direct_message(node_test.candidate_info_message_use_wrong_old_signature(true));

    assert!(!node_test.has_candidate_info());
    assert!(node_test.has_resource_proof_candidate());
    assert!(!node_test.is_candidate_a_valid_peer());
}

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
    chain::SectionKeyInfo,
    generate_bls_threshold_secret_key,
    messages::DirectMessage,
    mock::Network,
    outbox::EventBox,
    rng::{self, MainRng},
    state_machine::{State, StateMachine, Transition},
    unwrap, BlsSecretKeyShare, NetworkConfig, NetworkParams, NetworkService, ELDER_SIZE,
};
use std::{iter, net::SocketAddr};

// Minimal number of votes to reach accumulation.
const ACCUMULATE_VOTE_COUNT: usize = 5;
// Only one vote missing to reach accumulation.
const NOT_ACCUMULATE_ALONE_VOTE_COUNT: usize = 4;

struct JoiningNodeInfo {
    full_id: FullId,
    addr: SocketAddr,
}
struct DkgToSectionInfo {
    participants: BTreeSet<PublicId>,
    new_pk_set: BlsPublicKeySet,
    new_other_ids: Vec<(FullId, BlsSecretKeyShare)>,
    new_elder_info: EldersInfo,
}

impl JoiningNodeInfo {
    fn with_addr(rng: &mut MainRng, addr: &str) -> Self {
        Self {
            full_id: FullId::gen(rng),
            addr: unwrap!(addr.parse()),
        }
    }

    fn public_id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo::from(self.addr)
    }
}

struct ElderUnderTest {
    pub rng: MainRng,
    pub machine: StateMachine,
    pub full_id: (FullId, BlsSecretKeyShare),
    pub other_ids: Vec<(FullId, BlsSecretKeyShare)>,
    pub elders_info: EldersInfo,
    pub candidate: P2pNode,
}

impl ElderUnderTest {
    fn new(sec_size: usize) -> Self {
        let mut rng = rng::new();
        let socket_addr: SocketAddr = unwrap!("127.0.0.1:9999".parse());
        let connection_info = ConnectionInfo::from(socket_addr);
        let full_ids: BTreeMap<_, _> = (0..sec_size)
            .map(|_| {
                let id = FullId::gen(&mut rng);
                (*id.public_id().name(), id)
            })
            .collect();

        let prefix = Prefix::<XorName>::default();
        let elders_info = unwrap!(EldersInfo::new(
            full_ids
                .iter()
                .map(|(name, id)| (
                    *name,
                    P2pNode::new(*id.public_id(), connection_info.clone())
                ))
                .collect(),
            prefix,
            iter::empty()
        ));
        let first_ages = full_ids
            .values()
            .map(|id| (*id.public_id(), MIN_AGE_COUNTER))
            .collect();

        let secret_key_set = generate_bls_threshold_secret_key(&mut rng, full_ids.len());
        let gen_pfx_info = GenesisPfxInfo {
            first_info: elders_info.clone(),
            first_bls_keys: secret_key_set.public_keys(),
            first_state_serialized: Vec::new(),
            first_ages,
            latest_info: EldersInfo::default(),
            parsec_version: 0,
        };

        let full_and_bls_ids = full_ids
            .values()
            .enumerate()
            .map(|(idx, full_id)| (full_id.clone(), secret_key_set.secret_key_share(idx)))
            .collect_vec();

        let full_id = full_and_bls_ids[0].clone();
        let machine =
            make_state_machine(&mut rng, (&full_id.0, &full_id.1), &gen_pfx_info, &mut ());

        let other_ids = full_and_bls_ids[1..].iter().cloned().collect_vec();

        let candidate_addr: SocketAddr = unwrap!("127.0.0.2:9999".parse());
        let candidate = P2pNode::new(
            *FullId::gen(&mut rng).public_id(),
            ConnectionInfo::from(candidate_addr),
        );

        let mut elder_test = Self {
            rng,
            machine,
            full_id,
            other_ids,
            elders_info,
            candidate,
        };

        // Process initial unpolled event including genesis
        elder_test.n_vote_for_unconsensused_events(elder_test.other_ids.len());
        unwrap!(elder_test.create_gossip());
        elder_test
    }

    fn elder_state(&self) -> &Elder {
        unwrap!(self.machine.current().elder_state())
    }

    fn n_vote_for(&mut self, count: usize, events: impl IntoIterator<Item = AccumulatingEvent>) {
        let parsec = unwrap!(self.machine.current_mut().elder_state_mut()).parsec_map_mut();
        for event in events {
            self.other_ids
                .iter()
                .take(count)
                .for_each(|(full_id, bls_id)| {
                    let sig_event =
                        if let AccumulatingEvent::SectionInfo(ref _info, ref section_key) = event {
                            Some(unwrap!(EventSigPayload::new_for_section_key_info(
                                &bls_id,
                                section_key
                            )))
                        } else {
                            None
                        };

                    info!("Vote as {:?} for event {:?}", full_id.public_id(), event);
                    parsec.vote_for_as(
                        event.clone().into_network_event_with(sig_event).into_obs(),
                        &full_id,
                    );
                });
        }
    }

    fn n_vote_for_unconsensused_events(&mut self, count: usize) {
        let parsec = unwrap!(self.machine.current_mut().elder_state_mut()).parsec_map_mut();
        let events = parsec.our_unpolled_observations().cloned().collect_vec();
        for event in events.into_iter() {
            self.other_ids.iter().take(count).for_each(|(full_id, _)| {
                info!(
                    "Vote as {:?} for unconsensused event {:?}",
                    full_id.public_id(),
                    event
                );
                parsec.vote_for_as(event.clone(), &full_id);
            });
        }
    }

    fn create_gossip(&mut self) -> Result<(), RoutingError> {
        let other_pub_id = *self.other_ids[0].0.public_id();
        let addr: SocketAddr = unwrap!("127.0.0.3:9999".parse());
        let connection_info = ConnectionInfo::from(addr);
        let parsec = unwrap!(self.machine.current_mut().elder_state_mut()).parsec_map_mut();
        let parsec_version = parsec.last_version();
        let request = parsec::Request::new();
        let message = DirectMessage::ParsecRequest(parsec_version, request);
        self.handle_direct_message((message, P2pNode::new(other_pub_id, connection_info)))
    }

    fn n_vote_for_gossipped(
        &mut self,
        count: usize,
        events: impl IntoIterator<Item = AccumulatingEvent>,
    ) -> Result<(), RoutingError> {
        self.n_vote_for(count, events);
        self.create_gossip()
    }

    fn accumulate_online(&mut self, p2p_node: P2pNode) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            iter::once(AccumulatingEvent::Online(OnlinePayload {
                p2p_node,
                age: MIN_AGE,
            })),
        );
    }

    fn updated_other_ids(&mut self, new_elder_info: EldersInfo) -> DkgToSectionInfo {
        let participants: BTreeSet<_> = new_elder_info.member_ids().copied().collect();
        let parsec = unwrap!(self.machine.current_mut().elder_state_mut()).parsec_map_mut();

        let dkg_results = self
            .other_ids
            .iter()
            .map(|(full_id, _)| {
                (
                    full_id.clone(),
                    unwrap!(parsec.get_dkg_result_as(participants.clone(), &full_id)),
                )
            })
            .collect_vec();

        let new_pk_set = unwrap!(dkg_results.first()).1.public_key_set.clone();
        let new_other_ids = dkg_results
            .into_iter()
            .filter_map(|(full_id, result)| (result.secret_key_share.map(|share| (full_id, share))))
            .collect_vec();
        DkgToSectionInfo {
            participants,
            new_pk_set,
            new_other_ids,
            new_elder_info,
        }
    }

    fn accumulate_section_info_if_vote(&mut self, new_info: &DkgToSectionInfo) {
        let section_key_info = SectionKeyInfo::from_elders_info(
            &new_info.new_elder_info,
            new_info.new_pk_set.public_key(),
        );
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            iter::once(AccumulatingEvent::SectionInfo(
                new_info.new_elder_info.clone(),
                section_key_info,
            )),
        );
    }

    fn accumulate_voted_unconsensused_events(&mut self) {
        self.n_vote_for_unconsensused_events(ACCUMULATE_VOTE_COUNT);
        let _ = self.create_gossip();
    }

    fn accumulate_offline(&mut self, offline_payload: PublicId) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            iter::once(AccumulatingEvent::Offline(offline_payload)),
        );
    }

    fn accumulate_start_dkg(&mut self, info: &DkgToSectionInfo) {
        let _ = self.n_vote_for_gossipped(
            ACCUMULATE_VOTE_COUNT,
            iter::once(AccumulatingEvent::StartDkg(info.participants.clone())),
        );
    }

    fn new_elders_info_with_candidate(&mut self) -> DkgToSectionInfo {
        assert!(
            self.elders_info.len() < ELDER_SIZE,
            "There is already ELDER_SIZE elders - the candidate won't be promoted"
        );

        let new_elder_info = unwrap!(EldersInfo::new(
            self.elders_info
                .member_nodes()
                .chain(iter::once(&self.candidate))
                .map(|node| (*node.public_id().name(), node.clone()))
                .collect(),
            *self.elders_info.prefix(),
            Some(&self.elders_info)
        ));

        self.updated_other_ids(new_elder_info)
    }

    fn new_elders_info_without_candidate(&mut self) -> DkgToSectionInfo {
        let old_info = self.new_elders_info_with_candidate();
        let new_elder_info = unwrap!(EldersInfo::new(
            self.elders_info.member_map().clone(),
            *old_info.new_elder_info.prefix(),
            Some(&old_info.new_elder_info)
        ));
        self.updated_other_ids(new_elder_info)
    }

    fn has_unpolled_observations(&self) -> bool {
        self.elder_state().has_unpolled_observations()
    }

    fn is_candidate_member(&self) -> bool {
        self.elder_state()
            .chain()
            .is_peer_our_member(self.candidate.public_id())
    }

    fn is_candidate_elder(&self) -> bool {
        self.elder_state()
            .chain()
            .is_peer_our_elder(self.candidate.public_id())
    }

    fn handle_direct_message(&mut self, msg: (DirectMessage, P2pNode)) -> Result<(), RoutingError> {
        let _ = self
            .machine
            .elder_state_mut()
            .handle_direct_message(msg.0, msg.1, &mut ())?;
        Ok(())
    }

    fn handle_connected_to(&mut self, conn_info: ConnectionInfo) {
        match self
            .machine
            .elder_state_mut()
            .handle_connected_to(conn_info, &mut ())
        {
            Transition::Stay => (),
            _ => panic!("Unexpected transition"),
        }
    }

    fn handle_bootstrap_request(&mut self, pub_id: PublicId, conn_info: ConnectionInfo) {
        self.handle_connected_to(conn_info.clone());
        unwrap!(self
            .machine
            .elder_state_mut()
            .handle_bootstrap_request(P2pNode::new(pub_id, conn_info), *pub_id.name()));
    }

    fn is_connected(&self, peer_addr: &SocketAddr) -> bool {
        self.machine.current().is_connected(peer_addr)
    }
}

fn new_elder_state(
    (full_id, secret_key_share): (&FullId, &BlsSecretKeyShare),
    gen_pfx_info: &GenesisPfxInfo,
    network_service: NetworkService,
    timer: Timer,
    rng: &mut MainRng,
    outbox: &mut dyn EventBox,
) -> State {
    let public_id = *full_id.public_id();

    let parsec_map = ParsecMap::default().with_init(rng, full_id.clone(), gen_pfx_info);
    let chain = Chain::new(
        Default::default(),
        public_id,
        gen_pfx_info.clone(),
        Some(secret_key_share.clone()),
    );

    let details = ElderDetails {
        chain,
        network_service,
        event_backlog: Default::default(),
        full_id: full_id.clone(),
        gen_pfx_info: gen_pfx_info.clone(),
        routing_msg_queue: Default::default(),
        routing_msg_backlog: Default::default(),
        direct_msg_backlog: Default::default(),
        sig_accumulator: Default::default(),
        parsec_map,
        routing_msg_filter: RoutingMessageFilter::new(),
        timer,
        rng: rng::new_from(rng),
    };

    let prefix = *gen_pfx_info.first_info.prefix();
    Elder::from_adult(details, prefix, outbox)
        .map(State::Elder)
        .unwrap_or(State::Terminated)
}

fn make_state_machine(
    rng: &mut MainRng,
    full_id: (&FullId, &BlsSecretKeyShare),
    gen_pfx_info: &GenesisPfxInfo,
    outbox: &mut dyn EventBox,
) -> StateMachine {
    let network = Network::new(NetworkParams {
        elder_size: ELDER_SIZE,
        safe_section_size: ELDER_SIZE,
    });

    let endpoint = network.gen_addr();
    let config = NetworkConfig::node().with_hard_coded_contact(endpoint);

    StateMachine::new(
        move |network_service, timer, outbox2| {
            new_elder_state(full_id, gen_pfx_info, network_service, timer, rng, outbox2)
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
    let elder_test = ElderUnderTest::new(ELDER_SIZE - 1);

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.is_candidate_elder());
}

#[test]
fn when_accumulate_online_then_node_is_added_to_our_members() {
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE - 1);
    let new_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_online(elder_test.candidate.clone());
    elder_test.accumulate_start_dkg(&new_info);

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.is_candidate_member());
    assert!(!elder_test.is_candidate_elder());
}

#[test]
fn when_accumulate_online_and_start_dkg_and_section_info_then_node_is_added_to_our_elders() {
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE - 1);
    let new_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_online(elder_test.candidate.clone());
    elder_test.accumulate_start_dkg(&new_info);

    elder_test.accumulate_section_info_if_vote(&new_info);
    elder_test.accumulate_voted_unconsensused_events();

    assert!(!elder_test.has_unpolled_observations());
    assert!(elder_test.is_candidate_member());
    assert!(elder_test.is_candidate_elder());
}

#[test]
fn when_accumulate_offline_then_node_is_removed_from_our_members() {
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE - 1);
    let new_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_online(elder_test.candidate.clone());
    elder_test.accumulate_start_dkg(&new_info);
    elder_test.accumulate_section_info_if_vote(&new_info);
    elder_test.accumulate_voted_unconsensused_events();

    elder_test.other_ids = new_info.new_other_ids;
    let new_info = elder_test.new_elders_info_without_candidate();
    elder_test.accumulate_offline(*elder_test.candidate.public_id());
    elder_test.accumulate_start_dkg(&new_info);

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.is_candidate_member());
    assert!(elder_test.is_candidate_elder());
}

#[test]
fn when_accumulate_offline_and_start_dkg_and_section_info_then_node_is_removed_from_our_elders() {
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE - 1);
    let new_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_online(elder_test.candidate.clone());
    elder_test.accumulate_start_dkg(&new_info);
    elder_test.accumulate_section_info_if_vote(&new_info);
    elder_test.accumulate_voted_unconsensused_events();

    elder_test.other_ids = new_info.new_other_ids;
    let new_info = elder_test.new_elders_info_without_candidate();
    elder_test.accumulate_offline(*elder_test.candidate.public_id());
    elder_test.accumulate_start_dkg(&new_info);
    elder_test.accumulate_section_info_if_vote(&new_info);
    elder_test.accumulate_voted_unconsensused_events();

    assert!(!elder_test.has_unpolled_observations());
    assert!(!elder_test.is_candidate_member());
    assert!(!elder_test.is_candidate_elder());
}

#[test]
fn accept_previously_rejected_node_after_reaching_elder_size() {
    // Set section size to one less than the desired number of the elders in a section. This makes
    // us reject any bootstrapping nodes.
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE - 1);
    let node = JoiningNodeInfo::with_addr(&mut elder_test.rng, "198.51.100.0:5000");

    // Bootstrap fails for insufficient section size.
    elder_test.handle_bootstrap_request(*node.public_id(), node.connection_info());
    assert!(!elder_test.is_connected(&node.connection_info().peer_addr));

    // Add new section member to reach elder_size.
    let new_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_online(elder_test.candidate.clone());
    elder_test.accumulate_start_dkg(&new_info);
    elder_test.accumulate_section_info_if_vote(&new_info);

    // Re-bootstrap now succeeds.
    elder_test.handle_bootstrap_request(*node.public_id(), node.connection_info());
    assert!(elder_test.is_connected(&node.connection_info().peer_addr));
}

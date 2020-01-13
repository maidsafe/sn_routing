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

use super::{super::test_utils, *};
use crate::{
    chain::SectionKeyInfo,
    generate_bls_threshold_secret_key,
    messages::DirectMessage,
    rng::{self, MainRng},
    state_machine::Transition,
    unwrap, ELDER_SIZE,
};
use mock_quic_p2p::Network;
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
    new_pk_set: bls::PublicKeySet,
    new_other_ids: Vec<(FullId, bls::SecretKeyShare)>,
    new_elders_info: EldersInfo,
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
    pub network: Network,
    pub elder: Elder,
    pub other_ids: Vec<(FullId, bls::SecretKeyShare)>,
    pub elders_info: EldersInfo,
    pub candidate: P2pNode,
}

impl ElderUnderTest {
    fn new(sec_size: usize) -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let (elders_info, full_ids) =
            test_utils::create_elders_info(&mut rng, &network, sec_size, None);
        let secret_key_set = generate_bls_threshold_secret_key(&mut rng, full_ids.len());
        let gen_pfx_info =
            test_utils::create_gen_pfx_info(elders_info.clone(), secret_key_set.public_keys(), 0);

        let mut full_and_bls_ids = full_ids
            .into_iter()
            .enumerate()
            .map(|(idx, (_, full_id))| (full_id, secret_key_set.secret_key_share(idx)))
            .collect_vec();

        let (full_id, secret_key_share) = full_and_bls_ids.remove(0);
        let other_ids = full_and_bls_ids;
        let elder = new_elder_state(&mut rng, &network, full_id, secret_key_share, gen_pfx_info);
        let candidate = gen_p2p_node(&mut rng, &network);

        let mut elder_test = Self {
            rng,
            network,
            elder,
            other_ids,
            elders_info,
            candidate,
        };

        // Process initial unpolled event including genesis
        elder_test.n_vote_for_unconsensused_events(elder_test.other_ids.len());
        unwrap!(elder_test.create_gossip());
        elder_test
    }

    fn n_vote_for(&mut self, count: usize, events: impl IntoIterator<Item = AccumulatingEvent>) {
        assert!(count <= self.other_ids.len());

        let parsec = self.elder.parsec_map_mut();
        for event in events {
            self.other_ids
                .iter()
                .take(count)
                .for_each(|(full_id, bls_id)| {
                    let sig_event =
                        if let AccumulatingEvent::SectionInfo(ref _info, ref section_key) = event {
                            Some(unwrap!(EventSigPayload::new_for_section_key_info(
                                bls_id,
                                section_key
                            )))
                        } else {
                            None
                        };

                    info!("Vote as {:?} for event {:?}", full_id.public_id(), event);
                    parsec.vote_for_as(
                        event.clone().into_network_event_with(sig_event).into_obs(),
                        full_id,
                    );
                });
        }
    }

    fn n_vote_for_unconsensused_events(&mut self, count: usize) {
        let parsec = self.elder.parsec_map_mut();
        let events = parsec.our_unpolled_observations().cloned().collect_vec();
        for event in events {
            self.other_ids.iter().take(count).for_each(|(full_id, _)| {
                info!(
                    "Vote as {:?} for unconsensused event {:?}",
                    full_id.public_id(),
                    event
                );
                parsec.vote_for_as(event.clone(), full_id);
            });
        }
    }

    fn create_gossip(&mut self) -> Result<(), RoutingError> {
        let other_pub_id = *self.other_ids[0].0.public_id();
        let addr: SocketAddr = unwrap!("127.0.0.3:9999".parse());
        let connection_info = ConnectionInfo::from(addr);
        let parsec = self.elder.parsec_map_mut();
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

    fn updated_other_ids(&mut self, new_elders_info: EldersInfo) -> DkgToSectionInfo {
        let participants: BTreeSet<_> = new_elders_info.member_ids().copied().collect();
        let parsec = self.elder.parsec_map_mut();

        let dkg_results = self
            .other_ids
            .iter()
            .map(|(full_id, _)| {
                (
                    full_id.clone(),
                    unwrap!(parsec.get_dkg_result_as(participants.clone(), full_id)),
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
            new_elders_info,
        }
    }

    fn accumulate_section_info_if_vote(&mut self, new_info: &DkgToSectionInfo) {
        let section_key_info = SectionKeyInfo::from_elders_info(
            &new_info.new_elders_info,
            new_info.new_pk_set.public_key(),
        );
        let _ = self.n_vote_for_gossipped(
            NOT_ACCUMULATE_ALONE_VOTE_COUNT,
            iter::once(AccumulatingEvent::SectionInfo(
                new_info.new_elders_info.clone(),
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

    // Accumulate `AckMessage` for the latest version of our own section.
    fn accumulate_self_ack_message(&mut self) {
        let event = AccumulatingEvent::AckMessage(AckMessagePayload {
            dst_name: self.elders_info.prefix().name(),
            src_prefix: *self.elders_info.prefix(),
            ack_version: self.elders_info.version(),
        });

        // This event needs total consensus.
        self.elder.vote_for_event(event.clone());
        let _ = self.n_vote_for_gossipped(self.other_ids.len(), iter::once(event));
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
            *old_info.new_elders_info.prefix(),
            Some(&old_info.new_elders_info)
        ));
        self.updated_other_ids(new_elder_info)
    }

    // Returns the EldersInfo after an elder is dropped and an adult is promoted to take
    // its place.
    fn new_elders_info_after_offline_and_promote(
        &mut self,
        dropped_elder_id: &PublicId,
        promoted_adult_node: P2pNode,
    ) -> DkgToSectionInfo {
        let new_member_map = self
            .elders_info
            .member_map()
            .iter()
            .filter(|(_, node)| node.public_id() != dropped_elder_id)
            .map(|(name, node)| (*name, node.clone()))
            .chain(iter::once((
                *promoted_adult_node.name(),
                promoted_adult_node,
            )))
            .collect();

        let new_elders_info = unwrap!(EldersInfo::new(
            new_member_map,
            *self.elders_info.prefix(),
            Some(&self.elders_info)
        ));
        self.updated_other_ids(new_elders_info)
    }

    fn has_unpolled_observations(&self) -> bool {
        self.elder.has_unpolled_observations()
    }

    fn is_candidate_member(&self) -> bool {
        self.elder
            .chain()
            .is_peer_our_member(self.candidate.public_id())
    }

    fn is_candidate_elder(&self) -> bool {
        self.elder
            .chain()
            .is_peer_our_elder(self.candidate.public_id())
    }

    fn handle_direct_message(&mut self, msg: (DirectMessage, P2pNode)) -> Result<(), RoutingError> {
        let _ = self.elder.handle_direct_message(msg.0, msg.1, &mut ())?;
        Ok(())
    }

    fn handle_connected_to(&mut self, conn_info: ConnectionInfo) {
        match self.elder.handle_connected_to(conn_info, &mut ()) {
            Transition::Stay => (),
            _ => panic!("Unexpected transition"),
        }
    }

    fn handle_bootstrap_request(&mut self, pub_id: PublicId, conn_info: ConnectionInfo) {
        self.handle_connected_to(conn_info.clone());
        self.elder
            .handle_bootstrap_request(P2pNode::new(pub_id, conn_info), *pub_id.name());
    }

    fn is_connected(&self, peer_addr: &SocketAddr) -> bool {
        self.elder.peer_map().has(peer_addr)
    }

    fn gen_p2p_node(&mut self) -> P2pNode {
        gen_p2p_node(&mut self.rng, &self.network)
    }
}

fn new_elder_state(
    rng: &mut MainRng,
    network: &Network,
    full_id: FullId,
    secret_key_share: bls::SecretKeyShare,
    gen_pfx_info: GenesisPfxInfo,
) -> Elder {
    let parsec_map = ParsecMap::default().with_init(rng, full_id.clone(), &gen_pfx_info);
    let chain = Chain::new(
        Default::default(),
        *full_id.public_id(),
        gen_pfx_info.clone(),
        Some(secret_key_share),
    );

    let prefix = *gen_pfx_info.first_info.prefix();
    let details = ElderDetails {
        chain,
        network_service: test_utils::create_network_service(network),
        event_backlog: Default::default(),
        full_id,
        gen_pfx_info,
        routing_msg_queue: Default::default(),
        routing_msg_backlog: Default::default(),
        direct_msg_backlog: Default::default(),
        sig_accumulator: Default::default(),
        parsec_map,
        routing_msg_filter: RoutingMessageFilter::new(),
        timer: test_utils::create_timer(),
        rng: rng::new_from(rng),
    };

    unwrap!(Elder::from_adult(details, prefix, &mut ()))
}

fn gen_p2p_node(rng: &mut MainRng, network: &Network) -> P2pNode {
    P2pNode::new(
        *FullId::gen(rng).public_id(),
        ConnectionInfo::from(network.gen_addr()),
    )
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
fn accept_node_before_and_after_reaching_elder_size() {
    // Set section size to one less than the desired number of the elders in a section. This makes
    // us reject any bootstrapping nodes.
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE - 1);
    let node0 = JoiningNodeInfo::with_addr(&mut elder_test.rng, "198.51.100.0:5000");

    // Bootstrap succeed even with too few elders.
    elder_test.handle_bootstrap_request(*node0.public_id(), node0.connection_info());
    assert!(elder_test.is_connected(&node0.connection_info().peer_addr));

    let node1 = JoiningNodeInfo::with_addr(&mut elder_test.rng, "198.51.100.1:5000");

    // Add new section member to reach elder_size.
    let new_info = elder_test.new_elders_info_with_candidate();
    elder_test.accumulate_online(elder_test.candidate.clone());
    elder_test.accumulate_start_dkg(&new_info);
    elder_test.accumulate_section_info_if_vote(&new_info);

    // Bootstrap succeeds.
    elder_test.handle_bootstrap_request(*node1.public_id(), node1.connection_info());
    assert!(elder_test.is_connected(&node1.connection_info().peer_addr));
}

#[test]
fn send_genesis_update() {
    let mut elder_test = ElderUnderTest::new(ELDER_SIZE);

    // let orig_section_version = elder_test.elders_info.version();

    let adult0 = elder_test.gen_p2p_node();
    let adult1 = elder_test.gen_p2p_node();

    elder_test.accumulate_online(adult0.clone());
    elder_test.accumulate_online(adult1.clone());

    // Remove one existing elder and promote an adult to take its place. This increments the
    // section version.
    let dropped_id = *elder_test.other_ids[0].0.public_id();
    let new_info = elder_test.new_elders_info_after_offline_and_promote(&dropped_id, adult0);

    elder_test.accumulate_offline(dropped_id);
    elder_test.accumulate_start_dkg(&new_info);
    elder_test.accumulate_section_info_if_vote(&new_info);
    elder_test.accumulate_voted_unconsensused_events();
    elder_test.elders_info = new_info.new_elders_info;
    elder_test.other_ids = new_info.new_other_ids;
    elder_test.accumulate_self_ack_message();

    let messages = elder_test.elder.create_genesis_updates();
    assert_eq!(messages.len(), 1); // only one adult.
    assert_eq!(messages[0].0, adult1);

    // TODO: uncomment this when the corresponding functionality is implemented.
    /*
    // Check the proof contains the version the adult is at.
    let proof_chain = unwrap!(messages[0].1.proof_chain());
    assert!(
        proof_chain
            .all_key_infos()
            .any(|key_info| key_info.version() == orig_section_version),
        "{:?} doesn't contain expected version {}",
        proof_chain,
        orig_section_version
    );
    */
}

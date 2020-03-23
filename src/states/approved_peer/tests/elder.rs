// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/* TODO: re-enable these tests

use super::{super::super::approved_peer::*, utils as test_utils};
use crate::{
    chain::{
        AccumulatingEvent, AckMessagePayload, EldersInfo, EventSigPayload, OnlinePayload,
        SectionKeyInfo, SectionProofSlice, MIN_AGE,
    },
    event::Connected,
    generate_bls_threshold_secret_key,
    id::FullId,
    messages::{BootstrapResponse, MemberKnowledge, Variant},
    parsec, quic_p2p,
    rng::{self, MainRng},
    utils, ELDER_SIZE,
};
use crossbeam_channel::Receiver;
use itertools::Itertools;
use mock_quic_p2p::Network;
use std::{collections::BTreeSet, iter, net::SocketAddr};

// Minimal number of votes to reach accumulation.
const ACCUMULATE_VOTE_COUNT: usize = 5;
// Only one vote missing to reach accumulation.
const NOT_ACCUMULATE_ALONE_VOTE_COUNT: usize = 4;

struct DkgToSectionInfo {
    participants: BTreeSet<PublicId>,
    new_pk_set: bls::PublicKeySet,
    new_other_ids: Vec<(FullId, bls::SecretKeyShare)>,
    new_elders_info: EldersInfo,
}

struct Env {
    pub rng: MainRng,
    pub network: Network,
    pub subject: ApprovedPeer,
    pub other_ids: Vec<(FullId, bls::SecretKeyShare)>,
    pub elders_info: EldersInfo,
    pub candidate: P2pNode,
}

impl Env {
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
        let subject = create_state(&mut rng, &network, full_id, secret_key_share, gen_pfx_info);
        let candidate = gen_p2p_node(&mut rng, &network);

        let mut env = Self {
            rng,
            network,
            subject,
            other_ids,
            elders_info,
            candidate,
        };

        // Process initial unpolled event including genesis
        env.n_vote_for_unconsensused_events(env.other_ids.len());
        env.create_gossip().unwrap();
        env
    }

    fn n_vote_for(&mut self, count: usize, events: impl IntoIterator<Item = AccumulatingEvent>) {
        assert!(count <= self.other_ids.len());

        let parsec = &mut self.subject.stage.approved_mut().parsec_map;
        for event in events {
            self.other_ids
                .iter()
                .take(count)
                .for_each(|(full_id, bls_id)| {
                    let sig_event =
                        if let AccumulatingEvent::SectionInfo(ref _info, ref section_key) = event {
                            Some(
                                EventSigPayload::new_for_section_key_info(bls_id, section_key)
                                    .unwrap(),
                            )
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
        let parsec = &mut self.subject.stage.approved_mut().parsec_map;
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
        let other_full_id = &self.other_ids[0].0;
        let addr: SocketAddr = "127.0.0.3:9999".parse().unwrap();
        let parsec = &mut self.subject.stage.approved_mut().parsec_map;
        let parsec_version = parsec.last_version();
        let request = parsec::Request::new();
        let message = Message::single_src(
            other_full_id,
            DstLocation::Direct,
            Variant::ParsecRequest(parsec_version, request),
        )
        .unwrap();

        let _ = self
            .subject
            .dispatch_message(Some(addr), message, &mut ())?;
        Ok(())
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
                their_knowledge: None,
            })),
        );
    }

    fn updated_other_ids(&mut self, new_elders_info: EldersInfo) -> DkgToSectionInfo {
        let participants: BTreeSet<_> = new_elders_info.member_ids().copied().collect();
        let parsec = &mut self.subject.stage.approved_mut().parsec_map;

        let dkg_results = self
            .other_ids
            .iter()
            .map(|(full_id, _)| {
                (
                    full_id.clone(),
                    parsec
                        .get_dkg_result_as(participants.clone(), full_id)
                        .expect("failed to get DKG result"),
                )
            })
            .collect_vec();

        let new_pk_set = dkg_results
            .first()
            .expect("no DKG results")
            .1
            .public_key_set
            .clone();
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
        self.subject
            .stage
            .approved_mut()
            .vote_for_event(event.clone());
        let _ = self.n_vote_for_gossipped(self.other_ids.len(), iter::once(event));
    }

    fn new_elders_info_with_candidate(&mut self) -> DkgToSectionInfo {
        assert!(
            self.elders_info.len() < ELDER_SIZE,
            "There is already ELDER_SIZE elders - the candidate won't be promoted"
        );

        let new_elder_info = EldersInfo::new(
            self.elders_info
                .member_nodes()
                .chain(iter::once(&self.candidate))
                .map(|node| (*node.public_id().name(), node.clone()))
                .collect(),
            *self.elders_info.prefix(),
            Some(&self.elders_info),
        )
        .unwrap();

        self.updated_other_ids(new_elder_info)
    }

    fn new_elders_info_without_candidate(&mut self) -> DkgToSectionInfo {
        let old_info = self.new_elders_info_with_candidate();
        let new_elder_info = EldersInfo::new(
            self.elders_info.member_map().clone(),
            *old_info.new_elders_info.prefix(),
            Some(&old_info.new_elders_info),
        )
        .unwrap();
        self.updated_other_ids(new_elder_info)
    }

    // Returns the EldersInfo after an elder is dropped and an adult is promoted to take
    // its place.
    fn new_elders_info_after_offline_and_promote(
        &mut self,
        dropped_elder_id: &PublicId,
        promoted_adult_node: P2pNode,
    ) -> DkgToSectionInfo {
        assert!(
            self.other_ids
                .iter()
                .any(|(full_id, _)| { full_id.public_id() == dropped_elder_id }),
            "dropped node must be one of the other elders"
        );

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

        let new_elders_info = EldersInfo::new(
            new_member_map,
            *self.elders_info.prefix(),
            Some(&self.elders_info),
        )
        .unwrap();
        self.updated_other_ids(new_elders_info)
    }

    fn has_unpolled_observations(&self) -> bool {
        self.subject.has_unpolled_observations()
    }

    fn is_candidate_member(&self) -> bool {
        self.subject
            .chain()
            .is_peer_our_member(self.candidate.public_id())
    }

    fn is_candidate_elder(&self) -> bool {
        self.subject
            .chain()
            .is_peer_our_elder(self.candidate.public_id())
    }

    fn gen_p2p_node(&mut self) -> P2pNode {
        gen_p2p_node(&mut self.rng, &self.network)
    }

    // Drop an existing elder and promote an adult to take its place. Drive the whole process to
    // completion by casting all necessary votes and letting them accumulate.
    fn perform_offline_and_promote(
        &mut self,
        dropped_elder_id: &PublicId,
        promoted_adult_node: P2pNode,
    ) {
        let new_info =
            self.new_elders_info_after_offline_and_promote(dropped_elder_id, promoted_adult_node);

        self.accumulate_offline(*dropped_elder_id);
        self.accumulate_start_dkg(&new_info);
        self.accumulate_section_info_if_vote(&new_info);
        self.accumulate_voted_unconsensused_events();
        self.elders_info = new_info.new_elders_info;
        self.other_ids = new_info.new_other_ids;
        self.accumulate_self_ack_message();
    }
}

fn create_state(
    rng: &mut MainRng,
    network: &Network,
    full_id: FullId,
    secret_key_share: bls::SecretKeyShare,
    gen_pfx_info: GenesisPfxInfo,
) -> ApprovedPeer {
    let core = Core {
        full_id,
        transport: test_utils::create_transport(network),
        msg_filter: Default::default(),
        msg_queue: Default::default(),
        timer: test_utils::create_timer(),
        rng: rng::new_from(rng),
    };

    let elder = ApprovedPeer::new(
        core,
        NetworkParams::default(),
        Connected::First,
        gen_pfx_info,
        Some(secret_key_share),
        &mut (),
    );
    assert!(elder.stage.approved().chain.is_self_elder());
    elder
}

fn gen_p2p_node(rng: &mut MainRng, network: &Network) -> P2pNode {
    P2pNode::new(*FullId::gen(rng).public_id(), network.gen_addr())
}

#[test]
fn construct() {
    let env = Env::new(ELDER_SIZE - 1);

    assert!(!env.has_unpolled_observations());
    assert!(!env.is_candidate_elder());
}

#[test]
fn when_accumulate_online_then_node_is_added_to_our_members() {
    let mut env = Env::new(ELDER_SIZE - 1);
    let new_info = env.new_elders_info_with_candidate();
    env.accumulate_online(env.candidate.clone());
    env.accumulate_start_dkg(&new_info);

    assert!(!env.has_unpolled_observations());
    assert!(env.is_candidate_member());
    assert!(!env.is_candidate_elder());
}

#[test]
fn when_accumulate_online_and_start_dkg_and_section_info_then_node_is_added_to_our_elders() {
    let mut env = Env::new(ELDER_SIZE - 1);
    let new_info = env.new_elders_info_with_candidate();
    env.accumulate_online(env.candidate.clone());
    env.accumulate_start_dkg(&new_info);

    env.accumulate_section_info_if_vote(&new_info);
    env.accumulate_voted_unconsensused_events();

    assert!(!env.has_unpolled_observations());
    assert!(env.is_candidate_member());
    assert!(env.is_candidate_elder());
}

#[test]
fn when_accumulate_offline_then_node_is_removed_from_our_members() {
    let mut env = Env::new(ELDER_SIZE - 1);
    let new_info = env.new_elders_info_with_candidate();
    env.accumulate_online(env.candidate.clone());
    env.accumulate_start_dkg(&new_info);
    env.accumulate_section_info_if_vote(&new_info);
    env.accumulate_voted_unconsensused_events();

    env.other_ids = new_info.new_other_ids;
    let new_info = env.new_elders_info_without_candidate();
    env.accumulate_offline(*env.candidate.public_id());
    env.accumulate_start_dkg(&new_info);

    assert!(!env.has_unpolled_observations());
    assert!(!env.is_candidate_member());
    assert!(env.is_candidate_elder());
}

#[test]
fn when_accumulate_offline_and_start_dkg_and_section_info_then_node_is_removed_from_our_elders() {
    let mut env = Env::new(ELDER_SIZE - 1);
    let new_info = env.new_elders_info_with_candidate();
    env.accumulate_online(env.candidate.clone());
    env.accumulate_start_dkg(&new_info);
    env.accumulate_section_info_if_vote(&new_info);
    env.accumulate_voted_unconsensused_events();

    env.other_ids = new_info.new_other_ids;
    let new_info = env.new_elders_info_without_candidate();
    env.accumulate_offline(*env.candidate.public_id());
    env.accumulate_start_dkg(&new_info);
    env.accumulate_section_info_if_vote(&new_info);
    env.accumulate_voted_unconsensused_events();

    assert!(!env.has_unpolled_observations());
    assert!(!env.is_candidate_member());
    assert!(!env.is_candidate_elder());
}

#[test]
fn handle_bootstrap() {
    let mut env = Env::new(ELDER_SIZE);
    let mut new_node = JoiningPeer::new(&mut env.rng);

    let p2p_node = P2pNode::new(*new_node.public_id(), new_node.our_connection_info());
    let dst_name = *new_node.public_id().name();

    env.subject.stage.approved_mut().handle_bootstrap_request(
        &mut env.subject.core,
        p2p_node,
        dst_name,
    );
    env.network.poll(&mut env.rng);

    let response = new_node.expect_bootstrap_response();
    match response {
        BootstrapResponse::Join(elders_info) => assert_eq!(elders_info, env.elders_info),
        BootstrapResponse::Rebootstrap(_) => panic!("Unexpected Rebootstrap response"),
    }
}

#[test]
fn send_genesis_update() {
    let mut env = Env::new(ELDER_SIZE);

    let orig_elders_version = env.elders_info.version();

    let adult0 = env.gen_p2p_node();
    let adult1 = env.gen_p2p_node();

    env.accumulate_online(adult0.clone());
    env.accumulate_online(adult1.clone());

    // Remove one existing elder and promote an adult to take its place. This increments the
    // section version.
    let dropped_id = *env.other_ids[0].0.public_id();
    env.perform_offline_and_promote(&dropped_id, adult0);

    // Create `GenesisUpdate` message and check its proof contains the version the adult is at.
    let message = utils::exactly_one(env.subject.stage.approved().create_genesis_updates());
    assert_eq!(message.0, adult1);

    let proof = &message.1.proof;
    verify_proof_chain_contains(proof, orig_elders_version);

    // Receive MemberKnowledge from the adult
    let parsec_version = env.subject.stage.approved().parsec_map.last_version();
    env.subject.stage.approved_mut().handle_member_knowledge(
        &mut env.subject.core,
        adult1,
        MemberKnowledge {
            elders_version: env.elders_info.version(),
            parsec_version,
        },
    );

    // Create another `GenesisUpdate` and check the proof contains the updated version and does not
    // contain the previous version.
    let message = utils::exactly_one(env.subject.stage.approved().create_genesis_updates());
    let proof = &message.1.proof;
    verify_proof_chain_contains(proof, env.elders_info.version());
    verify_proof_chain_does_not_contain(proof, orig_elders_version);
}

fn verify_proof_chain_contains(proof_chain: &SectionProofSlice, expected_version: u64) {
    assert!(
        proof_chain
            .all_prefix_version()
            .any(|(_, version)| version == expected_version),
        "{:?} doesn't contain expected version {}",
        proof_chain,
        expected_version,
    );
}

fn verify_proof_chain_does_not_contain(proof_chain: &SectionProofSlice, unexpected_version: u64) {
    assert!(
        proof_chain
            .all_prefix_version()
            .all(|(_, version)| version != unexpected_version),
        "{:?} contains unexpected version {}",
        proof_chain,
        unexpected_version,
    );
}

struct JoiningPeer {
    network_service: quic_p2p::QuicP2p,
    network_event_rx: Receiver<quic_p2p::Event>,
    full_id: FullId,
}

impl JoiningPeer {
    fn new(rng: &mut MainRng) -> Self {
        let (network_event_tx, network_event_rx) = {
            let (node_tx, node_rx) = crossbeam_channel::unbounded();
            let (client_tx, _) = crossbeam_channel::unbounded();
            (quic_p2p::EventSenders { node_tx, client_tx }, node_rx)
        };
        let network_service = quic_p2p::Builder::new(network_event_tx).build().unwrap();

        Self {
            network_service,
            network_event_rx,
            full_id: FullId::gen(rng),
        }
    }

    fn our_connection_info(&mut self) -> SocketAddr {
        self.network_service.our_connection_info().unwrap()
    }

    fn public_id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    fn expect_bootstrap_response(&self) -> BootstrapResponse {
        self.recv_messages()
            .find_map(|msg| match msg.variant {
                Variant::BootstrapResponse(response) => Some(response),
                _ => None,
            })
            .expect("BootstrapResponse not received")
    }

    fn recv_messages<'a>(&'a self) -> impl Iterator<Item = Message> + 'a {
        self.network_event_rx
            .try_iter()
            .filter_map(|event| match event {
                quic_p2p::Event::NewMessage { msg, .. } => Some(Message::from_bytes(&msg).unwrap()),
                _ => None,
            })
    }
}

*/

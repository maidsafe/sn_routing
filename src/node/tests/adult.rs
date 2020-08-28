// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils::{self as test_utils, MockTransport};
use crate::{
    consensus,
    id::FullId,
    location::DstLocation,
    messages::{AccumulatingMessage, Message, PlainMessage, Variant},
    network_params::NetworkParams,
    node::{Node, NodeConfig},
    rng::{self, MainRng},
    section::{self, EldersInfo, SectionProofChain, SharedState},
};

use mock_quic_p2p::Network;
use rand::Rng;
use xor_name::Prefix;

const ELDER_SIZE: usize = 3;
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: ELDER_SIZE,
    recommended_section_size: ELDER_SIZE + 1,
};

struct Env {
    rng: MainRng,
    network: Network,
    subject: Node,
    sk_set: bls::SecretKeySet,
    elders_info: EldersInfo,
    elder_full_ids: Vec<FullId>,
}

impl Env {
    fn new() -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let (elders_info, elder_full_ids) =
            section::gen_elders_info(&mut rng, Default::default(), ELDER_SIZE);
        let sk_set = consensus::generate_secret_key_set(&mut rng, ELDER_SIZE);

        let proven_elders_info = test_utils::create_proven(&sk_set, elders_info.clone());
        let shared_state = SharedState::new(
            SectionProofChain::new(proven_elders_info.proof.public_key),
            proven_elders_info,
        );

        let (subject, ..) = Node::approved(
            NodeConfig {
                network_params: NETWORK_PARAMS,
                ..Default::default()
            },
            shared_state,
            None,
        );

        Self {
            rng,
            network,
            subject,
            sk_set,
            elders_info,
            elder_full_ids,
        }
    }

    fn poll(&mut self) {
        self.network.poll(&mut self.rng)
    }

    // Create `MockTransport` for the `index`-th elder.
    fn create_elder_transport(&self, index: usize) -> MockTransport {
        let addr = self
            .elders_info
            .elders
            .get(self.elder_full_ids[index].public_id().name())
            .map(|p2p_node| p2p_node.peer_addr());
        MockTransport::new(addr)
    }

    // FIXME
    // fn send_elders_update(
    //     &mut self,
    //     parsec_version: u64,
    //     proof_chain: SectionProofChain,
    // ) -> Result<()> {
    //     let sender_full_id = &self.elder_full_ids[0];
    //     let sender_addr = *self
    //         .elders_info
    //         .elders
    //         .get(sender_full_id.public_id().name())
    //         .unwrap()
    //         .peer_addr();

    //     let elders_info = test_utils::create_proven(&self.sk_set, self.elders_info.clone());
    //     let elders_update = EldersUpdate {
    //         elders_info,
    //         parsec_version,
    //     };
    //     let variant = Variant::EldersUpdate(elders_update);
    //     let message = Message::single_src(
    //         sender_full_id,
    //         DstLocation::Direct,
    //         variant,
    //         Some(proof_chain),
    //         Some(self.public_key()),
    //     )?;

    //     test_utils::handle_message(&mut self.subject, sender_addr, message)
    // }

    fn create_user_message(&self, dst: DstLocation, content: Vec<u8>) -> Message {
        let pk_set = self.sk_set.public_keys();
        let pk = pk_set.public_key();

        let plain_msg = PlainMessage {
            src: Prefix::default(),
            dst,
            dst_key: pk,
            variant: Variant::UserMessage(content),
        };

        let proof_chain = SectionProofChain::new(pk);

        test_utils::accumulate_messages((0..ELDER_SIZE).map(|index| {
            let sk_share = self.sk_set.secret_key_share(index);
            let proof_share = plain_msg.prove(pk_set.clone(), index, &sk_share).unwrap();
            AccumulatingMessage::new(plain_msg.clone(), proof_chain.clone(), proof_share)
        }))
    }

    // fn public_key(&self) -> bls::PublicKey {
    //     self.sk_set.public_keys().public_key()
    // }
}

// FIXME
// #[test]
// fn handle_elders_update_on_parsec_prune() {
//     let mut env = Env::new();

//     assert_eq!(env.subject.parsec_last_version(), 0);

//     env.send_elders_update(1, SectionProofChain::new(env.public_key()))
//         .unwrap();
//     assert_eq!(env.subject.parsec_last_version(), 1);
// }

// FIXME
// #[test]
// fn handle_elders_update_on_elders_change() {
//     let mut env = Env::new();

//     let old_pk = env.subject.section_key().copied();

//     let mut proof_chain = SectionProofChain::new(env.public_key());

//     let new_sk_set = consensus::generate_secret_key_set(&mut env.rng, ELDER_SIZE);
//     let new_pk = new_sk_set.public_keys().public_key();

//     let new_pk_proof = test_utils::create_proof(&env.sk_set, &new_pk);
//     proof_chain.push(new_pk, new_pk_proof.signature);

//     env.sk_set = new_sk_set;
//     env.send_elders_update(1, proof_chain).unwrap();

//     assert_eq!(env.subject.parsec_last_version(), 1);
//     assert_ne!(env.subject.section_key(), old_pk.as_ref());
//     assert_eq!(env.subject.section_key(), Some(&new_pk));
// }

// FIXME
// #[test]
// fn handle_elders_update_ignore_old_parsec_vesions() {
//     let mut env = Env::new();

//     let proof_chain = SectionProofChain::new(env.public_key());

//     env.send_elders_update(1, proof_chain.clone()).unwrap();
//     assert_eq!(env.subject.parsec_last_version(), 1);

//     env.send_elders_update(2, proof_chain.clone()).unwrap();
//     assert_eq!(env.subject.parsec_last_version(), 2);

//     env.send_elders_update(1, proof_chain).unwrap();
//     assert_eq!(env.subject.parsec_last_version(), 2);
// }

// FIXME
// #[test]
// fn handle_elders_update_allow_skipped_parsec_versions() {
//     let mut env = Env::new();

//     assert_eq!(env.subject.parsec_last_version(), 0);

//     env.send_elders_update(2, SectionProofChain::new(env.public_key()))
//         .unwrap();
//     assert_eq!(env.subject.parsec_last_version(), 2);
// }

// FIXME
// #[test]
// fn untrusted_elders_update() {
//     let mut env = Env::new();

//     assert_eq!(env.subject.parsec_last_version(), 0);
//     let old_pk = env.subject.section_key().copied();

//     let new_sk_set = consensus::generate_secret_key_set(&mut env.rng, ELDER_SIZE);
//     let new_pk = new_sk_set.public_keys().public_key();

//     env.sk_set = new_sk_set;
//     env.send_elders_update(1, SectionProofChain::new(new_pk))
//         .unwrap();

//     assert_eq!(env.subject.parsec_last_version(), 0);
//     assert_eq!(env.subject.section_key(), old_pk.as_ref());
// }

#[test]
fn handle_unknown_message() {
    let mut env = Env::new();

    // adults can't handle messages addressed to sections.
    let dst = DstLocation::Section(env.rng.gen());
    let msg = env.create_user_message(dst, b"hello section".to_vec());
    let transport = env.create_elder_transport(0);

    test_utils::handle_message(&mut env.subject, *transport.addr(), msg).unwrap();

    env.poll();

    for (sender, msg) in transport.received_messages() {
        if sender == env.subject.our_connection_info().unwrap()
            && matches!(msg.variant(), Variant::BouncedUnknownMessage { .. })
        {
            return;
        }
    }

    panic!("BouncedUnknownMessage not received")
}

#[test]
fn handle_untrusted_accumulated_message() {
    let mut env = Env::new();

    // Generate new section key which the adult is not yet aware of.
    env.sk_set = consensus::generate_secret_key_set(&mut env.rng, ELDER_SIZE);

    // This message is signed with the new key so won't be trusted by the adult yet.
    let dst = DstLocation::Node(*env.subject.name());
    let msg = env.create_user_message(dst, b"hello node".to_vec());
    let transport = env.create_elder_transport(0);

    test_utils::handle_message(&mut env.subject, *transport.addr(), msg).unwrap();

    env.poll();

    for (sender, msg) in transport.received_messages() {
        if sender == env.subject.our_connection_info().unwrap()
            && matches!(msg.variant(), Variant::BouncedUntrustedMessage(_))
        {
            return;
        }
    }

    panic!("BouncedUntrustedMessage not received")
}

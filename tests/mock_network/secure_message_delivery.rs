// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes_until_split, poll_all, TestNode, LOWERED_ELDER_SIZE};
use routing::{
    generate_bls_threshold_secret_key, mock::Environment, rng::MainRng, AccumulatingMessage,
    DstLocation, EldersInfo, FullId, IndexedSecretKeyShare, Message, NetworkParams, P2pNode,
    PlainMessage, Prefix, SectionProofChain, Variant, XorName,
};
use std::{collections::BTreeMap, iter, net::SocketAddr};

fn get_prefix(node: &TestNode) -> Prefix<XorName> {
    *node.inner.our_prefix().unwrap()
}

fn get_position_with_other_prefix(nodes: &[TestNode], prefix: &Prefix<XorName>) -> usize {
    nodes
        .iter()
        .position(|node| get_prefix(node) != *prefix)
        .unwrap()
}

fn send_message(nodes: &mut [TestNode], src: usize, dst: usize, message: Message) {
    let connection_info = nodes[dst].inner.our_connection_info().unwrap();
    let targets = vec![connection_info];

    let _ = nodes[src]
        .inner
        .send_message_to_targets(&targets, 1, message);
}

enum FailType {
    TrustedProofInvalidSig,
    UntrustedProofValidSig,
}

// Create 2 sections, and then send a NeighbourInfo message from one to the other with
// a bad new SectionInfo signed by an unknown BLS Key. Either with a SectionProofChain containing
// that bad BLS key for `UntrustedProofValidSig` or a trusted SectionProofChain not containing it
// for `TrustedProofInvalidSig`.
fn message_with_invalid_security(fail_type: FailType) {
    // Arrange
    //
    let mut env = Environment::new(NetworkParams {
        elder_size: LOWERED_ELDER_SIZE,
        recommended_section_size: LOWERED_ELDER_SIZE,
    });
    env.expect_panic();
    let mut rng = env.new_rng();

    let mut nodes = create_connected_nodes_until_split(&env, &[1, 1]);

    let their_node_pos = 0;
    let their_prefix = get_prefix(&nodes[their_node_pos]);
    let their_key = *nodes[their_node_pos].inner.section_key().unwrap();

    let our_node_pos = get_position_with_other_prefix(&nodes, &their_prefix);
    let our_prefix = get_prefix(&nodes[our_node_pos]);

    let fake_full = FullId::gen(&mut env.new_rng());
    let bls_keys = generate_bls_threshold_secret_key(&mut rng, 1);
    let bls_secret_key_share = IndexedSecretKeyShare::from_set(&bls_keys, 0);

    let socket_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let members: BTreeMap<_, _> = iter::once((
        *fake_full.public_id().name(),
        P2pNode::new(*fake_full.public_id(), socket_addr),
    ))
    .collect();
    let new_info = EldersInfo::new(members, our_prefix, 10001);

    let content = PlainMessage {
        src: our_prefix,
        dst: DstLocation::Prefix(their_prefix),
        dst_key: their_key,
        variant: Variant::NeighbourInfo(new_info),
    };

    let message = {
        let proof = match fail_type {
            FailType::TrustedProofInvalidSig => nodes[our_node_pos]
                .inner
                .prove(&DstLocation::Prefix(their_prefix))
                .unwrap(),
            FailType::UntrustedProofValidSig => {
                create_invalid_proof_chain(&mut rng, bls_keys.public_keys().public_key())
            }
        };
        let pk_set = bls_keys.public_keys();

        let msg = AccumulatingMessage::new(content, &bls_secret_key_share, pk_set, proof).unwrap();
        msg.combine_signatures().unwrap()
    };

    // Act/Assert:
    // poll_all will panic, when the receiving node process the message
    // and detect an invalid signature or proof.
    //
    send_message(&mut nodes, our_node_pos, their_node_pos, message);
    poll_all(&env, &mut nodes);
}

#[test]
#[should_panic(expected = "FailedSignature")]
fn message_with_invalid_signature() {
    message_with_invalid_security(FailType::TrustedProofInvalidSig);
}

#[test]
#[should_panic(expected = "UntrustedMessage")]
fn message_with_invalid_proof() {
    message_with_invalid_security(FailType::UntrustedProofValidSig);
}

fn create_invalid_proof_chain(rng: &mut MainRng, last_pk: bls::PublicKey) -> SectionProofChain {
    let block0_key = generate_bls_threshold_secret_key(rng, 1)
        .public_keys()
        .public_key();

    let block1_signature = {
        let invalid_sk_set = generate_bls_threshold_secret_key(rng, 1);
        let invalid_sk_share = invalid_sk_set.secret_key_share(0);
        let signature_share = invalid_sk_share.sign(&last_pk.to_bytes()[..]);
        invalid_sk_set
            .public_keys()
            .combine_signatures(iter::once((0, &signature_share)))
            .unwrap()
    };

    let mut chain = SectionProofChain::new(block0_key);
    chain.push_without_validation(last_pk, block1_signature);
    chain
}

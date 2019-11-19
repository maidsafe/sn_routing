// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{create_connected_nodes_until_split, poll_all, Nodes, TestNode};
use routing::{
    bls_key_set_from_elders_info, elders_info_for_test, mock::Network,
    section_proof_chain_from_elders_info, Authority, ConnectionInfo, FullId, HopMessage, Message,
    MessageContent, NetworkParams, P2pNode, Prefix, RoutingMessage, SignedRoutingMessage, XorName,
};
use std::collections::BTreeMap;
use std::iter;
use std::net::SocketAddr;

fn get_prefix(node: &TestNode) -> Prefix<XorName> {
    *unwrap!(node.inner.our_prefix())
}

fn get_position_with_other_prefix(nodes: &Nodes, prefix: &Prefix<XorName>) -> usize {
    unwrap!(nodes.iter().position(|node| get_prefix(node) != *prefix))
}

fn send_message(nodes: &mut Nodes, src: usize, dst: usize, message: Message) {
    let connection_info = unwrap!(nodes[dst].inner.our_connection_info());
    let targets = vec![connection_info];

    let _ = nodes[src]
        .inner
        .elder_state_mut()
        .map(|state| state.send_msg_to_targets(&targets, 1, message));
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
    //
    // Arrange
    //
    let elder_size = 3;
    let safe_section_size = 3;
    let mut network = Network::new(NetworkParams {
        elder_size,
        safe_section_size,
    });
    network.expect_panic();

    let mut nodes = create_connected_nodes_until_split(&network, vec![1, 1]);

    let their_node_pos = 0;
    let their_prefix = get_prefix(&nodes[their_node_pos]);

    let our_node_pos = get_position_with_other_prefix(&nodes, &their_prefix);
    let our_prefix = get_prefix(&nodes[our_node_pos]);

    let fake_full = FullId::gen(&mut network.new_rng());
    let socket_addr: SocketAddr = unwrap!("127.0.0.1:9999".parse());
    let connection_info = ConnectionInfo::from(socket_addr);
    let members: BTreeMap<_, _> = iter::once((
        *fake_full.public_id(),
        P2pNode::new(*fake_full.public_id(), connection_info),
    ))
    .collect();
    let new_info = unwrap!(elders_info_for_test(members, our_prefix, 10001,));

    let routing_msg = RoutingMessage {
        src: Authority::Section(our_prefix.name()),
        dst: Authority::PrefixSection(their_prefix),
        content: MessageContent::NeighbourInfo(new_info.clone()),
    };

    let message = {
        let proof = match fail_type {
            FailType::TrustedProofInvalidSig => unwrap!(nodes[our_node_pos]
                .inner
                .prove(&Authority::PrefixSection(their_prefix))),
            FailType::UntrustedProofValidSig => section_proof_chain_from_elders_info(&new_info),
        };
        let pk_set = bls_key_set_from_elders_info(new_info);

        let mut signed_msg = unwrap!(SignedRoutingMessage::new(
            routing_msg.clone(),
            &fake_full,
            pk_set,
            proof
        ));
        signed_msg.combine_signatures();
        Message::Hop(unwrap!(HopMessage::new(signed_msg)))
    };

    //
    // Act/Assert:
    // poll_all will panic, when the receiving node process the message
    // and detect an invalid signature or proof.
    //
    send_message(&mut nodes, our_node_pos, their_node_pos, message);
    let _ = poll_all(&mut nodes);
}

#[test]
#[should_panic]
fn message_with_invalid_signature() {
    message_with_invalid_security(FailType::TrustedProofInvalidSig);
}

#[test]
#[should_panic]
fn message_with_invalid_proof() {
    message_with_invalid_security(FailType::UntrustedProofValidSig);
}

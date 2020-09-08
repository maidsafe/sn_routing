// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    event::Event,
    messages::{Message, Variant},
    mock::Environment,
    node::{Node, NodeConfig, BOOTSTRAP_TIMEOUT},
    qp2p::{EventSenders, Peer},
    transport::Transport,
    TransportConfig, TransportEvent,
};
use crossbeam_channel::{self as mpmc, TryRecvError};
use sn_fake_clock::FakeClock;

#[test]
// Check that losing our proxy connection while in the bootstrapping stage doesn't stall
// and instead triggers a re-bootstrap attempt..
fn lose_proxy_connection() {
    let env = Environment::new(Default::default());

    // Start a bare-bones network service "A".
    let (node_a_event_tx, node_a_event_rx) = {
        let (node_tx, node_rx) = mpmc::unbounded();
        let (client_tx, _) = mpmc::unbounded();
        (EventSenders { node_tx, client_tx }, node_rx)
    };
    let node_a_endpoint = env.gen_addr();
    let node_a_config = TransportConfig::node().with_endpoint(node_a_endpoint);
    let node_a_network_service = Transport::new(node_a_event_tx, node_a_config).unwrap();

    // Construct a node "B" which will start in the bootstrapping stage and bootstrap off the
    // network service above.
    let node_b_endpoint = env.gen_addr();
    let node_b_config = TransportConfig::node()
        .with_hard_coded_contact(node_a_endpoint)
        .with_endpoint(node_b_endpoint);

    let (mut node_b, node_b_event_rx, _) = Node::new(NodeConfig {
        transport_config: node_b_config,
        ..Default::default()
    });

    // Check that A received `ConnectedTo` from B.
    env.poll();
    match node_a_event_rx.try_recv().unwrap() {
        TransportEvent::ConnectedTo {
            peer: Peer::Node { .. },
        } => (),
        ev => panic!(
            "Should have received `ConnectedTo` event, received `{:?}`.",
            ev
        ),
    }

    // B should have received the `BootstrappedTo` event and this will have
    // caused it to send a `BootstrapRequest` message.
    env.poll();
    step_at_least_once(&mut node_b);

    // Check that A received the `BootstrapRequest` from B.
    env.poll();
    if let TransportEvent::NewMessage { peer, msg } = node_a_event_rx.try_recv().unwrap() {
        assert_eq!(peer.peer_addr(), node_b_endpoint);

        let message = Message::from_bytes(&msg).unwrap();
        match message.variant() {
            Variant::BootstrapRequest(_) => (),
            _ => panic!("Should have received a `BootstrapRequest`."),
        };
    } else {
        panic!("Should have received `NewMessage` event.");
    }

    // Drop A and let some time pass...
    drop(node_a_network_service);
    FakeClock::advance_time(BOOTSTRAP_TIMEOUT.as_secs() * 1000 + 1);
    env.poll();

    // ...which causes the bootstrap request to timeout and B then attempts to rebootstrap..
    step_at_least_once(&mut node_b);
    assert!(matches!(
        node_b_event_rx.try_recv(),
        Err(TryRecvError::Empty)
    ));
    env.poll();

    // ... but there is no one to bootstrap to, so the bootstrap fails which causes B to terminate.
    step_at_least_once(&mut node_b);
    assert!(matches!(node_b_event_rx.try_recv(), Ok(Event::Terminated)));
    assert!(matches!(
        node_b_event_rx.try_recv(),
        Err(TryRecvError::Empty)
    ));
}

fn step_at_least_once(node: &mut Node) {
    let mut sel = mpmc::Select::new();
    node.register(&mut sel);

    // Step for the first one.
    let op_index = sel.try_ready().unwrap();
    node.handle_selected_operation(op_index).unwrap();

    // Exhaust any remaining steps
    loop {
        let mut sel = mpmc::Select::new();
        node.register(&mut sel);

        if let Ok(op_index) = sel.try_ready() {
            node.handle_selected_operation(op_index).unwrap();
        } else {
            break;
        }
    }
}

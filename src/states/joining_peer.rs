// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/* TODO: re-enable this test

#[cfg(all(test, feature = "mock_base"))]
mod tests {
    use super::*;
    use crate::{
        chain::NetworkParams,
        event::Event,
        id::FullId,
        messages::{Message, Variant},
        mock::Environment,
        quic_p2p::{Builder, EventSenders, Peer},
        stage::BOOTSTRAP_TIMEOUT,
        state_machine::{State, StateMachine},
        unwrap, NetworkConfig, NetworkEvent,
    };
    use crossbeam_channel as mpmc;
    use fake_clock::FakeClock;

    #[test]
    // Check that losing our proxy connection while in the bootstrapping stage doesn't stall
    // and instead triggers a re-bootstrap attempt..
    fn lose_proxy_connection() {
        let mut network_cfg = NetworkParams::default();

        if cfg!(feature = "mock_base") {
            network_cfg.elder_size = 7;
            network_cfg.safe_section_size = 30;
        };

        let env = Environment::new(Default::default());
        let mut rng = env.new_rng();

        // Start a bare-bones network service.
        let (event_tx, (event_rx, _)) = {
            let (node_tx, node_rx) = mpmc::unbounded();
            let (client_tx, client_rx) = mpmc::unbounded();
            (EventSenders { node_tx, client_tx }, (node_rx, client_rx))
        };
        let node_a_endpoint = env.gen_addr();
        let config = NetworkConfig::node().with_endpoint(node_a_endpoint);
        let node_a_network_service = unwrap!(Builder::new(event_tx).with_config(config).build());

        // Construct a `StateMachine` which will start in the `BootstrappingPeer` state and
        // bootstrap off the network service above.
        let node_b_endpoint = env.gen_addr();
        let config = NetworkConfig::node()
            .with_hard_coded_contact(node_a_endpoint)
            .with_endpoint(node_b_endpoint);
        let node_b_full_id = FullId::gen(&mut rng);

        let mut node_b_outbox = Vec::new();
        let (node_b_client_tx, _) = mpmc::unbounded();

        let (_node_b_action_tx, mut node_b_state_machine) = StateMachine::new(
            move |transport, timer, _outbox2| {
                State::JoiningPeer(JoiningPeer::new(
                    Core {
                        full_id: node_b_full_id,
                        transport,
                        msg_filter: Default::default(),
                        msg_queue: Default::default(),
                        timer,
                        rng,
                    },
                    network_cfg,
                ))
            },
            config,
            node_b_client_tx,
            &mut node_b_outbox,
        );

        // Check the network service received `ConnectedTo`.
        env.poll();
        match unwrap!(event_rx.try_recv()) {
            NetworkEvent::ConnectedTo {
                peer: Peer::Node { .. },
            } => (),
            ev => panic!(
                "Should have received `ConnectedTo` event, received `{:?}`.",
                ev
            ),
        }

        // The state machine should have received the `BootstrappedTo` event and this will have
        // caused it to send a `BootstrapRequest` message.
        env.poll();
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);

        // Check the network service received the `BootstrapRequest`
        env.poll();
        if let NetworkEvent::NewMessage { peer, msg } = unwrap!(event_rx.try_recv()) {
            assert_eq!(peer.peer_addr(), node_b_endpoint);

            let message = unwrap!(Message::from_bytes(&msg));
            match message.variant {
                Variant::BootstrapRequest(_) => (),
                _ => panic!("Should have received a `BootstrapRequest`."),
            };
        } else {
            panic!("Should have received `NewMessage` event.");
        }

        // Drop the network service and let some time pass...
        drop(node_a_network_service);
        FakeClock::advance_time(BOOTSTRAP_TIMEOUT.as_secs() * 1000 + 1);
        env.poll();

        // ...which causes the bootstrap request to timeout and the node then attempts to
        // rebootstrap..
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);
        assert!(node_b_outbox.is_empty());
        env.poll();

        // ... but there is no one to bootstrap to, so the bootstrap fails which causes the state
        // machine to terminate.
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);
        assert_eq!(node_b_outbox.len(), 1);
        assert_eq!(node_b_outbox[0], Event::Terminated);
    }

    fn step_at_least_once(machine: &mut StateMachine, outbox: &mut dyn EventBox) {
        let mut sel = mpmc::Select::new();
        machine.register(&mut sel);

        // Step for the first one.
        let op_index = unwrap!(sel.try_ready());
        unwrap!(machine.step(op_index, outbox));

        // Exhaust any remaining steps
        loop {
            let mut sel = mpmc::Select::new();
            machine.register(&mut sel);

            if let Ok(op_index) = sel.try_ready() {
                unwrap!(machine.step(op_index, outbox));
            } else {
                break;
            }
        }
    }
}

*/

// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// These tests are almost straight up copied from crust::service::tests

use maidsafe_utilities::event_sender::{MaidSafeObserver, MaidSafeEventCategory};
use std::sync::mpsc::{self, Receiver};

use super::crust::{CrustEventSender, Event, Service};
use super::support::{Config, Network};

fn get_event_sender() -> (CrustEventSender, Receiver<MaidSafeEventCategory>, Receiver<Event>) {
    let (category_tx, category_rx) = mpsc::channel();
    let event_category = MaidSafeEventCategory::Crust;
    let (event_tx, event_rx) = mpsc::channel();

    (MaidSafeObserver::new(event_tx, event_category, category_tx), category_rx, event_rx)
}

#[test]
fn start_two_services_bootstrap_communicate_exit() {
    let network = Network::new();
    let endpoint0 = network.gen_endpoint(None);
    let endpoint1 = network.gen_endpoint(None);
    let config = Config::with_contacts(&[endpoint0, endpoint1]);

    let handle0 = network.new_service_handle(Some(config.clone()), Some(endpoint0));
    let handle1 = network.new_service_handle(Some(config.clone()), Some(endpoint1));

    let (event_sender_0, _category_rx_0, event_rx_0) = get_event_sender();
    let (event_sender_1, _category_rx_1, event_rx_1) = get_event_sender();

    let mut service_0 = unwrap_result!(Service::with_handle(&handle0, event_sender_0, 0));

    unwrap_result!(service_0.start_listening_tcp());
    unwrap_result!(service_0.start_listening_utp());

    // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
    // to bootstrap
    {
        let event_rxd = unwrap_result!(event_rx_0.try_recv());
        match event_rxd {
            Event::BootstrapFinished => (),
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    }

    service_0.start_service_discovery();

    let mut service_1 = unwrap_result!(Service::with_handle(&handle1, event_sender_1, 0));

    unwrap_result!(service_1.start_listening_tcp());
    unwrap_result!(service_1.start_listening_utp());

    // let service_1 finish bootstrap - it should bootstrap off service_0
    let id_0 = {
        let event_rxd = unwrap_result!(event_rx_1.try_recv());
        match event_rxd {
            Event::BootstrapConnect(their_id) => their_id,
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    };

    // now service_1 should get BootstrapFinished
    {
        let event_rxd = unwrap_result!(event_rx_1.try_recv());
        match event_rxd {
            Event::BootstrapFinished => (),
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    }

    // service_0 should have received service_1's bootstrap connection by now
    let id_1 = match unwrap_result!(event_rx_0.try_recv()) {
        Event::BootstrapAccept(their_id) => their_id,
        _ => panic!("0 Should have got a new connection from 1."),
    };

    assert!(id_0 != id_1);

    // send data from 0 to 1
    {
        let data_txd = vec![0, 1, 255, 254, 222, 1];
        unwrap_result!(service_0.send(&id_1, data_txd.clone()));

        // 1 should rx data
        let (data_rxd, peer_id) = {
            let event_rxd = unwrap_result!(event_rx_1.try_recv());
            match event_rxd {
                Event::NewMessage(their_id, msg) => (msg, their_id),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        assert_eq!(data_rxd, data_txd);
        assert_eq!(peer_id, id_0);
    }

    // send data from 1 to 0
    {
        let data_txd = vec![10, 11, 155, 214, 202];
        unwrap_result!(service_1.send(&id_0, data_txd.clone()));

        // 0 should rx data
        let (data_rxd, peer_id) = {
            let event_rxd = unwrap_result!(event_rx_0.try_recv());
            match event_rxd {
                Event::NewMessage(their_id, msg) => (msg, their_id),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        assert_eq!(data_rxd, data_txd);
        assert_eq!(peer_id, id_1);
    }

    assert!(service_0.disconnect(&id_1));

    match unwrap_result!(event_rx_1.try_recv()) {
        Event::LostPeer(id) => assert_eq!(id, id_0),
        e => panic!("Received unexpected event: {:?}", e),
    }
}

#[test]
fn start_two_services_rendezvous_connect() {
    let network = Network::new();
    let handle0 = network.new_service_handle(None, None);
    let handle1 = network.new_service_handle(None, None);

    let (event_sender_0, _category_rx_0, event_rx_0) = get_event_sender();
    let (event_sender_1, _category_rx_1, event_rx_1) = get_event_sender();

    let mut service_0 = unwrap_result!(Service::with_handle(&handle0, event_sender_0, 1234));
    // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
    // to bootstrap
    {
        let event_rxd = unwrap_result!(event_rx_0.try_recv());
        match event_rxd {
            Event::BootstrapFinished => (),
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    }

    let mut service_1 = unwrap_result!(Service::with_handle(&handle1, event_sender_1, 1234));
    // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
    // to bootstrap
    {
        let event_rxd = unwrap_result!(event_rx_1.try_recv());
        match event_rxd {
            Event::BootstrapFinished => (),
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    }

    const PREPARE_CI_TOKEN: u32 = 1234;

    service_0.prepare_connection_info(PREPARE_CI_TOKEN);
    let our_ci_0 = {
        let event_rxd = unwrap_result!(event_rx_0.try_recv());
        match event_rxd {
            Event::ConnectionInfoPrepared(cir) => {
                assert_eq!(cir.result_token, PREPARE_CI_TOKEN);
                unwrap_result!(cir.result)
            }
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    };

    service_1.prepare_connection_info(PREPARE_CI_TOKEN);
    let our_ci_1 = {
        let event_rxd = unwrap_result!(event_rx_1.try_recv());
        match event_rxd {
            Event::ConnectionInfoPrepared(cir) => {
                assert_eq!(cir.result_token, PREPARE_CI_TOKEN);
                unwrap_result!(cir.result)
            }
            _ => panic!("Received unexpected event: {:?}", event_rxd),
        }
    };

    let their_ci_0 = our_ci_0.to_their_connection_info();
    let their_ci_1 = our_ci_1.to_their_connection_info();

    service_0.connect(our_ci_0, their_ci_1);
    service_1.connect(our_ci_1, their_ci_0);

    let id_1 = match unwrap_result!(event_rx_0.try_recv()) {
        Event::NewPeer(Ok(()), their_id) => their_id,
        m => panic!("0 Should have connected to 1. Got message {:?}", m),
    };

    let id_0 = match unwrap_result!(event_rx_1.try_recv()) {
        Event::NewPeer(Ok(()), their_id) => their_id,
        m => panic!("1 Should have connected to 0. Got message {:?}", m),
    };

    // send data from 0 to 1
    {
        let data_txd = vec![0, 1, 255, 254, 222, 1];
        unwrap_result!(service_0.send(&id_1, data_txd.clone()));

        // 1 should rx data
        let (data_rxd, peer_id) = {
            let event_rxd = unwrap_result!(event_rx_1.try_recv());
            match event_rxd {
                Event::NewMessage(their_id, msg) => (msg, their_id),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        assert_eq!(data_rxd, data_txd);
        assert_eq!(peer_id, id_0);
    }

    // send data from 1 to 0
    {
        let data_txd = vec![10, 11, 155, 214, 202];
        unwrap_result!(service_1.send(&id_0, data_txd.clone()));

        // 0 should rx data
        let (data_rxd, peer_id) = {
            let event_rxd = unwrap_result!(event_rx_0.try_recv());
            match event_rxd {
                Event::NewMessage(their_id, msg) => (msg, their_id),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        assert_eq!(data_rxd, data_txd);
        assert_eq!(peer_id, id_1);
    }
}

#[test]
fn drop() {
    use std::mem;

    let network = Network::new();
    let handle0 = network.new_service_handle(None, None);

    let config = Config::with_contacts(&[handle0.endpoint()]);
    let handle1 = network.new_service_handle(Some(config), None);

    let port = 45669;
    let (event_sender_0, _category_rx_0, event_rx_0) = get_event_sender();
    let (event_sender_1, _category_rx_1, event_rx_1) = get_event_sender();

    let mut service_0 = unwrap_result!(Service::with_handle(&handle0, event_sender_0, port));
    unwrap_result!(service_0.start_listening_tcp());

    // Let service_0 finish bootstrap - it should not find any peer.
    match unwrap_result!(event_rx_0.try_recv()) {
        Event::BootstrapFinished => (),
        event_rxd => panic!("Received unexpected event: {:?}", event_rxd),
    }

    let mut service_1 = unwrap_result!(Service::with_handle(&handle1, event_sender_1, port));
    unwrap_result!(service_1.start_listening_tcp());

    // Let service_1 finish bootstrap - it should bootstrap off service_0.
    let id_0 = match unwrap_result!(event_rx_1.try_recv()) {
        Event::BootstrapConnect(their_id) => their_id,
        event => panic!("Received unexpected event: {:?}", event),
    };

    // Now service_1 should get BootstrapFinished.
    match unwrap_result!(event_rx_1.try_recv()) {
        Event::BootstrapFinished => (),
        event => panic!("Received unexpected event: {:?}", event),
    }

    // service_0 should have received service_1's bootstrap connection by now.
    match unwrap_result!(event_rx_0.try_recv()) {
        Event::BootstrapAccept(..) => (),
        _ => panic!("0 Should have got a new connection from 1."),
    };

    // Dropping service_0 should make service_1 receive a LostPeer event.
    mem::drop(service_0);
    match unwrap_result!(event_rx_1.try_recv()) {
        Event::LostPeer(id) => assert_eq!(id, id_0),
        event => panic!("Received unexpected event: {:?}", event),
    }
}

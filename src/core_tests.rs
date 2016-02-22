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

use std::sync::mpsc;
use crust_mock::Network;
use core::Core;
use event::Event;

#[test]
fn one_node_and_one_client() {
  let network = Network::new();
  let node_service = network.new_service();
  let client_service = network.new_service();

  let (node_tx, _node_rx) = mpsc::channel();
  let (client_tx, client_rx) = mpsc::channel();

  let _node = Core::new(node_service.clone(), node_tx, false, None).unwrap();
  let _client = Core::new(client_service.clone(), client_tx, true, None).unwrap();

  network.process_events();

  for event in client_rx.iter() {
    match event {
      Event::Connected => break,
      _ => panic!("Unexpected event {:?}", event),
    }
  }
}
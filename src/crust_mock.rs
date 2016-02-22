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

#![allow(unused)]

use crust::{self, CrustEventSender, OurConnectionInfo, PeerId, TheirConnectionInfo};
use sodiumoxide::crypto::box_;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};

/// TODO: docs
#[derive(Clone)]
pub struct Network(Arc<NetworkImp>);

impl Network {
  pub fn new() -> Self {
    Network(Arc::new(NetworkImp {
      services: Mutex::new(HashMap::new()),
      next_endpoint: ATOMIC_USIZE_INIT,
      event_queue: Mutex::new(VecDeque::new()),
    }))
  }

  pub fn new_service(&self, config: Config) -> Service {
    let endpoint = self.next_endpoint();
    let service = Service::new(self.clone(), endpoint, config);
    let _ = self.0.services.lock()
                           .unwrap()
                           .insert(endpoint, Arc::downgrade(&service.0));

    service
  }

  /// TODO: doc
  pub fn process_events(&self) {
    // TODO:
  }

  fn next_endpoint(&self) -> Endpoint {
    Endpoint(self.0.next_endpoint.fetch_add(1, Ordering::AcqRel))
  }
}

pub struct NetworkImp {
  services: Mutex<HashMap<Endpoint, Weak<ServiceImp>>>,
  next_endpoint: AtomicUsize,
  event_queue: Mutex<VecDeque<Event>>,
}

#[derive(Clone)]
pub struct Service(Arc<ServiceImp>);

impl Service {
  fn new(network: Network, endpoint: Endpoint, config: Config) -> Self {
    let (public_key, _) = box_::gen_keypair();

    Service(Arc::new(ServiceImp {
      network: network,
      endpoint: endpoint,
      peer_id: crust::new_id(public_key),
    }))
  }

  // Note: in `crust::Service`, bootstrapping is handled inside `new`, so there
  // is no `start_bootstrap` there.
  pub fn start_bootstrap(&self, _event_sender: CrustEventSender, _beacon_port: u16) {
    // TODO
    println!("{:?} start_bootstrap", self.id());
  }

  pub fn stop_bootstrap(&self) {
    // TODO
    println!("{:?} stop_bootstrap", self.id());
  }

  pub fn restart(&self, _event_sender: CrustEventSender, _beacon_port: u16) {
    // TODO
  }

  pub fn start_service_discovery(&self) {
    // TODO
    println!("{:?} start_service_discovery", self.id());
  }

  pub fn start_listening_tcp(&self) -> io::Result<()> {
    // TODO
    println!("{:?} start_listening_tcp", self.id());
    Ok(())
  }

  pub fn start_listening_utp(&self) -> io::Result<()> {
    // TODO
    println!("{:?} start_listening_utp", self.id());
    Ok(())
  }

  pub fn prepare_connection_info(&self, result_token: u32) {
    println!("{:?} prepare_connection_info", self.id());
    // TODO
  }

  // TODO: rename to connect
  pub fn tcp_connect(&self, _our_info: OurConnectionInfo,
                            _their_info: TheirConnectionInfo) {
    println!("{:?} tcp_connect", self.id());
    // TODO
  }

  pub fn disconnect(&self, _id: &PeerId) -> bool {
    // TODO
    println!("{:?} disconnect", self.id());
    false
  }

  pub fn send(&self, _id: &PeerId, _data: Vec<u8>) -> io::Result<()> {
    // TODO
    println!("{:?} send", self.id());
    Ok(())
  }

  pub fn id(&self) -> PeerId {
    self.0.peer_id
  }

  pub fn endpoint(&self) -> Endpoint {
    self.0.endpoint
  }
}

struct ServiceImp {
  network: Network,
  endpoint: Endpoint,
  peer_id: PeerId,
}

pub struct Config {
  pub hard_coded_contacts: Vec<Endpoint>,
}

impl Config {
  pub fn new() -> Self {
    Self::new_with_contacts(&[])
  }

  pub fn new_with_contacts(contacts: &[Endpoint]) -> Self {
    Config {
      hard_coded_contacts: contains.collect()
    }
  }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Endpoint(usize);

enum Event {
  Connect,
}

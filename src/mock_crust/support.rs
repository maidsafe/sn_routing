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

// It seems that code used only in tests is considered unused by rust.
// TODO: Remove `unsafe_code` here again, once these changes are in stable:
//       https://github.com/rust-lang/rust/issues/30756
#![allow(unused, unsafe_code, shadow_reuse)]

use rand;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::rc::{Rc, Weak};

use super::crust::{ConnectionInfoResult, CrustEventSender, Event, OurConnectionInfo, PeerId,
                   TheirConnectionInfo};

/// Mock network. Create one before testing with mocks. Use it to create `ServiceHandle`s.
#[derive(Clone)]
pub struct Network(Rc<RefCell<NetworkImpl>>);

pub struct NetworkImpl {
    services: HashMap<Endpoint, Weak<RefCell<ServiceImpl>>>,
    next_endpoint: usize,
    queue: VecDeque<(Endpoint, Endpoint, Packet)>,
}

impl Network {
    /// Create new mock Network.
    #[allow(new_without_default)]
    pub fn new() -> Self {
        Network(Rc::new(RefCell::new(NetworkImpl {
            services: HashMap::new(),
            next_endpoint: 0,
            queue: VecDeque::new(),
        })))
    }

    /// Create new ServiceHandle.
    pub fn new_service_handle(&self,
                              config: Option<Config>,
                              endpoint: Option<Endpoint>)
                              -> ServiceHandle {
        let config = config.unwrap_or_else(Config::new);
        let endpoint = endpoint.unwrap_or_else(|| self.gen_endpoint());

        let handle = ServiceHandle::new(self.clone(), config, endpoint);
        let _ = self.0
                    .borrow_mut()
                    .services
                    .insert(endpoint, Rc::downgrade(&handle.0));

        handle
    }

    pub fn gen_endpoint(&self) -> Endpoint {
        let mut imp = self.0.borrow_mut();
        let num = imp.next_endpoint;
        imp.next_endpoint += 1;

        Endpoint(num)
    }

    pub fn poll(&self) {
        while let Some((sender, receiver, packet)) = self.pop_packet() {
            self.process_packet(sender, receiver, packet);
        }
    }

    fn send(&self, sender: Endpoint, receiver: Endpoint, packet: Packet) {
        self.0.borrow_mut().queue.push_back((sender, receiver, packet));
    }

    fn pop_packet(&self) -> Option<(Endpoint, Endpoint, Packet)> {
        self.0.borrow_mut().queue.pop_front()
    }

    fn process_packet(&self, sender: Endpoint, receiver: Endpoint, packet: Packet) {
        if let Some(service) = self.find_service(receiver) {
            service.borrow_mut().receive_packet(sender, packet);
        } else {
            // Packet was sent to a non-existing receiver.
            if let Some(failure) = packet.to_failure() {
                self.send(receiver, sender, failure);
            }
        }
    }

    fn find_service(&self, endpoint: Endpoint) -> Option<Rc<RefCell<ServiceImpl>>> {
        self.0.borrow().services.get(&endpoint).and_then(|s| s.upgrade())
    }
}

/// ServiceHandle is associated with the mock Service and allows to configrue
/// and instrument it.
#[derive(Clone)]
pub struct ServiceHandle(pub Rc<RefCell<ServiceImpl>>);

impl ServiceHandle {
    fn new(network: Network, config: Config, endpoint: Endpoint) -> Self {
        ServiceHandle(Rc::new(RefCell::new(ServiceImpl::new(network, config, endpoint))))
    }

    pub fn endpoint(&self) -> Endpoint {
        self.0.borrow().endpoint
    }
}

pub struct ServiceImpl {
    pub network: Network,
    endpoint: Endpoint,
    pub peer_id: PeerId,
    config: Config,
    pub listening_tcp: bool,
    pub listening_udp: bool,
    event_sender: Option<CrustEventSender>,
    pending_bootstraps: u64,
    pending_connects: HashSet<PeerId>,
    connections: Vec<(PeerId, Endpoint)>,
}

impl ServiceImpl {
    fn new(network: Network, config: Config, endpoint: Endpoint) -> Self {
        ServiceImpl {
            network: network,
            endpoint: endpoint,
            peer_id: gen_peer_id(endpoint),
            config: config,
            listening_tcp: false,
            listening_udp: false,
            event_sender: None,
            pending_bootstraps: 0,
            pending_connects: HashSet::new(),
            connections: Vec::new(),
        }
    }

    pub fn start(&mut self, event_sender: CrustEventSender, _beacon_port: u16) {
        let mut pending_bootstraps = 0;

        for endpoint in &self.config.hard_coded_contacts {
            if *endpoint == self.endpoint {
                continue;
            }

            self.send_packet(*endpoint, Packet::BootstrapRequest(self.peer_id));
            pending_bootstraps += 1;
        }

        // If we have no contacts in the config, we can fire BootstrapFinished
        // immediately.
        if pending_bootstraps == 0 {
            event_sender.send(Event::BootstrapFinished)
                        .expect("Failed to send Event::BootstrapFinished");
        }

        self.pending_bootstraps = pending_bootstraps;
        self.event_sender = Some(event_sender);
    }

    pub fn restart(&mut self, event_sender: CrustEventSender, beacon_port: u16) {
        trace!("{:?} restart", self.endpoint);

        self.disconnect_all();

        self.peer_id = gen_peer_id(self.endpoint);
        self.listening_tcp = false;
        self.listening_udp = false;

        self.start(event_sender, beacon_port)
    }

    pub fn send_message(&self, peer_id: &PeerId, data: Vec<u8>) -> bool {
        if let Some(endpoint) = self.find_endpoint_by_peer_id(peer_id) {
            self.send_packet(endpoint, Packet::Message(data));
            true
        } else {
            false
        }
    }

    pub fn prepare_connection_info(&self, result_token: u32) {
        // TODO: should we also simulate failure here?
        // TODO: should we simulate asynchrony here?

        let result = ConnectionInfoResult {
            result_token: result_token,
            result: Ok(OurConnectionInfo(self.peer_id, self.endpoint)),
        };

        self.send_event(Event::ConnectionInfoPrepared(result));
    }

    pub fn connect(&self, _our_info: OurConnectionInfo, their_info: TheirConnectionInfo) {
        let TheirConnectionInfo(_, peer_endpoint) = their_info;
        self.send_packet(peer_endpoint, Packet::ConnectRequest(self.peer_id));
    }

    fn send_packet(&self, receiver: Endpoint, packet: Packet) {
        self.network.send(self.endpoint, receiver, packet);
    }

    fn receive_packet(&mut self, sender: Endpoint, packet: Packet) {
        // TODO: filter packets

        match packet {
            Packet::BootstrapRequest(peer_id) => self.handle_bootstrap_request(sender, peer_id),
            Packet::BootstrapSuccess(peer_id) => self.handle_bootstrap_success(sender, peer_id),
            Packet::BootstrapFailure => self.handle_bootstrap_failure(sender),
            Packet::ConnectRequest(peer_id) => self.handle_connect_request(sender, peer_id),
            Packet::ConnectSuccess(peer_id) => self.handle_connect_success(sender, peer_id),
            Packet::ConnectFailure(peer_id) => self.handle_connect_failure(sender, peer_id),
            Packet::Message(data) => self.handle_message(sender, data),
            Packet::Disconnect => self.handle_disconnect(sender),
        }
    }

    fn handle_bootstrap_request(&mut self, peer_endpoint: Endpoint, peer_id: PeerId) {
        if self.is_listening() {
            self.handle_bootstrap_accept(peer_endpoint, peer_id);
            self.send_packet(peer_endpoint, Packet::BootstrapSuccess(self.peer_id));
        } else {
            self.send_packet(peer_endpoint, Packet::BootstrapFailure);
        }
    }

    fn handle_bootstrap_accept(&mut self, peer_endpoint: Endpoint, peer_id: PeerId) {
        self.add_connection(peer_id, peer_endpoint);
        self.send_event(Event::BootstrapAccept(peer_id));
    }

    fn handle_bootstrap_success(&mut self, peer_endpoint: Endpoint, peer_id: PeerId) {
        self.add_connection(peer_id, peer_endpoint);
        self.send_event(Event::BootstrapConnect(peer_id));
        self.decrement_pending_bootstraps();
    }

    fn handle_bootstrap_failure(&mut self, _peer_endpoint: Endpoint) {
        self.decrement_pending_bootstraps();
    }

    fn handle_connect_request(&mut self, peer_endpoint: Endpoint, peer_id: PeerId) {
        if self.is_connected(&peer_endpoint, &peer_id) &&
           !self.pending_connects.contains(&peer_id) {
            warn!("Connection already exist");
        }

        self.add_rendezvous_connection(peer_id, peer_endpoint);
        self.send_packet(peer_endpoint, Packet::ConnectSuccess(self.peer_id));
    }

    fn handle_connect_success(&mut self, peer_endpoint: Endpoint, peer_id: PeerId) {
        self.add_rendezvous_connection(peer_id, peer_endpoint);
    }

    fn handle_connect_failure(&self, _peer_endpoint: Endpoint, peer_id: PeerId) {
        let err = io::Error::new(io::ErrorKind::NotFound, "Peer not found");
        self.send_event(Event::NewPeer(Err(err), peer_id));
    }

    fn handle_message(&self, peer_endpoint: Endpoint, data: Vec<u8>) {
        if let Some(peer_id) = self.find_peer_id_by_endpoint(&peer_endpoint) {
            self.send_event(Event::NewMessage(peer_id, data));
        } else {
            unreachable!("Received message from non-connected {:?}", peer_endpoint);
        }
    }

    fn handle_disconnect(&mut self, peer_endpoint: Endpoint) {
        if let Some(peer_id) = self.remove_connection_by_endpoint(peer_endpoint) {
            self.send_event(Event::LostPeer(peer_id));
        }
    }

    fn send_event(&self, event: Event) {
        let _ = self.event_sender
                    .as_ref()
                    .expect("Failed to send event")
                    .send(event);
    }

    fn is_listening(&self) -> bool {
        self.listening_tcp || self.listening_udp
    }

    fn decrement_pending_bootstraps(&mut self) {
        if self.pending_bootstraps == 0 {
            return;
        }

        self.pending_bootstraps -= 1;

        if self.pending_bootstraps == 0 {
            self.send_event(Event::BootstrapFinished);
        }
    }

    fn add_connection(&mut self, peer_id: PeerId, peer_endpoint: Endpoint) -> bool {
        if self.connections.iter().any(|&(id, ep)| id == peer_id && ep == peer_endpoint) {
            // Connection already exists
            return false;
        }

        self.connections.push((peer_id, peer_endpoint));
        true
    }

    fn add_rendezvous_connection(&mut self, peer_id: PeerId, peer_endpoint: Endpoint) {
        self.add_connection(peer_id, peer_endpoint);

        if !self.pending_connects.insert(peer_id) {
            self.pending_connects.remove(&peer_id);
            self.send_event(Event::NewPeer(Ok(()), peer_id));
        }
    }

    // Remove connected peer with the given peer id and return its endpoint,
    // or None if no such peer exists.
    fn remove_connection_by_peer_id(&mut self, peer_id: &PeerId) -> Option<Endpoint> {
        if let Some(i) = self.connections
                             .iter()
                             .position(|&(id, _)| id == *peer_id) {
            Some(self.connections.swap_remove(i).1)
        } else {
            None
        }
    }

    fn remove_connection_by_endpoint(&mut self, endpoint: Endpoint) -> Option<PeerId> {
        if let Some(i) = self.connections
                             .iter()
                             .position(|&(_, ep)| ep == endpoint) {
            Some(self.connections.swap_remove(i).0)
        } else {
            None
        }
    }

    fn find_endpoint_by_peer_id(&self, peer_id: &PeerId) -> Option<Endpoint> {
        self.connections
            .iter()
            .find(|&&(id, _)| id == *peer_id)
            .map(|&(_, ep)| ep)
    }

    fn find_peer_id_by_endpoint(&self, endpoint: &Endpoint) -> Option<PeerId> {
        self.connections
            .iter()
            .find(|&&(_, ep)| ep == *endpoint)
            .map(|&(id, _)| id)
    }

    fn is_connected(&self, endpoint: &Endpoint, peer_id: &PeerId) -> bool {
        self.connections.iter().any(|&conn| conn == (*peer_id, *endpoint))
    }

    pub fn disconnect(&mut self, peer_id: &PeerId) -> bool {
        if let Some(endpoint) = self.remove_connection_by_peer_id(peer_id) {
            self.send_packet(endpoint, Packet::Disconnect);
            true
        } else {
            false
        }
    }

    pub fn disconnect_all(&mut self) {
        let endpoints = self.connections
                            .drain(..)
                            .map(|(_, ep)| ep)
                            .collect::<Vec<_>>();

        for endpoint in endpoints {
            self.send_packet(endpoint, Packet::Disconnect);
        }
    }
}

impl Drop for ServiceImpl {
    fn drop(&mut self) {
        self.disconnect_all();
    }
}

fn gen_peer_id(endpoint: Endpoint) -> PeerId {
    PeerId(endpoint.0, rand::random())
}

/// Simulated crust config file.
#[derive(Clone, Default)]
pub struct Config {
    pub hard_coded_contacts: Vec<Endpoint>,
}

impl Config {
    pub fn new() -> Self {
        Self::with_contacts(&[])
    }

    pub fn with_contacts(contacts: &[Endpoint]) -> Self {
        Config { hard_coded_contacts: contacts.into_iter().cloned().collect() }
    }
}

/// Simulated network endpoint (socket address). This is used to identify and
/// address Services in the mock network.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, RustcEncodable, RustcDecodable)]
pub struct Endpoint(usize);

#[derive(Clone, Debug)]
enum Packet {
    BootstrapRequest(PeerId),
    BootstrapSuccess(PeerId),
    BootstrapFailure,

    ConnectRequest(PeerId),
    ConnectSuccess(PeerId),
    ConnectFailure(PeerId),

    Message(Vec<u8>),
    Disconnect,
}

impl Packet {
    // Given a request packet, returns the corresponding failure packet.
    fn to_failure(&self) -> Option<Packet> {
        match *self {
            Packet::BootstrapRequest(..) => Some(Packet::BootstrapFailure),
            Packet::ConnectRequest(peer_id) => Some(Packet::ConnectFailure(peer_id)),
            _ => None,
        }
    }
}

// The following code facilitates passing ServiceHandles to mock Services, so we
// don't need separate test and non-test version of `routing::Core::new`.
thread_local! {
    static CURRENT: RefCell<Option<ServiceHandle>> = RefCell::new(None)
}

/// Make the ServiceHandle current so it can be picked up by mock Services created
/// inside the passed-in lambda.
pub fn make_current<F, R>(handle: &ServiceHandle, f: F) -> R
    where F: FnOnce() -> R
{
    CURRENT.with(|current| {
        *current.borrow_mut() = Some(handle.clone());
        let result = f();
        *current.borrow_mut() = None;
        result
    })
}

pub fn get_current() -> ServiceHandle {
    CURRENT.with(|current| {
        current.borrow_mut()
               .take()
               .expect("get_current can be only called in the closure passed to make_current")
    })
}

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

use std::cell::RefCell;
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::{Rc, Weak};

use super::crust::{ConnectionInfoResult, CrustEventSender, Event, PrivConnectionInfo, PeerId,
                   PubConnectionInfo};

/// Mock network. Create one before testing with mocks. Use it to create `ServiceHandle`s.
#[derive(Clone)]
pub struct Network(Rc<RefCell<NetworkImpl>>);

pub struct NetworkImpl {
    services: HashMap<Endpoint, Weak<RefCell<ServiceImpl>>>,
    next_endpoint: usize,
    queue: VecDeque<(Endpoint, Endpoint, Packet)>,
    blocked_connections: HashSet<(Endpoint, Endpoint)>,
}

impl Network {
    /// Create new mock Network.
    pub fn new() -> Self {
        Network(Rc::new(RefCell::new(NetworkImpl {
            services: HashMap::new(),
            next_endpoint: 0,
            queue: VecDeque::new(),
            blocked_connections: HashSet::new(),
        })))
    }

    /// Create new ServiceHandle.
    pub fn new_service_handle(&self,
                              opt_config: Option<Config>,
                              opt_endpoint: Option<Endpoint>)
                              -> ServiceHandle {
        let config = opt_config.unwrap_or_else(Config::new);
        let endpoint = self.gen_endpoint(opt_endpoint);

        let handle = ServiceHandle::new(self.clone(), config, endpoint);
        let _ = self.0
            .borrow_mut()
            .services
            .insert(endpoint, Rc::downgrade(&handle.0));

        handle
    }

    /// Generate unique Endpoint
    pub fn gen_endpoint(&self, opt_endpoint: Option<Endpoint>) -> Endpoint {
        let mut imp = self.0.borrow_mut();
        let endpoint = if let Some(endpoint) = opt_endpoint {
            endpoint
        } else {
            Endpoint(imp.next_endpoint)
        };
        imp.next_endpoint = cmp::max(imp.next_endpoint, endpoint.0 + 1);
        endpoint
    }

    /// Poll and process all queued Packets.
    pub fn poll(&self) {
        while let Some((sender, receiver, packet)) = self.pop_packet() {
            self.process_packet(sender, receiver, packet);
        }
    }

    /// Causes all packets from `sender` to `receiver` to fail.
    pub fn block_connection(&self, sender: Endpoint, receiver: Endpoint) {
        let mut imp = self.0.borrow_mut();
        imp.blocked_connections.insert((sender, receiver));
    }

    fn connection_blocked(&self, sender: Endpoint, receiver: Endpoint) -> bool {
        self.0.borrow().blocked_connections.contains(&(sender, receiver))
    }

    fn send(&self, sender: Endpoint, receiver: Endpoint, packet: Packet) {
        self.0.borrow_mut().queue.push_back((sender, receiver, packet));
    }

    fn pop_packet(&self) -> Option<(Endpoint, Endpoint, Packet)> {
        self.0.borrow_mut().queue.pop_front()
    }

    fn process_packet(&self, sender: Endpoint, receiver: Endpoint, packet: Packet) {
        if self.connection_blocked(sender, receiver) {
            if let Some(failure) = packet.to_failure() {
                self.send(receiver, sender, failure);
                return;
            }
        }

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

impl Default for Network {
    fn default() -> Network {
        Network::new()
    }
}

/// `ServiceHandle` is associated with the mock `Service` and allows to configure
/// and instrument it.
#[derive(Clone)]
pub struct ServiceHandle(pub Rc<RefCell<ServiceImpl>>);

impl ServiceHandle {
    fn new(network: Network, config: Config, endpoint: Endpoint) -> Self {
        ServiceHandle(Rc::new(RefCell::new(ServiceImpl::new(network, config, endpoint))))
    }

    /// Endpoint of the `Service` bound to this handle.
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
    event_sender: Option<CrustEventSender>,
    pending_bootstraps: u64,
    connections: Vec<(PeerId, Endpoint)>,
}

impl ServiceImpl {
    fn new(network: Network, config: Config, endpoint: Endpoint) -> Self {
        ServiceImpl {
            network: network,
            endpoint: endpoint,
            peer_id: PeerId(endpoint.0),
            config: config,
            listening_tcp: false,
            event_sender: None,
            pending_bootstraps: 0,
            connections: Vec::new(),
        }
    }

    pub fn start(&mut self, event_sender: CrustEventSender) {
        self.event_sender = Some(event_sender);
    }

    pub fn restart(&mut self, event_sender: CrustEventSender) {
        trace!("{:?} restart", self.endpoint);

        self.disconnect_all();

        self.peer_id = PeerId(self.endpoint.0);
        self.listening_tcp = false;

        self.start(event_sender)
    }

    pub fn start_bootstrap(&mut self) {
        let mut pending_bootstraps = 0;

        for endpoint in &self.config.hard_coded_contacts {
            if *endpoint == self.endpoint {
                continue;
            }

            self.send_packet(*endpoint, Packet::BootstrapRequest(self.peer_id));
            pending_bootstraps += 1;
        }

        // If we have no contacts in the config, we can fire BootstrapFailed
        // immediately.
        if pending_bootstraps == 0 {
            unwrap_result!(self.event_sender
                .as_ref()
                .unwrap()
                .send(Event::BootstrapFailed));
        }

        self.pending_bootstraps = pending_bootstraps;
    }

    pub fn send_message(&self, peer_id: &PeerId, data: Vec<u8>) -> bool {
        if let Some(endpoint) = self.find_endpoint_by_peer_id(peer_id) {
            self.send_packet(endpoint, Packet::Message(data));
            true
        } else {
            false
        }
    }

    pub fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.find_endpoint_by_peer_id(peer_id).is_some()
    }

    pub fn prepare_connection_info(&self, result_token: u32) {
        // TODO: should we also simulate failure here?
        // TODO: should we simulate asynchrony here?

        let result = ConnectionInfoResult {
            result_token: result_token,
            result: Ok(PrivConnectionInfo(self.peer_id, self.endpoint)),
        };

        self.send_event(Event::ConnectionInfoPrepared(result));
    }

    pub fn connect(&self, _our_info: PrivConnectionInfo, their_info: PubConnectionInfo) {
        let PubConnectionInfo(their_id, peer_endpoint) = their_info;
        let packet = Packet::ConnectRequest(self.peer_id, their_id);
        self.send_packet(peer_endpoint, packet);
    }

    pub fn start_listening_tcp(&mut self, port: u16) {
        self.listening_tcp = true;
        self.send_event(Event::ListenerStarted(port));
    }

    fn send_packet(&self, receiver: Endpoint, packet: Packet) {
        self.network.send(self.endpoint, receiver, packet);
    }

    fn receive_packet(&mut self, sender: Endpoint, packet: Packet) {
        match packet {
            Packet::BootstrapRequest(peer_id) => self.handle_bootstrap_request(sender, peer_id),
            Packet::BootstrapSuccess(peer_id) => self.handle_bootstrap_success(sender, peer_id),
            Packet::BootstrapFailure => self.handle_bootstrap_failure(sender),
            Packet::ConnectRequest(their_id, _) => self.handle_connect_request(sender, their_id),
            Packet::ConnectSuccess(their_id, _) => self.handle_connect_success(sender, their_id),
            Packet::ConnectFailure(their_id, _) => self.handle_connect_failure(sender, their_id),
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
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(123, 123, 255, 255)),
                                          peer_id.0 as u16);
        self.send_event(Event::BootstrapConnect(peer_id, socket_addr));
        self.decrement_pending_bootstraps();
    }

    fn handle_bootstrap_failure(&mut self, _peer_endpoint: Endpoint) {
        self.decrement_pending_bootstraps();
    }

    fn handle_connect_request(&mut self, peer_endpoint: Endpoint, their_id: PeerId) {
        if self.is_connected(&peer_endpoint, &their_id) {
            return;
        }

        self.add_rendezvous_connection(their_id, peer_endpoint);
        self.send_packet(peer_endpoint,
                         Packet::ConnectSuccess(self.peer_id, their_id));
    }

    fn handle_connect_success(&mut self, peer_endpoint: Endpoint, their_id: PeerId) {
        self.add_rendezvous_connection(their_id, peer_endpoint);
    }

    fn handle_connect_failure(&self, _peer_endpoint: Endpoint, their_id: PeerId) {
        let err = io::Error::new(io::ErrorKind::NotFound, "Peer not found");
        self.send_event(Event::NewPeer(Err(err), their_id));
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
        let sender = unwrap_option!(self.event_sender.as_ref(), "Could not get event sender.");
        unwrap_result!(sender.send(event));
    }

    fn is_listening(&self) -> bool {
        self.listening_tcp
    }

    fn decrement_pending_bootstraps(&mut self) {
        if self.pending_bootstraps == 0 {
            return;
        }

        self.pending_bootstraps -= 1;

        if self.pending_bootstraps == 0 && self.connections.is_empty() {
            self.send_event(Event::BootstrapFailed);
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
        self.send_event(Event::NewPeer(Ok(()), peer_id));
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

/// Simulated crust config file.
#[derive(Clone)]
pub struct Config {
    /// Contacts to bootstrap against.
    pub hard_coded_contacts: Vec<Endpoint>,
}

impl Config {
    /// Create default `Config`.
    pub fn new() -> Self {
        Self::with_contacts(&[])
    }

    /// Create `Config` with the given hardcoded contacts.
    pub fn with_contacts(contacts: &[Endpoint]) -> Self {
        Config { hard_coded_contacts: contacts.into_iter().cloned().collect() }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

/// Simulated network endpoint (think socket address). This is used to identify
/// and address `Service`s in the mock network.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, RustcEncodable, RustcDecodable)]
pub struct Endpoint(pub usize);

#[derive(Clone, Debug)]
enum Packet {
    BootstrapRequest(PeerId),
    BootstrapSuccess(PeerId),
    BootstrapFailure,

    ConnectRequest(PeerId, PeerId),
    ConnectSuccess(PeerId, PeerId),
    ConnectFailure(PeerId, PeerId),

    Message(Vec<u8>),
    Disconnect,
}

impl Packet {
    // Given a request packet, returns the corresponding failure packet.
    fn to_failure(&self) -> Option<Packet> {
        match *self {
            Packet::BootstrapRequest(..) => Some(Packet::BootstrapFailure),
            Packet::ConnectRequest(our_id, their_id) => {
                Some(Packet::ConnectFailure(their_id, our_id))
            }
            _ => None,
        }
    }
}

// The following code facilitates passing ServiceHandles to mock Services, so we
// don't need separate test and non-test version of `routing::Core::new`.
thread_local! {
    static CURRENT: RefCell<Option<ServiceHandle>> = RefCell::new(None)
}

/// Make the `ServiceHandle` current so it can be picked up by mock `Service`s created
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
    CURRENT.with(|current| unwrap_option!(current.borrow_mut().take(), "Couldn't borrow service."))
}

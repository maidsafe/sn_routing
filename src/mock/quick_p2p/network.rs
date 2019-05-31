// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{node::Node, OurType};
#[cfg(feature = "mock_parsec")]
use crate::mock::parsec;
use bytes::Bytes;
use fxhash::{FxHashMap, FxHashSet};
use maidsafe_utilities::SeededRng;
use rand::Rng;
use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{hash_map::Entry, VecDeque},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    rc::{Rc, Weak},
};

const IP_BASE: Ipv4Addr = Ipv4Addr::LOCALHOST;
const PORT: u16 = 9999;

/// Mock network. Create one before testing with mocks. Call `set_next_node_addr` or
/// `gen_next_node_addr` before creating a `QuicP2p` instance.
pub struct Network(Rc<RefCell<Inner>>);

impl Network {
    /// Construct new mock network.
    pub fn new(seed: Option<[u32; 4]>) -> Self {
        let mut rng = if let Some(seed) = seed {
            SeededRng::from_seed(seed)
        } else {
            SeededRng::new()
        };

        unwrap!(safe_crypto::init_with_rng(&mut rng));

        #[cfg(feature = "mock_parsec")]
        parsec::init_mock();

        Network(Rc::new(RefCell::new(Inner {
            rng,
            nodes: Default::default(),
            connections: Default::default(),
            used_ips: Default::default(),
        })))
    }

    /// Generate new unique socket addrs.
    pub fn gen_addr(&self) -> SocketAddr {
        let mut inner = self.0.borrow_mut();

        let ip = inner
            .nodes
            .keys()
            .filter_map(|addr| match addr {
                SocketAddr::V4(addr) => Some(addr.ip()),
                SocketAddr::V6(_) => None,
            })
            .chain(&inner.used_ips)
            .max()
            .map(next_ip)
            .unwrap_or(IP_BASE);

        let _ = inner.used_ips.insert(ip);

        SocketAddr::V4(SocketAddrV4::new(ip, PORT))
    }

    /// Generate new socket address to be used by the next created `QuicP2p` instance and return it.
    pub fn gen_next_addr(&self) -> SocketAddr {
        let addr = self.gen_addr();
        self.set_next_addr(addr);
        addr
    }

    /// Set the socket address for the next created `QuicP2p` instance.
    pub fn set_next_addr(&self, addr: SocketAddr) {
        NEXT_NODE_DETAILS.with(|details| {
            *details.borrow_mut() = Some(NodeDetails {
                network: self.0.clone(),
                addr,
            });
        })
    }

    /// Poll the network by delivering the queued messages.
    pub fn poll(&self) {
        while let Some((connection, packet)) = self.pop_random_packet() {
            self.process_packet(&connection, packet)
        }
    }

    fn pop_random_packet(&self) -> Option<(Connection, Packet)> {
        self.0.borrow_mut().pop_random_packet()
    }

    fn process_packet(&self, connection: &Connection, packet: Packet) {
        let response = if let Some(dst) = self.find_node(&connection.dst) {
            dst.borrow_mut().receive_packet(connection.src, packet);
            None
        } else {
            match packet {
                Packet::BootstrapRequest(_) => Some(Packet::BootstrapFailure),
                Packet::ConnectRequest(_) => Some(Packet::ConnectFailure),
                Packet::Message(msg) => Some(Packet::MessageFailure(msg)),
                _ => None,
            }
        };

        if let Some(packet) = response {
            self.send(connection.dst, connection.src, packet)
        }
    }

    fn find_node(&self, addr: &SocketAddr) -> Option<Rc<RefCell<Node>>> {
        self.0.borrow().find_node(addr)
    }

    fn send(&self, src: SocketAddr, dst: SocketAddr, packet: Packet) {
        self.0.borrow_mut().send(src, dst, packet)
    }
}

pub(super) struct Inner {
    rng: SeededRng,
    nodes: FxHashMap<SocketAddr, Weak<RefCell<Node>>>,
    connections: FxHashMap<Connection, Queue>,
    used_ips: FxHashSet<Ipv4Addr>,
}

impl Inner {
    pub fn insert_node(&mut self, addr: SocketAddr, node: Rc<RefCell<Node>>) {
        use std::collections::hash_map::Entry;

        match self.nodes.entry(addr) {
            Entry::Occupied(_) => panic!("Node with {} already exists", addr),
            Entry::Vacant(entry) => {
                let _ = entry.insert(Rc::downgrade(&node));
            }
        }
    }

    pub fn remove_node(&mut self, addr: &SocketAddr) {
        let _ = self.nodes.remove(addr);
    }

    pub fn send(&mut self, src: SocketAddr, dst: SocketAddr, packet: Packet) {
        self.connections
            .entry(Connection::new(src, dst))
            .or_insert_with(Queue::new)
            .push(packet)
    }

    fn find_node(&self, addr: &SocketAddr) -> Option<Rc<RefCell<Node>>> {
        self.nodes.get(addr).and_then(Weak::upgrade)
    }

    fn pop_random_packet(&mut self) -> Option<(Connection, Packet)> {
        let connections: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .map(|(connection, _)| connection)
            .collect();

        let connection = if let Some(connection) = self.rng.choose(&connections) {
            **connection
        } else {
            return None;
        };

        self.pop_packet(connection)
            .map(|packet| (connection, packet))
    }

    fn pop_packet(&mut self, connection: Connection) -> Option<Packet> {
        match self.connections.entry(connection) {
            Entry::Occupied(mut entry) => {
                let packet = entry.get_mut().pop();
                if entry.get().is_empty() {
                    let _ = entry.remove_entry();
                }
                packet
            }
            Entry::Vacant(_) => None,
        }
    }
}

#[derive(Debug)]
pub(super) enum Packet {
    BootstrapRequest(OurType),
    BootstrapSuccess,
    BootstrapFailure,
    ConnectRequest(OurType),
    ConnectSuccess,
    ConnectFailure,
    Message(Bytes),
    MessageFailure(Bytes),
    Disconnect,
}

struct Queue(VecDeque<Packet>);

impl Queue {
    fn new() -> Self {
        Queue(VecDeque::new())
    }

    fn push(&mut self, packet: Packet) {
        self.0.push_back(packet)
    }

    fn pop(&mut self) -> Option<Packet> {
        self.0.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
struct Connection {
    src: SocketAddr,
    dst: SocketAddr,
}

impl Connection {
    fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }
}

thread_local! {
    pub(super) static NEXT_NODE_DETAILS: RefCell<Option<NodeDetails>> = RefCell::new(None);
}

pub(super) struct NodeDetails {
    pub network: Rc<RefCell<Inner>>,
    pub addr: SocketAddr,
}

fn next_ip(ip_addr: &Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32_from_be_bytes(ip_addr.octets()) + 1)
}

fn u32_from_be_bytes(bytes: [u8; 4]) -> u32 {
    ((bytes[0] as u32) << 24)
        + ((bytes[1] as u32) << 16)
        + ((bytes[2] as u32) << 8)
        + ((bytes[3] as u32) << 0)
}

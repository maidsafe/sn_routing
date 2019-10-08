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
use crate::NetworkBytes;
use fxhash::{FxHashMap, FxHashSet};
use maidsafe_utilities::SeededRng;
use rand::Rng;
use std::{
    cell::RefCell,
    cmp,
    collections::{hash_map::Entry, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::{Rc, Weak},
    sync::Once,
};

const IP_BASE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const PORT: u16 = 9999;

static PRINT_SEED: Once = Once::new();

/// Handle to the mock network. Create one before testing with mocks. Call `set_next_node_addr` or
/// `gen_next_node_addr` before creating a `QuicP2p` instance.
/// This handle is cheap to clone. Each clone refers to the same underlying mock network instance.
#[derive(Clone)]
pub struct Network(Rc<RefCell<Inner>>);

impl Network {
    /// Construct new mock network.
    pub fn new(min_section_size: usize, seed: Option<[u32; 4]>) -> Self {
        let rng = if let Some(seed) = seed {
            SeededRng::from_seed(seed)
        } else {
            SeededRng::new()
        };

        PRINT_SEED.call_once(|| eprintln!("{:?}", rng));

        #[cfg(feature = "mock_parsec")]
        parsec::init_mock();

        let inner = Rc::new(RefCell::new(Inner {
            min_section_size,
            rng,
            nodes: Default::default(),
            connections: Default::default(),
            used_ips: Default::default(),
            message_sent: false,
        }));

        NETWORK.with(|network| *network.borrow_mut() = Some(inner.clone()));

        Network(inner)
    }

    /// Generate new unique socket addrs.
    pub fn gen_addr(&self) -> SocketAddr {
        self.0.borrow_mut().gen_addr(None, None)
    }

    /// Poll the network by delivering the queued messages.
    pub fn poll(&self) {
        while let Some((connection, packet)) = self.pop_random_packet() {
            self.process_packet(&connection, packet)
        }
    }

    /// Disconnect peer at `addr0` from the peer at `addr1`.
    pub fn disconnect(&self, addr0: &SocketAddr, addr1: &SocketAddr) {
        let node = self.0.borrow().find_node(addr0);
        if let Some(node) = node {
            node.borrow_mut().disconnect(*addr1)
        }
    }

    /// Is the peer at `addr0` connected to the one at `addr1`?
    pub fn is_connected(&self, addr0: &SocketAddr, addr1: &SocketAddr) -> bool {
        self.0.borrow().is_connected(addr0, addr1)
    }

    /// Get min section size.
    pub fn min_section_size(&self) -> usize {
        self.0.borrow().min_section_size
    }

    /// Construct a new random number generator using a seed generated from random data provided by `self`.
    pub fn new_rng(&self) -> SeededRng {
        self.0.borrow_mut().rng.new_rng()
    }

    /// Return whether sent any message since previous query and reset the flag.
    pub fn reset_message_sent(&self) -> bool {
        let mut inner = self.0.borrow_mut();
        let message_sent = inner.message_sent;
        inner.message_sent = false;
        message_sent
    }

    fn pop_random_packet(&self) -> Option<(Connection, Packet)> {
        self.0.borrow_mut().pop_random_packet()
    }

    fn process_packet(&self, connection: &Connection, packet: Packet) {
        let response = if let Some(dst) = self.find_node(&connection.dst) {
            let msg = if let Packet::Message(ref msg, msg_id) = packet {
                Some(Packet::MessageSent(msg.clone(), msg_id))
            } else {
                None
            };
            dst.borrow_mut().receive_packet(connection.src, packet);
            msg
        } else {
            match packet {
                Packet::BootstrapRequest(_) => Some(Packet::BootstrapFailure),
                Packet::ConnectRequest(_) => Some(Packet::ConnectFailure),
                Packet::Message(msg, msg_id) => Some(Packet::MessageFailure(msg, msg_id)),
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
    min_section_size: usize,
    rng: SeededRng,
    nodes: FxHashMap<SocketAddr, Weak<RefCell<Node>>>,
    connections: FxHashMap<Connection, Queue>,
    used_ips: FxHashSet<IpAddr>,
    message_sent: bool,
}

impl Inner {
    pub fn gen_addr(&mut self, ip: Option<IpAddr>, port: Option<u16>) -> SocketAddr {
        let ip = ip.unwrap_or_else(|| {
            self.nodes
                .keys()
                .map(|addr| addr.ip())
                .chain(self.used_ips.iter().cloned())
                .max()
                .map(next_ip)
                .unwrap_or(IP_BASE)
        });
        let port = port.unwrap_or(PORT);

        let _ = self.used_ips.insert(ip);

        SocketAddr::new(ip, port)
    }

    pub fn insert_node(&mut self, addr: SocketAddr, node: Rc<RefCell<Node>>) {
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
        // Ignore gossip messages from being considered as a message that
        // requires further polling.
        if !packet.is_parsec_gossip() {
            self.message_sent = true;
        }

        self.connections
            .entry(Connection::new(src, dst))
            .or_insert_with(Queue::new)
            .push(packet)
    }

    pub fn disconnect(&mut self, src: SocketAddr, dst: SocketAddr) {
        self.send(src, dst, Packet::Disconnect);
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
                let packet = entry.get_mut().pop_random_msg(&mut self.rng);
                if entry.get().is_empty() {
                    let _ = entry.remove_entry();
                }
                packet
            }
            Entry::Vacant(_) => None,
        }
    }

    fn is_connected(&self, addr0: &SocketAddr, addr1: &SocketAddr) -> bool {
        self.find_node(addr0)
            .map(|node| node.borrow().is_connected(addr1))
            .unwrap_or(false)
    }
}

// The 4-byte tags of `Message::Direct` and `DirectMessage::ParsecRequest`.
// A serialised Parsec request message starts with these bytes.
#[cfg(not(feature = "mock_serialise"))]
static PARSEC_REQ_MSG_TAGS: &[u8] = &[0, 0, 0, 0, 6, 0, 0, 0];
// The 4-byte tags of `Message::Direct` and `DirectMessage::ParsecResponse`.
// A serialised Parsec response message starts with these bytes.
#[cfg(not(feature = "mock_serialise"))]
static PARSEC_RSP_MSG_TAGS: &[u8] = &[0, 0, 0, 0, 7, 0, 0, 0];

#[derive(Debug)]
pub(super) enum Packet {
    BootstrapRequest(OurType),
    BootstrapSuccess,
    BootstrapFailure,
    ConnectRequest(OurType),
    ConnectSuccess,
    ConnectFailure,
    Message(NetworkBytes, u64),
    MessageFailure(NetworkBytes, u64),
    MessageSent(NetworkBytes, u64),
    Disconnect,
}

impl Packet {
    // Returns `true` if this packet contains a Parsec request or response.
    #[cfg(not(feature = "mock_serialise"))]
    pub fn is_parsec_gossip(&self) -> bool {
        match self {
            Packet::Message(bytes, _) if bytes.len() >= 8 => {
                &bytes[..8] == PARSEC_REQ_MSG_TAGS || &bytes[..8] == PARSEC_RSP_MSG_TAGS
            }
            _ => false,
        }
    }

    #[cfg(feature = "mock_serialise")]
    pub fn is_parsec_gossip(&self) -> bool {
        use crate::messages::{DirectMessage, Message};

        match self {
            Packet::Message(ref message, _) => match **message {
                Message::Direct(ref message) => match message.content() {
                    DirectMessage::ParsecRequest(..) | DirectMessage::ParsecResponse(..) => true,
                    _ => false,
                },
                _ => false,
            },
            _ => false,
        }
    }
}

struct Queue(VecDeque<Packet>);

impl Queue {
    fn new() -> Self {
        Queue(VecDeque::new())
    }

    fn push(&mut self, packet: Packet) {
        self.0.push_back(packet)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // This function will pop random msg from the queue.
    fn pop_random_msg(&mut self, rng: &mut SeededRng) -> Option<Packet> {
        let first_non_msg_packet = self
            .0
            .iter()
            .position(|packet| {
                if let Packet::Message(_, _) = packet {
                    false
                } else {
                    true
                }
            })
            .unwrap_or(0);

        let selected = rng.gen_range(0, cmp::max(first_non_msg_packet, 1));
        self.0.remove(selected)
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
    pub(super) static NETWORK: RefCell<Option<Rc<RefCell<Inner>>>> = RefCell::new(None);
}

fn next_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(ip.octets()) + 1)),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(ip.octets()) + 1)),
    }
}

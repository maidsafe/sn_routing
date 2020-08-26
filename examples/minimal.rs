// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Example of a minimal routing node.
//!
//! This example node can connect to the other nodes, perform section operations like split,
//! relocation, promotion and demotion and print important updates to the stdout. It doesn't
//! currently do anything else, in particular it doesn't support sending/receiving user messages or
//! voting for user observations. Such features might be added in the future.
//!
//! # Usage
//!
//! Run as a standalone binary:
//!
//!     minimal ARGS...
//!
//! Or via cargo (release mode recommended):
//!
//!     cargo run --release --example minimal -- ARGS...
//!
//! Run with `--help` (or `-h`) to see the command line options and their explanation.
//!
//!
//! # Multiple nodes
//!
//! It is possible to start multiple nodes with a single invocation of this example. Such nodes
//! would all run within the same process, but each in its own thread. See the `--count` (or `-c`)
//! command-line option for more details.
//!

use crossbeam_channel::{Receiver, Select, Sender};
use hex_fmt::HexFmt;
use log::LevelFilter;
use routing::{
    event::{Connected, Event},
    Node, NodeConfig, TransportConfig,
};
use std::{
    collections::HashSet,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    thread::{self, JoinHandle},
};
use structopt::StructOpt;

/// Minimal example node.
#[derive(Debug, StructOpt)]
struct Options {
    /// Socket address (e.g. 203.0.113.45:6789) of a node(s) to bootstrap against. Multiple
    /// contacts can be specified by passing the option multiple times. If omitted, will try to use
    /// contacts cached from previous run, if any.
    #[structopt(short, long, name = "bootstrap-contact", value_name = "SOCKET_ADDRESS")]
    bootstrap_contacts: Vec<SocketAddr>,
    /// Whether this is the first node ("genesis node") of the network. Only one node can be first.
    #[structopt(short, long, conflicts_with = "bootstrap-contact")]
    first: bool,
    /// IP address to bind to. Default is localhost which is fine when spawning example nodes
    /// on a single machine. If one wants to run nodes on multiple machines, an address that is
    /// reachable from all of them must be used.
    ///
    /// Note: unspecified (0.0.0.0) currently doesn't work due to limitation of the underlying
    /// networking layer.
    ///
    /// If starting multiple nodes (see --count), then this option applies only to the first one.
    /// The rest are started as regular nodes.
    #[structopt(short, long, value_name = "IP")]
    ip: Option<IpAddr>,
    /// Port to listen to. If omitted, a randomly assigned port is used.
    ///
    /// If starting multiple nodes (see --count), then this is used as base port and the actual
    /// port of `n-th` node is calculated as `port + n` (if available)
    #[structopt(short, long, value_name = "PORT")]
    port: Option<u16>,
    /// Number of nodes to start. Each node is started in its own thread. Default is to start just
    /// one node.
    #[structopt(
        short,
        long,
        default_value,
        value_name = "COUNT",
        hide_default_value = true
    )]
    count: usize,
    /// Enable verbose output. Can be specified multiple times for increased verbosity.
    #[structopt(short, parse(from_occurrences))]
    verbosity: u8,
}

fn main() {
    if cfg!(feature = "mock") {
        panic!("This example must be built without the `mock` feature");
    }

    let opts = Options::from_args();
    init_log(opts.verbosity);

    if opts.count <= 1 {
        start_single_node(opts.first, opts.bootstrap_contacts, opts.ip, opts.port)
    } else {
        start_multiple_nodes(
            opts.count,
            opts.first,
            opts.bootstrap_contacts,
            opts.ip,
            opts.port,
        )
    }
}

// Starts a single node and block until it terminates.
fn start_single_node(
    first: bool,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    port: Option<u16>,
) {
    start_node(0, first, contacts.into_iter().collect(), ip, port, None)
}

// Starts `count` nodes and blocks until all of them terminate.
//
// If `first` is true, the first spawned node will start as the first (genesis) node. The rest will
// always start as regular nodes.
fn start_multiple_nodes(
    count: usize,
    first: bool,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
) {
    let mut join_handles = Vec::with_capacity(count);

    let (first_index, first_contact) = if first {
        let (join_handle, first_contact) = spawn_first_node(ip, base_port);
        join_handles.push(join_handle);
        (1, Some(first_contact))
    } else {
        (0, None)
    };

    let contacts: HashSet<_> = contacts.into_iter().chain(first_contact).collect();

    for index in first_index..count {
        let join_handle = spawn_other_node(index, contacts.clone(), ip, base_port);
        join_handles.push(join_handle);
    }
}

// Spawns the first (genesis) node in its own thread and blocks until its contact info becomes
// available.
fn spawn_first_node(ip: Option<IpAddr>, base_port: Option<u16>) -> (ScopedJoinHandle, SocketAddr) {
    let (contact_tx, contact_rx) = crossbeam_channel::bounded(0);
    let join_handle = thread::spawn(move || {
        start_node(0, true, HashSet::default(), ip, base_port, Some(contact_tx))
    })
    .into();
    let contact = contact_rx
        .recv()
        .expect("failed to receive contact info of the first node");

    (join_handle, contact)
}

// Spawns regular (non-first) node in its own thread.
//
// `index` is used to differentiate the nodes in the log output. Should be unique.
fn spawn_other_node(
    index: usize,
    contacts: HashSet<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
) -> ScopedJoinHandle {
    thread::spawn(move || start_node(index, false, contacts, ip, base_port, None)).into()
}

// Starts a single node and blocks until it terminates.
fn start_node(
    index: usize,
    first: bool,
    contacts: HashSet<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
    contact_tx: Option<Sender<SocketAddr>>,
) {
    let ip = ip.unwrap_or_else(|| Ipv4Addr::LOCALHOST.into());
    let port = base_port.map(|base_port| {
        index
            .try_into()
            .ok()
            .and_then(|offset| base_port.checked_add(offset))
            .expect("port out of range")
    });

    let transport_config = TransportConfig {
        hard_coded_contacts: contacts,
        ip: Some(ip),
        port,
        ..Default::default()
    };

    log::info!("Node #{} starting...", index);

    // The returned triple is:
    // - The routing node itself.
    // - The receiver for events that the node notifies the application about.
    // - The receiver for client network events. We don't support clients in this example, so we
    //   can ignore it
    let (node, event_rx, _client_event_rx) = Node::new(NodeConfig {
        first,
        transport_config,
        ..Default::default()
    });

    run_node(index, node, event_rx, contact_tx)
}

// Runs the nodes event loop. Blocks until terminated.
fn run_node(
    index: usize,
    mut node: Node,
    event_rx: Receiver<Event>,
    contact_tx: Option<Sender<SocketAddr>>,
) {
    loop {
        // We need receive from multiple channels. As a minimum, we need to receive from the
        // channels used internally by `Node` and from the node event channel. Additionally we might
        // want to receive from the client network event channel (not used in this example) or from
        // any other channel used by the application. To achieve this, we use the `Select`
        // mechanism of `crossbeam-channel`.

        // First create an instance of `Select`.
        let mut select = Select::new();

        // Pass it to node to let it register its own internal channels.
        node.register(&mut select);

        // Then register the event channel.
        let event_rx_idx = select.recv(&event_rx);

        // Block until one (or more) of the channels receive something.
        let selected_operation = select.ready();

        if selected_operation == event_rx_idx {
            // If the receiving channel is the event channel, receive the event and handle it.
            let event = match event_rx.recv() {
                Ok(event) => event,
                Err(error) => panic!("Node #{} failed to receive event: {}", index, error),
            };

            if !handle_event(index, &mut node, event, contact_tx.as_ref()) {
                break;
            }
        } else {
            // Otherwise the receiving channel is internal to node, so let it handle it.
            if let Err(error) = node.handle_selected_operation(selected_operation) {
                log::error!(
                    "Node #{} failed to handle selected operation: {}",
                    index,
                    error
                );
                break;
            }
        }
    }
}

// Handles the event emitted by the node.
//
// If `contact_tx` is `Some`, it will be used to send the contact info of the node once it becomes
// available.
fn handle_event(
    index: usize,
    node: &mut Node,
    event: Event,
    contact_tx: Option<&Sender<SocketAddr>>,
) -> bool {
    match event {
        Event::Connected(Connected::First) => {
            let contact_info = node
                .our_connection_info()
                .expect("failed to retrieve node contact info");
            log::info!(
                "Node #{} connected - name: {}, contact: {}",
                index,
                node.name(),
                contact_info
            );

            if let Some(contact_tx) = contact_tx {
                contact_tx
                    .send(contact_info)
                    .expect("failed to send contact info")
            }
        }
        Event::Connected(Connected::Relocate) => {
            log::info!("Node #{} relocated - new name: {}", index, node.name());
        }
        Event::PromotedToElder => {
            log::info!("Node #{} promoted to Elder", index);
        }
        Event::PromotedToAdult => {
            log::info!("Node #{} promoted to Adult", index);
        }
        Event::Demoted => {
            log::info!("Node #{} demoted", index);
        }
        Event::MemberJoined {
            name,
            previous_name,
            age,
        } => {
            log::info!(
                "Node #{} member joined - name: {}, previous_name: {}, age: {}",
                index,
                name,
                previous_name,
                age
            );
        }
        Event::InfantJoined { name, age } => {
            log::info!(
                "Node #{} infant joined - name: {}, age: {}",
                index,
                name,
                age
            );
        }
        Event::MemberLeft { name, age } => {
            log::info!("Node #{} member left - name: {}, age: {}", index, name, age);
        }
        Event::EldersChanged {
            prefix,
            key,
            elders,
        } => {
            log::info!(
                "Node #{} elders changed - prefix: {:b}, key: {:?}, elders: {:?}",
                index,
                prefix,
                key,
                elders
            );
        }
        Event::MessageReceived { content, src, dst } => log::info!(
            "Node #{} received message - src: {:?}, dst: {:?}, content: {}",
            index,
            src,
            dst,
            HexFmt(content)
        ),
        Event::RelocationInitiated { name, destination } => log::debug!(
            "Node #{} initiated relocation of {} to {}",
            index,
            name,
            destination
        ),
        Event::Terminated => {
            log::info!("Node #{} terminated", index);
            return false;
        }
        Event::RestartRequired => {
            log::info!("Node #{} requires restart", index);
            return false;
        }
    }

    true
}

const TARGET_SELF: &str = "minimal";
const TARGET_ROUTING: &str = "routing";

fn init_log(verbosity: u8) {
    let mut builder = env_logger::builder();

    // By default, show only logs from this example.
    builder
        .filter(None, LevelFilter::Off)
        .filter(Some(TARGET_SELF), LevelFilter::Info);

    if verbosity > 0 {
        // Enable info logs from routing.
        builder.filter(Some(TARGET_ROUTING), LevelFilter::Info);
    }
    if verbosity > 1 {
        // Enable debug logs from routing
        builder.filter(Some(TARGET_ROUTING), LevelFilter::Debug);
    }
    if verbosity > 2 {
        // Enable trace logs from routing
        builder.filter(Some(TARGET_ROUTING), LevelFilter::Trace);
    }
    if verbosity > 3 {
        // Enable trace logs from all crates
        builder.filter(None, LevelFilter::Trace);
    }

    builder.init()
}

// RAII-like wrapper for `std::thread::JoinHandle` which joins the thread when dropped.
struct ScopedJoinHandle(Option<JoinHandle<()>>);

impl From<JoinHandle<()>> for ScopedJoinHandle {
    fn from(inner: JoinHandle<()>) -> Self {
        Self(Some(inner))
    }
}

impl Drop for ScopedJoinHandle {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            inner.join().expect("failed to join - thread panicked")
        }
    }
}

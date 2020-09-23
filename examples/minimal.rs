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

use hex_fmt::HexFmt;
use log::{info, LevelFilter};
use sn_routing::{
    event::{Connected, Event},
    EventStream, Node, NodeConfig, TransportConfig,
};
use std::{
    collections::HashSet,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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

#[tokio::main]
async fn main() {
    if cfg!(feature = "mock") {
        panic!("This example must be built without the `mock` feature");
    }

    let opts = Options::from_args();
    init_log(opts.verbosity);

    if opts.count <= 1 {
        start_single_node(opts.first, opts.bootstrap_contacts, opts.ip, opts.port).await
    } else {
        start_multiple_nodes(
            opts.count,
            opts.first,
            opts.bootstrap_contacts,
            opts.ip,
            opts.port,
        )
        .await
    }
}

// Starts a single node and block until it terminates.
async fn start_single_node(
    first: bool,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    port: Option<u16>,
) {
    let _contact = start_node(0, first, contacts.into_iter().collect(), ip, port).await;
}

// Starts `count` nodes and blocks until all of them terminate.
//
// If `first` is true, the first spawned node will start as the first (genesis) node. The rest will
// always start as regular nodes.
async fn start_multiple_nodes(
    count: usize,
    first: bool,
    mut contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
) {
    let first_index = if first {
        let first_contact = spawn_first_node(ip, base_port).await;
        contacts.push(first_contact);
        1
    } else {
        0
    };

    for index in first_index..count {
        spawn_other_node(index, contacts.clone(), ip, base_port).await;
    }
}

// Spawns the first (genesis) node in its own thread
async fn spawn_first_node(ip: Option<IpAddr>, base_port: Option<u16>) -> SocketAddr {
    start_node(0, true, Vec::default(), ip, base_port).await
}

// Spawns regular (non-first) node in its own thread.
//
// `index` is used to differentiate the nodes in the log output. Should be unique.
async fn spawn_other_node(
    index: usize,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
) {
    let _contact_info = start_node(index, false, contacts, ip, base_port).await;
}

// Starts a single node and blocks until it terminates.
async fn start_node(
    index: usize,
    first: bool,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
) -> SocketAddr {
    let ip = ip.unwrap_or_else(|| Ipv4Addr::LOCALHOST.into());
    let port = base_port.map(|base_port| {
        index
            .try_into()
            .ok()
            .and_then(|offset| base_port.checked_add(offset))
            .expect("port out of range")
    });

    let contacts: HashSet<_> = contacts.into_iter().collect();
    let transport_config = TransportConfig {
        hard_coded_contacts: contacts,
        ip: Some(ip),
        port,
        ..Default::default()
    };

    info!("Node #{} starting...", index);

    let config = NodeConfig {
        first,
        transport_config,
        ..Default::default()
    };
    let (node, event_stream) = Node::new(config)
        .await
        .expect("Failed to instantiate a Node");

    let contact_info = node
        .our_connection_info()
        .await
        .expect("Failed to obtain node's contact info.");

    run_node(index, node, event_stream).await;

    contact_info
}

// Runs the nodes event loop. Blocks until terminated.
async fn run_node(index: usize, mut node: Node, mut event_stream: EventStream) {
    tokio::spawn(async move {
        while let Some(event) = event_stream.next().await {
            if !handle_event(index, &mut node, event).await {
                break;
            }
        }
    });
}

// Handles the event emitted by the node.
async fn handle_event(index: usize, node: &mut Node, event: Event) -> bool {
    match event {
        Event::Connected(Connected::First) => {
            let contact_info = node
                .our_connection_info()
                .await
                .expect("failed to retrieve node contact info");

            info!(
                "Node #{} connected - name: {}, contact: {}",
                index,
                node.name().await,
                contact_info
            );
        }
        Event::Connected(Connected::Relocate { previous_name }) => {
            info!(
                "Node #{} relocated - old name: {}, new name: {}",
                index,
                previous_name,
                node.name().await
            );
        }
        Event::PromotedToElder => {
            info!("Node #{} promoted to Elder", index);
        }
        Event::PromotedToAdult => {
            info!("Node #{} promoted to Adult", index);
        }
        Event::Demoted => {
            info!("Node #{} demoted", index);
        }
        Event::MemberJoined {
            name,
            previous_name,
            age,
        } => {
            info!(
                "Node #{} member joined - name: {}, previous_name: {}, age: {}",
                index, name, previous_name, age
            );
        }
        Event::InfantJoined { name, age } => {
            info!(
                "Node #{} infant joined - name: {}, age: {}",
                index, name, age
            );
        }
        Event::MemberLeft { name, age } => {
            info!("Node #{} member left - name: {}, age: {}", index, name, age);
        }
        Event::EldersChanged {
            prefix,
            key,
            elders,
        } => {
            info!(
                "Node #{} elders changed - prefix: {:b}, key: {:?}, elders: {:?}",
                index, prefix, key, elders
            );
        }
        Event::MessageReceived { content, src, dst } => info!(
            "Node #{} received message - src: {:?}, dst: {:?}, content: {}",
            index,
            src,
            dst,
            HexFmt(content)
        ),
        Event::RelocationStarted { previous_name } => info!(
            "Node #{} relocation started - previous_name: {}",
            index, previous_name
        ),
        Event::RestartRequired => {
            info!("Node #{} requires restart", index);
            return false;
        }
        Event::ClientMessageReceived { content, src, .. } => info!(
            "Node #{} received message from client: {:?}, content: {}",
            index,
            src,
            HexFmt(content)
        ),
    }

    true
}

const TARGET_SELF: &str = "minimal";
const TARGET_ROUTING: &str = "sn_routing";

fn init_log(verbosity: u8) {
    let mut builder = env_logger::builder();

    // By default, show only logs from this example.
    builder
        .filter(None, LevelFilter::Off)
        .filter(Some(TARGET_SELF), LevelFilter::Info);

    if verbosity > 0 {
        // Enable info logs from sn_routing.
        builder.filter(Some(TARGET_ROUTING), LevelFilter::Info);
    }
    if verbosity > 1 {
        // Enable debug logs from sn_routing
        builder.filter(Some(TARGET_ROUTING), LevelFilter::Debug);
    }
    if verbosity > 2 {
        // Enable trace logs from sn_routing
        builder.filter(Some(TARGET_ROUTING), LevelFilter::Trace);
    }
    if verbosity > 3 {
        // Enable trace logs from all crates
        builder.filter(None, LevelFilter::Trace);
    }

    builder.init()
}

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

use futures::future::join_all;
use hex_fmt::HexFmt;
use sn_routing::{Config, Event, EventStream, Routing, TransportConfig};
use std::{
    collections::HashSet,
    convert::TryInto,
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use structopt::StructOpt;
use tokio::task::JoinHandle;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Minimal example node.
#[derive(Debug, StructOpt)]
struct Options {
    /// Socket address (e.g. 203.0.113.45:6789) of a node(s) to bootstrap against. Multiple
    /// contacts can be specified by passing the option multiple times. If omitted, will try to use
    /// contacts cached from previous run, if any.
    #[structopt(
        short,
        long,
        name = "bootstrap-contact",
        value_name = "SOCKET_ADDRESS",
        required_unless = "first"
    )]
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
    let opts = Options::from_args();
    init_log(opts.verbosity);

    let handles: Vec<_> = if opts.count <= 1 {
        let handle =
            start_single_node(opts.first, opts.bootstrap_contacts, opts.ip, opts.port).await;
        iter::once(handle).collect()
    } else {
        start_multiple_nodes(
            opts.count,
            opts.first,
            opts.bootstrap_contacts,
            opts.ip,
            opts.port,
        )
        .await
    };
    let _ = join_all(handles).await;
}

// Starts a single node and block until it terminates.
async fn start_single_node(
    first: bool,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    port: Option<u16>,
) -> JoinHandle<()> {
    let (_contact, handle) = start_node(0, first, contacts.into_iter().collect(), ip, port).await;
    handle
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
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    let first_index = if first {
        let (first_contact, first_handle) =
            start_node(0, true, Vec::default(), ip, base_port).await;
        contacts.push(first_contact);
        handles.push(first_handle);
        1
    } else {
        0
    };

    for index in first_index..count {
        let (_contact_info, handle) =
            start_node(index, false, contacts.clone(), ip, base_port).await;
        handles.push(handle);
    }
    handles
}

// Starts a single node and blocks until it terminates.
async fn start_node(
    index: usize,
    first: bool,
    contacts: Vec<SocketAddr>,
    ip: Option<IpAddr>,
    base_port: Option<u16>,
) -> (SocketAddr, JoinHandle<()>) {
    let ip = ip.unwrap_or_else(|| Ipv4Addr::LOCALHOST.into());
    let local_port = base_port.map(|base_port| {
        index
            .try_into()
            .ok()
            .and_then(|offset| base_port.checked_add(offset))
            .expect("port out of range")
    });

    let contacts: HashSet<_> = contacts.into_iter().collect();
    let transport_config = TransportConfig {
        hard_coded_contacts: contacts,
        local_ip: Some(ip),
        local_port,
        ..Default::default()
    };

    info!("Node #{} starting...", index);

    let config = Config {
        first,
        transport_config,
        ..Default::default()
    };
    let (node, event_stream) = Routing::new(config)
        .await
        .expect("Failed to instantiate a Node");

    let contact_info = node.our_connection_info();

    info!(
        "Node #{} connected - name: {}, contact: {}",
        index,
        node.name().await,
        contact_info
    );

    let handle = run_node(index, node, event_stream);

    (contact_info, handle)
}

// Spawns a task to run the node until terminated.
fn run_node(index: usize, mut node: Routing, mut event_stream: EventStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = event_stream.next().await {
            if !handle_event(index, &mut node, event).await {
                break;
            }
        }
    })
}

// Handles the event emitted by the node.
async fn handle_event(index: usize, node: &mut Routing, event: Event) -> bool {
    match event {
        Event::Genesis => {
            info!("Node #{} is Genesis", index);
        }
        Event::MemberJoined {
            name,
            previous_name,
            age,
        } => {
            info!(
                "Node #{} member joined - name: {}, previous_name: {:?}, age: {}",
                index, name, previous_name, age
            );
        }
        Event::MemberLeft { name, age } => {
            info!("Node #{} member left - name: {}, age: {}", index, name, age);
        }
        Event::EldersChanged {
            elders,
            sibling_elders,
            self_status_change,
        } => {
            info!(
                "Node #{} elders changed - prefix: {:b}, key: {:?}, sibling elders: {:?}, elders: {:?}, node elder status change: {:?}",
                index, elders.prefix, elders.key, sibling_elders, elders.elders, self_status_change
            );
        }
        Event::MessageReceived { content, src, dst } => info!(
            "Node #{} received message - src: {:?}, dst: {:?}, content: {}",
            index,
            src,
            dst,
            HexFmt(&content)
        ),
        Event::RelocationStarted { previous_name } => info!(
            "Node #{} relocation started - previous_name: {}",
            index, previous_name
        ),
        Event::Relocated { previous_name, .. } => {
            let new_name = node.name().await;
            info!(
                "Node #{} relocated - old name: {}, new name: {}",
                index, previous_name, new_name,
            );
        }
        Event::RestartRequired => {
            info!("Node #{} requires restart", index);
            return false;
        }
        Event::ClientMessageReceived { msg, user, .. } => info!(
            "Node #{} received message from user: {:?}, msg: {:?}",
            index, user, msg
        ),
        Event::ClientLost(addr) => info!("Node #{} received ClientLost({:?})", index, addr),
    }

    true
}

fn init_log(verbosity: u8) {
    let filter = match verbosity {
        0 => EnvFilter::new("minimal=info,sn_routing=warn"),
        1 => EnvFilter::new("minimal,sn_routing=info"),
        2 => EnvFilter::new("minimal,sn_routing=debug"),
        3 => EnvFilter::new("minimal,sn_routing=trace"),
        _ => EnvFilter::new("trace"),
    };

    tracing_subscriber::fmt().with_env_filter(filter).init()
}

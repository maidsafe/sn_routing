// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use anyhow::{format_err, Context, Error, Result};
use bls_signature_aggregator::{ProofShare, SignatureAggregator};
use futures::{
    future,
    stream::{self, StreamExt},
    Stream,
};
use itertools::Itertools;
use lru_time_cache::LruCache;
use rand::{
    distributions::{Distribution, WeightedIndex},
    Rng,
};
use serde::{Deserialize, Serialize};
use sn_messaging::{
    location::{Aggregation, Itinerary},
    DstLocation, SrcLocation,
};
use sn_routing::{
    Config, Error as RoutingError, Event as RoutingEvent, NodeElderChange, Routing, TransportConfig,
};
use std::{collections::BTreeMap, fs::File, io::BufWriter, net::{Ipv4Addr, SocketAddr}, time::{Duration, Instant}, io};
use structopt::StructOpt;
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task, time,
};
use tokio_util::time::delay_queue::DelayQueue;
use tracing_subscriber::EnvFilter;
use xor_name::{Prefix, XorName};
use tui::backend::CrosstermBackend;
use tui::{Terminal, symbols};
use tui::layout::{Layout, Direction, Constraint, Alignment};
use tui::widgets::{Block, Borders, Paragraph, BorderType, Dataset, GraphType, Chart, Axis};
use tui::text::Span;
use tui::style::{Color, Style, Modifier};
use tui::symbols::Marker;
use crossterm::event::{read, Event as TerminalEvent, KeyEvent, KeyCode};
use futures::channel::mpsc::{unbounded, channel};
use tokio::sync::mpsc::{unbounded_channel, Sender};
use std::collections::HashSet;
use futures::stream::FuturesUnordered;

// Minimal delay between two consecutive prints of the network status.
const MIN_PRINT_DELAY: Duration = Duration::from_millis(500);

// Time after which we stop tracking a probe message, regardless of its state (delivered or not).
const PROBE_WINDOW: Duration = Duration::from_secs(60);

/// Stress test for sn-routing.
#[derive(Debug, StructOpt)]
struct Options {
    /// Enable logging. Takes path to a file to log to or "-" to log to stdout. If omitted, logging
    /// is disabled.
    #[structopt(short, long, name = "PATH")]
    log: Option<String>,
    /// How many probe messages to send per second.
    ///
    /// Probe messages are used to determine network health. The higher the percentage of
    /// successfully delivered probe messages, the healthier the network is.
    #[structopt(short, long, default_value = "1")]
    probe_frequency: f64,
    /// Churn schedule: DURATION1 JOINS1 DROPS1 DURATION2 JOINS2 DROPS2, ...
    ///
    /// Given as a list of numbers which are taken in groups of three. Each triple defines one churn
    /// period. The first number defines the duration of the period in seconds, the second number
    /// defines the number of nodes to add during this period and the third number defines the
    /// number of nodes to remove. The actual times of the churn events are chosen randomly within
    /// the period. Multiple periods can be specified and are then executed sequentially. If the
    /// number of entries is not divisible by three, the missing numbers are assumed to be zeroes.
    ///
    /// Example
    ///
    /// 10 5 0 20 15 8
    ///
    /// Defines a schedule where there is 5 nodes added and none removed during the first
    /// 10 seconds and then 15 nodes added and 8 nodes removed during the subsequent 20 seconds.
    /// No more churn (apart from internal churn due to relocation) is be generated afterwards.
    schedule: Vec<String>,

    #[structopt(short, long)]
    interactive: bool,
}

enum Event {
    Input(TerminalEvent),
    Tick
}

#[derive(Debug, Default)]
struct App {
    data: Vec<(f64, f64)>,

}

enum MenuOption {
    Add,
    Remove
}

#[tokio::main]
async fn main() -> Result<()> {
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let (event_tx, mut event_rx) = unbounded_channel();
    let mut network = Network::new();
    let probe_interval = Duration::from_secs_f64(1.0);
    let mut probes = time::interval(probe_interval);
    let app = App::default();

    let (mut tx, mut rx) = channel(5);
    let mut kx = tx.clone();

    std::thread::spawn(move || {
        loop {
            let _ = tx.try_send(Event::Tick);
            std::thread::sleep(probe_interval);
        }
    });
    std::thread::spawn(move || {
        loop {
            if let Ok(key) = read() {
                let _ = kx.try_send(Event::Input(key));
            }
        }
    });

    // Create the genesis node
    network.create_nodes(event_tx.clone(), 1u32).await;
    terminal.clear();
    let mut option_selected: Option<MenuOption> = None;
    let (tcx, mut rcx) = unbounded_channel();
    let mut buffer = vec![];
    loop {
        match rx.try_next()? {
            Some(Event::Input(input)) => {
               match input {
                   TerminalEvent::Key(KeyEvent {
                                  code: KeyCode::Char(ch), ..
                              }) => {
                       match (&option_selected, ch) {
                           (_, 'q')  => break,
                           (None, '1') => { option_selected = Some(MenuOption::Add); continue },
                           (None, '2') => { option_selected = Some(MenuOption::Remove); continue },
                           (Some(_), n) => {
                                   buffer.push(n);
                               },
                           (Some(MenuOption::Add), '\n') =>{
                               let buf = buffer.clone().into_iter().collect::<String>();
                               let n = buf.parse::<u32>().unwrap_or(0);
                               if n > 0 {
                                   network.create_nodes(tcx.clone(), n).await;
                               }
                           }
                           (Some(MenuOption::Remove), '\n') =>{
                               let buf = buffer.clone().into_iter().collect::<String>();
                               let n = buf.parse::<u32>().unwrap_or(0);
                               if n > 0 {
                                   network.remove_random_nodes(n);
                               }
                           }
                           _ => {}
                       }
                   },
                   TerminalEvent::Mouse(_) => {}
                   TerminalEvent::Resize(_, _) => {}
                   _ => {}
               }
            }
            Some(Event::Tick) => {
                if let Some(event) =  rcx.recv().await {
                        network.handle_event(event).await?;
                }
                let _ = terminal.draw(|f| {
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .margin(1)
                        .constraints(
                            [
                                Constraint::Percentage(20),
                                Constraint::Percentage(20),
                                Constraint::Percentage(60),
                            ].as_ref()
                        )
                        .split(f.size());
                    let block = Block::default()
                        .style(Style::default().bg(Color::Black).fg(Color::White))
                        .borders(Borders::ALL);

                    f.render_widget(block, chunks[0]);

                    let stats = Paragraph::new(format!("{:?} \n", network.stats))
                        .style(Style::default().fg(Color::LightCyan))
                        .alignment(Alignment::Center)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .style(Style::default().fg(Color::White))
                                .title("Stats")
                                .border_type(BorderType::Plain)
                        );

                    f.render_widget(stats, chunks[0]);

                    let message = if option_selected.is_none() {
                        String::from( "1. Add Node 2. Remove Node")
                    } else {
                        String::from("Enter the number of nodes")
                    };

                    let menu = Paragraph::new(message)
                        .style(Style::default().fg(Color::Cyan))
                        .alignment(Alignment::Center)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .style(Style::default().fg(Color::White))
                                .title("Menu")
                                .border_type(BorderType::Plain)
                        );
                    f.render_widget(menu, chunks[1]);

                    let datasets = vec![Dataset::default()
                        .name("data")
                        .marker(Marker::Braille)
                        .style(Style::default().fg(Color::Yellow))
                        .graph_type(GraphType::Line)
                        .data(&app.data)];
                    let chart = Chart::new(datasets)
                        .block(
                            Block::default()
                                .title(Span::styled(
                                    "Chart 2",
                                    Style::default()
                                        .fg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                ))

                                .borders(Borders::ALL),
                        )
                        .x_axis(
                            Axis::default()
                                .title("X Axis")
                                .style(Style::default().fg(Color::Gray))
                                .bounds([0.0, 5.0])
                                .labels(vec![
                                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                                    Span::raw("2.5"),
                                    Span::styled("5.0", Style::default().add_modifier(Modifier::BOLD)),
                                ]),
                        )
                        .y_axis(
                            Axis::default()
                                .title("Y Axis")
                                .style(Style::default().fg(Color::Gray))
                                .bounds([0.0, 5.0])
                                .labels(vec![
                                    Span::styled("0", Style::default().add_modifier(Modifier::BOLD)),
                                    Span::raw("2.5"),
                                    Span::styled("5.0", Style::default().add_modifier(Modifier::BOLD)),
                                ]),
                        );
                    f.render_widget(chart, chunks[2]);
                });
            },
            _ => {}
        }
}
    Ok(())
}


#[allow(clippy::large_enum_variant)]
enum NodeEvent {
    // Node successfully joined the network.
    JoinSuccess { id: u64, node: Routing },
    // Node failed to join the network.
    JoinFailure { id: u64, error: Error },
    // Node fired a routing event.
    Routing { id: u64, event: RoutingEvent },
}

#[allow(clippy::large_enum_variant)]
enum Node {
    // Node is bootstrapping into the network for the first time.
    Joining,
    // Node has joined the network and is either a member of a section or being relocated
    Joined {
        node: Routing,
        name: XorName,
        age: u8,
        prefix: Prefix,
        is_relocating: bool,
        // `Some` if this node is elder, otherwise `None`.
        elder: Option<ElderState>,
    },
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct ElderState {
    key: bls::PublicKey,
    num_elders: usize,
}

struct Network {
    nodes: BTreeMap<u64, Node>,
    next_id: u64,
    start_time: Instant,
    print_time: Instant,
    probe_tracker: ProbeTracker,
    stats: Stats,
}

impl Network {
    fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            next_id: 0,
            start_time: Instant::now(),
            print_time: Instant::now() - MIN_PRINT_DELAY,
            probe_tracker: ProbeTracker::default(),
            stats: Stats::default(),
        }
    }

    // Create new node and let it join the network.
    async fn create_nodes(&mut self, event_tx: UnboundedSender<NodeEvent>, number: u32) {
        let bootstrap_addrs = self.get_bootstrap_addrs();
        let first = bootstrap_addrs.is_empty();
        let contacts: HashSet<_> = bootstrap_addrs.into_iter().collect();

        for i in 1..=number {
            let id = self.new_node_id();
            let _ = self.nodes.insert(id, Node::Joining);
            self.stats.join_attempts += 1;

            let config = Config {
                first,
                transport_config: TransportConfig {
                    hard_coded_contacts: contacts.clone(),
                    local_ip: Some(Ipv4Addr::LOCALHOST.into()),
                    ..Default::default()
                },
                ..Default::default()
            };

            let _ = task::spawn(add_node(id, config, event_tx.clone()));
        }

        self.try_print_status();
    }

    // Remove a random node where the probability of a node to be removed is inversely proportional
    // to its age. That is, younger nodes are more likely to be dropped than older nodes. More
    // specifically, a node with age N is twice a likely to be dropped than a node with age N + 1.
    fn remove_random_nodes(&mut self, n: u32) {
        let weighted_ids: Vec<_> = self
            .nodes
            .iter()
            .filter_map(|(id, node)| match node {
                Node::Joined { age, .. } => Some((*id, 1.0 / 2f64.powf(*age as f64))),
                Node::Joining => None,
            })
            .collect();

        let dist =
            if let Ok(dist) = WeightedIndex::new(weighted_ids.iter().map(|(_, weight)| *weight)) {
                dist
            } else {
                return;
            };

        let index = dist.sample(&mut rand::thread_rng());
        let id = weighted_ids[index].0;

        if let Some(node) = self.nodes.remove(&id) {
            self.stats.drops += 1;

            if let Node::Joined {
                is_relocating: true,
                ..
            } = node
            {
                // We dropped a node that is being relocated. Count this as success to avoid
                // this showing up as relocation failure which it isn't.
                self.stats.relocation_successes += 1;
            }

            self.try_print_status();
        }
    }

    async fn handle_event(&mut self, event: NodeEvent) -> Result<()> {
        match event {
            NodeEvent::JoinSuccess { id, node } => {
                let name = node.name().await;
                let age = node.age().await;
                let prefix = node.our_prefix().await;

                let _ = self.nodes.insert(
                    id,
                    Node::Joined {
                        node,
                        name,
                        age,
                        prefix,
                        is_relocating: false,
                        elder: None,
                    },
                );
                self.stats.join_successes += 1;
            }
            NodeEvent::JoinFailure { id, error } => {
                // println!("{}: {}", self.theme.error.paint("join failure"), error);
                let _ = self.nodes.remove(&id);
                self.stats.join_failures += 1;
            }
            NodeEvent::Routing { id, event } => match event {
                RoutingEvent::EldersChanged {
                    elders,
                    self_status_change,
                    ..
                } => {
                    if let Some(Node::Joined {
                                    name,
                                    prefix,
                                    elder,
                                    ..
                                }) = self.nodes.get_mut(&id)
                    {
                        *prefix = elders.prefix;

                        if elders.added.contains(name) {
                            *elder = Some(ElderState {
                                key: elders.key,
                                num_elders: elders.remaining.len() + elders.added.len(),
                            });
                        } else {
                            *elder = None;
                        }
                    }
                    match self_status_change {
                        NodeElderChange::Promoted => self.stats.promotions += 1,
                        NodeElderChange::Demoted => self.stats.demotions += 1,
                        NodeElderChange::None => (),
                    };
                }
                RoutingEvent::RelocationStarted { .. } => {
                    if let Some(Node::Joined { is_relocating, .. }) = self.nodes.get_mut(&id) {
                        *is_relocating = true;
                        self.stats.relocation_attempts += 1;
                    }
                }
                RoutingEvent::Relocated { .. } => {
                    if let Some(Node::Joined {
                                    node,
                                    name,
                                    age,
                                    is_relocating,
                                    ..
                                }) = self.nodes.get_mut(&id)
                    {
                        *name = node.name().await;
                        *age = node.age().await;
                        *is_relocating = false;
                        self.stats.relocation_successes += 1;
                    }
                }
                RoutingEvent::MessageReceived { content, dst, .. } => {
                    let message: ProbeMessage = bincode::deserialize(&content)?;
                    let dst = match dst {
                        DstLocation::Section(name) => name,
                        DstLocation::Node(name) => name,
                        DstLocation::Direct | DstLocation::EndUser(_) => {
                            return Err(format_err!("unexpected probe message dst: {:?}", dst))
                        }
                    };

                    self.probe_tracker.receive(&dst, message.proof_share);
                }
                _ => {
                    // Currently ignore the other event variants. This might change in the future,
                    // if we come up with something interesting to use those events for.
                }
            },
        }

        self.try_print_status();

        Ok(())
    }

    fn new_node_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).expect("too many nodes");
        id
    }

    // Returns the socket addresses to bootstrap against.
    fn get_bootstrap_addrs(&self) -> Vec<SocketAddr> {
        // Number of bootstrap contacts to use. Use more than one to increase the chance of
        // successful bootstrap in case some of the bootstrap nodes get dropped.
        //
        // FIXME: seems there is a bug which causes a hang if more than one contact is used.
        // Need to investigate.
        const COUNT: usize = 1;

        // Use the oldest nodes in the network as the bootstrap contacts.
        self.nodes
            .values()
            .filter_map(|node| match node {
                Node::Joined { node, age, .. } => Some((node, age)),
                Node::Joining => None,
            })
            .sorted_by(|(_, lhs_age), (_, rhs_age)| lhs_age.cmp(rhs_age).reverse())
            .take(COUNT)
            .map(|(node, _)| node.our_connection_info())
            .collect::<Vec<_>>()
    }

    // Send messages to probe network health.
    async fn send_probes(&mut self) -> Result<()> {
        // Cache the (src, dst) pairs of sent messages to ensure every node from the same
        // section sends the same message.
        let mut cache = BTreeMap::new();

        let nodes = self.nodes.values().filter_map(|node| match node {
            Node::Joined { node, prefix, .. } => Some((node, prefix)),
            Node::Joining => None,
        });

        for (node, prefix) in nodes {
            let dst = *cache
                .entry(prefix)
                .or_insert_with(|| prefix.substituted_in(rand::random()));

            if self.try_send_probe(node, dst).await? {
                self.probe_tracker.send(*prefix, dst);
            }
        }

        self.probe_tracker.prune();

        self.try_print_status();

        Ok(())
    }

    async fn try_send_probe(&self, node: &Routing, dst: XorName) -> Result<bool> {
        let public_key_set = if let Ok(public_key_set) = node.public_key_set().await {
            public_key_set
        } else {
            // The node doesn't have BLS keys. Skip.
            return Ok(false);
        };

        // There can be a significant delay between a node being relocated and us receiving the
        // `Relocated` event. Using the current node name instead of the one reported by the last
        // `Relocated` event reduced send errors due to src location mismatch which would cause the
        // section health to appear lower than it actually is.
        let src = node.name().await;

        // The message dst is unique so we use it also as its indentifier.
        let bytes = bincode::serialize(&dst)?;
        let signature_share = node
            .sign_as_elder(&bytes, &public_key_set.public_key())
            .await
            .with_context(|| format!("failed to sign probe by {}", src))?;

        let index = node
            .our_index()
            .await
            .with_context(|| format!("failed to retrieve key share index by {}", src))?;

        let message = ProbeMessage {
            proof_share: ProofShare {
                public_key_set,
                index,
                signature_share,
            },
        };
        let bytes = bincode::serialize(&message)?.into();

        let itinerary = Itinerary {
            src: SrcLocation::Node(src),
            dst: DstLocation::Section(dst),
            aggregation: Aggregation::None,
        };

        match node.send_message(itinerary, bytes, None).await {
            Ok(()) => Ok(true),
            Err(RoutingError::InvalidSrcLocation) => Ok(false), // node name changed
            Err(error) => {
                Err(Error::from(error).context(format!("failed to send probe by {}", src)))
            }
        }
    }

    fn try_print_status(&mut self) {
        if self.print_time.elapsed() > MIN_PRINT_DELAY {
            self.print_time = Instant::now();
            self.print_status();
        }
    }

    fn print_status(&self) {
        let mut num_active = 0;
        let mut num_joining = 0;
        let mut num_relocating = 0;
        let mut num_elders = 0;
        let mut ages = vec![0; 256];
        let mut sections = BTreeMap::new();

        for node in self.nodes.values() {
            match node {
                Node::Joining => {
                    num_joining += 1;
                }
                Node::Joined {
                    age,
                    prefix,
                    is_relocating,
                    elder,
                    ..
                } => {
                    if *is_relocating {
                        num_relocating += 1;
                    } else {
                        num_active += 1;
                    }

                    if elder.is_some() {
                        num_elders += 1;
                    }

                    ages[*age as usize] += 1;
                    *sections.entry(prefix).or_insert(0) += 1;
                }
            }
        }
        // println!(
        //     "{:18} join attempts: {} (successes: {}, failures: {}), drops: {}",
            // self.theme.label.paint("churn:"),
            // self.theme.value.paint(self.stats.join_attempts),
            // self.theme.value.paint(format_args!(
            //     "{} ({:.0}%)",
            //     self.stats.join_successes,
            //     percent(self.stats.join_successes, self.stats.join_attempts)
            // )),
            // failure_style.paint(format_args!(
            //     "{} ({:.0}%)",
            //     self.stats.join_failures,
            //     percent(self.stats.join_failures, self.stats.join_attempts)
            // )),
            // self.theme.value.paint(self.stats.drops)
        // );

        // println!(
            // "{:18} attempts: {}, successes: {}",
            // self.theme.label.paint("relocations:"),
            // self.theme.value.paint(self.stats.relocation_attempts),
            // self.theme.value.paint(format_args!(
            //     "{} ({:.0}%)",
            //     self.stats.relocation_successes,
            //     percent(
            //         self.stats.relocation_successes,
            //         self.stats.relocation_attempts
            //     )
            // ))
        // );

        // println!(
        //     "{:18} promotions: {}, demotions: {}",
        //     self.theme.label.paint("elder churn:"),
        //     self.theme.value.paint(self.stats.promotions),
        //     self.theme.value.paint(self.stats.demotions)
        // );

    }
}

async fn add_node(id: u64, config: Config, event_tx: UnboundedSender<NodeEvent>) {
    let (node, mut events) = match Routing::new(config).await {
        Ok(output) => output,
        Err(error) => {
            let _ = event_tx.send(NodeEvent::JoinFailure {
                id,
                error: error.into(),
            });
            return;
        }
    };

    let _ = event_tx.send(NodeEvent::JoinSuccess { id, node });

    while let Some(event) = events.next().await {
        if event_tx.send(NodeEvent::Routing { id, event }).is_err() {
            break;
        }
    }
}

#[derive(Default, Debug)]
struct Stats {
    join_attempts: usize,
    join_failures: usize,
    join_successes: usize,
    drops: usize,
    relocation_attempts: usize,
    relocation_successes: usize,
    promotions: usize,
    demotions: usize,
}

#[derive(Serialize, Deserialize)]

struct ProbeMessage {
    proof_share: ProofShare,
}

enum ProbeState {
    Pending(SignatureAggregator),
    Success,
}

#[derive(Default)]
struct ProbeTracker {
    sections: BTreeMap<Prefix, LruCache<XorName, ProbeState>>,
}

impl ProbeTracker {
    fn send(&mut self, src: Prefix, dst: XorName) {
        let _ = self
            .sections
            .entry(src)
            .or_insert_with(|| LruCache::with_expiry_duration(PROBE_WINDOW))
            .entry(dst)
            .or_insert_with(|| ProbeState::Pending(SignatureAggregator::new()));
    }

    fn receive(&mut self, dst: &XorName, proof_share: ProofShare) {
        let state = if let Some(state) = self
            .sections
            .values_mut()
            .find_map(|section| section.get_mut(dst))
        {
            state
        } else {
            return;
        };

        let aggregator = match state {
            ProbeState::Pending(aggregator) => aggregator,
            ProbeState::Success => return,
        };

        if aggregator.add(dst, proof_share).is_ok() {
            *state = ProbeState::Success;
        }
    }

    // Returns iterator that yields the numbers of (delivered, sent) probe messages for each section.
    fn status(&self) -> impl Iterator<Item = (&Prefix, usize, usize)> {
        self.sections.iter().map(|(prefix, section)| {
            let success = section
                .peek_iter()
                .filter(|(_, state)| match state {
                    ProbeState::Success => true,
                    ProbeState::Pending(_) => false,
                })
                .count();

            (prefix, success, section.len())
        })
    }

    fn prune(&mut self) {
        let remove: Vec<_> = self
            .sections
            .iter()
            .filter(|(_, section)| section.is_empty())
            .map(|(prefix, _)| *prefix)
            .collect();

        for prefix in remove {
            let _ = self.sections.remove(&prefix);
        }
    }
}

struct Theme {
    label: Style,
    value: Style,
    error: Style,
}

// impl Theme {
//     fn health(&self, health: f64) -> Style {
//         if health > 80.0 {
//             Style::new(Color::Green).bold()
//         } else if health > 50.0 {
//             Style::new(Color::Yellow).bold()
//         } else {
//             Style::new(Color::Red).bold()
//         }
//     }
// }

// impl Default for Theme {
//     fn default() -> Self {
//         Self {
//             label: Style::new(Color::Magenta).bold(),
//             value: Style::new(Color::Blue).bold(),
//             error: Style::new(Color::Red).bold(),
//         }
//     }
// }

fn percent(num: usize, den: usize) -> f64 {
    if den > 0 {
        100.0 * num as f64 / den as f64
    } else {
        0.0
    }
}

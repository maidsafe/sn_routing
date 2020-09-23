// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// HACK: there is a bug in cargo which triggers `unused` warning for things defined here that are
// not used in *all* the test files, but only some: https://github.com/rust-lang/rust/issues/46379
#![allow(unused)]

use anyhow::{bail, format_err, Error, Result};
use futures::future;
use itertools::Itertools;
use sn_routing::{
    event::{Connected, Event},
    EventStream, FullId, NetworkParams, Node, NodeConfig, TransportConfig, MIN_AGE,
};
use std::{
    collections::{BTreeSet, HashSet},
    io::Write,
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Once,
    time::Duration,
};

static LOG_INIT: Once = Once::new();

// -----  TestNode and builder  -----

pub struct TestNodeBuilder {
    config: NodeConfig,
}

impl<'a> TestNodeBuilder {
    pub fn new(config: Option<NodeConfig>) -> Self {
        // We initialise the logger but only once for all tests
        LOG_INIT.call_once(|| {
            env_logger::builder()
                // the test framework will capture the log output and show it only on failure.
                // Run the tests with --nocapture to override.
                .is_test(true)
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "{:.1} {} ({}:{})",
                        record.level(),
                        record.args(),
                        record.file().unwrap_or("<unknown>"),
                        record.line().unwrap_or(0)
                    )
                })
                .init()
        });

        let config = config.unwrap_or_else(NodeConfig::default);

        Self { config }
    }

    pub fn first(mut self) -> Self {
        self.config.first = true;
        self
    }

    pub fn with_contact(mut self, contact: SocketAddr) -> Self {
        let mut contacts = HashSet::default();
        contacts.insert(contact);
        self.config.transport_config.hard_coded_contacts = contacts;
        self
    }

    pub fn network_params(mut self, params: NetworkParams) -> Self {
        self.config.network_params = params;
        self
    }

    pub fn elder_size(mut self, size: usize) -> Self {
        self.config.network_params.elder_size = size;
        self
    }

    pub fn full_id(mut self, full_id: FullId) -> Self {
        self.config.full_id = Some(full_id);
        self
    }

    pub async fn create(self) -> Result<(Node, EventStream)> {
        // make sure we set 127.0.0.1 as the IP if was not set
        let config = if self.config.transport_config.ip.is_none() {
            let mut config = self.config;
            config.transport_config.ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            config
        } else {
            self.config
        };

        Ok(Node::new(config).await?)
    }
}

pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Expect that the next event raised by the node matches the given pattern.
/// Errors if no event, or an event that does not match the pattern is raised.
#[macro_export]
macro_rules! expect_next_event {
    ($node:expr, $pattern:pat) => {
        match tokio::time::timeout($crate::utils::TIMEOUT, $node.next()).await {
            Ok(Some($pattern)) => Ok(()),
            Ok(other) => Err(anyhow::format_err!(
                "Expecting {}, got {:?}",
                stringify!($pattern),
                other
            )),
            Err(_) => Err(anyhow::format_err!(
                "Timeout when expecting {}",
                stringify!($pattern)
            )),
        }
    };
}

/// Create the given number of nodes and wait until they all connect.
pub async fn create_connected_nodes(
    count: usize,
    network_params: NetworkParams,
) -> Result<Vec<(Node, EventStream)>> {
    let mut nodes = vec![];

    // Create the first node
    let (node, mut event_stream) = TestNodeBuilder::new(None)
        .first()
        .network_params(network_params)
        .create()
        .await?;
    expect_next_event!(event_stream, Event::Connected(Connected::First))?;
    expect_next_event!(event_stream, Event::PromotedToElder)?;

    let bootstrap_contact = node.our_connection_info().await?;

    nodes.push((node, event_stream));

    // Create the other nodes bootstrapping off the first node.
    let other_nodes = (1..count).map(|_| async {
        let (node, mut event_stream) = TestNodeBuilder::new(None)
            .network_params(network_params)
            .with_contact(bootstrap_contact)
            .create()
            .await?;

        expect_next_event!(event_stream, Event::Connected(Connected::First))?;

        Ok::<_, Error>((node, event_stream))
    });

    for result in future::join_all(other_nodes).await {
        nodes.push(result?);
    }

    // Wait until the first node receives `InfantJoined` event for all the other nodes.
    let mut not_joined = HashSet::new();
    for (node, _) in &nodes[1..] {
        let _ = not_joined.insert(node.name().await);
    }

    while let Some(event) = nodes[0].1.next().await {
        if let Event::InfantJoined { name, age } = event {
            assert_eq!(age, MIN_AGE);
            let _ = not_joined.remove(&name);
        }

        if not_joined.is_empty() {
            break;
        }
    }

    assert!(
        not_joined.is_empty(),
        "Event::InfantJoined not received for: {:?}",
        not_joined
    );

    Ok(nodes)
}

pub async fn verify_invariants_for_node(node: &Node, elder_size: usize) -> Result<()> {
    let our_name = node.name().await;
    assert!(node.matches_our_prefix(&our_name).await?);

    let our_prefix = node
        .our_prefix()
        .await
        .ok_or_else(|| format_err!("Failed to get node's prefix"))?;

    let our_section_elders: BTreeSet<_> = node
        .our_section()
        .await
        .ok_or_else(|| format_err!("Failed to get node's prefix"))?
        .elders
        .keys()
        .copied()
        .collect();

    if !our_prefix.is_empty() {
        assert!(
            our_section_elders.len() >= elder_size,
            "{}({:b}) Our section is below the minimum size ({}/{})",
            our_name,
            our_prefix,
            our_section_elders.len(),
            elder_size,
        );
    }

    if let Some(name) = our_section_elders
        .iter()
        .find(|name| !our_prefix.matches(name))
    {
        bail!(
            "{}({:b}) A name in our section doesn't match its prefix: {}",
            our_name,
            our_prefix,
            name,
        );
    }

    if !node.is_elder().await {
        return Ok(());
    }

    let neighbour_sections = node.neighbour_sections().await;

    if let Some(compatible_prefix) = neighbour_sections
        .iter()
        .map(|info| &info.prefix)
        .find(|prefix| prefix.is_compatible(&our_prefix))
    {
        bail!(
            "{}({:b}) Our prefix is compatible with one of the neighbour prefixes: {:?} (neighbour_sections: {:?})",
            our_name,
            our_prefix,
            compatible_prefix,
            neighbour_sections,
        );
    }

    if let Some(info) = neighbour_sections
        .iter()
        .find(|info| info.elders.len() < elder_size)
    {
        bail!(
            "{}({:b}) A neighbour section {:?} is below the minimum size ({}/{}) (neighbour_sections: {:?})",
            our_name,
            our_prefix,
            info.prefix,
            info.elders.len(),
            elder_size,
            neighbour_sections,
        );
    }

    for info in &neighbour_sections {
        if let Some(name) = info.elders.keys().find(|name| !info.prefix.matches(name)) {
            bail!(
                "{}({:b}) A name in a section doesn't match its prefix: {:?}, {:?}",
                our_name,
                our_prefix,
                name,
                info.prefix,
            );
        }
    }

    let non_neighbours: Vec<_> = neighbour_sections
        .iter()
        .map(|info| &info.prefix)
        .filter(|prefix| !our_prefix.is_neighbour(prefix))
        .collect();
    if !non_neighbours.is_empty() {
        bail!(
            "{}({:b}) Some of our known sections aren't neighbours of our section: {:?}",
            our_name,
            our_prefix,
            non_neighbours,
        );
    }

    let all_neighbours_covered = {
        (0..our_prefix.bit_count()).all(|i| {
            our_prefix
                .with_flipped_bit(i as u8)
                .is_covered_by(neighbour_sections.iter().map(|info| &info.prefix))
        })
    };
    if !all_neighbours_covered {
        bail!(
            "{}({:b}) Some neighbours aren't fully covered by our known sections: {:?}",
            our_name,
            our_prefix,
            iter::once(our_prefix)
                .chain(neighbour_sections.iter().map(|info| info.prefix))
                .format(", ")
        );
    }

    Ok(())
}

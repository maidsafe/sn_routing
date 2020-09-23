// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use anyhow::{bail, ensure, format_err, Result};
use itertools::Itertools;
use sn_routing::{EventStream, FullId, Node, NodeConfig, TransportConfig};
use std::{
    collections::{BTreeSet, HashSet},
    io::Write,
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Once,
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

    #[allow(dead_code)]
    pub fn elder_size(mut self, size: usize) -> Self {
        self.config.network_params.elder_size = size;
        self
    }

    #[allow(dead_code)]
    pub fn recommended_section_size(mut self, size: usize) -> Self {
        self.config.network_params.recommended_section_size = size;
        self
    }

    #[allow(dead_code)]
    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.config.transport_config = config;
        self
    }

    #[allow(dead_code)]
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

/// Expect that the next event raised by the node matches the given pattern.
/// Errors if no event, or an event that does not match the pattern is raised.
#[macro_export]
macro_rules! expect_next_event {
    ($node:expr, $pattern:pat) => {
        match tokio::time::timeout(std::time::Duration::from_secs(10), $node.next()).await {
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

#[allow(dead_code)]
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
        ensure!(
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

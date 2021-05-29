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
use ed25519_dalek::Keypair;
use futures::future;
use itertools::Itertools;
use sn_routing::{
    Config, Event, EventStream, NodeElderChange, Routing, SectionAuthorityProviderUtils,
    TransportConfig, MIN_AGE,
};
use std::{
    collections::{BTreeSet, HashSet},
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Once,
    time::Duration,
};
use tracing_subscriber::EnvFilter;
use xor_name::Prefix;

static LOG_INIT: Once = Once::new();

pub async fn create_node(mut config: Config) -> Result<(Routing, EventStream)> {
    // We initialise the logger but only once for all tests
    LOG_INIT.call_once(|| {
        tracing_subscriber::fmt()
            // NOTE: comment out this line for more compact (but less readable) log output.
            .pretty()
            .with_env_filter(EnvFilter::from_default_env())
            .with_target(false)
            // the test framework will capture the log output and show it only on failure.
            // Run the tests with --nocapture to override.
            .with_test_writer()
            .init()
    });

    // make sure we set 127.0.0.1 as the IP if was not set
    if config.transport_config.local_ip.is_none() {
        config.transport_config.local_ip = Some(Ipv4Addr::LOCALHOST.into());
    }

    Ok(Routing::new(config).await?)
}

pub fn config_with_contact(contact: SocketAddr) -> Config {
    let mut config = Config::default();
    config.transport_config.hard_coded_contacts = iter::once(contact).collect();
    config
}

// Note: setting the timeout quite high, so that if it triggers it mostly likely indicates an
// actual error rather than the test just being slow.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Assert that the next event in the event stream matches the given pattern.
/// Fails if no event, or an event that does not match the pattern is raised within `TIMEOUT`.
#[macro_export]
macro_rules! assert_next_event {
    ($event_stream:expr, $pattern:pat $(if $cond:expr)?) => {
        match tokio::time::timeout($crate::utils::TIMEOUT, $event_stream.next()).await {
            Ok(Some($pattern)) $(if $cond)? => {}
            Ok(other) => panic!("Expecting {}, got {:?}", stringify!($pattern), other),
            Err(_) => panic!("Timeout when expecting {}", stringify!($pattern)),
        }
    };
}

/// Assert that at least one event in the event stream matches the given pattern.
/// Fails if no event matching the pattern is raised within `TIMEOUT`.
#[macro_export]
macro_rules! assert_event {
    ($event_stream:expr, $pattern:pat $(if $cond:expr)?) => {
        loop {
            match tokio::time::timeout($crate::utils::TIMEOUT, $event_stream.next()).await {
                Ok(Some($pattern)) $(if $cond)? => break,
                Ok(other) => tracing::trace!("Received {:?}", other),
                Err(_) => panic!("Timeout when expecting {}", stringify!($pattern)),
            }
        }
    };
}

/// Create the given number of nodes and wait until they all connect.
pub async fn create_connected_nodes(count: usize) -> Result<Vec<(Routing, EventStream)>> {
    let mut nodes = vec![];

    // Create the first node
    let (node, mut event_stream) = create_node(Config {
        first: true,
        ..Default::default()
    })
    .await?;
    assert_next_event!(event_stream, Event::EldersChanged { .. });

    let bootstrap_contact = node.our_connection_info();

    nodes.push((node, event_stream));

    // Create the other nodes bootstrapping off the first node.
    let other_nodes = (1..count).map(|_| create_node(config_with_contact(bootstrap_contact)));

    for node in future::try_join_all(other_nodes).await? {
        nodes.push(node);
    }

    // Wait until the first node receives `MemberJoined` event for all the other
    // nodes.
    let mut joined_count = 1;

    while let Some(event) = nodes[0].1.next().await {
        if let Event::MemberJoined { name, .. } = event {
            joined_count += 1
        }

        if joined_count == nodes.len() {
            break;
        }
    }

    assert_eq!(joined_count, nodes.len());

    Ok(nodes)
}

pub async fn verify_invariants_for_node(node: &Routing, elder_size: usize) -> Result<()> {
    let our_name = node.name().await;
    assert!(node.matches_our_prefix(&our_name).await);

    let our_prefix = node.our_prefix().await;
    let our_section_elders: BTreeSet<_> = node.our_section().await.names();

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

    let other_sections = node.other_sections().await;

    if let Some(compatible_prefix) = other_sections
        .iter()
        .map(|info| &info.prefix)
        .find(|prefix| prefix.is_compatible(&our_prefix))
    {
        bail!(
            "{}({:b}) Our prefix is compatible with one of the other prefixes: {:?} (other_sections: {:?})",
            our_name,
            our_prefix,
            compatible_prefix,
            other_sections,
        );
    }

    if let Some(info) = other_sections
        .iter()
        .find(|info| info.elder_count() < elder_size)
    {
        bail!(
            "{}({:b}) An other section {:?} is below the minimum size ({}/{}) (other_sections: {:?})",
            our_name,
            our_prefix,
            info.prefix,
            info.elder_count(),
            elder_size,
            other_sections,
        );
    }

    for info in &other_sections {
        if let Some(name) = info.names().iter().find(|&name| !info.prefix.matches(name)) {
            bail!(
                "{}({:b}) A name in a section doesn't match its prefix: {:?}, {:?}",
                our_name,
                our_prefix,
                name,
                info.prefix,
            );
        }
    }

    let address_space_covered = Prefix::default().is_covered_by(
        iter::once(&our_prefix).chain(other_sections.iter().map(|info| &info.prefix)),
    );

    if !address_space_covered {
        bail!(
            "{}({:b}) Known sections don't fully cover the whole address space: {:?}",
            our_name,
            our_prefix,
            iter::once(our_prefix)
                .chain(other_sections.iter().map(|info| info.prefix))
                .format(", ")
        );
    }

    Ok(())
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use anyhow::{Error, Result};
use ed25519_dalek::Keypair;
use futures::future;
use sn_routing::{Config, Event, ELDER_SIZE};
use std::collections::HashSet;
use tokio::time;
use utils::*;

#[tokio::test]
async fn test_genesis_node() -> Result<()> {
    let keypair = Keypair::generate(&mut rand::thread_rng());
    let pub_key = keypair.public;
    let (node, mut event_stream) = create_node(Config {
        first: true,
        keypair: Some(keypair),
        ..Default::default()
    })
    .await?;

    assert_eq!(pub_key, node.public_key().await);

    assert_next_event!(event_stream, Event::PromotedToElder);

    assert!(node.is_elder().await);

    Ok(())
}

#[tokio::test]
async fn test_node_bootstrapping() -> Result<()> {
    let (genesis_node, mut event_stream) = create_node(Config {
        first: true,
        ..Default::default()
    })
    .await?;

    // spawn genesis node events listener
    let genesis_handler = tokio::spawn(async move {
        assert_next_event!(event_stream, Event::PromotedToElder);
        assert_next_event!(event_stream, Event::MemberJoined { .. });
        // TODO: we should expect `EldersChanged` too.
        // assert_next_event!(event_stream, Event::EldersChanged { .. });
    });

    // bootstrap a second node with genesis
    let genesis_contact = genesis_node.our_connection_info().await?;
    let (node1, _event_stream) = create_node(config_with_contact(genesis_contact)).await?;

    // just await for genesis node to finish receiving all events
    genesis_handler.await?;

    let elder_size = 2;
    verify_invariants_for_node(&genesis_node, elder_size).await?;
    verify_invariants_for_node(&node1, elder_size).await?;

    Ok(())
}

#[tokio::test]
async fn test_startup_section_bootstrapping() -> Result<()> {
    // Create the genesis node.
    let (genesis_node, mut event_stream) = create_node(Config {
        first: true,
        ..Default::default()
    })
    .await?;
    let other_node_count = ELDER_SIZE - 1;

    // Then add more nodes to form a section. Because there is only `ELDER_SIZE` nodes in total,
    // we expect every one to be promoted to elder.
    let genesis_contact = genesis_node.our_connection_info().await?;
    let nodes_joining_tasks = (0..other_node_count).map(|_| async {
        let (node, mut event_stream) = create_node(config_with_contact(genesis_contact)).await?;
        assert_event!(event_stream, Event::PromotedToElder);
        Ok::<_, Error>(node)
    });
    let other_nodes = future::try_join_all(nodes_joining_tasks).await?;

    // Keep track of the joined nodes the genesis node knows about.
    let mut joined_names = HashSet::new();

    // Keep listening to the events from the genesis node until it becomes aware of all the other
    // nodes in the section.
    while let Some(event) = time::timeout(TIMEOUT, event_stream.next()).await? {
        let _ = match event {
            Event::MemberJoined { name, .. } => joined_names.insert(name),
            Event::MemberLeft { name, .. } => joined_names.remove(&name),
            _ => false,
        };

        let actual_names: HashSet<_> = future::join_all(other_nodes.iter().map(|node| node.name()))
            .await
            .into_iter()
            .collect();

        if joined_names == actual_names {
            return Ok(());
        }
    }

    panic!("event stream unexpectedly closed")
}

// Test that the first `ELDER_SIZE` nodes in the network are promoted to elders.
#[tokio::test]
async fn test_startup_elders() -> Result<()> {
    let mut nodes = create_connected_nodes(ELDER_SIZE).await?;

    future::join_all(nodes.iter_mut().map(|(node, stream)| async move {
        if node.is_elder().await {
            return;
        }

        assert_event!(stream, Event::PromotedToElder)
    }))
    .await;

    Ok(())
}

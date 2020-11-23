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
    let (genesis_node, mut event_stream) = create_node(Config {
        first: true,
        ..Default::default()
    })
    .await?;
    let other_node_count = ELDER_SIZE - 1;

    // spawn genesis node events listener
    let genesis_handler = tokio::spawn(async move {
        let mut joined_nodes = vec![];
        // expect events for all nodes
        while let Some(event) = event_stream.next().await {
            if let Event::MemberJoined { name, .. } = event {
                joined_nodes.push(name)
            }

            if joined_nodes.len() == other_node_count {
                break;
            }
        }

        joined_nodes
    });

    // bootstrap several nodes with genesis to form a section
    let genesis_contact = genesis_node.our_connection_info().await?;
    let nodes_joining_tasks: Vec<_> = (0..other_node_count)
        .map(|_| async {
            let (node, mut event_stream) =
                create_node(config_with_contact(genesis_contact)).await?;

            // During the startup phase, joining nodes are instantly relocated.
            assert_next_event!(event_stream, Event::RelocationStarted { .. });
            assert_next_event!(event_stream, Event::Relocated { .. });

            Ok::<_, Error>(node)
        })
        .collect();

    let nodes = future::try_join_all(nodes_joining_tasks).await?;

    // just await for genesis node to finish receiving all events
    let joined_nodes = genesis_handler.await?;

    for node in nodes {
        let name = node.name().await;

        // assert names of nodes joined match
        assert!(joined_nodes.contains(&name));

        verify_invariants_for_node(&node, ELDER_SIZE).await?;
    }

    Ok(())
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

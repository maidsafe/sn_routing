// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use self::utils::*;
use anyhow::Result;

use ed25519_dalek::Keypair;

use sn_routing::{Config, Event, XorName, ELDER_SIZE};
use std::iter;

#[tokio::test]
async fn test_node_drop() -> Result<()> {
    // NOTE: create at least 3 nodes, so when one is dropped the remaining ones still form a
    // majority and the `Offline` votes accumulate.
    let mut nodes = create_connected_nodes(3).await?;

    for (_, events) in &mut nodes[1..] {
        assert_event!(events, Event::PromotedToElder);
    }

    // Wait for the DKG(s) to complete, to make sure there are no more messages being exchanged
    // when we drop the node. This is to verify the lost peer detection works even if there is no
    // network traffic.
    let node_count = nodes.len();
    for (node, events) in &mut nodes {
        if node.our_elders().await.len() == node_count {
            continue;
        }

        assert_event!(events, Event::EldersChanged { elders, .. } if elders.len() == node_count);
    }

    // Drop one node
    let dropped_node = nodes.remove(1).0;
    let dropped_name = dropped_node.name().await;
    let dropped_addr = dropped_node.our_connection_info().await?;
    drop(dropped_node);

    log::info!("Dropped {} at {}", dropped_name, dropped_addr);

    for (_, events) in &mut nodes {
        assert_event!(events, Event::MemberLeft { name, .. } if name == dropped_name)
    }

    Ok(())
}

// Test a node rejoin after dropped with the same keypair will be accepted with new name.
#[tokio::test]
async fn test_node_rejoin() -> Result<()> {
    let mut nodes = create_connected_nodes(ELDER_SIZE).await?;
    for (_, events) in &mut nodes[1..] {
        assert_event!(events, Event::PromotedToElder);
    }

    // Add a target node then drop it.
    let keypair = Keypair::generate(&mut rand::thread_rng());
    let target_name = XorName(keypair.public.to_bytes());
    let keypair_bytes = keypair.to_bytes();
    let mut config = Config {
        keypair: Some(keypair),
        ..Default::default()
    };
    config.transport_config.hard_coded_contacts =
        iter::once(nodes[0].0.our_connection_info().await?).collect();

    let (node, _) = create_node(config).await?;
    for (_, events) in &mut nodes {
        assert_event!(events, Event::MemberJoined { .. })
    }
    drop(node);
    for (_, events) in &mut nodes {
        assert_event!(events, Event::MemberLeft { .. })
    }

    // Rejoin the target node with the same config.
    let keypair = Keypair::from_bytes(&keypair_bytes)?;
    let mut config = Config {
        keypair: Some(keypair),
        ..Default::default()
    };
    config.transport_config.hard_coded_contacts =
        iter::once(nodes[0].0.our_connection_info().await?).collect();
    let (node, _) = create_node(config).await?;
    for (_, events) in &mut nodes {
        assert_event!(events, Event::MemberJoined { .. })
    }

    assert!(node.name().await != target_name);

    Ok(())
}

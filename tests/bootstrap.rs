// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use anyhow::{Error, Result};
use futures::future::join_all;
use sn_routing::{
    event::{Connected, Event},
    rng::MainRng,
    FullId, Node,
};
use utils::*;
use xor_name::XorName;

#[tokio::test]
async fn test_genesis_node() -> Result<()> {
    let full_id = FullId::gen(&mut MainRng::default());
    let (node, mut event_stream) = TestNodeBuilder::new(None)
        .first()
        .full_id(full_id.clone())
        .create()
        .await?;

    assert_eq!(*full_id.public_id(), node.id().await);

    expect_next_event!(event_stream, Event::Connected(Connected::First))?;
    expect_next_event!(event_stream, Event::PromotedToElder)?;

    assert!(node.is_elder().await);

    Ok(())
}

#[tokio::test]
async fn test_node_bootstrapping() -> Result<()> {
    let (genesis_node, mut event_stream) = TestNodeBuilder::new(None).first().create().await?;

    // spawn genesis node events listener
    let genesis_handler = tokio::spawn(async move {
        expect_next_event!(event_stream, Event::Connected(Connected::First))?;
        expect_next_event!(event_stream, Event::PromotedToElder)?;
        expect_next_event!(event_stream, Event::InfantJoined { age: 4, name: _ })?;
        // TODO: Should we expect EldersChanged event too ??
        // expect_next_event!(event_stream, Event::EldersChanged { .. })?;
        Ok::<(), Error>(())
    });

    // bootstrap a second node with genesis
    let genesis_contact = genesis_node.our_connection_info().await?;
    let (node1, mut event_stream) = TestNodeBuilder::new(None)
        .with_contact(genesis_contact)
        .create()
        .await?;

    expect_next_event!(event_stream, Event::Connected(Connected::First))?;

    // just await for genesis node to finish receiving all events
    genesis_handler.await??;

    let elder_size = 2;
    verify_invariants_for_node(&genesis_node, elder_size).await?;
    verify_invariants_for_node(&node1, elder_size).await?;

    Ok(())
}

#[tokio::test]
async fn test_section_bootstrapping() -> Result<()> {
    let num_of_nodes = 7;
    let (genesis_node, mut event_stream) = TestNodeBuilder::new(None)
        .elder_size(num_of_nodes)
        .first()
        .create()
        .await?;

    // spawn genesis node events listener
    let genesis_handler = tokio::spawn(async move {
        // expect events for all nodes
        let mut joined_nodes = Vec::default();
        while let Some(event) = event_stream.next().await {
            match event {
                Event::InfantJoined { age, name } => {
                    assert_eq!(age, 4);
                    joined_nodes.push(name);
                }
                _other => {}
            }

            if joined_nodes.len() == num_of_nodes {
                break;
            }
        }

        Ok::<Vec<XorName>, Error>(joined_nodes)
    });

    // bootstrap several nodes with genesis to form a section
    let genesis_contact = genesis_node.our_connection_info().await?;
    let mut nodes_joining_tasks = Vec::with_capacity(num_of_nodes);
    for _ in 0..num_of_nodes {
        nodes_joining_tasks.push(async {
            let (node, mut event_stream) = TestNodeBuilder::new(None)
                .with_contact(genesis_contact)
                .create()
                .await?;

            expect_next_event!(event_stream, Event::Connected(Connected::First))?;

            Ok::<Node, Error>(node)
        });
    }

    let nodes = join_all(nodes_joining_tasks).await;

    // just await for genesis node to finish receiving all events
    let joined_nodes = genesis_handler.await??;

    for result in nodes {
        let node = result?;
        let name = node.name().await;

        // assert names of nodes joined match
        let found = joined_nodes.iter().find(|n| **n == name);
        assert!(found.is_some());

        verify_invariants_for_node(&node, num_of_nodes).await?;
    }

    Ok(())
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use routing::{
    event::{Connected, Event},
    Error, Result,
};
use utils::*;

#[tokio::test]
async fn test_genesis_node() -> Result<()> {
    let (node, mut event_stream) = TestNodeBuilder::new(None).first().create().await?;

    expect_next_event!(event_stream, Event::Connected(Connected::First))?;
    expect_next_event!(event_stream, Event::PromotedToElder)?;
    assert!(node.is_genesis());
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
        expect_next_event!(event_stream, Event::EldersChanged { .. })?;
        Ok::<(), Error>(())
    });

    // bootstrap a second node with genesis
    let genesis_contact = genesis_node.our_connection_info().await?;
    let (node1, mut event_stream) = TestNodeBuilder::new(None)
        .with_contact(genesis_contact)
        .create()
        .await?;

    assert!(!node1.is_genesis());
    expect_next_event!(event_stream, Event::Connected(Connected::First))?;

    // just await for genesis node to finish receiving all events
    genesis_handler
        .await
        .map_err(|err| Error::Unexpected(format!("{}", err)))??;

    let elder_size = 2;
    verify_invariants_for_node(&genesis_node, elder_size).await?;
    verify_invariants_for_node(&node1, elder_size).await?;

    Ok(())
}

#[tokio::test]
async fn test_section_bootstrapping() -> Result<()> {
    let (genesis_node, mut event_stream) = TestNodeBuilder::new(None).first().create().await?;
    let num_of_nodes = 5;

    // spawn genesis node events listener
    let genesis_handler = tokio::spawn(async move {
        // TODO: expect events for all nodes
        expect_next_event!(event_stream, Event::InfantJoined { age: 4, name: _ })?;
        //expect_next_event!(event_stream, Event::EldersChanged { .. })?;
        Ok(())
    });

    let genesis_contact = genesis_node.our_connection_info().await?;
    // bootstrap several nodes with genesis to form a section
    for _ in 0..num_of_nodes {
        let (_, mut event_stream) = TestNodeBuilder::new(None)
            .with_contact(genesis_contact)
            .create()
            .await?;

        expect_next_event!(event_stream, Event::Connected(Connected::First))?;
    }

    // just await for genesis node to finish receiving all events
    genesis_handler
        .await
        .map_err(|err| Error::Unexpected(format!("{}", err)))?
}

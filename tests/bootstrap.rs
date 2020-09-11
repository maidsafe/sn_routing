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
use tokio::sync::mpsc;
use utils::*;

#[tokio::test]
async fn test_genesis_node() -> Result<()> {
    let mut node = TestNode::builder(None).first().create().await?;

    expect_next_event!(node, Event::Connected(Connected::First))?;
    expect_next_event!(node, Event::PromotedToElder)?;

    Ok(())
}

#[tokio::test]
async fn test_node_bootstrapping() -> Result<()> {
    let mut genesis_node = TestNode::builder(None).first().create().await?;
    let genesis_contact = genesis_node.endpoint().await?;
    let (mut tx, mut rx) = mpsc::channel(1);

    // spawn genesis node events listener
    tokio::spawn(async move {
        expect_next_event!(genesis_node, Event::Connected(Connected::First))?;
        expect_next_event!(genesis_node, Event::PromotedToElder)?;
        expect_next_event!(genesis_node, Event::InfantJoined { .. })?;
        // just notify that it received the expected events
        tx.send(())
            .await
            .map_err(|err| Error::Unexpected(format!("{}", err)))
    });

    // bootstrap a second node with genesis
    let mut bootstrapping_node = TestNode::builder(None)
        .with_contact(genesis_contact)
        .create()
        .await?;

    expect_next_event!(bootstrapping_node, Event::Connected(Connected::First))?;

    // just await for genesis node to confirm that received all events
    match rx.recv().await {
        Some(()) => Ok(()),
        None => Err(Error::Unexpected(
            "First node didn't received all events".to_string(),
        )),
    }
}

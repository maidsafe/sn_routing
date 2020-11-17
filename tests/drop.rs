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
use sn_routing::Event;

#[tokio::test]
async fn test_node_drop() -> Result<()> {
    // NOTE: create at least 3 nodes, so when one is dropped the remaining ones still form a
    // majority and the `Offline` votes accumulate.
    let mut nodes = create_connected_nodes(3).await?;

    // We are in the startup phase, so the second and third node are instantly relocated.
    // Let's wait until they re-join.
    for (_, events) in &mut nodes[1..] {
        assert_next_event!(events, Event::RelocationStarted { .. });
        assert_next_event!(events, Event::Relocated { .. });
    }

    // Wait for the DKG(s) to complete, to make sure there are no more messages being exchanged
    // when we drop the node. This is to verify the lost peer detection works even if there is no
    // network traffic.
    let node_count = nodes.len();
    for (node, events) in &mut nodes {
        if node.our_elders().await.len() == node_count {
            continue;
        }

        let mut received = false;
        while let Some(event) = events.next().await {
            match event {
                Event::EldersChanged { elders, .. } if elders.len() == node_count => {
                    received = true;
                    break;
                }
                _ => {}
            }
        }

        assert!(
            received,
            "event stream closed before receiving Event::EldersChanged"
        );
    }

    // Drop one node
    let dropped_node = nodes.remove(1).0;
    let dropped_name = dropped_node.name().await;
    let dropped_addr = dropped_node.our_connection_info().await?;
    drop(dropped_node);

    log::info!("Dropped {} at {}", dropped_name, dropped_addr);

    while let Some(event) = nodes[0].1.next().await {
        match event {
            Event::MemberLeft { name, .. } if name == dropped_name => return Ok(()),
            _ => {}
        }
    }

    panic!("event stream closed before receiving Event::MemberLeft");
}

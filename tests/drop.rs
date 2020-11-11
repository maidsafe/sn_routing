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
use bytes::Bytes;
use sn_routing::{DstLocation, Event, SrcLocation};
use tokio::time;

#[tokio::test]
async fn test_node_drop() -> Result<()> {
    let mut nodes = create_connected_nodes(2).await?;

    // We are in the startup phase, so the second node is instantly relocated. Let's wait until it
    // re-joins.
    assert_next_event!(nodes[1].1, Event::RelocationStarted { .. });
    assert_next_event!(nodes[1].1, Event::Relocated { .. });

    // Wait for the DKG(s) to complete, to make sure there are no more messages being exchanged.
    let node_count = nodes.len();
    for (node, events) in &mut nodes {
        if node.our_elders().await.len() == node_count {
            continue;
        }

        while let Some(event) = events.next().await {
            match event {
                Event::EldersChanged { elders, .. } if elders.len() == node_count => continue,
                _ => {}
            }
        }

        panic!("event stream closed before receiving Event::EldersChanged");
    }

    // Drop one node
    let dropped_name = nodes.remove(1).0.name().await;

    // Send a message to the dropped node. This will cause us to detect it as gone.
    let src = SrcLocation::Node(nodes[0].0.name().await);
    let dst = DstLocation::Node(dropped_name);
    nodes[0]
        .0
        .send_message(src, dst, Bytes::from_static(b"ping"))
        .await?;

    let expect_event = async {
        while let Some(event) = nodes[0].1.next().await {
            match event {
                Event::MemberLeft { name, .. } if name == dropped_name => return,
                _ => {}
            }
        }

        panic!("event stream closed before receiving Event::MemberLeft");
    };

    time::timeout(TIMEOUT, expect_event).await?;

    Ok(())
}

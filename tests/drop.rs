// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use self::utils::*;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use sn_messaging::{Aggregation, DstLocation, Itinerary, SrcLocation};
use sn_routing::{Event, NodeElderChange};

#[tokio::test]
async fn test_node_drop() -> Result<()> {
    // NOTE: create at least 4 nodes, so when one is dropped the remaining ones still form a
    // supermajority and the `Offline` proposals reach agreement.
    let mut nodes = create_connected_nodes(4).await?;

    for (_, events) in &mut nodes[1..] {
        assert_event!(
            events,
            Event::EldersChanged {
                self_status_change: NodeElderChange::Promoted,
                ..
            }
        );
    }

    // Wait for the DKG(s) to complete, to make sure there are no more messages being exchanged
    // when we drop the node. This is to verify the lost peer detection works even if there is no
    // network traffic.
    let node_count = nodes.len();
    for (node, events) in &mut nodes {
        if node.our_elders().await.len() == node_count {
            continue;
        }

        assert_event!(events, Event::EldersChanged { elders, .. } if (elders.remaining.len() + elders.added.len()) == node_count);
    }

    // Drop one node
    let dropped_node = nodes.remove(1).0;
    let dropped_name = dropped_node.name().await;
    let dropped_addr = dropped_node.our_connection_info();
    drop(dropped_node);

    tracing::info!("Dropped {} at {}", dropped_name, dropped_addr);

    //  A failed send_message from any node should
    // trigger voting by all nodes
    {
        let (node, _) = nodes.iter().last().ok_or_else(|| anyhow!("Missing Node"))?;
        let itinerary = Itinerary {
            src: SrcLocation::Node(node.name().await),
            dst: DstLocation::Node(dropped_name),
            aggregation: Aggregation::None,
        };
        node.send_message(itinerary, Bytes::from(b"hello".to_vec()), None)
            .await?
    }

    for (_, events) in &mut nodes {
        assert_event!(events, Event::MemberLeft { name, .. } if name == dropped_name)
    }

    Ok(())
}

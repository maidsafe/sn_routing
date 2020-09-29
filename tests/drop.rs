// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use self::utils::*;
use anyhow::{format_err, Result};
use bytes::Bytes;
use sn_routing::{event::Event, DstLocation, Error, NetworkParams, SrcLocation};
use tokio::time;

#[tokio::test]
async fn test_node_drop() -> Result<()> {
    let mut nodes = create_connected_nodes(2, NetworkParams::default()).await?;

    // Drop one node
    let dropped_name = nodes.remove(1).0.name().await;

    // Send a message to the dropped node. This will cause us to detect it as gone.
    let src = SrcLocation::Node(nodes[0].0.name().await);
    let dst = DstLocation::Node(dropped_name);
    nodes[0]
        .0
        .send_message(src, dst, Bytes::from_static(b"ping"))
        .await
        .or_else(|error| match error {
            Error::FailedSend => Ok(()),
            _ => Err(error),
        })?;

    let expect_event = async {
        while let Some(event) = nodes[0].1.next().await {
            if let Event::MemberLeft { name, .. } = event {
                assert_eq!(
                    name, dropped_name,
                    "unexpected dropped node {} (expecting {})",
                    name, dropped_name
                );
                return Ok(());
            }
        }

        Err(format_err!(
            "Event::MemberLeft not received for {}",
            dropped_name
        ))
    };

    time::timeout(TIMEOUT, expect_event).await?
}

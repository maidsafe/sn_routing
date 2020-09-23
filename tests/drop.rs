// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use self::utils::*;
use anyhow::{ensure, format_err, Result};
use sn_routing::{event::Event, NetworkParams};
use tokio::time;

#[tokio::test]
async fn test_node_drop() -> Result<()> {
    let mut nodes = create_connected_nodes(2, NetworkParams::default()).await?;

    // Drop one node
    let dropped_name = nodes.remove(1).0.name().await;
    let expect_event = async {
        while let Some(event) = nodes[0].1.next().await {
            if let Event::MemberLeft { name, .. } = event {
                ensure!(
                    name == dropped_name,
                    "unexpected dropped node {} (expecting {})",
                    name,
                    dropped_name
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

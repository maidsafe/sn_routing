// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use bytes::Bytes;
use qp2p::QuicP2p;
use sn_routing::{
    event::{Connected, Event},
    DstLocation, Error, Result, SrcLocation,
};
use utils::*;

#[tokio::test]
async fn test_messages_client_node() -> Result<()> {
    let msg = b"hello!";
    let response = b"good bye!";

    let (node, mut event_stream) = TestNodeBuilder::new(None).first().create().await?;

    // spawn node events listener
    let node_handler = tokio::spawn(async move {
        while let Some(event) = event_stream.next().await {
            match event {
                Event::ClientMessageReceived {
                    content, mut send, ..
                } => {
                    assert_eq!(content, Bytes::from_static(msg));
                    send.send(Bytes::from_static(response)).await?;
                    break;
                }
                _other => {}
            }
        }
        Ok::<(), Error>(())
    });

    // create a client which sends a message to the node
    let node_addr = node.our_connection_info().await?;
    let mut client = QuicP2p::new()?;
    let (_, conn) = client.connect_to(&node_addr).await?;
    let (_, mut recv) = conn.send(Bytes::from_static(msg)).await?;

    // just await for node to respond to client
    node_handler
        .await
        .map_err(|err| Error::Unexpected(format!("{}", err)))??;

    let resp = recv.next().await?;
    assert_eq!(resp, Bytes::from_static(response));

    Ok(())
}

#[tokio::test]
async fn test_messages_between_nodes() -> Result<()> {
    let msg = b"hello!";
    let response = b"good bye!";

    let (mut node1, mut event_stream) = TestNodeBuilder::new(None).first().create().await?;
    let node1_contact = node1.our_connection_info().await?;
    let node1_name = node1.name().await;

    // spawn node events listener
    let node_handler = tokio::spawn(async move {
        while let Some(event) = event_stream.next().await {
            match event {
                Event::MessageReceived { content, src, .. } => {
                    assert_eq!(content, Bytes::from_static(msg));
                    return Ok(src.to_dst());
                }
                _other => {}
            }
        }
        Err(Error::Unexpected("".to_string()))
    });

    // start a second node which sends a message to the first node
    let (mut node2, mut event_stream) = TestNodeBuilder::new(None)
        .with_contact(node1_contact)
        .create()
        .await?;
    let node2_name = node2.name().await;

    expect_next_event!(event_stream, Event::Connected(Connected::First))?;
    node2
        .send_message(
            SrcLocation::Node(node2_name),
            DstLocation::Node(node1_name),
            Bytes::from_static(msg),
        )
        .await?;

    // just await for node1 to receive message from node2
    let dst = node_handler
        .await
        .map_err(|err| Error::Unexpected(format!("{}", err)))??;

    // send response from node1 to node2
    node1
        .send_message(
            SrcLocation::Node(node1_name),
            dst,
            Bytes::from_static(response),
        )
        .await?;

    // check we received the response message from node1
    while let Some(event) = event_stream.next().await {
        match event {
            Event::MessageReceived { content, src, .. } => {
                assert_eq!(content, Bytes::from_static(response));
                assert_eq!(src, SrcLocation::Node(node1_name));
                break;
            }
            _other => {}
        }
    }

    Ok(())
}

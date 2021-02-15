// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod utils;

use anyhow::{format_err, Result};
use bytes::Bytes;
use qp2p::QuicP2p;
use sn_data_types::Keypair;
use sn_messaging::{
    client::{Message, Query, TransferQuery},
    DstLocation, MessageId, SrcLocation, WireMsg,
};
use sn_routing::{Config, Error, Event, NodeElderChange};
use std::net::{IpAddr, Ipv4Addr};
use utils::*;
use xor_name::XorName;

#[tokio::test]
async fn test_messages_client_node() -> Result<()> {
    let (node, mut event_stream) = create_node(Config {
        first: true,
        ..Default::default()
    })
    .await?;

    // create a client message
    let mut rng = rand::thread_rng();
    let keypair = Keypair::new_ed25519(&mut rng);
    let pk = keypair.public_key();

    let random_xor = XorName::random();
    let id = MessageId(random_xor);
    let message = Message::Query {
        query: Query::Transfer(TransferQuery::GetBalance(pk)),
        id,
        target_section_pk: None,
    };

    let message_clone = message.clone();

    let node_addr = node.our_connection_info();
    // spawn node events listener
    let node_handler = tokio::spawn(async move {
        while let Some(event) = event_stream.next().await {
            match event {
                Event::ClientMessageReceived { msg, user } => {
                    assert_eq!(*msg, message_clone.clone());
                    node.send_message(
                        SrcLocation::Node(node.name().await),
                        DstLocation::EndUser(user),
                        message_clone.clone().serialize()?,
                    )
                    .await?;
                    break;
                }
                _other => {}
            }
        }
        Ok::<(), Error>(())
    });

    // create a client which sends a message to the node
    let mut config = sn_routing::TransportConfig {
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        ..Default::default()
    };
    config.local_ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let client = QuicP2p::with_config(Some(config), &[node_addr], false)?;
    let (client_endpoint, _, mut incoming_messages, _) = client.new_endpoint().await?;
    client_endpoint.connect_to(&node_addr).await?;

    let client_msg_bytes = WireMsg::serialize_client_msg(&message)?;

    client_endpoint
        .send_message(client_msg_bytes, &node_addr)
        .await?;

    // just await for node to respond to client
    node_handler.await??;

    if let Some((_, resp)) = incoming_messages.next().await {
        let expected_bytes = message.serialize()?;
        assert_eq!(resp, expected_bytes);
    }

    Ok(())
}

#[tokio::test]
async fn test_messages_between_nodes() -> Result<()> {
    let msg = b"hello!";
    let response = b"good bye!";

    let (node1, mut event_stream) = create_node(Config {
        first: true,
        ..Default::default()
    })
    .await?;
    let node1_contact = node1.our_connection_info();
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
        Err(format_err!("message not received"))
    });

    // start a second node which sends a message to the first node
    let (node2, mut event_stream) = create_node(config_with_contact(node1_contact)).await?;

    assert_event!(
        event_stream,
        Event::EldersChanged {
            self_status_change: NodeElderChange::Promoted,
            ..
        }
    );

    let node2_name = node2.name().await;

    node2
        .send_message(
            SrcLocation::Node(node2_name),
            DstLocation::Node(node1_name),
            Bytes::from_static(msg),
        )
        .await?;

    // just await for node1 to receive message from node2
    let dst = node_handler.await??;

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
                return Ok(());
            }
            _other => {}
        }
    }

    Err(format_err!("message not received"))
}

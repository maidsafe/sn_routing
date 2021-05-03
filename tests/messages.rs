// Copyright 2021 MaidSafe.net limited.
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
use sn_messaging::client::ProcessMsg;
use sn_messaging::{
    client::{ClientMsg, Query, TransferQuery},
    location::{Aggregation, Itinerary},
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

    let id = MessageId::new();

    // create a client which sends a message to the node
    let mut config = sn_routing::TransportConfig {
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        ..Default::default()
    };
    config.local_ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let node_addr = node.our_connection_info();
    let section_key = *node.section_chain().await.last_key();

    let client = QuicP2p::with_config(Some(config), &[node_addr], false)?;
    let (client_endpoint, _, mut incoming_messages, _) = client.new_endpoint().await?;
    client_endpoint.connect_to(&node_addr).await?;

    let socket_addr = client_endpoint.socket_addr();
    let socketaddr_sig = keypair.sign(&bincode::serialize(&socket_addr)?);
    let registration = sn_messaging::section_info::Message::RegisterEndUserCmd {
        end_user: pk,
        socketaddr_sig,
    };
    let registration_bytes =
        WireMsg::serialize_sectioninfo_msg(&registration, XorName::from(pk), section_key)?;

    client_endpoint
        .send_message(registration_bytes, &node_addr)
        .await?;

    let query = ClientMsg::Process(ProcessMsg::Query {
        query: Query::Transfer(TransferQuery::GetBalance(pk)),
        id,
    });
    let query_clone = query.clone();
    let client_msg_bytes = WireMsg::serialize_client_msg(&query, XorName::from(pk), section_key)?;

    // spawn node events listener
    let node_handler = tokio::spawn(async move {
        while let Some(event) = event_stream.next().await {
            match event {
                Event::ClientMsgReceived { msg, user } => {
                    assert_eq!(*msg, query_clone.clone());
                    node.send_message(
                        Itinerary {
                            src: SrcLocation::Node(node.name().await),
                            dst: DstLocation::EndUser(user),
                            aggregation: Aggregation::None,
                        },
                        query_clone
                            .clone()
                            .serialize(XorName::from(pk), section_key)?,
                        None,
                    )
                    .await?;
                    break;
                }
                _other => println!("{:?}", _other),
            }
        }
        Ok::<(), Error>(())
    });

    client_endpoint
        .send_message(client_msg_bytes, &node_addr)
        .await?;

    // just await for node to respond to client
    node_handler.await??;

    if let Some((_, resp)) = incoming_messages.next().await {
        let expected_bytes = query.serialize(XorName::from(pk), section_key)?;
        assert_eq!(resp, expected_bytes);
    }

    Ok(())
}

#[tokio::test]
#[ignore]
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

    println!("spawning node handler");

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

    println!("node handler spawned");

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

    println!("sending msg..");

    let itinerary = Itinerary {
        src: SrcLocation::Node(node2_name),
        dst: DstLocation::Node(node1_name),
        aggregation: Aggregation::None,
    };

    node2
        .send_message(itinerary, Bytes::from_static(msg), None)
        .await?;

    println!("msg sent");

    // just await for node1 to receive message from node2
    let dst = node_handler.await??;
    println!("Got dst: {:?} (expecting: {}", dst.name(), node2_name);
    println!("sending response from {:?}..", node1_name);

    let itinerary = Itinerary {
        src: SrcLocation::Node(node1_name),
        dst,
        aggregation: Aggregation::None,
    };

    // send response from node1 to node2
    node1
        .send_message(itinerary, Bytes::from_static(response), None)
        .await?;

    println!("checking response received..");

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

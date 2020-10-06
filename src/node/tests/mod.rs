// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO: convert the tests in these module to use the Command paradigm.
#[cfg(feature = "mock")]
mod adult;
#[cfg(feature = "mock")]
mod bootstrapping;
#[cfg(feature = "mock")]
mod elder;
#[cfg(feature = "mock")]
mod utils;

use super::{Approved, Bootstrapping, Comm, Command, NodeInfo, Stage, State};
use crate::{
    consensus::Vote,
    crypto,
    event::Event,
    location::DstLocation,
    messages::{BootstrapResponse, JoinRequest, Message, Variant},
    peer::Peer,
    rng,
    section::{EldersInfo, PeerState},
    ELDER_SIZE, MIN_AGE,
};
use anyhow::Result;
use assert_matches::assert_matches;
use ed25519_dalek::Keypair;
use itertools::Itertools;
use std::{cell::Cell, collections::HashSet, net::SocketAddr};
use tokio::sync::mpsc;
use xor_name::Prefix;

#[tokio::test]
async fn send_bootstrap_request() -> Result<()> {
    let bootstrap_addr = create_addr();
    let (node_info, _) = create_node_info();
    let (state, command) = Bootstrapping::new(None, vec![bootstrap_addr], node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let recipients = assert_matches!(
        command,
        Command::SendBootstrapRequest(recipients) => recipients
    );
    assert_eq!(recipients, [bootstrap_addr]);

    let mut commands = node
        .handle_command(Command::SendBootstrapRequest(recipients))
        .await?
        .into_iter();

    let (recipients, message) = assert_matches!(
        commands.next(),
        Some(Command::SendMessage {
            recipients,
            message, ..
        }) => (recipients, message)
    );
    assert_eq!(recipients, [bootstrap_addr]);

    let message = Message::from_bytes(&message)?;
    assert_matches!(
        message.variant(),
        Variant::BootstrapRequest(name) => assert_eq!(*name, node.name().await)
    );

    assert!(commands.next().is_none());

    Ok(())
}

#[tokio::test]
async fn receive_bootstrap_request() -> Result<()> {
    let comm = create_comm()?;
    let addr = comm.our_connection_info()?;
    let (node_info, _) = create_node_info();
    let state = Approved::first_node(node_info, addr)?;
    let node = Stage::new(state.into(), comm);

    let new_node_keypair = create_keypair();
    let new_node_addr = create_addr();

    let message = Message::single_src(
        &new_node_keypair,
        MIN_AGE,
        DstLocation::Direct,
        Variant::BootstrapRequest(crypto::name(&new_node_keypair.public)),
        None,
        None,
    )?;

    let mut commands = node
        .handle_command(Command::HandleMessage {
            message,
            sender: Some(new_node_addr),
        })
        .await?
        .into_iter();

    let (recipients, message) = assert_matches!(
        commands.next(),
        Some(Command::SendMessage {
            recipients,
            message, ..
        }) => (recipients, message)
    );

    assert_eq!(recipients, [new_node_addr]);

    let message = Message::from_bytes(&message)?;
    assert_matches!(
        message.variant(),
        Variant::BootstrapResponse(BootstrapResponse::Join { .. })
    );

    Ok(())
}

#[tokio::test]
async fn receive_bootstrap_response_join() -> Result<()> {
    let (node_info, _) = create_node_info();
    let (state, _) = Bootstrapping::new(None, vec![create_addr()], node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let (elders_info, elder_keypairs) = create_elders_info();
    let elder_addr = *elders_info
        .elders
        .values()
        .next()
        .expect("elders_info is empty")
        .addr();
    let section_key = bls::SecretKey::random().public_key();

    let message = Message::single_src(
        &elder_keypairs[0],
        MIN_AGE,
        DstLocation::Direct,
        Variant::BootstrapResponse(BootstrapResponse::Join {
            elders_info: elders_info.clone(),
            section_key,
        }),
        None,
        None,
    )?;
    let mut commands = node
        .handle_command(Command::HandleMessage {
            sender: Some(elder_addr),
            message,
        })
        .await?
        .into_iter();

    assert_matches!(commands.next(), Some(Command::Transition(state)) => {
        assert_matches!(*state, State::Joining(_))
    });

    let (recipients, delivery_group_size, message) = assert_matches!(
        commands.next(),
        Some(Command::SendMessage {
            recipients,
            delivery_group_size,
            message,
        }) => (recipients, delivery_group_size, message)
    );
    assert_eq!(delivery_group_size, elders_info.elders.len());
    let expected_recipients: HashSet<_> = elders_info.elders.values().map(Peer::addr).collect();
    let actual_recipients: HashSet<_> = recipients.iter().collect();
    assert_eq!(actual_recipients, expected_recipients);

    let message = Message::from_bytes(&message)?;
    let payload = assert_matches!(message.variant(), Variant::JoinRequest(payload) => payload);
    assert_eq!(payload.section_key, section_key);
    assert!(payload.relocate_payload.is_none());

    Ok(())
}

#[tokio::test]
async fn receive_bootstrap_response_rebootstrap() -> Result<()> {
    let (node_info, _) = create_node_info();
    let node_name = node_info.name();
    let (state, _) = Bootstrapping::new(None, vec![create_addr()], node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let old_keypair = create_keypair();
    let old_addr = create_addr();

    let new_addrs: Vec<_> = (0..ELDER_SIZE).map(|_| create_addr()).collect();

    let message = Message::single_src(
        &old_keypair,
        MIN_AGE,
        DstLocation::Direct,
        Variant::BootstrapResponse(BootstrapResponse::Rebootstrap(new_addrs.clone())),
        None,
        None,
    )?;
    let mut commands = node
        .handle_command(Command::HandleMessage {
            sender: Some(old_addr),
            message,
        })
        .await?
        .into_iter();

    let (recipients, delivery_group_size, message) = assert_matches!(
        commands.next(),
        Some(Command::SendMessage {
            recipients,
            delivery_group_size,
            message,
        }) => (recipients, delivery_group_size, message)
    );
    assert_eq!(recipients, new_addrs);
    assert_eq!(delivery_group_size, new_addrs.len());

    let message = Message::from_bytes(&message)?;
    let destination = assert_matches!(message.variant(), Variant::BootstrapRequest(name) => name);
    assert_eq!(*destination, node_name);

    Ok(())
}

#[tokio::test]
async fn receive_join_request() -> Result<()> {
    let (node_info, _) = create_node_info();
    let comm = create_comm()?;
    let addr = comm.our_connection_info()?;
    let state = Approved::first_node(node_info, addr)?;
    let node = Stage::new(state.into(), comm);

    let new_node_keypair = create_keypair();
    let new_node_addr = create_addr();
    let section_key = *node
        .our_history()
        .await
        .expect("node has no section chain")
        .last_key();

    let message = Message::single_src(
        &new_node_keypair,
        MIN_AGE,
        DstLocation::Direct,
        Variant::JoinRequest(Box::new(JoinRequest {
            section_key,
            relocate_payload: None,
        })),
        None,
        None,
    )?;
    let mut commands = node
        .handle_command(Command::HandleMessage {
            sender: Some(new_node_addr),
            message,
        })
        .await?
        .into_iter();

    let vote = assert_matches!(
        commands.next(),
        Some(Command::HandleVote { vote, .. }) => vote
    );
    assert_matches!(
        vote,
        Vote::Online { member_info, previous_name, their_knowledge } => {
            assert_eq!(*member_info.peer.name(), crypto::name(&new_node_keypair.public));
            assert_eq!(*member_info.peer.addr(), new_node_addr);
            assert_eq!(member_info.peer.age(), MIN_AGE);
            assert_eq!(member_info.state, PeerState::Joined);
            assert_eq!(previous_name, None);
            assert_eq!(their_knowledge, None);
        }
    );

    Ok(())
}

// TODO: add more tests here

// Returns unique SocketAddr
fn create_addr() -> SocketAddr {
    thread_local! {
        static NEXT_PORT: Cell<u16> = Cell::new(1000);
    }

    let port = NEXT_PORT.with(|cell| cell.replace(cell.get().wrapping_add(1)));

    ([192, 0, 2, 0], port).into()
}

fn create_node_info() -> (NodeInfo, mpsc::UnboundedReceiver<Event>) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let node_info = NodeInfo::new(create_keypair(), Default::default(), event_tx);
    (node_info, event_rx)
}

fn create_keypair() -> Keypair {
    let mut rng = rng::new();
    Keypair::generate(&mut rng)
}

fn create_comm() -> Result<Comm> {
    Ok(Comm::new(Default::default())?)
}

// Generate random EldersInfo and the corresponding Keypairs.
fn create_elders_info() -> (EldersInfo, Vec<Keypair>) {
    let mut rng = rng::new();
    let keypairs: Vec<_> = (0..ELDER_SIZE)
        .map(|_| Keypair::generate(&mut rng))
        .sorted_by_key(|keypair| crypto::name(&keypair.public))
        .collect();
    let elders = keypairs
        .iter()
        .map(|keypair| Peer::new(crypto::name(&keypair.public), create_addr(), MIN_AGE))
        .map(|peer| (*peer.name(), peer))
        .collect();
    let elders_info = EldersInfo {
        elders,
        prefix: Prefix::default(),
    };

    (elders_info, keypairs)
}

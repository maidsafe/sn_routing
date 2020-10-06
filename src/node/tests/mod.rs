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
mod elder;
#[cfg(feature = "mock")]
mod utils;

use super::{Approved, Bootstrapping, Comm, Command, NodeInfo, Stage, State};
use crate::{
    consensus::{Proven, Vote},
    crypto,
    event::Event,
    location::DstLocation,
    messages::{BootstrapResponse, JoinRequest, Message, Variant},
    peer::Peer,
    rng,
    section::{
        majority_count, EldersInfo, MemberInfo, PeerState, SectionKeyShare, SectionProofChain,
        SharedState, MIN_AGE,
    },
    ELDER_SIZE,
};
use anyhow::Result;
use assert_matches::assert_matches;
use bls_signature_aggregator::Proof;
use ed25519_dalek::Keypair;
use itertools::Itertools;
use serde::Serialize;
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

#[tokio::test]
async fn accumulate_votes() -> Result<()> {
    let (elders_info, mut full_ids) = create_elders_info();
    let sk_set = create_secret_key_set();
    let pk_set = sk_set.public_keys();
    let (shared_state, section_key_share) = create_shared_state(&elders_info, &sk_set)?;
    let (node_info, _) = create_node_info_for(full_ids.remove(0));

    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let new_node_name = crypto::name(&create_keypair().public);
    let new_node_addr = create_addr();
    let member_info = MemberInfo {
        peer: Peer::new(new_node_name, new_node_addr, MIN_AGE),
        state: PeerState::Joined,
    };
    let vote = Vote::Online {
        member_info,
        previous_name: None,
        their_knowledge: None,
    };

    for index in 0..THRESHOLD {
        let proof_share = vote.prove(pk_set.clone(), index, &sk_set.secret_key_share(index))?;
        let commands = node
            .handle_command(Command::HandleVote {
                vote: vote.clone(),
                proof_share,
            })
            .await?;
        assert!(commands.is_empty());
    }

    let proof_share = vote.prove(
        pk_set.clone(),
        THRESHOLD,
        &sk_set.secret_key_share(THRESHOLD),
    )?;
    let mut commands = node
        .handle_command(Command::HandleVote {
            vote: vote.clone(),
            proof_share,
        })
        .await?
        .into_iter();

    assert_matches!(
        commands.next(),
        Some(Command::HandleConsensus { vote: consensus, .. }) => {
            assert_eq!(consensus, vote);
        }
    );

    Ok(())
}

#[tokio::test]
async fn handle_consensus_on_online() -> Result<()> {
    let (elders_info, mut full_ids) = create_elders_info();
    let sk_set = create_secret_key_set();
    let (shared_state, section_key_share) = create_shared_state(&elders_info, &sk_set)?;
    let (node_info, mut event_rx) = create_node_info_for(full_ids.remove(0));

    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let new_node_name = crypto::name(&create_keypair().public);
    let new_node_addr = create_addr();
    let member_info = MemberInfo {
        peer: Peer::new(new_node_name, new_node_addr, MIN_AGE),
        state: PeerState::Joined,
    };
    let vote = Vote::Online {
        member_info,
        previous_name: None,
        their_knowledge: None,
    };
    let proof = create_proof(&sk_set, &vote.as_signable())?;

    let commands = node
        .handle_command(Command::HandleConsensus { vote, proof })
        .await?;

    let mut node_approval_sent = false;

    for command in commands {
        match command {
            Command::SendMessage {
                recipients,
                message,
                ..
            } => {
                let message = Message::from_bytes(&message)?;
                match message.variant() {
                    Variant::NodeApproval(proven_elders_info) => {
                        assert_eq!(proven_elders_info.value, elders_info);
                        assert_eq!(recipients, [new_node_addr]);
                        node_approval_sent = true;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    assert!(node_approval_sent);

    assert_matches!(event_rx.try_recv(), Ok(Event::InfantJoined { name, age, }) => {
        assert_eq!(name, new_node_name);
        assert_eq!(age, MIN_AGE);
    });

    Ok(())
}

// TODO: add more tests here

const THRESHOLD: usize = majority_count(ELDER_SIZE) - 1;

// Returns unique SocketAddr
fn create_addr() -> SocketAddr {
    thread_local! {
        static NEXT_PORT: Cell<u16> = Cell::new(1000);
    }

    let port = NEXT_PORT.with(|cell| cell.replace(cell.get().wrapping_add(1)));

    ([192, 0, 2, 0], port).into()
}

fn create_node_info() -> (NodeInfo, mpsc::UnboundedReceiver<Event>) {
    create_node_info_for(create_keypair())
}

fn create_node_info_for(keypair: Keypair) -> (NodeInfo, mpsc::UnboundedReceiver<Event>) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let node_info = NodeInfo::new(keypair, Default::default(), event_tx);
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
        .map(|keypair| Peer::new(crypto::name(&keypair.public), create_addr(), MIN_AGE + 1))
        .map(|peer| (*peer.name(), peer))
        .collect();
    let elders_info = EldersInfo {
        elders,
        prefix: Prefix::default(),
    };

    (elders_info, keypairs)
}

fn create_secret_key_set() -> bls::SecretKeySet {
    bls::SecretKeySet::random(THRESHOLD, &mut rng::new())
}

fn create_proof<T: Serialize>(sk_set: &bls::SecretKeySet, payload: &T) -> Result<Proof> {
    let pk_set = sk_set.public_keys();
    let bytes = bincode::serialize(payload)?;
    let signature_shares: Vec<_> = (0..sk_set.threshold() + 1)
        .map(|index| sk_set.secret_key_share(index).sign(&bytes))
        .collect();
    let signature = pk_set
        .combine_signatures(signature_shares.iter().enumerate())
        .unwrap();

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}

fn create_shared_state(
    elders_info: &EldersInfo,
    sk_set: &bls::SecretKeySet,
) -> Result<(SharedState, SectionKeyShare)> {
    let pk_set = sk_set.public_keys();
    let section_chain = SectionProofChain::new(pk_set.public_key());
    let elders_info_proof = create_proof(sk_set, elders_info)?;
    let proven_elders_info = Proven::new(elders_info.clone(), elders_info_proof);

    let mut shared_state = SharedState::new(section_chain, proven_elders_info);

    for peer in elders_info.elders.values().copied() {
        let member_info = MemberInfo {
            peer,
            state: PeerState::Joined,
        };
        let proof = create_proof(sk_set, &member_info)?;
        let _ = shared_state.update_member(member_info, proof);
    }

    let section_key_share = SectionKeyShare {
        public_key_set: pk_set,
        index: 0,
        secret_key_share: sk_set.secret_key_share(0),
    };

    Ok((shared_state, section_key_share))
}

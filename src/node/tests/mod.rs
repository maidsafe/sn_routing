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
use bytes::Bytes;
use ed25519_dalek::Keypair;
use itertools::Itertools;
use serde::Serialize;
use std::{
    cell::Cell,
    collections::{BTreeSet, HashSet},
    iter,
    net::{Ipv4Addr, SocketAddr},
    ops::Deref,
};
use tokio::sync::mpsc;
use xor_name::Prefix;

#[tokio::test]
async fn send_bootstrap_request() -> Result<()> {
    let bootstrap_addr = create_addr();
    let (node_info, _) = create_node_info();
    let (state, command) = Bootstrapping::new(None, vec![bootstrap_addr], node_info)?;
    let node = Stage::new(state.into(), create_comm()?);

    let (recipients, message) = assert_matches!(
        command,
        Command::SendMessage {
            recipients,
            message, ..
        } => (recipients, message)
    );
    assert_eq!(recipients, [bootstrap_addr]);

    let message = Message::from_bytes(&message)?;
    assert_matches!(
        message.variant(),
        Variant::BootstrapRequest(name) => assert_eq!(*name, node.name().await)
    );

    Ok(())
}

#[tokio::test]
async fn receive_bootstrap_request() -> Result<()> {
    let comm = create_comm()?;
    let addr = comm.our_connection_info()?;
    let (node_info, _) = create_node_info();
    let state = Approved::first_node(node_info, addr)?;
    let node = Stage::new(state.into(), comm);

    let new_keypair = create_keypair();
    let new_addr = create_addr();

    let message = Message::single_src(
        &new_keypair,
        MIN_AGE,
        DstLocation::Direct,
        Variant::BootstrapRequest(crypto::name(&new_keypair.public)),
        None,
        None,
    )?;

    let mut commands = node
        .handle_command(Command::HandleMessage {
            message,
            sender: Some(new_addr),
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

    assert_eq!(recipients, [new_addr]);

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
    let (state, _) = Bootstrapping::new(None, vec![create_addr()], node_info)?;
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
        MIN_AGE + 1,
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
    let (state, _) = Bootstrapping::new(None, vec![create_addr()], node_info)?;
    let node = Stage::new(state.into(), create_comm()?);

    let old_keypair = create_keypair();
    let old_addr = create_addr();

    let new_addrs: Vec<_> = (0..ELDER_SIZE).map(|_| create_addr()).collect();

    let message = Message::single_src(
        &old_keypair,
        MIN_AGE + 1,
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

    let new_keypair = create_keypair();
    let new_addr = create_addr();
    let section_key = *node
        .our_history()
        .await
        .expect("node has no section chain")
        .last_key();

    let message = Message::single_src(
        &new_keypair,
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
            sender: Some(new_addr),
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
            assert_eq!(*member_info.peer.name(), crypto::name(&new_keypair.public));
            assert_eq!(*member_info.peer.addr(), new_addr);
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
    let (elders_info, mut keypairs) = create_elders_info();
    let sk_set = SecretKeySet::random();
    let pk_set = sk_set.public_keys();
    let (shared_state, section_key_share) = create_shared_state(&elders_info, &sk_set)?;
    let (node_info, _) = create_node_info_for(keypairs.remove(0));
    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let new_peer = create_peer();
    let member_info = MemberInfo::joined(new_peer);
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
    let (elders_info, mut keypairs) = create_elders_info();
    let sk_set = SecretKeySet::random();
    let (shared_state, section_key_share) = create_shared_state(&elders_info, &sk_set)?;
    let (node_info, mut event_rx) = create_node_info_for(keypairs.remove(0));
    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let new_peer = create_peer();
    let member_info = MemberInfo::joined(new_peer);
    let vote = Vote::Online {
        member_info,
        previous_name: None,
        their_knowledge: None,
    };
    let proof = create_proof(sk_set.secret_key(), &vote.as_signable())?;

    let commands = node
        .handle_command(Command::HandleConsensus { vote, proof })
        .await?;

    let mut node_approval_sent = false;

    for command in commands {
        if let Command::SendMessage {
            recipients,
            message,
            ..
        } = command
        {
            let message = Message::from_bytes(&message)?;
            if let Variant::NodeApproval(proven_elders_info) = message.variant() {
                assert_eq!(proven_elders_info.value, elders_info);
                assert_eq!(recipients, [*new_peer.addr()]);
                node_approval_sent = true;
            }
        }
    }

    assert!(node_approval_sent);

    assert_matches!(event_rx.try_recv(), Ok(Event::InfantJoined { name, age, }) => {
        assert_eq!(name, *new_peer.name());
        assert_eq!(age, MIN_AGE);
    });

    Ok(())
}

#[tokio::test]
async fn handle_consensus_on_offline_of_non_elder() -> Result<()> {
    let (elders_info, mut keypairs) = create_elders_info();
    let sk_set = SecretKeySet::random();

    let (mut shared_state, section_key_share) = create_shared_state(&elders_info, &sk_set)?;

    let existing_peer = create_peer();
    let member_info = MemberInfo::joined(existing_peer);
    let proof = create_proof(sk_set.secret_key(), &member_info)?;
    let _ = shared_state.update_member(member_info, proof);

    let (node_info, mut event_rx) = create_node_info_for(keypairs.remove(0));
    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let member_info = MemberInfo {
        peer: existing_peer,
        state: PeerState::Left,
    };
    let vote = Vote::Offline(member_info);
    let proof = create_proof(sk_set.secret_key(), &vote.as_signable())?;

    let _ = node
        .handle_command(Command::HandleConsensus { vote, proof })
        .await?;

    assert_matches!(event_rx.try_recv(), Ok(Event::MemberLeft { name, age, }) => {
        assert_eq!(name, *existing_peer.name());
        assert_eq!(age, MIN_AGE);
    });

    Ok(())
}

#[tokio::test]
async fn handle_consensus_on_offline_of_elder() -> Result<()> {
    let (elders_info, mut keypairs) = create_elders_info();
    let sk_set = SecretKeySet::random();

    let (mut shared_state, section_key_share) = create_shared_state(&elders_info, &sk_set)?;

    let existing_peer = create_peer();
    let member_info = MemberInfo::joined(existing_peer);
    let proof = create_proof(sk_set.secret_key(), &member_info)?;
    let _ = shared_state.update_member(member_info, proof);

    // Pick the elder to remove.
    let remove_peer = *elders_info
        .elders
        .values()
        .rev()
        .next()
        .expect("elders_info is empty");
    let remove_member_info = shared_state
        .our_members
        .get(remove_peer.name())
        .expect("member not found")
        .leave();

    // Create our node
    let (node_info, mut event_rx) = create_node_info_for(keypairs.remove(0));
    let node_name = node_info.name();
    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    // Handle the consensus on the Offline vote
    let vote = Vote::Offline(remove_member_info);
    let proof = create_proof(sk_set.secret_key(), &vote.as_signable())?;

    let commands = node
        .handle_command(Command::HandleConsensus { vote, proof })
        .await?;

    // Verify we sent a `DKGStart` message with the expected participants.
    let mut dkg_start_sent = false;

    for command in commands {
        let (recipients, message) = match command {
            Command::SendMessage {
                recipients,
                message,
                ..
            } => (recipients, message),
            _ => continue,
        };

        let message = Message::from_bytes(&message)?;
        let message = match message.variant() {
            Variant::Vote {
                content: Vote::SendMessage { message, .. },
                ..
            } => message,
            _ => continue,
        };

        let actual_elders_info = match &message.variant {
            Variant::DKGStart { elders_info, .. } => elders_info,
            _ => continue,
        };

        let expected_new_elders: BTreeSet<_> = elders_info
            .elders
            .values()
            .filter(|peer| **peer != remove_peer)
            .copied()
            .chain(iter::once(existing_peer))
            .collect();
        itertools::assert_equal(actual_elders_info.elders.values(), &expected_new_elders);

        let expected_dkg_start_recipients: Vec<_> = expected_new_elders
            .iter()
            .filter(|peer| *peer.name() != node_name)
            .map(Peer::addr)
            .copied()
            .collect();
        assert_eq!(recipients, expected_dkg_start_recipients);

        dkg_start_sent = true;
    }

    assert!(dkg_start_sent);

    assert_matches!(event_rx.try_recv(), Ok(Event::MemberLeft { name, .. }) => {
        assert_eq!(name, *remove_peer.name());
    });

    // The removed peer is still our elder because we haven't yet processed the section update.
    assert!(node.our_elders().await.contains(&remove_peer));

    Ok(())
}

#[tokio::test]
async fn handle_bounced_unknown_message() -> Result<()> {
    let (elders_info, mut keypairs) = create_elders_info();

    // Create `SharedState` whose section chain has two keys.
    let sk0 = bls::SecretKey::random();
    let pk0 = sk0.public_key();

    let sk1_set = SecretKeySet::random();
    let pk1 = sk1_set.secret_key().public_key();
    let pk1_signature = sk0.sign(&bincode::serialize(&pk1)?);

    let mut section_chain = SectionProofChain::new(pk0);
    let _ = section_chain.push(pk1, pk1_signature);

    let proof = create_proof(&sk0, &elders_info)?;
    let proven_elders_info = Proven {
        value: elders_info,
        proof,
    };
    let shared_state = SharedState::new(section_chain, proven_elders_info);
    let section_key_share = create_section_key_share(&sk1_set, 0);

    let (node_info, _) = create_node_info_for(keypairs.remove(0));

    // Create the original message whose bounce we want to test. The content of the message doesn't
    // matter for the purpose of this test.
    let peer_keypair = create_keypair();
    let peer_addr = create_addr();
    let original_message_content = Bytes::from_static(b"unknown message");
    let original_message = Message::single_src(
        &node_info.keypair,
        MIN_AGE + 1,
        DstLocation::Node(crypto::name(&peer_keypair.public)),
        Variant::UserMessage(original_message_content.clone()),
        None,
        None,
    )?;

    let state = Approved::new(shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    let bounced_message = Message::single_src(
        &peer_keypair,
        MIN_AGE,
        DstLocation::Direct,
        Variant::BouncedUnknownMessage {
            src_key: pk0,
            message: original_message.to_bytes(),
        },
        None,
        None,
    )?;

    let commands = node
        .handle_command(Command::HandleMessage {
            message: bounced_message,
            sender: Some(peer_addr),
        })
        .await?;

    let mut sync_sent = false;
    let mut original_message_sent = false;

    for command in commands {
        let (recipients, message) = match command {
            Command::SendMessage {
                recipients,
                message,
                ..
            } => (recipients, message),
            _ => continue,
        };

        let message = Message::from_bytes(&message)?;

        match message.variant() {
            Variant::Sync(state) => {
                assert_eq!(recipients, [peer_addr]);
                assert_eq!(*state.our_history.last_key(), pk1);
                sync_sent = true;
            }
            Variant::UserMessage(content) => {
                assert_eq!(recipients, [peer_addr]);
                assert_eq!(*content, original_message_content);
                original_message_sent = true;
            }
            _ => continue,
        }
    }

    assert!(sync_sent);
    assert!(original_message_sent);

    Ok(())
}

#[tokio::test]
async fn handle_sync() -> Result<()> {
    // Create first `SharedState` with a chain of length 2
    let sk0_set = SecretKeySet::random();
    let pk0 = sk0_set.secret_key().public_key();
    let sk1_set = SecretKeySet::random();
    let pk1 = sk1_set.secret_key().public_key();
    let pk1_signature = sk0_set.secret_key().sign(bincode::serialize(&pk1)?);

    let mut chain = SectionProofChain::new(pk0);
    assert!(chain.push(pk1, pk1_signature));

    let (old_elders_info, mut keypairs) = create_elders_info();
    let old_elders_info_proof = create_proof(sk0_set.secret_key(), &old_elders_info)?;
    let old_shared_state = SharedState::new(
        chain.clone(),
        Proven {
            value: old_elders_info.clone(),
            proof: old_elders_info_proof,
        },
    );

    // Create our node
    let section_key_share = create_section_key_share(&sk1_set, 0);
    let (node_info, mut event_rx) = create_node_info_for(keypairs.remove(0));
    let state = Approved::new(old_shared_state, Some(section_key_share), node_info);
    let node = Stage::new(state.into(), create_comm()?);

    // Create new `SharedState` as a successor to the previous one.
    let sk2 = bls::SecretKey::random();
    let pk2 = sk2.public_key();
    let pk2_signature = sk1_set.secret_key().sign(bincode::serialize(&pk2)?);
    assert!(chain.push(pk2, pk2_signature));

    let old_peer = *old_elders_info
        .elders
        .values()
        .nth(1)
        .expect("not enough elders");
    let old_peer_keypair = keypairs.remove(0);

    // Create the new `EldersInfo` by replacing the last peer with a new one.
    let new_peer = create_peer();
    let new_elders_info = EldersInfo::new(
        old_elders_info
            .elders
            .values()
            .take(old_elders_info.elders.len() - 1)
            .copied()
            .chain(iter::once(new_peer))
            .map(|peer| (*peer.name(), peer))
            .collect(),
        old_elders_info.prefix,
    );
    let new_elders: BTreeSet<_> = new_elders_info.elders.keys().copied().collect();
    let new_elders_info_proof = create_proof(sk1_set.secret_key(), &new_elders_info)?;

    let new_shared_state = SharedState::new(
        chain,
        Proven {
            value: new_elders_info,
            proof: new_elders_info_proof,
        },
    );

    // Create the `Sync` message containing the new shared state.
    let message = Message::single_src(
        &old_peer_keypair,
        MIN_AGE + 1,
        DstLocation::Direct,
        Variant::Sync(new_shared_state),
        None,
        None,
    )?;

    // Handle the message.
    let _ = node
        .handle_command(Command::HandleMessage {
            message,
            sender: Some(*old_peer.addr()),
        })
        .await?;

    // Verify our `SharedState` got updated.
    assert_matches!(
        event_rx.try_recv(),
        Ok(Event::EldersChanged { key, elders, .. }) => {
            assert_eq!(key, pk2);
            assert_eq!(elders, new_elders);
        }
    );

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

fn create_keypair() -> Keypair {
    let mut rng = rng::new();
    Keypair::generate(&mut rng)
}

fn create_peer() -> Peer {
    Peer::new(
        crypto::name(&create_keypair().public),
        create_addr(),
        MIN_AGE,
    )
}

fn create_node_info() -> (NodeInfo, mpsc::UnboundedReceiver<Event>) {
    create_node_info_for(create_keypair())
}

fn create_node_info_for(keypair: Keypair) -> (NodeInfo, mpsc::UnboundedReceiver<Event>) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let node_info = NodeInfo::new(keypair, Default::default(), event_tx);
    (node_info, event_rx)
}

fn create_comm() -> Result<Comm> {
    Ok(Comm::new(qp2p::Config {
        ip: Some(Ipv4Addr::LOCALHOST.into()),
        ..Default::default()
    })?)
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

fn create_section_key_share(sk_set: &bls::SecretKeySet, index: usize) -> SectionKeyShare {
    SectionKeyShare {
        public_key_set: sk_set.public_keys(),
        index,
        secret_key_share: sk_set.secret_key_share(index),
    }
}

fn create_proof<T: Serialize>(sk: &bls::SecretKey, payload: &T) -> Result<Proof> {
    let bytes = bincode::serialize(payload)?;
    let signature = sk.sign(&bytes);

    Ok(Proof {
        public_key: sk.public_key(),
        signature,
    })
}

fn create_shared_state(
    elders_info: &EldersInfo,
    sk_set: &SecretKeySet,
) -> Result<(SharedState, SectionKeyShare)> {
    let section_chain = SectionProofChain::new(sk_set.secret_key().public_key());
    let elders_info_proof = create_proof(sk_set.secret_key(), elders_info)?;
    let proven_elders_info = Proven::new(elders_info.clone(), elders_info_proof);

    let mut shared_state = SharedState::new(section_chain, proven_elders_info);

    for peer in elders_info.elders.values().copied() {
        let member_info = MemberInfo::joined(peer);
        let proof = create_proof(sk_set.secret_key(), &member_info)?;
        let _ = shared_state.update_member(member_info, proof);
    }

    let section_key_share = create_section_key_share(sk_set, 0);

    Ok((shared_state, section_key_share))
}

// Wrapper for `bls::SecretKeySet` that also allows to retrieve the corresponding `bls::SecretKey`.
// Note: `bls::SecretKeySet` does have a `secret_key` method, but it's test-only and not available
// for the consumers of the crate.
struct SecretKeySet {
    set: bls::SecretKeySet,
    key: bls::SecretKey,
}

impl SecretKeySet {
    fn random() -> Self {
        let poly = bls::poly::Poly::random(THRESHOLD, &mut rng::new());
        let key = bls::SecretKey::from_mut(&mut poly.evaluate(0));
        let set = bls::SecretKeySet::from(poly);

        Self { set, key }
    }

    fn secret_key(&self) -> &bls::SecretKey {
        &self.key
    }
}

impl Deref for SecretKeySet {
    type Target = bls::SecretKeySet;

    fn deref(&self) -> &Self::Target {
        &self.set
    }
}

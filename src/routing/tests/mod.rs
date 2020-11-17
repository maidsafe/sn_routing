// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Approved, Comm, Command, Stage};
use crate::{
    consensus::{test_utils::*, Proven, Vote},
    crypto,
    event::Event,
    location::DstLocation,
    majority,
    messages::{BootstrapResponse, JoinRequest, Message, PlainMessage, Variant},
    network::Network,
    node::Node,
    peer::Peer,
    relocation,
    section::{
        test_utils::*, EldersInfo, MemberInfo, PeerState, Section, SectionKeyShare,
        SectionProofChain, MIN_AGE,
    },
    Error, ELDER_SIZE,
};
use anyhow::Result;
use assert_matches::assert_matches;
use bls_signature_aggregator::Proof;
use bytes::Bytes;
use std::{cmp, collections::BTreeSet, iter, net::Ipv4Addr, ops::Deref};
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

#[tokio::test]
async fn receive_bootstrap_request() -> Result<()> {
    let node = create_node();
    let state = Approved::first_node(node, mpsc::unbounded_channel().0)?;
    let stage = Stage::new(state, create_comm()?);

    let new_node = Node::new(crypto::gen_keypair(), gen_addr());

    let message = Message::single_src(
        &new_node,
        DstLocation::Direct,
        Variant::BootstrapRequest(new_node.name()),
        None,
        None,
    )?;

    let mut commands = stage
        .handle_command(Command::HandleMessage {
            message,
            sender: Some(new_node.addr),
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

    assert_eq!(recipients, [new_node.addr]);

    let message = Message::from_bytes(&message)?;
    assert_matches!(
        message.variant(),
        Variant::BootstrapResponse(BootstrapResponse::Join { .. })
    );

    Ok(())
}

#[tokio::test]
async fn receive_join_request() -> Result<()> {
    let node = create_node();
    let state = Approved::first_node(node, mpsc::unbounded_channel().0)?;
    let stage = Stage::new(state, create_comm()?);

    let new_node = Node::new(crypto::gen_keypair(), gen_addr());
    let section_key = *stage.state.lock().await.section().chain().last_key();

    let message = Message::single_src(
        &new_node,
        DstLocation::Direct,
        Variant::JoinRequest(Box::new(JoinRequest {
            section_key,
            relocate_payload: None,
        })),
        None,
        None,
    )?;
    let mut commands = stage
        .handle_command(Command::HandleMessage {
            sender: Some(new_node.addr),
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
            assert_eq!(*member_info.peer.name(), new_node.name());
            assert_eq!(*member_info.peer.addr(), new_node.addr);
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
    let (elders_info, mut nodes) = create_elders_info();
    let sk_set = SecretKeySet::random();
    let pk_set = sk_set.public_keys();
    let (section, section_key_share) = create_section(&sk_set, &elders_info)?;
    let node = nodes.remove(0);
    let state = Approved::new(
        node,
        section,
        Some(section_key_share),
        mpsc::unbounded_channel().0,
    );
    let stage = Stage::new(state, create_comm()?);

    let new_peer = create_peer();
    let member_info = MemberInfo::joined(new_peer);
    let vote = Vote::Online {
        member_info,
        previous_name: None,
        their_knowledge: None,
    };

    for index in 0..THRESHOLD {
        let proof_share = vote.prove(pk_set.clone(), index, &sk_set.secret_key_share(index))?;
        let commands = stage
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
    let mut commands = stage
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
async fn handle_consensus_on_online_of_infant_during_startup_phase() -> Result<()> {
    handle_consensus_on_online_of_infant(NetworkPhase::Startup).await
}

#[tokio::test]
async fn handle_consensus_on_online_of_infant_after_startup_phase() -> Result<()> {
    handle_consensus_on_online_of_infant(NetworkPhase::Regular).await
}

enum NetworkPhase {
    Startup,
    Regular,
}

async fn handle_consensus_on_online_of_infant(phase: NetworkPhase) -> Result<()> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();

    let prefix = match phase {
        NetworkPhase::Startup => Prefix::default(),
        NetworkPhase::Regular => "0".parse().unwrap(),
    };

    let (elders_info, mut nodes) = gen_elders_info(prefix, ELDER_SIZE);
    let sk_set = SecretKeySet::random();
    let (section, section_key_share) = create_section(&sk_set, &elders_info)?;
    let node = nodes.remove(0);
    let state = Approved::new(node, section, Some(section_key_share), event_tx);
    let stage = Stage::new(state, create_comm()?);

    let new_peer = create_peer();

    let (node_approval_sent, relocate_age) =
        handle_online_command(&new_peer, &sk_set, &stage, elders_info).await?;
    assert!(node_approval_sent);

    match phase {
        NetworkPhase::Startup => {
            assert!(relocate_age.unwrap() > MIN_AGE);
            assert!(event_rx.try_recv().is_err());
        }
        NetworkPhase::Regular => {
            assert_matches!(event_rx.try_recv(), Ok(Event::MemberJoined { name, age, .. }) => {
                assert_eq!(name, *new_peer.name());
                assert_eq!(age, MIN_AGE);
            });
        }
    }

    Ok(())
}

#[tokio::test]
async fn handle_consensus_on_online_of_elder_candidate() -> Result<()> {
    let sk_set = SecretKeySet::random();
    let chain = SectionProofChain::new(sk_set.secret_key().public_key());

    // Creates nodes where everybody has age 6 except the last one who has 5.
    let mut nodes: Vec<_> = gen_sorted_nodes(ELDER_SIZE)
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            if index < ELDER_SIZE - 1 {
                node.with_age(MIN_AGE + 2)
            } else {
                node.with_age(MIN_AGE + 1)
            }
        })
        .collect();

    let elders_info = EldersInfo::new(nodes.iter().map(Node::peer), Prefix::default());
    let proven_elders_info = proven(sk_set.secret_key(), elders_info.clone())?;
    let mut section = Section::new(chain, proven_elders_info)?;

    for peer in elders_info.elders.values() {
        let member_info = MemberInfo::joined(*peer);
        let proof = prove(sk_set.secret_key(), &member_info)?;
        let _ = section.update_member(Proven {
            value: member_info,
            proof,
        });
    }

    let node = nodes.remove(0);
    let node_name = node.name();
    let section_key_share = create_section_key_share(&sk_set, 0);
    let state = Approved::new(
        node,
        section,
        Some(section_key_share),
        mpsc::unbounded_channel().0,
    );
    let stage = Stage::new(state, create_comm()?);

    // Handle the consensus on Online of a peer that is older than the youngest
    // current elder - that means this peer is going to be promoted.
    let new_peer = create_peer().with_age(MIN_AGE + 2);
    let member_info = MemberInfo::joined(new_peer);
    let vote = Vote::Online {
        member_info,
        previous_name: Some(XorName::random()),
        their_knowledge: Some(sk_set.secret_key().public_key()),
    };
    let proof = prove(sk_set.secret_key(), &vote.as_signable())?;

    let commands = stage
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
            .take(elders_info.elders.len() - 1)
            .copied()
            .chain(iter::once(new_peer))
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

    Ok(())
}

// Handles a concensused Online vote. Collects the resulted commands.
// returns with (node_approval_sent, Option<relocate_age>)
// with None of relocate age indicates no Relocate message sent.
async fn handle_online_command(
    peer: &Peer,
    sk_set: &SecretKeySet,
    stage: &Stage,
    elders_info: EldersInfo,
) -> Result<(bool, Option<u8>)> {
    let member_info = MemberInfo::joined(*peer);
    let vote = Vote::Online {
        member_info,
        previous_name: None,
        their_knowledge: None,
    };
    let proof = prove(sk_set.secret_key(), &vote.as_signable())?;

    let commands = stage
        .handle_command(Command::HandleConsensus { vote, proof })
        .await?;

    let mut node_approval_sent = false;
    let mut relocate_age = None;
    for command in commands {
        let (message, recipients) = match command {
            Command::SendMessage {
                recipients,
                message,
                ..
            } => (Message::from_bytes(&message).unwrap(), recipients),
            _ => continue,
        };

        match message.variant() {
            Variant::NodeApproval(proven_elders_info) => {
                assert_eq!(proven_elders_info.value, elders_info);
                assert_eq!(recipients, [*peer.addr()]);
                node_approval_sent = true;
            }
            Variant::Vote { content, .. } => {
                let message = if let Vote::SendMessage { message, .. } = content {
                    message
                } else {
                    continue;
                };

                let details = if let Variant::Relocate(details) = &message.variant {
                    details
                } else {
                    continue;
                };

                assert_eq!(details.pub_id, *peer.name());
                assert_eq!(details.destination, *peer.name());
                relocate_age = Some(details.age);
                assert_eq!(recipients, [*peer.addr()]);
            }
            _ => continue,
        }
    }

    Ok((node_approval_sent, relocate_age))
}

async fn handle_consensus_on_online_of_rejoined_node(phase: NetworkPhase, age: u8) -> Result<()> {
    let prefix = match phase {
        NetworkPhase::Startup => Prefix::default(),
        NetworkPhase::Regular => "0".parse().unwrap(),
    };
    let (elders_info, mut nodes) = gen_elders_info(prefix, ELDER_SIZE);
    let sk_set = SecretKeySet::random();
    let (mut section, section_key_share) = create_section(&sk_set, &elders_info)?;

    // Make a left peer.
    let peer = create_peer().with_age(age);
    let member_info = MemberInfo {
        peer,
        state: PeerState::Left,
    };
    let member_info = proven(sk_set.secret_key(), member_info)?;
    let _ = section.update_member(member_info);

    // Make a Node
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let node = nodes.remove(0);
    let state = Approved::new(node, section, Some(section_key_share), event_tx);
    let stage = Stage::new(state, create_comm()?);

    // Simulate peer with the same name is rejoin and verify resulted behaviours.
    let (node_approval_sent, relocate_age) =
        handle_online_command(&peer, &sk_set, &stage, elders_info).await?;
    assert!(event_rx.try_recv().is_err());
    // After startup, a rejoin node with low age will be rejected.
    if let NetworkPhase::Regular = phase {
        if age / 2 <= MIN_AGE {
            assert!(!node_approval_sent);
            assert!(relocate_age.is_none());
            return Ok(());
        }
    }
    assert!(node_approval_sent);
    let expected_age = cmp::max(MIN_AGE, age / 2);
    assert!(relocate_age == Some(expected_age));

    Ok(())
}

#[tokio::test]
async fn handle_consensus_on_online_of_rejoined_node_with_high_age_in_startup() -> Result<()> {
    handle_consensus_on_online_of_rejoined_node(NetworkPhase::Startup, 16).await
}

#[tokio::test]
async fn handle_consensus_on_online_of_rejoined_node_with_high_age_after_startup() -> Result<()> {
    handle_consensus_on_online_of_rejoined_node(NetworkPhase::Regular, 16).await
}

#[tokio::test]
async fn handle_consensus_on_online_of_rejoined_node_with_low_age_in_startup() -> Result<()> {
    handle_consensus_on_online_of_rejoined_node(NetworkPhase::Startup, 8).await
}

#[tokio::test]
async fn handle_consensus_on_online_of_rejoined_node_with_low_age_after_startup() -> Result<()> {
    handle_consensus_on_online_of_rejoined_node(NetworkPhase::Regular, 8).await
}

#[tokio::test]
async fn handle_consensus_on_offline_of_non_elder() -> Result<()> {
    let (elders_info, mut nodes) = create_elders_info();
    let sk_set = SecretKeySet::random();

    let (mut section, section_key_share) = create_section(&sk_set, &elders_info)?;

    let existing_peer = create_peer();
    let member_info = MemberInfo::joined(existing_peer);
    let member_info = proven(sk_set.secret_key(), member_info)?;
    let _ = section.update_member(member_info);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let node = nodes.remove(0);
    let state = Approved::new(node, section, Some(section_key_share), event_tx);
    let stage = Stage::new(state, create_comm()?);

    let member_info = MemberInfo {
        peer: existing_peer,
        state: PeerState::Left,
    };
    let vote = Vote::Offline(member_info);
    let proof = prove(sk_set.secret_key(), &vote.as_signable())?;

    let _ = stage
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
    let (elders_info, mut nodes) = create_elders_info();
    let sk_set = SecretKeySet::random();

    let (mut section, section_key_share) = create_section(&sk_set, &elders_info)?;

    let existing_peer = create_peer();
    let member_info = MemberInfo::joined(existing_peer);
    let member_info = proven(sk_set.secret_key(), member_info)?;
    let _ = section.update_member(member_info);

    // Pick the elder to remove.
    let remove_peer = *elders_info
        .elders
        .values()
        .rev()
        .next()
        .expect("elders_info is empty");
    let remove_member_info = section
        .members()
        .get(remove_peer.name())
        .expect("member not found")
        .leave()?;

    // Create our node
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let node = nodes.remove(0);
    let node_name = node.name();
    let state = Approved::new(node, section, Some(section_key_share), event_tx);
    let stage = Stage::new(state, create_comm()?);

    // Handle the consensus on the Offline vote
    let vote = Vote::Offline(remove_member_info);
    let proof = prove(sk_set.secret_key(), &vote.as_signable())?;

    let commands = stage
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
    assert!(stage
        .state
        .lock()
        .await
        .section()
        .elders_info()
        .elders
        .contains_key(remove_peer.name()));

    Ok(())
}

#[tokio::test]
async fn handle_unknown_message_from_our_elder() -> Result<()> {
    handle_unknown_message(UnknownMessageSource::OurElder).await
}

#[tokio::test]
async fn handle_unknown_message_from_non_elder() -> Result<()> {
    handle_unknown_message(UnknownMessageSource::NonElder).await
}

enum UnknownMessageSource {
    OurElder,
    NonElder,
}

async fn handle_unknown_message(source: UnknownMessageSource) -> Result<()> {
    let (elders_info, mut nodes) = create_elders_info();

    let (sender_node, expected_recipients) = match source {
        UnknownMessageSource::OurElder => {
            // When the unknown message is sent from one of our elders, we should bounce it back to
            // that elder only.
            let node = nodes.remove(0);
            let addr = node.addr;
            (node, vec![addr])
        }
        UnknownMessageSource::NonElder => {
            // When the unknown message is sent from a peer that is not our elder (including peers
            // from other sections), bounce it to our elders.
            (
                Node::new(crypto::gen_keypair(), gen_addr()),
                elders_info
                    .elders
                    .values()
                    .map(Peer::addr)
                    .copied()
                    .collect(),
            )
        }
    };

    let sk = bls::SecretKey::random();
    let chain = SectionProofChain::new(sk.public_key());

    let proven_elders_info = proven(&sk, elders_info)?;
    let section = Section::new(chain, proven_elders_info)?;

    let node = create_node();
    let state = Approved::new(node, section, None, mpsc::unbounded_channel().0);
    let stage = Stage::new(state, create_comm()?);

    // non-elders can't handle messages addressed to sections.
    let original_message = Message::single_src(
        &sender_node,
        DstLocation::Section(rand::random()),
        Variant::UserMessage(Bytes::from_static(b"hello")),
        None,
        None,
    )?;
    let original_message_bytes = original_message.to_bytes();

    let commands = stage
        .handle_command(Command::HandleMessage {
            message: original_message,
            sender: Some(sender_node.addr),
        })
        .await?;

    let mut bounce_sent = false;

    // TODO: test also that the message got relayed to the elders.

    for command in commands {
        let (recipients, message) = if let Command::SendMessage {
            recipients,
            message,
            ..
        } = command
        {
            (recipients, message)
        } else {
            continue;
        };

        let message = Message::from_bytes(&message)?;
        let (src_key, message) =
            if let Variant::BouncedUnknownMessage { src_key, message } = message.variant() {
                (src_key, message)
            } else {
                continue;
            };

        assert_eq!(recipients, expected_recipients);
        assert_eq!(*src_key, sk.public_key());
        assert_eq!(*message, original_message_bytes);

        bounce_sent = true;
    }

    assert!(bounce_sent);

    Ok(())
}

#[tokio::test]
async fn handle_untrusted_message_from_peer() -> Result<()> {
    handle_untrusted_message(UntrustedMessageSource::Peer).await
}

#[tokio::test]
async fn handle_untrusted_accumulated_message() -> Result<()> {
    handle_untrusted_message(UntrustedMessageSource::Accumulation).await
}

enum UntrustedMessageSource {
    Peer,
    Accumulation,
}

async fn handle_untrusted_message(source: UntrustedMessageSource) -> Result<()> {
    let sk0 = bls::SecretKey::random();
    let pk0 = sk0.public_key();
    let chain = SectionProofChain::new(pk0);

    let (elders_info, _) = create_elders_info();

    let (sender, expected_recipients) = match source {
        UntrustedMessageSource::Peer => {
            // When the untrusted message is sent from a single peer, we should bounce it back to
            // that peer.
            let sender = *elders_info
                .elders
                .values()
                .next()
                .expect("elders_info is empty")
                .addr();
            (Some(sender), vec![sender])
        }
        UntrustedMessageSource::Accumulation => {
            // When the untrusted message is the result of message accumulation, we should bounce
            // it to our elders.
            (
                None,
                elders_info
                    .elders
                    .values()
                    .map(Peer::addr)
                    .copied()
                    .collect(),
            )
        }
    };

    let proven_elders_info = proven(&sk0, elders_info)?;
    let section = Section::new(chain.clone(), proven_elders_info)?;

    let node = create_node();
    let node_name = node.name();
    let state = Approved::new(node, section, None, mpsc::unbounded_channel().0);
    let stage = Stage::new(state, create_comm()?);

    let sk1 = bls::SecretKey::random();
    let pk1 = sk1.public_key();

    // Create a message signed by a key now known to the node.
    let message = PlainMessage {
        src: Prefix::default(),
        dst: DstLocation::Node(node_name),
        dst_key: pk1,
        variant: Variant::UserMessage(Bytes::from_static(b"hello")),
    };
    let signature = sk1.sign(&bincode::serialize(&message.as_signable())?);
    let original_message = Message::section_src(message, signature, SectionProofChain::new(pk1))?;

    let commands = stage
        .handle_command(Command::HandleMessage {
            message: original_message.clone(),
            sender,
        })
        .await?;

    let mut bounce_sent = false;

    for command in commands {
        let (recipients, message) = if let Command::SendMessage {
            recipients,
            message,
            ..
        } = command
        {
            (recipients, message)
        } else {
            continue;
        };

        let message = Message::from_bytes(&message)?;

        if let Variant::BouncedUntrustedMessage(bounced_message) = message.variant() {
            assert_eq!(recipients, expected_recipients);
            assert_eq!(**bounced_message, original_message);
            assert_eq!(*message.dst_key(), Some(pk0));

            bounce_sent = true;
        }
    }

    assert!(bounce_sent);

    Ok(())
}

#[tokio::test]
async fn handle_bounced_unknown_message() -> Result<()> {
    let (elders_info, mut nodes) = create_elders_info();

    // Create section chain with two keys.
    let sk0 = bls::SecretKey::random();
    let pk0 = sk0.public_key();

    let sk1_set = SecretKeySet::random();
    let pk1 = sk1_set.secret_key().public_key();
    let pk1_signature = sk0.sign(&bincode::serialize(&pk1)?);

    let mut section_chain = SectionProofChain::new(pk0);
    let _ = section_chain.push(pk1, pk1_signature);

    let proven_elders_info = proven(&sk0, elders_info)?;
    let section = Section::new(section_chain, proven_elders_info)?;
    let section_key_share = create_section_key_share(&sk1_set, 0);

    let node = nodes.remove(0);

    // Create the original message whose bounce we want to test. The content of the message doesn't
    // matter for the purpose of this test.
    let other_node = Node::new(crypto::gen_keypair(), gen_addr());
    let original_message_content = Bytes::from_static(b"unknown message");
    let original_message = Message::single_src(
        &node,
        DstLocation::Node(other_node.name()),
        Variant::UserMessage(original_message_content.clone()),
        None,
        None,
    )?;

    let state = Approved::new(
        node,
        section,
        Some(section_key_share),
        mpsc::unbounded_channel().0,
    );
    let stage = Stage::new(state, create_comm()?);

    let bounced_message = Message::single_src(
        &other_node,
        DstLocation::Direct,
        Variant::BouncedUnknownMessage {
            src_key: pk0,
            message: original_message.to_bytes(),
        },
        None,
        None,
    )?;

    let commands = stage
        .handle_command(Command::HandleMessage {
            message: bounced_message,
            sender: Some(other_node.addr),
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
            Variant::Sync { section, .. } => {
                assert_eq!(recipients, [other_node.addr]);
                assert_eq!(*section.chain().last_key(), pk1);
                sync_sent = true;
            }
            Variant::UserMessage(content) => {
                assert_eq!(recipients, [other_node.addr]);
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
async fn handle_bounced_untrusted_message() -> Result<()> {
    let (elders_info, mut nodes) = create_elders_info();

    // Create section chain with two keys.
    let sk0 = bls::SecretKey::random();
    let pk0 = sk0.public_key();

    let sk1_set = SecretKeySet::random();
    let pk1 = sk1_set.secret_key().public_key();
    let pk1_signature = sk0.sign(&bincode::serialize(&pk1)?);

    let mut chain = SectionProofChain::new(pk0);
    let _ = chain.push(pk1, pk1_signature);

    let proven_elders_info = proven(&sk0, elders_info)?;
    let section = Section::new(chain.clone(), proven_elders_info)?;
    let section_key_share = create_section_key_share(&sk1_set, 0);

    let node = nodes.remove(0);

    // Create the original message whose bounce we want to test. Attach a proof that starts
    // at `pk1`.
    let other_node = Node::new(crypto::gen_keypair(), gen_addr());

    let original_message_content = Bytes::from_static(b"unknown message");
    let original_message = PlainMessage {
        src: Prefix::default(),
        dst: DstLocation::Node(other_node.name()),
        dst_key: pk1,
        variant: Variant::UserMessage(original_message_content.clone()),
    };
    let signature = sk1_set
        .secret_key()
        .sign(&bincode::serialize(&original_message.as_signable())?);
    let proof_chain = chain.slice(1..);
    let original_message = Message::section_src(original_message, signature, proof_chain)?;

    // Create our node.
    let state = Approved::new(
        node,
        section,
        Some(section_key_share),
        mpsc::unbounded_channel().0,
    );
    let stage = Stage::new(state, create_comm()?);

    // Create the bounced message, indicating the last key the peer knows is `pk0`
    let bounced_message = Message::single_src(
        &other_node,
        DstLocation::Direct,
        Variant::BouncedUntrustedMessage(Box::new(original_message)),
        None,
        Some(pk0),
    )?;

    let commands = stage
        .handle_command(Command::HandleMessage {
            message: bounced_message,
            sender: Some(other_node.addr),
        })
        .await?;

    let mut message_sent = false;

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
            Variant::UserMessage(content) => {
                assert_eq!(recipients, [other_node.addr]);
                assert_eq!(*content, original_message_content);
                assert_eq!(*message.proof_chain()?, chain);

                message_sent = true;
            }
            _ => continue,
        }
    }

    assert!(message_sent);

    Ok(())
}

#[tokio::test]
async fn handle_sync() -> Result<()> {
    // Create first `Section` with a chain of length 2
    let sk0_set = SecretKeySet::random();
    let pk0 = sk0_set.secret_key().public_key();
    let sk1_set = SecretKeySet::random();
    let pk1 = sk1_set.secret_key().public_key();
    let pk1_signature = sk0_set.secret_key().sign(bincode::serialize(&pk1)?);

    let mut chain = SectionProofChain::new(pk0);
    assert!(chain.push(pk1, pk1_signature));

    let (old_elders_info, mut nodes) = create_elders_info();
    let proven_old_elders_info = proven(sk0_set.secret_key(), old_elders_info.clone())?;
    let old_section = Section::new(chain.clone(), proven_old_elders_info)?;

    // Create our node
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let section_key_share = create_section_key_share(&sk1_set, 0);
    let node = nodes.remove(0);
    let state = Approved::new(node, old_section, Some(section_key_share), event_tx);
    let stage = Stage::new(state, create_comm()?);

    // Create new `Section` as a successor to the previous one.
    let sk2 = bls::SecretKey::random();
    let pk2 = sk2.public_key();
    let pk2_signature = sk1_set.secret_key().sign(bincode::serialize(&pk2)?);
    assert!(chain.push(pk2, pk2_signature));

    let old_node = nodes.remove(0);

    // Create the new `EldersInfo` by replacing the last peer with a new one.
    let new_peer = create_peer();
    let new_elders_info = EldersInfo::new(
        old_elders_info
            .elders
            .values()
            .take(old_elders_info.elders.len() - 1)
            .copied()
            .chain(iter::once(new_peer)),
        old_elders_info.prefix,
    );
    let new_elders: BTreeSet<_> = new_elders_info.elders.keys().copied().collect();
    let proven_new_elders_info = proven(sk1_set.secret_key(), new_elders_info)?;
    let new_section = Section::new(chain, proven_new_elders_info)?;

    // Create the `Sync` message containing the new `Section`.
    let message = Message::single_src(
        &old_node,
        DstLocation::Direct,
        Variant::Sync {
            section: new_section,
            network: Network::new(),
        },
        None,
        None,
    )?;

    // Handle the message.
    let _ = stage
        .handle_command(Command::HandleMessage {
            message,
            sender: Some(old_node.addr),
        })
        .await?;

    // Verify our `Section` got updated.
    assert_matches!(
        event_rx.try_recv(),
        Ok(Event::EldersChanged { key, elders, .. }) => {
            assert_eq!(key, pk2);
            assert_eq!(elders, new_elders);
        }
    );

    Ok(())
}

// TODO: add test that untrusted `Sync` is not applied

#[tokio::test]
async fn receive_message_with_invalid_proof_chain() -> Result<()> {
    let sk0_good_set = SecretKeySet::random();
    let pk0_good = sk0_good_set.secret_key().public_key();

    let node = create_node();
    let peer = node.peer();

    let chain = SectionProofChain::new(pk0_good);
    let elders_info = EldersInfo::new(iter::once(peer), Prefix::default());
    let proven_elders_info = proven(sk0_good_set.secret_key(), elders_info)?;
    let section = Section::new(chain, proven_elders_info)?;
    let section_key_share = create_section_key_share(&sk0_good_set, 0);

    let state = Approved::new(
        node,
        section,
        Some(section_key_share),
        mpsc::unbounded_channel().0,
    );
    let stage = Stage::new(state, create_comm()?);

    // Create a message with a valid signature but invalid proof chain (the last key in the chain
    // not signed with the previous key)
    let sk0_bad = bls::SecretKey::random();
    let sk1_bad = bls::SecretKey::random();
    let pk1_bad = sk1_bad.public_key();
    let pk1_bad_signature = sk0_bad.sign(&bincode::serialize(&pk1_bad)?);

    let mut bad_chain = SectionProofChain::new(pk0_good);
    bad_chain.push_without_validation(pk1_bad, pk1_bad_signature);

    let message = PlainMessage {
        src: Prefix::default(),
        dst: DstLocation::Node(*peer.name()),
        dst_key: pk0_good,
        variant: Variant::UserMessage(Bytes::from_static(b"hello")),
    };
    let signature = sk1_bad.sign(&bincode::serialize(&message.as_signable())?);
    let message = Message::section_src(message, signature, bad_chain)?;

    let result = stage
        .handle_command(Command::HandleMessage {
            message,
            sender: Some(gen_addr()),
        })
        .await;

    assert_matches!(result, Err(Error::UntrustedMessage));

    Ok(())
}

#[tokio::test]
async fn relocation_of_non_elder() -> Result<()> {
    relocation(RelocatedPeerRole::NonElder).await
}

const THRESHOLD: usize = majority(ELDER_SIZE) - 1;

#[allow(dead_code)]
enum RelocatedPeerRole {
    NonElder,
    Elder,
}

async fn relocation(relocated_peer_role: RelocatedPeerRole) -> Result<()> {
    let sk_set = SecretKeySet::random();

    let prefix: Prefix = "0".parse().unwrap();
    let (elders_info, mut nodes) = gen_elders_info(prefix, ELDER_SIZE);
    let (mut section, section_key_share) = create_section(&sk_set, &elders_info)?;

    let non_elder_peer = create_peer();
    let member_info = MemberInfo::joined(non_elder_peer);
    let member_info = proven(sk_set.secret_key(), member_info)?;
    assert!(section.update_member(member_info));

    let node = nodes.remove(0);
    let state = Approved::new(
        node,
        section,
        Some(section_key_share),
        mpsc::unbounded_channel().0,
    );
    let stage = Stage::new(state, create_comm()?);

    let relocated_peer = match relocated_peer_role {
        RelocatedPeerRole::Elder => elders_info.peers().nth(1).expect("too few elders"),
        RelocatedPeerRole::NonElder => &non_elder_peer,
    };

    let (vote, proof) = create_relocation_trigger(sk_set.secret_key(), relocated_peer.age())?;
    let commands = stage
        .handle_command(Command::HandleConsensus { vote, proof })
        .await?;

    let mut relocate_sent = false;

    for command in commands {
        let (recipients, message) = match command {
            Command::SendMessage {
                recipients,
                message,
                ..
            } => (recipients, message),
            _ => continue,
        };

        if recipients != [*relocated_peer.addr()] {
            continue;
        }

        let message = Message::from_bytes(&message)?;
        let message = match message.variant() {
            Variant::Vote {
                content: Vote::SendMessage { message, .. },
                ..
            } => message,
            _ => continue,
        };

        match relocated_peer_role {
            RelocatedPeerRole::NonElder => {
                let details = match &message.variant {
                    Variant::Relocate(details) => details,
                    _ => continue,
                };

                assert_eq!(details.pub_id, *relocated_peer.name());
                assert_eq!(details.age, relocated_peer.age() + 1);
            }
            RelocatedPeerRole::Elder => {
                let promise = match &message.variant {
                    Variant::RelocatePromise(promise) => promise,
                    _ => continue,
                };

                assert_eq!(promise.name, *relocated_peer.name());
            }
        }

        relocate_sent = true;
    }

    assert!(relocate_sent);

    Ok(())
}

// TODO: add more tests here

fn create_peer() -> Peer {
    Peer::new(rand::random(), gen_addr(), MIN_AGE)
}

fn create_node() -> Node {
    Node::new(crypto::gen_keypair(), gen_addr())
}

fn create_comm() -> Result<Comm> {
    let (tx, _rx) = mpsc::channel(1);
    Ok(Comm::new(
        qp2p::Config {
            ip: Some(Ipv4Addr::LOCALHOST.into()),
            ..Default::default()
        },
        tx,
    )?)
}

// Generate random EldersInfo and the corresponding Nodes.
fn create_elders_info() -> (EldersInfo, Vec<Node>) {
    gen_elders_info(Default::default(), ELDER_SIZE)
}

fn create_section_key_share(sk_set: &bls::SecretKeySet, index: usize) -> SectionKeyShare {
    SectionKeyShare {
        public_key_set: sk_set.public_keys(),
        index,
        secret_key_share: sk_set.secret_key_share(index),
    }
}

fn create_section(
    sk_set: &SecretKeySet,
    elders_info: &EldersInfo,
) -> Result<(Section, SectionKeyShare)> {
    let section_chain = SectionProofChain::new(sk_set.secret_key().public_key());
    let proven_elders_info = proven(sk_set.secret_key(), elders_info.clone())?;

    let mut section = Section::new(section_chain, proven_elders_info)?;

    for peer in elders_info.elders.values().copied() {
        let member_info = MemberInfo::joined(peer);
        let member_info = proven(sk_set.secret_key(), member_info)?;
        let _ = section.update_member(member_info);
    }

    let section_key_share = create_section_key_share(sk_set, 0);

    Ok((section, section_key_share))
}

// Create a `Vote::Online` whose consensus handling triggers relocation of a node with the given age.
// NOTE: recommended to call this with low `age` (4 or 5), otherwise it might take very long time
// to complete because it needs to generate a signature with the number of trailing zeroes equal to
// (or greater that) `age`.
fn create_relocation_trigger(sk: &bls::SecretKey, age: u8) -> Result<(Vote, Proof)> {
    loop {
        let vote = Vote::Online {
            member_info: MemberInfo::joined(create_peer().with_age(MIN_AGE + 1)),
            previous_name: Some(rand::random()),
            their_knowledge: None,
        };

        let signature = sk.sign(&bincode::serialize(&vote.as_signable())?);

        if relocation::check(age, &signature) && !relocation::check(age + 1, &signature) {
            let proof = Proof {
                public_key: sk.public_key(),
                signature,
            };

            return Ok((vote, proof));
        }
    }
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
        let poly = bls::poly::Poly::random(THRESHOLD, &mut rand::thread_rng());
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

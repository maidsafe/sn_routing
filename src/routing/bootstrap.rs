// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{comm::ConnectionEvent, Comm};
use crate::{
    consensus::Proven,
    crypto::{self, Signature},
    error::{Error, Result},
    location::DstLocation,
    messages::{JoinRequest, Message, ResourceProofResponse, Variant, VerifyStatus},
    node::Node,
    peer::Peer,
    relocation::{RelocatePayload, SignedRelocateDetails},
    section::{EldersInfo, Section},
    SectionProofChain,
};
use bytes::Bytes;
use futures::future;
use resource_proof::ResourceProof;
use sn_messaging::{
    infrastructure::{GetSectionResponse, Query},
    node::NodeMessage,
    MessageType, WireMsg,
};
use std::{
    collections::{BTreeMap, VecDeque},
    mem,
    net::SocketAddr,
};
use tokio::sync::mpsc;
use tracing::Instrument;
use xor_name::{Prefix, XorName};

const BACKLOG_CAPACITY: usize = 100;

/// Bootstrap into the network as new node.
///
/// NOTE: It's not guaranteed this function ever returns. This can happen due to messages being
/// lost in transit or other reasons. It's the responsibility of the caller to handle this case,
/// for example by using a timeout.
pub(crate) async fn initial(
    node: Node,
    comm: &Comm,
    incoming_conns: &mut mpsc::Receiver<ConnectionEvent>,
    bootstrap_addr: SocketAddr,
) -> Result<(Node, Section, Vec<(Message, SocketAddr)>)> {
    let (send_tx, send_rx) = mpsc::channel(1);
    let recv_rx = MessageReceiver::Raw(incoming_conns);

    let span = trace_span!("bootstrap::initial", name = %node.name());

    let state = State::new(node, send_tx, recv_rx)?;

    future::join(
        state.run(vec![bootstrap_addr], None),
        send_messages(send_rx, comm),
    )
    .instrument(span)
    .await
    .0
}

/// Re-bootstrap as a relocated node.
///
/// NOTE: It's not guaranteed this function ever returns. This can happen due to messages being
/// lost in transit or other reasons. It's the responsibility of the caller to handle this case,
/// for example by using a timeout.
pub(crate) async fn relocate(
    node: Node,
    comm: &Comm,
    recv_rx: mpsc::Receiver<(MessageType, SocketAddr)>,
    bootstrap_addrs: Vec<SocketAddr>,
    relocate_details: SignedRelocateDetails,
) -> Result<(Node, Section, Vec<(Message, SocketAddr)>)> {
    let (send_tx, send_rx) = mpsc::channel(1);
    let recv_rx = MessageReceiver::Deserialized(recv_rx);

    let span = trace_span!("bootstrap::relocate", name = %node.name());

    let state = State::new(node, send_tx, recv_rx)?;

    future::join(
        state.run(bootstrap_addrs, Some(relocate_details)),
        send_messages(send_rx, comm),
    )
    .instrument(span)
    .await
    .0
}

struct State<'a> {
    // Sender for outgoing messages.
    send_tx: mpsc::Sender<(MessageType, Vec<SocketAddr>)>,
    // Receiver for incoming messages.
    recv_rx: MessageReceiver<'a>,
    node: Node,
    // Backlog for unknown messages
    backlog: VecDeque<(Message, SocketAddr)>,
}

impl<'a> State<'a> {
    fn new(
        node: Node,
        send_tx: mpsc::Sender<(MessageType, Vec<SocketAddr>)>,
        recv_rx: MessageReceiver<'a>,
    ) -> Result<Self> {
        Ok(Self {
            send_tx,
            recv_rx,
            node,
            backlog: VecDeque::with_capacity(BACKLOG_CAPACITY),
        })
    }

    async fn run(
        mut self,
        bootstrap_addrs: Vec<SocketAddr>,
        relocate_details: Option<SignedRelocateDetails>,
    ) -> Result<(Node, Section, Vec<(Message, SocketAddr)>)> {
        let (prefix, section_key, elders) = self
            .bootstrap(bootstrap_addrs, relocate_details.as_ref())
            .await?;

        let relocate_payload = if let Some(details) = relocate_details {
            Some(self.process_relocation(&prefix, details))
        } else {
            None
        };

        self.join(section_key, elders, relocate_payload).await
    }

    // Send a `GetSectionRequest` and waits for the response. If the response is `Redirect`,
    // repeat with the new set of contacts. If it is `Success`, proceeed to the `join` phase.
    async fn bootstrap(
        &mut self,
        mut bootstrap_addrs: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<(Prefix, bls::PublicKey, BTreeMap<XorName, SocketAddr>)> {
        loop {
            self.send_get_section_request(mem::take(&mut bootstrap_addrs), relocate_details)
                .await?;

            let (response, sender) = self.receive_get_section_response().await?;

            match response {
                GetSectionResponse::Success {
                    prefix,
                    key,
                    elders,
                } => {
                    info!(
                        "Joining a section ({:b}), key: {:?}, elders: {:?} (given by {:?})",
                        prefix, key, elders, sender
                    );
                    return Ok((prefix, key, elders));
                }
                GetSectionResponse::Redirect(new_bootstrap_addrs) => {
                    info!(
                        "Bootstrapping redirected to another set of peers: {:?}",
                        new_bootstrap_addrs,
                    );
                    bootstrap_addrs = new_bootstrap_addrs.to_vec();
                }
            }
        }
    }

    async fn send_get_section_request(
        &mut self,
        recipients: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<()> {
        debug!(
            "{} Sending GetSectionRequest to {:?}",
            self.node, recipients
        );

        let destination = match relocate_details {
            Some(details) => *details.destination(),
            None => self.node.name(),
        };

        let message = Query::GetSectionRequest(destination);

        let _ = self
            .send_tx
            .send((MessageType::InfrastructureQuery(message), recipients))
            .await;

        Ok(())
    }

    async fn receive_get_section_response(&mut self) -> Result<(GetSectionResponse, SocketAddr)> {
        while let Some((message, sender)) = self.recv_rx.next().await {
            match message {
                MessageType::InfrastructureQuery(Query::GetSectionResponse(response)) => {
                    match response {
                        GetSectionResponse::Redirect(addrs) if addrs.is_empty() => {
                            error!("Invalid GetSectionResponse::Redirect: missing peers");
                            continue;
                        }
                        GetSectionResponse::Success { prefix, .. }
                            if !prefix.matches(&self.node.name()) =>
                        {
                            error!("Invalid GetSectionResponse::Success: bad prefix");
                            continue;
                        }
                        GetSectionResponse::Redirect(_) | GetSectionResponse::Success { .. } => {
                            return Ok((response, sender))
                        }
                    }
                }
                MessageType::NodeMessage(NodeMessage(msg_bytes)) => {
                    let message = Message::from_bytes(Bytes::from(msg_bytes))?;
                    self.backlog_message(message, sender)
                }
                MessageType::InfrastructureQuery(_)
                | MessageType::ClientMessage(_)
                | MessageType::Ping => {}
            }
        }

        error!("Message sender unexpectedly closed");
        // TODO: consider more specific error here (e.g. `BootstrapInterrupted`)
        Err(Error::InvalidState)
    }

    // Change our name to fit the destination section and apply the new age.
    fn process_relocation(
        &mut self,
        prefix: &Prefix,
        relocate_details: SignedRelocateDetails,
    ) -> RelocatePayload {
        // We are relocating so we need to change our name.
        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            prefix.bit_count() + extra_split_count,
            *relocate_details.destination(),
        );

        let new_keypair = crypto::gen_keypair_within_range(&name_prefix.range_inclusive());
        let new_name = crypto::name(&new_keypair.public);
        let age = relocate_details.relocate_details().age;
        let relocate_payload =
            RelocatePayload::new(relocate_details, &new_name, &self.node.keypair);

        info!("Changing name to {}", new_name);
        self.node = Node::new(new_keypair, self.node.addr).with_age(age);

        relocate_payload
    }

    // Send `JoinRequest` and wait for the response. If the response is `Rejoin`, repeat with the
    // new info. If it is `Approval`, returns the initial `Section` value to use by this node,
    // completing the bootstrap. If it is `Challenge`, carries out a resource proof calculation.
    async fn join(
        mut self,
        mut section_key: bls::PublicKey,
        elders: BTreeMap<XorName, SocketAddr>,
        relocate_payload: Option<RelocatePayload>,
    ) -> Result<(Node, Section, Vec<(Message, SocketAddr)>)> {
        let join_request = JoinRequest {
            section_key,
            relocate_payload: relocate_payload.clone(),
            resource_proof_response: None,
        };
        let recipients = elders.into_iter().map(|(_, addr)| addr).collect();
        self.send_join_requests(join_request, recipients).await?;

        loop {
            let (response, sender) = self
                .receive_join_response(relocate_payload.as_ref())
                .await?;

            match response {
                JoinResponse::Approval {
                    elders_info,
                    age,
                    section_chain,
                } => {
                    return Ok((
                        self.node.with_age(age),
                        Section::new(section_chain, elders_info)?,
                        self.backlog.into_iter().collect(),
                    ));
                }
                JoinResponse::Rejoin {
                    elders_info,
                    section_key: new_section_key,
                } => {
                    if new_section_key == section_key {
                        continue;
                    }

                    if elders_info.prefix.matches(&self.node.name()) {
                        info!(
                            "Newer Join response for our prefix {:?} from {:?}",
                            elders_info, sender
                        );
                        section_key = new_section_key;
                        let join_request = JoinRequest {
                            section_key,
                            relocate_payload: relocate_payload.clone(),
                            resource_proof_response: None,
                        };
                        let recipients = elders_info.peers().map(Peer::addr).copied().collect();
                        self.send_join_requests(join_request, recipients).await?;
                    } else {
                        warn!(
                            "Newer Join response not for our prefix {:?} from {:?}",
                            elders_info, sender,
                        );
                    }
                }
                JoinResponse::ResourceChallenge {
                    data_size,
                    difficulty,
                    nonce,
                    nonce_signature,
                } => {
                    let rp = ResourceProof::new(data_size, difficulty);
                    let data = rp.create_proof_data(&nonce);
                    let mut prover = rp.create_prover(data.clone());
                    let solution = prover.solve();

                    let join_request = JoinRequest {
                        section_key,
                        relocate_payload: relocate_payload.clone(),
                        resource_proof_response: Some(ResourceProofResponse {
                            solution,
                            data,
                            nonce,
                            nonce_signature,
                        }),
                    };
                    let recipients = vec![sender];
                    self.send_join_requests(join_request, recipients).await?;
                }
            }
        }
    }

    async fn send_join_requests(
        &mut self,
        join_request: JoinRequest,
        recipients: Vec<SocketAddr>,
    ) -> Result<()> {
        info!("Sending {:?} to {:?}", join_request, recipients);

        let variant = Variant::JoinRequest(Box::new(join_request));
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;
        let node_msg = NodeMessage::new(message.to_bytes());

        let _ = self
            .send_tx
            .send((MessageType::NodeMessage(node_msg), recipients))
            .await;

        Ok(())
    }

    async fn receive_join_response(
        &mut self,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<(JoinResponse, SocketAddr)> {
        while let Some((message, sender)) = self.recv_rx.next().await {
            let message = match message {
                MessageType::NodeMessage(NodeMessage(msg_bytes)) => {
                    Message::from_bytes(Bytes::from(msg_bytes))?
                }
                MessageType::Ping
                | MessageType::ClientMessage(_)
                | MessageType::InfrastructureQuery(_) => continue,
            };

            match message.variant() {
                Variant::Rejoin {
                    elders_info,
                    section_key,
                } => {
                    if !self.verify_message(&message, None) {
                        continue;
                    }

                    return Ok((
                        JoinResponse::Rejoin {
                            elders_info: elders_info.clone(),
                            section_key: *section_key,
                        },
                        sender,
                    ));
                }
                Variant::ResourceChallenge {
                    data_size,
                    difficulty,
                    nonce,
                    nonce_signature,
                } => {
                    if relocate_payload.is_some() {
                        trace!("Ignore ResourceChallenge when relocating");
                        continue;
                    }

                    if !self.verify_message(&message, None) {
                        continue;
                    }

                    return Ok((
                        JoinResponse::ResourceChallenge {
                            data_size: *data_size,
                            difficulty: *difficulty,
                            nonce: *nonce,
                            nonce_signature: *nonce_signature,
                        },
                        sender,
                    ));
                }
                Variant::NodeApproval {
                    elders_info,
                    member_info,
                } => {
                    if member_info.value.peer.name() != &self.node.name() {
                        trace!("Ignore NodeApproval not for us");
                        continue;
                    }

                    let trusted_key = if let Some(payload) = relocate_payload {
                        Some(&payload.relocate_details().destination_key)
                    } else {
                        None
                    };

                    if !self.verify_message(&message, trusted_key) {
                        continue;
                    }

                    // Transition from Joining to Approved
                    let section_chain = message.proof_chain()?.clone();

                    info!(
                        "This node has been approved to join the network at {:?}!",
                        elders_info.value.prefix,
                    );

                    return Ok((
                        JoinResponse::Approval {
                            elders_info: elders_info.clone(),
                            age: member_info.value.peer.age(),
                            section_chain,
                        },
                        sender,
                    ));
                }

                _ => self.backlog_message(message, sender),
            }
        }

        error!("Message sender unexpectedly closed");
        // TODO: consider more specific error here (e.g. `BootstrapInterrupted`)
        Err(Error::InvalidState)
    }

    fn verify_message(&self, message: &Message, trusted_key: Option<&bls::PublicKey>) -> bool {
        // The message verification will use only those trusted keys whose prefix is compatible with
        // the message source. By using empty prefix, we make sure `trusted_key` is always used.
        let prefix = Prefix::default();

        match message.verify(trusted_key.map(|key| (&prefix, key))) {
            Ok(VerifyStatus::Full) => true,
            Ok(VerifyStatus::Unknown) if trusted_key.is_none() => true,
            Ok(VerifyStatus::Unknown) => {
                // TODO: bounce
                error!("Verification failed - untrusted message: {:?}", message);
                false
            }
            Err(error) => {
                error!("Verification failed - {}: {:?}", error, message);
                false
            }
        }
    }

    fn backlog_message(&mut self, message: Message, sender: SocketAddr) {
        while self.backlog.len() >= BACKLOG_CAPACITY {
            let _ = self.backlog.pop_front();
        }

        self.backlog.push_back((message, sender))
    }
}

enum JoinResponse {
    Approval {
        elders_info: Proven<EldersInfo>,
        age: u8,
        section_chain: SectionProofChain,
    },
    Rejoin {
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
    },
    ResourceChallenge {
        data_size: usize,
        difficulty: u8,
        nonce: [u8; 32],
        nonce_signature: Signature,
    },
}

// Receiver of incoming messages that can be backed either by a raw `qp2p::ConnectionEvent` receiver
// or by receiver of deserialized `Message` and provides a unified interface on top of them.
enum MessageReceiver<'a> {
    Raw(&'a mut mpsc::Receiver<ConnectionEvent>),
    Deserialized(mpsc::Receiver<(MessageType, SocketAddr)>),
}

impl<'a> MessageReceiver<'a> {
    async fn next(&mut self) -> Option<(MessageType, SocketAddr)> {
        match self {
            Self::Raw(rx) => {
                while let Some(event) = rx.recv().await {
                    match event {
                        ConnectionEvent::Received(qp2p::Message::UniStream {
                            bytes, src, ..
                        }) => match WireMsg::deserialize(bytes) {
                            Ok(message) => return Some((message, src)),
                            Err(error) => debug!("Failed to deserialize message: {}", error),
                        },
                        ConnectionEvent::Received(qp2p::Message::BiStream { .. }) => {
                            trace!("Ignore bi-stream messages during bootstrap");
                        }
                        ConnectionEvent::Disconnected(_) => {}
                    }
                }
                None
            }
            Self::Deserialized(rx) => rx.recv().await,
        }
    }
}

// Keep reading messages from `rx` and send them using `comm`.
async fn send_messages(mut rx: mpsc::Receiver<(MessageType, Vec<SocketAddr>)>, comm: &Comm) {
    while let Some((message, recipients)) = rx.recv().await {
        match message.serialize() {
            Ok(msg_bytes) => {
                let _ = comm.send(&recipients, recipients.len(), msg_bytes).await;
            }
            Err(error) => error!(
                "Failed to send message {:?} to {:?}: {}",
                message, recipients, error
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::test_utils::*, section::test_utils::*, section::MemberInfo, ELDER_SIZE, MIN_AGE,
    };
    use anyhow::{Error, Result};
    use assert_matches::assert_matches;
    use futures::future::{self, Either};
    use tokio::{sync::mpsc::error::TryRecvError, task};

    #[tokio::test]
    async fn bootstrap_as_adult() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (elders_info, mut nodes) = gen_elders_info(Default::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let bootstrap_addr = bootstrap_node.addr;

        let sk = bls::SecretKey::random();
        let pk = sk.public_key();

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let peer = node.peer();
        let state = State::new(node, send_tx, recv_rx)?;

        // Create the bootstrap task, but don't run it yet.
        let bootstrap = async move {
            state
                .run(vec![bootstrap_addr], None)
                .await
                .map_err(Error::from)
        };

        // Create the task that executes the body of the test, but don't run it either.
        let others = async {
            task::yield_now().await;

            // Receive GetSectionRequest
            let (message, recipients) = send_rx.try_recv()?;

            assert_eq!(recipients, [bootstrap_addr]);
            assert_matches!(message, MessageType::InfrastructureQuery(Query::GetSectionRequest(name)) => {
                assert_eq!(name, *peer.name());
            });

            // Send GetSectionResponse::Success
            let message = Query::GetSectionResponse(GetSectionResponse::Success {
                prefix: elders_info.prefix,
                key: pk,
                elders: elders_info
                    .peers()
                    .map(|peer| (*peer.name(), *peer.addr()))
                    .collect(),
            });
            recv_tx.try_send((MessageType::InfrastructureQuery(message), bootstrap_addr))?;
            task::yield_now().await;

            // Receive JoinRequest
            let (message, recipients) = send_rx.try_recv()?;
            let message = assert_matches!(message, MessageType::NodeMessage(NodeMessage(bytes)) => Message::from_bytes(Bytes::from(bytes))?);

            itertools::assert_equal(&recipients, elders_info.peers().map(Peer::addr));
            assert_matches!(message.variant(), Variant::JoinRequest(request) => {
                assert_eq!(request.section_key, pk);
                assert!(request.relocate_payload.is_none());
            });

            // Send NodeApproval
            let elders_info = proven(&sk, elders_info.clone())?;
            let member_info = proven(&sk, MemberInfo::joined(peer.with_age(MIN_AGE + 1)))?;
            let proof_chain = SectionProofChain::new(pk);
            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::NodeApproval {
                    elders_info,
                    member_info,
                },
                Some(proof_chain),
                None,
            )?;

            recv_tx.try_send((
                MessageType::NodeMessage(NodeMessage::new(message.to_bytes())),
                bootstrap_addr,
            ))?;

            Ok(())
        };

        // Drive both tasks to completion concurrently (but on the same thread).
        let ((node, section, _backlog), _) = future::try_join(bootstrap, others).await?;

        assert_eq!(*section.elders_info(), elders_info);
        assert_eq!(*section.chain().last_key(), pk);
        assert_eq!(node.age, MIN_AGE + 1);

        Ok(())
    }

    #[tokio::test]
    async fn receive_get_section_response_redirect() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(crypto::gen_keypair(), gen_addr());

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let mut state = State::new(node, send_tx, recv_rx)?;

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);
        let test_task = async {
            task::yield_now().await;

            // Receive GetSectionRequest
            let (message, recipients) = send_rx.try_recv()?;

            assert_eq!(recipients, vec![bootstrap_node.addr]);
            assert_matches!(
                message,
                MessageType::InfrastructureQuery(Query::GetSectionRequest(_))
            );

            // Send GetSectionResponse::Redirect
            let new_bootstrap_addrs: Vec<_> = (0..ELDER_SIZE).map(|_| gen_addr()).collect();
            let message = Query::GetSectionResponse(GetSectionResponse::Redirect(
                new_bootstrap_addrs.clone(),
            ));

            recv_tx.try_send((
                MessageType::InfrastructureQuery(message),
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            // Receive new GetSectionRequest
            let (message, recipients) = send_rx.try_recv()?;

            assert_eq!(recipients, new_bootstrap_addrs);
            assert_matches!(
                message,
                MessageType::InfrastructureQuery(Query::GetSectionRequest(_))
            );

            Ok(())
        };

        futures::pin_mut!(bootstrap_task);
        futures::pin_mut!(test_task);

        match future::select(bootstrap_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }

    #[tokio::test]
    async fn invalid_get_section_response_redirect() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(crypto::gen_keypair(), gen_addr());

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let mut state = State::new(node, send_tx, recv_rx)?;

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);
        let test_task = async {
            task::yield_now().await;

            let (message, _) = send_rx.try_recv()?;
            assert_matches!(
                message,
                MessageType::InfrastructureQuery(Query::GetSectionRequest(_))
            );

            let message = Query::GetSectionResponse(GetSectionResponse::Redirect(vec![]));

            recv_tx.try_send((
                MessageType::InfrastructureQuery(message),
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;
            assert_matches!(send_rx.try_recv(), Err(TryRecvError::Empty));

            let addrs = (0..ELDER_SIZE).map(|_| gen_addr()).collect();
            let message = Query::GetSectionResponse(GetSectionResponse::Redirect(addrs));

            recv_tx.try_send((
                MessageType::InfrastructureQuery(message),
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            let (message, _) = send_rx.try_recv()?;
            assert_matches!(
                message,
                MessageType::InfrastructureQuery(Query::GetSectionRequest(_))
            );

            Ok(())
        };

        futures::pin_mut!(bootstrap_task);
        futures::pin_mut!(test_task);

        match future::select(bootstrap_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }

    #[tokio::test]
    async fn invalid_get_section_response_success() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(crypto::gen_keypair(), gen_addr());
        let node = Node::new(crypto::gen_keypair(), gen_addr());

        let (good_prefix, bad_prefix) = {
            let p0 = Prefix::default().pushed(false);
            let p1 = Prefix::default().pushed(true);

            if node.name().bit(0) {
                (p1, p0)
            } else {
                (p0, p1)
            }
        };

        let mut state = State::new(node, send_tx, recv_rx)?;

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);

        // Send an invalid `BootstrapResponse::Join` followed by a valid one. The invalid one is
        // ignored and the valid one processed normally.
        let test_task = async {
            task::yield_now().await;

            let (message, _) = send_rx.try_recv()?;
            assert_matches!(
                message,
                MessageType::InfrastructureQuery(Query::GetSectionRequest(_))
            );

            let message = Query::GetSectionResponse(GetSectionResponse::Success {
                prefix: bad_prefix,
                key: bls::SecretKey::random().public_key(),
                elders: (0..ELDER_SIZE)
                    .map(|_| (bad_prefix.substituted_in(rand::random()), gen_addr()))
                    .collect(),
            });

            recv_tx.try_send((
                MessageType::InfrastructureQuery(message),
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;
            assert_matches!(send_rx.try_recv(), Err(TryRecvError::Empty));

            let message = Query::GetSectionResponse(GetSectionResponse::Success {
                prefix: good_prefix,
                key: bls::SecretKey::random().public_key(),
                elders: (0..ELDER_SIZE)
                    .map(|_| (good_prefix.substituted_in(rand::random()), gen_addr()))
                    .collect(),
            });

            recv_tx.try_send((
                MessageType::InfrastructureQuery(message),
                bootstrap_node.addr,
            ))?;

            Ok(())
        };

        let (bootstrap_result, test_result) = future::join(bootstrap_task, test_task).await;
        let _ = bootstrap_result?;
        test_result
    }

    #[tokio::test]
    async fn invalid_join_response_rejoin() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(crypto::gen_keypair(), gen_addr());
        let node = Node::new(crypto::gen_keypair(), gen_addr());

        let (good_prefix, bad_prefix) = {
            let p0 = Prefix::default().pushed(false);
            let p1 = Prefix::default().pushed(true);

            if node.name().bit(0) {
                (p1, p0)
            } else {
                (p0, p1)
            }
        };

        let state = State::new(node, send_tx, recv_rx)?;

        let section_key = bls::SecretKey::random().public_key();
        let elders = (0..ELDER_SIZE)
            .map(|_| (good_prefix.substituted_in(rand::random()), gen_addr()))
            .collect();
        let join_task = state.join(section_key, elders, None);

        let test_task = async {
            task::yield_now().await;

            let (message, _) = send_rx.try_recv()?;
            let message = assert_matches!(message, MessageType::NodeMessage(NodeMessage(bytes)) => Message::from_bytes(Bytes::from(bytes))?);
            assert_matches!(message.variant(), Variant::JoinRequest(_));

            // Send `Rejoin` with bad prefix
            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::Rejoin {
                    elders_info: gen_elders_info(bad_prefix, ELDER_SIZE).0,
                    section_key: bls::SecretKey::random().public_key(),
                },
                None,
                None,
            )?;

            recv_tx.try_send((
                MessageType::NodeMessage(NodeMessage::new(message.to_bytes())),
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;
            assert_matches!(send_rx.try_recv(), Err(TryRecvError::Empty));

            // Send `Rejoin` with good prefix
            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::Rejoin {
                    elders_info: gen_elders_info(good_prefix, ELDER_SIZE).0,
                    section_key: bls::SecretKey::random().public_key(),
                },
                None,
                None,
            )?;

            recv_tx.try_send((
                MessageType::NodeMessage(NodeMessage::new(message.to_bytes())),
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            let (message, _) = send_rx.try_recv()?;
            let message = assert_matches!(message, MessageType::NodeMessage(NodeMessage(bytes)) => Message::from_bytes(Bytes::from(bytes))?);
            assert_matches!(message.variant(), Variant::JoinRequest(_));

            Ok(())
        };

        futures::pin_mut!(join_task);
        futures::pin_mut!(test_task);

        match future::select(join_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }
}

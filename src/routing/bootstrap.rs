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
    external_messages::{ExternalMessage, GetSectionResponse},
    location::DstLocation,
    messages::{
        BootstrapResponse, JoinRequest, Message, ResourceProofResponse, Variant, VerifyStatus,
    },
    node::Node,
    peer::Peer,
    relocation::{RelocatePayload, SignedRelocateDetails},
    section::{EldersInfo, Section},
    SectionProofChain,
};
use bytes::Bytes;
use futures::{future, stream::FuturesUnordered, StreamExt};
use itertools::Itertools;
use resource_proof::ResourceProof;
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
};
use tokio::sync::{mpsc, oneshot};
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

    let state = State::new(node, send_tx, recv_rx)?;

    future::join(
        state.run(vec![bootstrap_addr], None),
        send_messages(send_rx, comm),
    )
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
    recv_rx: mpsc::Receiver<(Message, SocketAddr)>,
    bootstrap_addrs: Vec<SocketAddr>,
    relocate_details: SignedRelocateDetails,
) -> Result<(Node, Section, Vec<(Message, SocketAddr)>)> {
    let (send_tx, send_rx) = mpsc::channel(1);
    let recv_rx = MessageReceiver::Deserialized(recv_rx);

    let state = State::new(node, send_tx, recv_rx)?;

    future::join(
        state.run(bootstrap_addrs, Some(relocate_details)),
        send_messages(send_rx, comm),
    )
    .await
    .0
}

struct State<'a> {
    // Sender for outgoing messages.
    send_tx: mpsc::Sender<(Bytes, Target)>,
    // Receiver for incoming messages.
    recv_rx: MessageReceiver<'a>,
    node: Node,
    // Backlog for unknown messages
    backlog: VecDeque<(Message, SocketAddr)>,
}

impl<'a> State<'a> {
    fn new(
        node: Node,
        send_tx: mpsc::Sender<(Bytes, Target)>,
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

        self.join(elders, section_key, relocate_payload).await
    }

    // Query the network for the information about the section to join.
    async fn bootstrap(
        &mut self,
        addrs: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<(Prefix, bls::PublicKey, BTreeMap<XorName, SocketAddr>)> {
        let destination = match relocate_details {
            Some(details) => *details.destination(),
            None => self.node.name(),
        };

        let request = ExternalMessage::GetSection(destination);
        let request: Bytes = bincode::serialize(&request)?.into();

        // Task to send `GetSection` request to a single node and await the response.
        let task = |addr| {
            let mut send_tx = self.send_tx.clone();
            let request = request.clone();
            async move {
                trace!("Sending GetSection to {}", addr);

                let (target, rx) = Target::bi(addr);
                let _ = send_tx.send((request.clone(), target)).await;
                let response = rx.await.ok()?;
                let response: GetSectionResponse = bincode::deserialize(&response).ok()?;
                Some(response)
            }
        };

        // Send the requests to all the recipients concurrently.
        let mut tasks: FuturesUnordered<_> = addrs.into_iter().map(task).collect();

        while let Some(response) = tasks.next().await {
            match response {
                Some(GetSectionResponse::Ok {
                    prefix,
                    key,
                    elders,
                }) if prefix.matches(&destination) => {
                    info!(
                        "Joining section ({:b}), key: {:?}, elders: {{{}}})",
                        prefix,
                        key,
                        elders.keys().format(", ")
                    );
                    return Ok((prefix, key, elders));
                }
                Some(GetSectionResponse::Ok { .. }) => {
                    error!("Invalid GetSectionResponse: bad prefix");
                    continue;
                }
                Some(GetSectionResponse::Redirect(addrs)) => {
                    info!(
                        "Bootstrapping redirected to another set of peers: {:?}",
                        addrs
                    );

                    for addr in addrs {
                        tasks.push(task(addr));
                    }
                }
                None => continue,
            }
        }

        error!("Failed to retrieve section details");
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

        info!("{} Changing name to {}.", self.node, new_name);
        self.node = Node::new(new_keypair, self.node.addr).with_age(age);

        relocate_payload
    }

    // Send `JoinRequest` and wait for the response. If the response is `Rejoin`, repeat with the
    // new info. If it is `Approval`, returns the initial `Section` value to use by this node,
    // completing the bootstrap. If it is `Challenge`, carries out a resource proof calculation.
    async fn join(
        mut self,
        elders: BTreeMap<XorName, SocketAddr>,
        mut section_key: bls::PublicKey,
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
                            "{} Newer Join response for our prefix {:?} from {:?}",
                            self.node, elders_info, sender
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
        info!(
            "{} Sending {:?} to {:?}",
            self.node, join_request, recipients
        );

        let variant = Variant::JoinRequest(Box::new(join_request));
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;

        let _ = self
            .send_tx
            .send((message.to_bytes(), Target::Uni(recipients)))
            .await;

        Ok(())
    }

    async fn receive_join_response(
        &mut self,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<(JoinResponse, SocketAddr)> {
        while let Some((message, sender)) = self.recv_rx.next().await {
            match message.variant() {
                Variant::BootstrapResponse(BootstrapResponse::Join {
                    elders_info,
                    section_key,
                }) => {
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
                        "{} This node has been approved to join the network at {:?}!",
                        self.node, elders_info.value.prefix,
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

        error!("{} Message sender unexpectedly closed", self.node);
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
    Deserialized(mpsc::Receiver<(Message, SocketAddr)>),
}

impl<'a> MessageReceiver<'a> {
    async fn next(&mut self) -> Option<(Message, SocketAddr)> {
        match self {
            Self::Raw(rx) => {
                while let Some(event) = rx.recv().await {
                    match event {
                        ConnectionEvent::Received(qp2p::Message::UniStream {
                            bytes, src, ..
                        }) => match Message::from_bytes(&bytes) {
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

#[derive(Debug)]
enum Target {
    Uni(Vec<SocketAddr>),
    Bi {
        addr: SocketAddr,
        tx: oneshot::Sender<Bytes>,
    },
}

impl Target {
    fn bi(addr: SocketAddr) -> (Self, oneshot::Receiver<Bytes>) {
        let (tx, rx) = oneshot::channel();
        (Self::Bi { addr, tx }, rx)
    }
}

// Keep reading messages from `rx` and send them using `comm`.
async fn send_messages(mut rx: mpsc::Receiver<(Bytes, Target)>, comm: &Comm) {
    while let Some((message, target)) = rx.recv().await {
        match target {
            Target::Uni(addrs) => {
                let _ = comm
                    .send_message_to_targets(&addrs, addrs.len(), message)
                    .await;
            }
            Target::Bi { addr, tx } => {
                let _ = send_and_receive(comm, &addr, message, tx).await;
            }
        }
    }
}

async fn send_and_receive(
    comm: &Comm,
    addr: &SocketAddr,
    message: Bytes,
    tx: oneshot::Sender<Bytes>,
) -> Result<(), qp2p::Error> {
    let conn = comm.connect_to(addr).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.send_user_msg(message).await?;

    if let Ok(response) = recv.next().await {
        let _ = tx.send(response);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

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

            // Receive GetSection request
            let (addr, name, response_tx) = receive_get_section_request(&mut send_rx)?;
            assert_eq!(addr, bootstrap_addr);
            assert_eq!(name, *peer.name());

            // Send GetSection response
            let response = GetSectionResponse::Ok {
                prefix: elders_info.prefix,
                key: pk,
                elders: elders_info
                    .peers()
                    .map(|peer| (*peer.name(), *peer.addr()))
                    .collect(),
            };
            let response = bincode::serialize(&response)?.into();

            let _ = response_tx.send(response);
            task::yield_now().await;

            // Receive JoinRequest
            let (bytes, target) = send_rx.try_recv()?;
            let message = Message::from_bytes(&bytes)?;

            let recipients = assert_matches!(target, Target::Uni(recipients) => recipients);
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

            recv_tx.try_send((message, bootstrap_addr))?;

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
        let (_, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(crypto::gen_keypair(), gen_addr());

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let mut state = State::new(node, send_tx, recv_rx)?;

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);
        let test_task = async {
            task::yield_now().await;

            // Receive GetSection request
            let (addr, _, response_tx) = receive_get_section_request(&mut send_rx)?;
            assert_eq!(addr, bootstrap_node.addr);

            // Send GetSection response: Redirect
            let new_bootstrap_addrs: BTreeSet<_> = (0..ELDER_SIZE).map(|_| gen_addr()).collect();

            let response = GetSectionResponse::Redirect(new_bootstrap_addrs.clone());
            let response = bincode::serialize(&response)?.into();

            let _ = response_tx.send(response);
            task::yield_now().await;

            // Receive new GetSection request for each new bootstrap addr.
            let mut recipients = BTreeSet::new();

            while let Ok((addr, ..)) = receive_get_section_request(&mut send_rx) {
                let _ = recipients.insert(addr);
                task::yield_now().await;
            }

            assert_eq!(recipients, new_bootstrap_addrs);

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
        let (_, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_addr0 = gen_addr();
        let bootstrap_addr1 = gen_addr();

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let mut state = State::new(node, send_tx, recv_rx)?;

        let bootstrap_task = state.bootstrap(vec![bootstrap_addr0, bootstrap_addr1], None);
        let test_task = async {
            // Receive the initial two GetSection requests
            task::yield_now().await;
            let (.., response_tx0) = receive_get_section_request(&mut send_rx)?;

            task::yield_now().await;
            let (.., response_tx1) = receive_get_section_request(&mut send_rx)?;

            // Send invalid response first.
            let response = GetSectionResponse::Redirect(BTreeSet::new());
            let response = bincode::serialize(&response)?.into();

            let _ = response_tx0.send(response);
            task::yield_now().await;

            // Nothing happens.
            assert_matches!(send_rx.try_recv(), Err(TryRecvError::Empty));

            // Then send a valid response.
            let addrs = (0..ELDER_SIZE).map(|_| gen_addr()).collect();
            let response = GetSectionResponse::Redirect(addrs);
            let response = bincode::serialize(&response)?.into();

            let _ = response_tx1.send(response);

            // Receive GetSection requests to the new addresses
            for _ in 0..ELDER_SIZE {
                task::yield_now().await;
                let _ = receive_get_section_request(&mut send_rx)?;
            }

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
    async fn invalid_get_section_response_ok() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (_, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_addr0 = gen_addr();
        let bootstrap_addr1 = gen_addr();

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

        let bootstrap_task = state.bootstrap(vec![bootstrap_addr0, bootstrap_addr1], None);

        // Send an invalid `GetSectionResponse::Ok` followed by a valid one. The invalid one is
        // ignored and the valid one processed normally.
        let test_task = async {
            task::yield_now().await;
            let (.., response_tx0) = receive_get_section_request(&mut send_rx)?;

            task::yield_now().await;
            let (.., response_tx1) = receive_get_section_request(&mut send_rx)?;

            // Send invalid response first
            let response = GetSectionResponse::Ok {
                prefix: bad_prefix,
                key: bls::SecretKey::random().public_key(),
                elders: (0..ELDER_SIZE)
                    .map(|_| (bad_prefix.substituted_in(rand::random()), gen_addr()))
                    .collect(),
            };
            let response = bincode::serialize(&response)?.into();
            let _ = response_tx0.send(response);

            task::yield_now().await;

            assert_matches!(send_rx.try_recv(), Err(TryRecvError::Empty));

            // Send valid response next.
            let response = GetSectionResponse::Ok {
                prefix: good_prefix,
                key: bls::SecretKey::random().public_key(),
                elders: (0..ELDER_SIZE)
                    .map(|_| (good_prefix.substituted_in(rand::random()), gen_addr()))
                    .collect(),
            };
            let response = bincode::serialize(&response)?.into();
            let _ = response_tx1.send(response);

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

        let elders = (0..ELDER_SIZE)
            .map(|_| (good_prefix.substituted_in(rand::random()), gen_addr()))
            .collect();
        let section_key = bls::SecretKey::random().public_key();
        let join_task = state.join(elders, section_key, None);

        let test_task = async {
            task::yield_now().await;

            let (bytes, _) = send_rx.try_recv()?;
            let message = Message::from_bytes(&bytes)?;
            assert_matches!(message.variant(), Variant::JoinRequest(_));

            // Send `BootstrapResponse::Join` with bad prefix
            let (elders_info, _) = gen_elders_info(bad_prefix, ELDER_SIZE);
            let section_key = bls::SecretKey::random().public_key();

            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::BootstrapResponse(BootstrapResponse::Join {
                    elders_info,
                    section_key,
                }),
                None,
                None,
            )?;

            recv_tx.try_send((message, bootstrap_node.addr))?;
            task::yield_now().await;
            assert_matches!(send_rx.try_recv(), Err(TryRecvError::Empty));

            // Send `BootstrapResponse::Join` with good prefix
            let (elders_info, _) = gen_elders_info(good_prefix, ELDER_SIZE);
            let section_key = bls::SecretKey::random().public_key();

            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::BootstrapResponse(BootstrapResponse::Join {
                    elders_info,
                    section_key,
                }),
                None,
                None,
            )?;

            recv_tx.try_send((message, bootstrap_node.addr))?;
            task::yield_now().await;

            let (bytes, _) = send_rx.try_recv()?;
            let message = Message::from_bytes(&bytes)?;
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

    // Receive a message on `send_rx` and assert that it is a `GetSection` request.
    // Returns the recipient address, the request name and the response sender.
    fn receive_get_section_request(
        send_rx: &mut mpsc::Receiver<(Bytes, Target)>,
    ) -> Result<(SocketAddr, XorName, oneshot::Sender<Bytes>)> {
        let (bytes, target) = send_rx.try_recv()?;
        let (addr, response_tx) = assert_matches!(target, Target::Bi { addr, tx } => (addr, tx));

        let request = bincode::deserialize(&bytes)?;
        let name = assert_matches!(request, ExternalMessage::GetSection(name) => name);

        Ok((addr, name, response_tx))
    }
}

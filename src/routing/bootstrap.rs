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
    crypto,
    error::{Error, Result},
    location::DstLocation,
    messages::{BootstrapResponse, JoinRequest, Message, Variant, VerifyStatus},
    node::Node,
    peer::Peer,
    relocation::{RelocatePayload, SignedRelocateDetails},
    section::{EldersInfo, Section},
    SectionProofChain,
};
use bytes::Bytes;
use futures::future;
use std::{collections::VecDeque, mem, net::SocketAddr};
use tokio::sync::mpsc;
use xor_name::Prefix;

const BACKLOG_CAPACITY: usize = 100;

/// Bootstrap into the network as an infant node.
///
/// NOTE: It's not guaranteed this function ever returns. This can happen due to messages being
/// lost in transit or other reasons. It's the responsibility of the caller to handle this case,
/// for example by using a timeout.
pub(crate) async fn infant(
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
    send_tx: mpsc::Sender<(Bytes, Vec<SocketAddr>)>,
    // Receiver for incoming messages.
    recv_rx: MessageReceiver<'a>,
    node: Node,
    // Backlog for unknown messages
    backlog: VecDeque<(Message, SocketAddr)>,
}

impl<'a> State<'a> {
    fn new(
        node: Node,
        send_tx: mpsc::Sender<(Bytes, Vec<SocketAddr>)>,
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
        let (elders_info, section_key) = self
            .bootstrap(bootstrap_addrs, relocate_details.as_ref())
            .await?;

        let relocate_payload = if let Some(details) = relocate_details {
            Some(self.process_relocation(&elders_info, details)?)
        } else {
            None
        };

        self.join(elders_info, section_key, relocate_payload).await
    }

    // Send a `BootstrapRequest` and waits for the response. If the response is `Rebootstrap`,
    // repeat with the new set of contacts. If it is `Join`, proceeed to the `join` phase.
    async fn bootstrap(
        &mut self,
        mut bootstrap_addrs: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<(EldersInfo, bls::PublicKey)> {
        loop {
            self.send_bootstrap_request(mem::take(&mut bootstrap_addrs), relocate_details)
                .await?;

            let (response, sender) = self.receive_bootstrap_response().await?;

            match response {
                BootstrapResponse::Join {
                    elders_info,
                    section_key,
                } => {
                    info!(
                        "{} Joining a section {:?} (given by {:?})",
                        self.node, elders_info, sender
                    );
                    return Ok((elders_info, section_key));
                }
                BootstrapResponse::Rebootstrap(new_bootstrap_addrs) => {
                    if new_bootstrap_addrs.is_empty() {
                        error!("{} Invalid rebootstrap response: missing peers", self.node);
                        return Err(Error::InvalidMessage);
                    }

                    info!(
                        "{} Bootstrapping redirected to another set of peers: {:?}",
                        self.node, new_bootstrap_addrs,
                    );
                    bootstrap_addrs = new_bootstrap_addrs.to_vec();
                }
            }
        }
    }

    async fn send_bootstrap_request(
        &mut self,
        recipients: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<()> {
        let destination = match relocate_details {
            Some(details) => *details.destination(),
            None => self.node.name(),
        };

        let message = Message::single_src(
            &self.node,
            DstLocation::Direct,
            Variant::BootstrapRequest(destination),
            None,
            None,
        )?;

        debug!("{} Sending BootstrapRequest to {:?}", self.node, recipients);

        let _ = self.send_tx.send((message.to_bytes(), recipients)).await;

        Ok(())
    }

    async fn receive_bootstrap_response(&mut self) -> Result<(BootstrapResponse, SocketAddr)> {
        while let Some((message, sender)) = self.recv_rx.next().await {
            match message.variant() {
                Variant::BootstrapResponse(response) => {
                    if !self.verify_message(&message, None) {
                        continue;
                    }

                    return Ok((response.clone(), sender));
                }
                _ => self.backlog_message(message, sender),
            }
        }

        error!("{} Message sender unexpectedly closed", self.node);
        Err(Error::InvalidState)
    }

    // Change our name to fit the destination section and apply the new age.
    fn process_relocation(
        &mut self,
        elders_info: &EldersInfo,
        relocate_details: SignedRelocateDetails,
    ) -> Result<RelocatePayload> {
        // We are relocating so we need to change our name.
        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            elders_info.prefix.bit_count() + extra_split_count,
            *relocate_details.destination(),
        );

        let new_keypair = crypto::gen_keypair_within_range(&name_prefix.range_inclusive());
        let new_name = crypto::name(&new_keypair.public);
        let age = relocate_details.relocate_details().age;
        let relocate_payload =
            RelocatePayload::new(relocate_details, &new_name, &self.node.keypair)?;

        info!("{} Changing name to {}.", self.node, new_name);
        self.node = Node::new(new_keypair, self.node.addr).with_age(age);

        Ok(relocate_payload)
    }

    // Send `JoinRequest` and wait for the response. If the response is `Rejoin`, repeat with the
    // new info. If it is `Approval`, returns the initial `Section` value to use by this node,
    // completing the bootstrap.
    async fn join(
        mut self,
        mut elders_info: EldersInfo,
        mut section_key: bls::PublicKey,
        relocate_payload: Option<RelocatePayload>,
    ) -> Result<(Node, Section, Vec<(Message, SocketAddr)>)> {
        loop {
            self.send_join_requests(&elders_info, section_key, relocate_payload.as_ref())
                .await?;

            let (response, sender) = self
                .receive_join_response(relocate_payload.as_ref())
                .await?;

            match response {
                JoinResponse::Approval {
                    elders_info,
                    section_chain,
                } => {
                    return Ok((
                        self.node,
                        Section::new(section_chain, elders_info)?,
                        self.backlog.into_iter().collect(),
                    ));
                }
                JoinResponse::Rejoin {
                    elders_info: new_elders_info,
                    section_key: new_section_key,
                } => {
                    if new_section_key == section_key {
                        continue;
                    }

                    if new_elders_info.prefix.matches(&self.node.name()) {
                        info!(
                            "{} Newer Join response for our prefix {:?} from {:?}",
                            self.node, new_elders_info, sender
                        );
                        elders_info = new_elders_info;
                        section_key = new_section_key;
                    } else {
                        warn!(
                            "Newer Join response not for our prefix {:?} from {:?}",
                            new_elders_info, sender,
                        );
                    }
                }
            }
        }
    }

    async fn send_join_requests(
        &mut self,
        elders_info: &EldersInfo,
        section_key: bls::PublicKey,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<()> {
        let recipients: Vec<_> = elders_info
            .elders
            .values()
            .map(Peer::addr)
            .copied()
            .collect();

        let join_request = JoinRequest {
            section_key,
            relocate_payload: relocate_payload.cloned(),
        };

        info!(
            "{} Sending {:?} to {:?}",
            self.node, join_request, recipients
        );

        let variant = Variant::JoinRequest(Box::new(join_request));
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None, None)?;

        let _ = self.send_tx.send((message.to_bytes(), recipients)).await;

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
                Variant::NodeApproval(elders_info) => {
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
                            section_chain,
                        },
                        sender,
                    ));
                }

                _ => self.backlog_message(message, sender),
            }
        }

        error!("{} Message sender unexpectedly closed", self.node);
        Err(Error::InvalidState)
    }

    fn verify_message(&self, message: &Message, trusted_key: Option<&bls::PublicKey>) -> bool {
        // The message verification will use only those trusted keys whose prefix is compatible with
        // the message source. By using empty prefix, we make sure `trusted_key` is always used.
        let prefix = Prefix::default();

        let result = message
            .verify(trusted_key.map(|key| (&prefix, key)))
            .and_then(|status| match (status, trusted_key) {
                (VerifyStatus::Full, _) | (VerifyStatus::Unknown, None) => Ok(()),
                (VerifyStatus::Unknown, Some(_)) => Err(Error::UntrustedMessage),
            });

        match result {
            Ok(()) => true,
            Err(error) => {
                error!(
                    "{} Verification of {:?} failed: {}",
                    self.node, message, error
                );
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
        section_chain: SectionProofChain,
    },
    Rejoin {
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
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

// Keep reading messages from `rx` and send them using `comm`.
async fn send_messages(mut rx: mpsc::Receiver<(Bytes, Vec<SocketAddr>)>, comm: &Comm) {
    while let Some((message, recipients)) = rx.recv().await {
        let _ = comm
            .send_message_to_targets(&recipients, recipients.len(), message)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus::test_utils::*, section::test_utils::*, ELDER_SIZE};
    use anyhow::{Error, Result};
    use assert_matches::assert_matches;
    use futures::future;
    use tokio::task;

    #[tokio::test]
    async fn bootstrap_as_infant() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (elders_info, mut nodes) = gen_elders_info(Default::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let bootstrap_addr = bootstrap_node.addr;

        let sk = bls::SecretKey::random();
        let pk = sk.public_key();

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let node_name = node.name();
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

            // Receive BootstrapRequest
            let (bytes, recipients) = send_rx.try_recv()?;
            let message = Message::from_bytes(&bytes)?;

            assert_eq!(recipients, [bootstrap_addr]);
            assert_matches!(message.variant(), Variant::BootstrapRequest(name) => {
                assert_eq!(*name, node_name);
            });

            // Send BootstrapResponse
            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::BootstrapResponse(BootstrapResponse::Join {
                    elders_info: elders_info.clone(),
                    section_key: pk,
                }),
                None,
                None,
            )?;

            recv_tx.try_send((message, bootstrap_addr))?;
            task::yield_now().await;

            // Receive JoinRequest
            let (bytes, recipients) = send_rx.try_recv()?;
            let message = Message::from_bytes(&bytes)?;

            itertools::assert_equal(&recipients, elders_info.peers().map(Peer::addr));
            assert_matches!(message.variant(), Variant::JoinRequest(request) => {
                assert_eq!(request.section_key, pk);
                assert!(request.relocate_payload.is_none());
            });

            // Send NodeApproval
            let proven_elders_info = proven(&sk, elders_info.clone())?;
            let proof_chain = SectionProofChain::new(pk);
            let message = Message::single_src(
                &bootstrap_node,
                DstLocation::Direct,
                Variant::NodeApproval(proven_elders_info),
                Some(proof_chain),
                None,
            )?;

            recv_tx.try_send((message, bootstrap_addr))?;

            Ok(())
        };

        // Drive both tasks to completion concurrently (but on the same thread).
        let ((_node, section, _backlog), _) = future::try_join(bootstrap, others).await?;

        assert_eq!(*section.elders_info(), elders_info);
        assert_eq!(*section.chain().last_key(), pk);

        Ok(())
    }

    #[tokio::test]
    async fn receive_bootstrap_response_rebootstrap() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (mut recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(crypto::gen_keypair(), gen_addr());

        let node = Node::new(crypto::gen_keypair(), gen_addr());
        let state = State::new(node, send_tx, recv_rx)?;

        // Spawn the bootstrap task on a `LocalSet` so that it runs concurrently with the main test
        // task, but is aborted when the test task finishes because we don't need it to complete
        // for the purpose of this test.
        let local_set = task::LocalSet::new();

        let _ = local_set.spawn_local(state.run(vec![bootstrap_node.addr], None));

        local_set
            .run_until(async {
                task::yield_now().await;

                // Receive BootstrapRequest
                let (bytes, recipients) = send_rx.try_recv()?;
                let message = Message::from_bytes(&bytes)?;

                assert_eq!(recipients, vec![bootstrap_node.addr]);
                assert_matches!(message.variant(), Variant::BootstrapRequest(_));

                // Send Rebootstrap BootstrapResponse
                let new_bootstrap_addrs: Vec<_> = (0..ELDER_SIZE).map(|_| gen_addr()).collect();

                let message = Message::single_src(
                    &bootstrap_node,
                    DstLocation::Direct,
                    Variant::BootstrapResponse(BootstrapResponse::Rebootstrap(
                        new_bootstrap_addrs.clone(),
                    )),
                    None,
                    None,
                )?;

                recv_tx.try_send((message, bootstrap_node.addr))?;
                task::yield_now().await;

                // Receive new BootstrapRequests
                let (bytes, recipients) = send_rx.try_recv()?;
                let message = Message::from_bytes(&bytes)?;

                assert_eq!(recipients, new_bootstrap_addrs);
                assert_matches!(message.variant(), Variant::BootstrapRequest(_));

                Ok(())
            })
            .await
    }

    // TODO: add test for bootstrap as relocated node
}

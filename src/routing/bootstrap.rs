// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{comm::ConnectionEvent, Comm};
use crate::{
    crypto::{self, Signature},
    error::{Error, Result},
    messages::{RoutingMsgUtils, VerifyStatus},
    node::Node,
    peer::PeerUtils,
    relocation::{RelocatePayloadUtils, SignedRelocateDetailsUtils},
    routing::comm::SendStatus,
    section::{SectionAuthorityProviderUtils, SectionUtils},
    FIRST_SECTION_MAX_AGE, FIRST_SECTION_MIN_AGE,
};
use futures::future;
use itertools::Itertools;
use rand::seq::IteratorRandom;
use resource_proof::ResourceProof;
use secured_linked_list::SecuredLinkedList;
use sn_data_types::PublicKey;
use sn_messaging::{
    node::{
        JoinRequest, Proven, RelocatePayload, ResourceProofResponse, RoutingMsg, Section,
        SectionAuthorityProvider, SignedRelocateDetails, Variant,
    },
    section_info::{GetSectionResponse, Message as SectionInfoMsg, SectionInfo},
    DestInfo, DstLocation, MessageType, WireMsg,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    mem,
    net::SocketAddr,
};
use tokio::sync::mpsc;
use tracing::Instrument;
use xor_name::{Prefix, XorName, XOR_NAME_LEN};

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
) -> Result<(Node, Section, Vec<(RoutingMsg, SocketAddr, DestInfo)>)> {
    let (send_tx, send_rx) = mpsc::channel(1);
    let recv_rx = MessageReceiver::Raw(incoming_conns);

    let span = trace_span!("bootstrap", name = %node.name());

    let state = State::new(node, send_tx, recv_rx);

    future::join(
        state.run(vec![bootstrap_addr], None, None),
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
    genesis_key: bls::PublicKey,
    relocate_details: SignedRelocateDetails,
) -> Result<(Node, Section, Vec<(RoutingMsg, SocketAddr, DestInfo)>)> {
    let (send_tx, send_rx) = mpsc::channel(1);
    let recv_rx = MessageReceiver::Deserialized(recv_rx);

    let state = State::new(node, send_tx, recv_rx);

    future::join(
        state.run(bootstrap_addrs, Some(genesis_key), Some(relocate_details)),
        send_messages(send_rx, comm),
    )
    .await
    .0
}

struct State<'a> {
    // Sender for outgoing messages.
    send_tx: mpsc::Sender<(MessageType, Vec<(XorName, SocketAddr)>)>,
    // Receiver for incoming messages.
    recv_rx: MessageReceiver<'a>,
    node: Node,
    // Backlog for unknown messages
    backlog: VecDeque<(RoutingMsg, SocketAddr, DestInfo)>,
}

impl<'a> State<'a> {
    fn new(
        node: Node,
        send_tx: mpsc::Sender<(MessageType, Vec<(XorName, SocketAddr)>)>,
        recv_rx: MessageReceiver<'a>,
    ) -> Self {
        Self {
            send_tx,
            recv_rx,
            node,
            backlog: VecDeque::with_capacity(BACKLOG_CAPACITY),
        }
    }

    async fn run(
        mut self,
        bootstrap_addrs: Vec<SocketAddr>,
        genesis_key: Option<bls::PublicKey>,
        relocate_details: Option<SignedRelocateDetails>,
    ) -> Result<(Node, Section, Vec<(RoutingMsg, SocketAddr, DestInfo)>)> {
        let (prefix, section_key, elders) = self
            .bootstrap(bootstrap_addrs, relocate_details.as_ref())
            .await?;

        // For the first section, using age random among 6 to 100 to avoid relocating too many nodes
        // at the same time.
        if prefix.is_empty() && self.node.name()[XOR_NAME_LEN - 1] < FIRST_SECTION_MIN_AGE {
            let age: u8 = (FIRST_SECTION_MIN_AGE..FIRST_SECTION_MAX_AGE)
                .choose(&mut rand::thread_rng())
                .unwrap_or(FIRST_SECTION_MAX_AGE);

            let new_keypair = crypto::gen_keypair(&Prefix::default().range_inclusive(), age);
            let new_name = crypto::name(&new_keypair.public);

            info!("Setting name to {}", new_name);
            self.node = Node::new(new_keypair, self.node.addr);
        }

        let relocate_payload = if let Some(details) = relocate_details {
            Some(self.process_relocation(&prefix, details)?)
        } else {
            None
        };

        self.join(section_key, elders, genesis_key, relocate_payload)
            .await
    }

    // Send a `GetSectionQuery` and waits for the response. If the response is `Redirect`,
    // repeat with the new set of contacts. If it is `Success`, proceeed to the `join` phase.
    async fn bootstrap(
        &mut self,
        mut bootstrap_addrs: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<(Prefix, bls::PublicKey, BTreeMap<XorName, SocketAddr>)> {
        // Avoid sending more than one request to the same peer.
        let mut used_addrs = HashSet::new();

        loop {
            used_addrs.extend(bootstrap_addrs.iter().copied());
            self.send_get_section_request(mem::take(&mut bootstrap_addrs), relocate_details)
                .await?;

            let (response, sender, _dest_info) =
                self.receive_get_section_response(relocate_details).await?;

            match response {
                GetSectionResponse::Success(SectionInfo {
                    prefix,
                    pk_set,
                    elders,
                    joins_allowed,
                }) => {
                    if !joins_allowed {
                        error!(
                            "Network is set to not taking any new joining node, try join later."
                        );
                        return Err(Error::TryJoinLater);
                    }
                    let key = pk_set.public_key();
                    info!(
                        "Joining a section ({:b}), key: {:?}, elders: {:?} (given by {:?})",
                        prefix, key, elders, sender
                    );
                    return Ok((prefix, key, elders));
                }
                GetSectionResponse::Redirect(mut new_bootstrap_addrs) => {
                    // Ignore already used addresses
                    new_bootstrap_addrs.retain(|addr| !used_addrs.contains(&addr.1));

                    if new_bootstrap_addrs.is_empty() {
                        debug!("Bootstrapping redirected to the same set of peers we already contacted - ignoring");
                    } else {
                        info!(
                            "Bootstrapping redirected to another set of peers: {:?}",
                            new_bootstrap_addrs,
                        );
                        bootstrap_addrs = new_bootstrap_addrs
                            .iter()
                            .map(|(_, addr)| addr)
                            .cloned()
                            .collect();
                    }
                }
                GetSectionResponse::SectionInfoUpdate(error) => {
                    error!("Infrastructure error: {:?}", error);
                }
            }
        }
    }

    async fn send_get_section_request(
        &mut self,
        recipients: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<()> {
        if recipients.is_empty() {
            return Ok(());
        }

        debug!("Sending GetSectionQuery to {:?}", recipients);

        let (dest_pk, dest_xorname) = match relocate_details {
            Some(details) => (
                PublicKey::from(details.relocate_details()?.destination_key),
                *details.destination()?,
            ),
            None => (PublicKey::from(self.node.keypair.public), self.node.name()),
        };

        let message = SectionInfoMsg::GetSectionQuery(PublicKey::from(self.node.keypair.public));

        // Group up with our XorName as we do not know their name yet.
        let recipients = recipients
            .iter()
            .map(|addr| (dest_xorname, *addr))
            .collect();

        let dest_info = DestInfo {
            dest: dest_xorname,
            dest_section_pk: PublicKey::bls(&dest_pk).unwrap_or_else(|| {
                // Create a random PK as we'll be getting the right one with the response
                bls::SecretKey::random().public_key()
            }),
        };
        let _ = self
            .send_tx
            .send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info,
                },
                recipients,
            ))
            .await;

        Ok(())
    }

    async fn receive_get_section_response(
        &mut self,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<(GetSectionResponse, SocketAddr, DestInfo)> {
        let destination = match relocate_details {
            Some(details) => *details.destination()?,
            None => self.node.name(),
        };

        while let Some((message, sender)) = self.recv_rx.next().await {
            match message {
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionResponse(response),
                    dest_info,
                } => match response {
                    GetSectionResponse::Redirect(addrs) if addrs.is_empty() => {
                        error!("Invalid GetSectionResponse::Redirect: missing peers");
                        continue;
                    }
                    GetSectionResponse::Success(SectionInfo { prefix, .. })
                        if !prefix.matches(&destination) =>
                    {
                        error!("Invalid GetSectionResponse::Success: bad prefix");
                        continue;
                    }
                    GetSectionResponse::Redirect(_)
                    | GetSectionResponse::Success { .. }
                    | GetSectionResponse::SectionInfoUpdate(_) => {
                        return Ok((response, sender, dest_info))
                    }
                },
                MessageType::Routing { msg, dest_info } => {
                    self.backlog_message(msg, sender, dest_info)
                }
                MessageType::Node { .. }
                | MessageType::SectionInfo { .. }
                | MessageType::Client { .. } => {}
            }
        }

        error!("RoutingMsg sender unexpectedly closed");
        // TODO: consider more specific error here (e.g. `BootstrapInterrupted`)
        Err(Error::InvalidState)
    }

    // Change our name to fit the destination section and apply the new age.
    fn process_relocation(
        &mut self,
        prefix: &Prefix,
        relocate_details: SignedRelocateDetails,
    ) -> Result<RelocatePayload> {
        // We are relocating so we need to change our name.
        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            prefix.bit_count() + extra_split_count,
            *relocate_details.destination()?,
        );

        let age = relocate_details.relocate_details()?.age;
        let new_keypair = crypto::gen_keypair(&name_prefix.range_inclusive(), age);
        let new_name = XorName::from(PublicKey::from(new_keypair.public));
        let relocate_payload =
            RelocatePayload::new(relocate_details, &new_name, &self.node.keypair);

        info!("Changing name to {}", new_name);
        self.node = Node::new(new_keypair, self.node.addr);

        Ok(relocate_payload)
    }

    // Send `JoinRequest` and wait for the response. If the response is `Rejoin`, repeat with the
    // new info. If it is `Approval`, returns the initial `Section` value to use by this node,
    // completing the bootstrap. If it is a `Challenge`, carry out resource proof calculation.
    async fn join(
        mut self,
        mut section_key: bls::PublicKey,
        elders: BTreeMap<XorName, SocketAddr>,
        genesis_key: Option<bls::PublicKey>,
        relocate_payload: Option<RelocatePayload>,
    ) -> Result<(Node, Section, Vec<(RoutingMsg, SocketAddr, DestInfo)>)> {
        let join_request = JoinRequest {
            section_key,
            relocate_payload: relocate_payload.clone(),
            resource_proof_response: None,
        };
        let recipients = elders
            .into_iter()
            .map(|(name, addr)| (name, addr))
            .collect_vec();
        self.send_join_requests(join_request, recipients, section_key)
            .await?;

        loop {
            let (response, sender, dest_info) = self
                .receive_join_response(genesis_key.as_ref(), relocate_payload.as_ref())
                .await?;

            match response {
                JoinResponse::Approval {
                    section_auth,
                    genesis_key,
                    section_chain,
                } => {
                    return Ok((
                        self.node,
                        Section::new(genesis_key, section_chain, section_auth)?,
                        self.backlog.into_iter().collect(),
                    ));
                }
                JoinResponse::Retry {
                    section_auth,
                    section_key: new_section_key,
                } => {
                    if new_section_key == section_key {
                        continue;
                    }

                    if section_auth.prefix().matches(&self.node.name()) {
                        info!(
                            "Newer Join response for our prefix {:?} from {:?}",
                            section_auth, sender
                        );
                        section_key = new_section_key;
                        let join_request = JoinRequest {
                            section_key,
                            relocate_payload: relocate_payload.clone(),
                            resource_proof_response: None,
                        };
                        let recipients = section_auth
                            .elders()
                            .iter()
                            .map(|(name, addr)| (*name, *addr))
                            .collect();
                        self.send_join_requests(join_request, recipients, section_key)
                            .await?;
                    } else {
                        warn!(
                            "Newer Join response not for our prefix {:?} from {:?}",
                            section_auth, sender,
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
                    let recipients = vec![(dest_info.dest, sender)];
                    self.send_join_requests(join_request, recipients, section_key)
                        .await?;
                }
            }
        }
    }

    async fn send_join_requests(
        &mut self,
        join_request: JoinRequest,
        recipients: Vec<(XorName, SocketAddr)>,
        section_key: bls::PublicKey,
    ) -> Result<()> {
        info!("Sending {:?} to {:?}", join_request, recipients);

        let variant = Variant::JoinRequest(Box::new(join_request));
        let message =
            RoutingMsg::single_src(&self.node, DstLocation::DirectAndUnrouted, variant, None)?;

        let _ = self
            .send_tx
            .send((
                MessageType::Routing {
                    msg: message,
                    dest_info: DestInfo {
                        // Will be overridden while sending to multiple elders
                        dest: XorName::random(),
                        dest_section_pk: section_key,
                    },
                },
                recipients,
            ))
            .await;

        Ok(())
    }

    async fn receive_join_response(
        &mut self,
        expected_genesis_key: Option<&bls::PublicKey>,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<(JoinResponse, SocketAddr, DestInfo)> {
        while let Some((message, sender)) = self.recv_rx.next().await {
            let (message, dest_info) = match message {
                MessageType::Routing { msg, dest_info } => (msg, dest_info),
                MessageType::Node { .. }
                | MessageType::Client { .. }
                | MessageType::SectionInfo { .. } => continue,
            };

            match message.variant() {
                Variant::JoinRetry {
                    section_auth,
                    section_key,
                } => {
                    if !self.verify_message(&message, None) {
                        continue;
                    }

                    return Ok((
                        JoinResponse::Retry {
                            section_auth: section_auth.clone(),
                            section_key: *section_key,
                        },
                        sender,
                        dest_info,
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
                        dest_info,
                    ));
                }
                Variant::NodeApproval {
                    genesis_key,
                    section_auth,
                    member_info,
                } => {
                    if member_info.value.peer.name() != &self.node.name() {
                        trace!("Ignore NodeApproval not for us");
                        continue;
                    }

                    if let Some(expected_genesis_key) = expected_genesis_key {
                        if expected_genesis_key != genesis_key {
                            trace!("Unexpected Genesis key");
                            continue;
                        }
                    }

                    let trusted_key = if let Some(payload) = relocate_payload {
                        Some(&payload.relocate_details()?.destination_key)
                    } else {
                        None
                    };

                    if !self.verify_message(&message, trusted_key) {
                        continue;
                    }

                    let section_chain = message.proof_chain()?.clone();

                    trace!(
                        "This node has been approved to join the network at {:?}!",
                        section_auth.value.prefix,
                    );

                    return Ok((
                        JoinResponse::Approval {
                            section_auth: section_auth.clone(),
                            genesis_key: *genesis_key,
                            section_chain,
                        },
                        sender,
                        dest_info,
                    ));
                }

                _ => self.backlog_message(message, sender, dest_info),
            }
        }

        error!("RoutingMsg sender unexpectedly closed");
        // TODO: consider more specific error here (e.g. `BootstrapInterrupted`)
        Err(Error::InvalidState)
    }

    fn verify_message(&self, message: &RoutingMsg, trusted_key: Option<&bls::PublicKey>) -> bool {
        match message.verify(trusted_key) {
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

    fn backlog_message(&mut self, message: RoutingMsg, sender: SocketAddr, dest_info: DestInfo) {
        while self.backlog.len() >= BACKLOG_CAPACITY {
            let _ = self.backlog.pop_front();
        }

        self.backlog.push_back((message, sender, dest_info))
    }
}

enum JoinResponse {
    Approval {
        section_auth: Proven<SectionAuthorityProvider>,
        genesis_key: bls::PublicKey,
        section_chain: SecuredLinkedList,
    },
    Retry {
        section_auth: SectionAuthorityProvider,
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
// or by receiver of deserialized `RoutingMsg` and provides a unified interface on top of them.
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
                        ConnectionEvent::Received((src, bytes)) => {
                            match WireMsg::deserialize(bytes) {
                                Ok(message) => {
                                    return Some((message, src));
                                }
                                Err(error) => debug!("Failed to deserialize message: {}", error),
                            }
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
async fn send_messages(
    mut rx: mpsc::Receiver<(MessageType, Vec<(XorName, SocketAddr)>)>,
    comm: &Comm,
) -> Result<()> {
    while let Some((message, recipients)) = rx.recv().await {
        match comm
            .send(&recipients, recipients.len(), message.clone())
            .await?
        {
            SendStatus::AllRecipients | SendStatus::MinDeliveryGroupSizeReached(_) => {}
            SendStatus::MinDeliveryGroupSizeFailed(recipients) => {
                error!("Failed to send message {:?} to {:?}", message, recipients,)
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::test_utils::*, error::Error as RoutingError, messages::RoutingMsgUtils,
        routing::tests::SecretKeySet, section::test_utils::*, section::MemberInfoUtils, ELDER_SIZE,
        MIN_ADULT_AGE, MIN_AGE,
    };
    use anyhow::{anyhow, Error, Result};
    use assert_matches::assert_matches;
    use futures::{
        future::{self, Either},
        pin_mut,
    };
    use sn_messaging::{node::MemberInfo, section_info::SectionInfo};
    use tokio::task;

    #[tokio::test]
    async fn bootstrap_as_adult() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (section_auth, mut nodes, _) =
            gen_section_authority_provider(Prefix::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let bootstrap_addr = bootstrap_node.addr;

        let sk_set = SecretKeySet::random();
        let pk_set = sk_set.public_keys();
        let sk = sk_set.secret_key();
        let pk = sk.public_key();

        // Node in first section has to have an age higher than MIN_ADULT_AGE
        // Otherwise during the bootstrap process, node will change its id and age.
        let node_age = MIN_AGE + 2;
        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), node_age),
            gen_addr(),
        );
        let peer = node.peer();
        let state = State::new(node, send_tx, recv_rx);

        // Create the bootstrap task, but don't run it yet.
        let bootstrap = async move {
            state
                .run(vec![bootstrap_addr], None, None)
                .await
                .map_err(Error::from)
        };

        // Create the task that executes the body of the test, but don't run it either.
        let others = async {
            // Receive GetSectionQuery
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            let bootstrap_addrs: Vec<SocketAddr> =
                recipients.iter().map(|(_name, addr)| *addr).collect();
            assert_eq!(bootstrap_addrs, [bootstrap_addr]);
            assert_matches!(message, MessageType::SectionInfo{ msg: SectionInfoMsg::GetSectionQuery(name), .. } => {
                assert_eq!(XorName::from(name), *peer.name());
            });

            let infrastructure_info = SectionInfo {
                prefix: section_auth.prefix,
                pk_set,
                elders: section_auth
                    .peers()
                    .map(|peer| (*peer.name(), *peer.addr()))
                    .collect(),
                joins_allowed: true,
            };
            // Send GetSectionResponse::Success
            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Success(
                infrastructure_info,
            ));
            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: *peer.name(),
                        dest_section_pk: pk,
                    },
                },
                bootstrap_addr,
            ))?;

            // Receive JoinRequest
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;
            let (message, dest_info) = assert_matches!(message, MessageType::Routing { msg, dest_info } =>
                (msg, dest_info));

            assert_eq!(dest_info.dest_section_pk, pk);
            itertools::assert_equal(
                recipients,
                section_auth
                    .elders()
                    .iter()
                    .map(|(name, addr)| (*name, *addr))
                    .collect::<Vec<_>>(),
            );
            assert_matches!(message.variant(), Variant::JoinRequest(request) => {
                assert_eq!(request.section_key, pk);
                assert!(request.relocate_payload.is_none());
            });

            // Send NodeApproval
            let section_auth = proven(sk, section_auth.clone())?;
            let member_info = proven(sk, MemberInfo::joined(peer))?;
            let proof_chain = SecuredLinkedList::new(pk);
            let message = RoutingMsg::single_src(
                &bootstrap_node,
                DstLocation::DirectAndUnrouted,
                Variant::NodeApproval {
                    genesis_key: pk,
                    section_auth,
                    member_info,
                },
                Some(proof_chain),
            )?;

            recv_tx.try_send((
                MessageType::Routing {
                    msg: message,
                    dest_info: DestInfo {
                        dest: *peer.name(),
                        dest_section_pk: pk,
                    },
                },
                bootstrap_addr,
            ))?;

            Ok(())
        };

        // Drive both tasks to completion concurrently (but on the same thread).
        let ((node, section, _backlog), _) = future::try_join(bootstrap, others).await?;

        assert_eq!(*section.authority_provider(), section_auth);
        assert_eq!(*section.chain().last_key(), pk);
        assert_eq!(node.age(), node_age);

        Ok(())
    }

    #[tokio::test]
    async fn receive_get_section_response_redirect() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );

        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let name = node.name();
        let mut state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);
        let test_task = async move {
            // Receive GetSectionQuery
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            assert_eq!(
                recipients
                    .into_iter()
                    .map(|peer| peer.1)
                    .collect::<Vec<_>>(),
                vec![bootstrap_node.addr]
            );
            assert_matches!(
                message,
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionQuery(_),
                    ..
                }
            );

            // Send GetSectionResponse::Redirect
            let new_bootstrap_addrs: Vec<_> = (0..ELDER_SIZE)
                .map(|_| (XorName::random(), gen_addr()))
                .collect();
            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Redirect(
                new_bootstrap_addrs.clone(),
            ));

            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: name,
                        dest_section_pk: bls::SecretKey::random().public_key(),
                    },
                },
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            // Receive new GetSectionQuery
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            assert_eq!(
                recipients
                    .into_iter()
                    .map(|peer| peer.1)
                    .collect::<Vec<_>>(),
                new_bootstrap_addrs
                    .into_iter()
                    .map(|(_, addr)| addr)
                    .collect::<Vec<_>>()
            );
            assert_matches!(
                message,
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionQuery(_),
                    ..
                }
            );

            Ok(())
        };

        pin_mut!(bootstrap_task);
        pin_mut!(test_task);

        match future::select(bootstrap_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }

    #[tokio::test]
    async fn invalid_get_section_response_redirect() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );

        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let node_name = node.name();
        let mut state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);
        let test_task = async {
            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            assert_matches!(
                message,
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionQuery(_),
                    ..
                }
            );

            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Redirect(vec![]));

            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: bls::SecretKey::random().public_key(),
                    },
                },
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            let addrs = (0..ELDER_SIZE)
                .map(|_| (XorName::random(), gen_addr()))
                .collect();
            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Redirect(addrs));

            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: bls::SecretKey::random().public_key(),
                    },
                },
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            assert_matches!(
                message,
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionQuery(_),
                    ..
                }
            );

            Ok(())
        };

        pin_mut!(bootstrap_task);
        pin_mut!(test_task);

        match future::select(bootstrap_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }

    #[tokio::test]
    async fn joins_disallowed_get_section_response_success() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (section_auth, mut nodes, _) =
            gen_section_authority_provider(Prefix::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let bootstrap_addr = bootstrap_node.addr;

        let sk_set = SecretKeySet::random();
        let pk_set = sk_set.public_keys();
        let pk = pk_set.public_key();

        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );

        let node_name = node.name();

        let mut state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.bootstrap(vec![bootstrap_addr], None);

        // Send an valid `BootstrapResponse::Join` followed by a valid one. The invalid one is
        // ignored and the valid one processed normally.
        let test_task = async {
            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            assert_matches!(
                message,
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionQuery(_),
                    ..
                }
            );

            let infrastructure_info = SectionInfo {
                prefix: section_auth.prefix,
                pk_set,
                elders: section_auth
                    .peers()
                    .map(|peer| (*peer.name(), *peer.addr()))
                    .collect(),
                joins_allowed: false,
            };
            // Send GetSectionResponse::Success with the flag of joins_allowed set to false.
            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Success(
                infrastructure_info,
            ));
            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: pk,
                    },
                },
                bootstrap_addr,
            ))?;

            Ok(())
        };

        let (bootstrap_result, test_result) = future::join(bootstrap_task, test_task).await;

        if let Err(RoutingError::TryJoinLater) = bootstrap_result {
        } else {
            return Err(anyhow!("Not getting an execpted network rejection."));
        }

        test_result
    }

    #[tokio::test]
    async fn invalid_get_section_response_success() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let node_name = node.name();

        let (good_prefix, bad_prefix) = {
            let p0 = Prefix::default().pushed(false);
            let p1 = Prefix::default().pushed(true);

            if node_name.bit(0) {
                (p1, p0)
            } else {
                (p0, p1)
            }
        };

        let mut state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.bootstrap(vec![bootstrap_node.addr], None);

        // Send an invalid `BootstrapResponse::Join` followed by a valid one. The invalid one is
        // ignored and the valid one processed normally.
        let test_task = async {
            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("GetSectionQuery was not received"))?;

            assert_matches!(
                message,
                MessageType::SectionInfo {
                    msg: SectionInfoMsg::GetSectionQuery(_),
                    ..
                }
            );

            let infrastructure_info = SectionInfo {
                prefix: bad_prefix,
                pk_set: bls::SecretKeySet::random(0, &mut rand::thread_rng()).public_keys(),
                elders: (0..ELDER_SIZE)
                    .map(|_| (bad_prefix.substituted_in(rand::random()), gen_addr()))
                    .collect(),
                joins_allowed: true,
            };

            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Success(
                infrastructure_info,
            ));

            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: bls::SecretKey::random().public_key(),
                    },
                },
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            let infrastructure_info = SectionInfo {
                prefix: good_prefix,
                pk_set: bls::SecretKeySet::random(0, &mut rand::thread_rng()).public_keys(),
                elders: (0..ELDER_SIZE)
                    .map(|_| (good_prefix.substituted_in(rand::random()), gen_addr()))
                    .collect(),
                joins_allowed: true,
            };

            let message = SectionInfoMsg::GetSectionResponse(GetSectionResponse::Success(
                infrastructure_info,
            ));

            recv_tx.try_send((
                MessageType::SectionInfo {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: bls::SecretKey::random().public_key(),
                    },
                },
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
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let node = Node::new(
            crypto::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let node_name = node.name();

        let (good_prefix, bad_prefix) = {
            let p0 = Prefix::default().pushed(false);
            let p1 = Prefix::default().pushed(true);

            if node.name().bit(0) {
                (p1, p0)
            } else {
                (p0, p1)
            }
        };

        let state = State::new(node, send_tx, recv_rx);

        let section_key = bls::SecretKey::random().public_key();
        let elders = (0..ELDER_SIZE)
            .map(|_| (good_prefix.substituted_in(rand::random()), gen_addr()))
            .collect();
        let join_task = state.join(section_key, elders, None, None);

        let test_task = async {
            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("RoutingMsg was not received"))?;

            let message = assert_matches!(message, MessageType::Routing{ msg, .. } => msg);
            assert_matches!(message.variant(), Variant::JoinRequest(_));

            // Send `Rejoin` with bad prefix
            let message = RoutingMsg::single_src(
                &bootstrap_node,
                DstLocation::DirectAndUnrouted,
                Variant::JoinRetry {
                    section_auth: gen_section_authority_provider(bad_prefix, ELDER_SIZE).0,
                    section_key: bls::SecretKey::random().public_key(),
                },
                None,
            )?;

            recv_tx.try_send((
                MessageType::Routing {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: section_key,
                    },
                },
                bootstrap_node.addr,
            ))?;
            task::yield_now().await;

            // Send `Rejoin` with good prefix
            let message = RoutingMsg::single_src(
                &bootstrap_node,
                DstLocation::DirectAndUnrouted,
                Variant::JoinRetry {
                    section_auth: gen_section_authority_provider(good_prefix, ELDER_SIZE).0,
                    section_key: bls::SecretKey::random().public_key(),
                },
                None,
            )?;

            recv_tx.try_send((
                MessageType::Routing {
                    msg: message,
                    dest_info: DestInfo {
                        dest: node_name,
                        dest_section_pk: section_key,
                    },
                },
                bootstrap_node.addr,
            ))?;

            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("RoutingMsg was not received"))?;

            let message = assert_matches!(message, MessageType::Routing{ msg, .. } => msg);
            assert_matches!(message.variant(), Variant::JoinRequest(_));

            Ok(())
        };

        pin_mut!(join_task);
        pin_mut!(test_task);

        match future::select(join_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }
}

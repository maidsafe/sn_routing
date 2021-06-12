// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{comm::ConnectionEvent, Comm};
use crate::{
    ed25519::{self},
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
use rand::seq::IteratorRandom;
use resource_proof::ResourceProof;
use sn_data_types::PublicKey;
use sn_messaging::{
    node::{
        JoinRejectionReason, JoinRequest, JoinResponse, RelocatePayload, ResourceProofResponse,
        RoutingMsg, Section, SignedRelocateDetails, Variant,
    },
    DestInfo, DstLocation, MessageType, WireMsg,
};
use std::{
    collections::{HashSet, VecDeque},
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
        self,
        bootstrap_addrs: Vec<SocketAddr>,
        genesis_key: Option<bls::PublicKey>,
        relocate_details: Option<SignedRelocateDetails>,
    ) -> Result<(Node, Section, Vec<(RoutingMsg, SocketAddr, DestInfo)>)> {
        let (dest_pk, dest_xorname) = match relocate_details {
            Some(ref details) => (
                details.relocate_details()?.destination_key,
                *details.destination()?,
            ),
            None => {
                // Use our XorName as we do not know their name or section key yet.
                (bls::SecretKey::random().public_key(), self.node.name())
            }
        };

        let elders = bootstrap_addrs
            .iter()
            .map(|addr| (dest_xorname, *addr))
            .collect();

        self.join(dest_pk, elders, genesis_key, relocate_details)
            .await
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
        let new_keypair = ed25519::gen_keypair(&name_prefix.range_inclusive(), age);
        let new_name = XorName::from(PublicKey::from(new_keypair.public));
        let relocate_payload =
            RelocatePayload::new(relocate_details, &new_name, &self.node.keypair);

        info!("Changing name to {}", new_name);
        self.node = Node::new(new_keypair, self.node.addr);

        Ok(relocate_payload)
    }

    // Send `JoinRequest` and wait for the response. If the response is:
    // - `Retry`: repeat with the new info.
    // - `Redirect`: repeat with the new set of addresses.
    // - `ResourceChallenge`: carry out resource proof calculation.
    // - `Approval`: returns the initial `Section` value to use by this node,
    //    completing the bootstrap.
    async fn join(
        mut self,
        mut section_key: bls::PublicKey,
        mut recipients: Vec<(XorName, SocketAddr)>,
        genesis_key: Option<bls::PublicKey>,
        relocate_details: Option<SignedRelocateDetails>,
    ) -> Result<(Node, Section, Vec<(RoutingMsg, SocketAddr, DestInfo)>)> {
        let join_request = JoinRequest {
            section_key,
            relocate_payload: None,
            resource_proof_response: None,
        };

        // Avoid sending more than one request to the same peer.
        let mut used_recipient = HashSet::<SocketAddr>::new();

        self.send_join_requests(join_request, &recipients, section_key)
            .await?;

        let mut relocate_payload = None;
        loop {
            used_recipient.extend(recipients.iter().map(|(_, addr)| addr));

            let (response, sender, dest_info) = self
                .receive_join_response(genesis_key.as_ref(), relocate_payload.as_ref())
                .await?;

            match response {
                JoinResponse::Rejected(JoinRejectionReason::NodeNotReachable(addr)) => {
                    error!(
                        "Node cannot join the network since it is not externally reachable: {}",
                        addr
                    );
                    return Err(Error::NodeNotReachable(addr));
                }
                JoinResponse::Rejected(JoinRejectionReason::JoinsDisallowed) => {
                    error!("Network is set to not taking any new joining node, try join later.");
                    return Err(Error::TryJoinLater);
                }
                JoinResponse::Approval {
                    section_auth,
                    genesis_key,
                    section_chain,
                    ..
                } => {
                    return Ok((
                        self.node,
                        Section::new(genesis_key, section_chain, section_auth)?,
                        self.backlog.into_iter().collect(),
                    ));
                }
                JoinResponse::Retry(section_auth) => {
                    if section_auth.section_key() == section_key {
                        continue;
                    }

                    let new_recipients: Vec<(XorName, SocketAddr)> = section_auth
                        .elders
                        .iter()
                        .map(|(name, addr)| (*name, *addr))
                        .collect();

                    let prefix = section_auth.prefix;

                    // For the first section, using age random among 6 to 100 to avoid
                    // relocating too many nodes at the same time.
                    if prefix.is_empty() && self.node.age() < FIRST_SECTION_MIN_AGE {
                        let age: u8 = (FIRST_SECTION_MIN_AGE..FIRST_SECTION_MAX_AGE)
                            .choose(&mut rand::thread_rng())
                            .unwrap_or(FIRST_SECTION_MAX_AGE);

                        let new_keypair =
                            ed25519::gen_keypair(&Prefix::default().range_inclusive(), age);
                        let new_name = ed25519::name(&new_keypair.public);

                        info!("Setting Node name to {}", new_name);
                        self.node = Node::new(new_keypair, self.node.addr);
                    }

                    // if we are relocating, and we didn't generate
                    // the relocation payload yet, we do it now
                    if relocate_payload.is_none() {
                        if let Some(ref details) = relocate_details {
                            relocate_payload =
                                Some(self.process_relocation(&prefix, details.clone())?);
                        }
                    }

                    if relocate_payload.is_some() || prefix.matches(&self.node.name()) {
                        info!(
                            "Newer Join response for our prefix {:?} from {:?}",
                            section_auth, sender
                        );
                        section_key = section_auth.section_key();
                        let join_request = JoinRequest {
                            section_key,
                            relocate_payload: relocate_payload.clone(),
                            resource_proof_response: None,
                        };

                        recipients = new_recipients;
                        self.send_join_requests(join_request, &recipients, section_key)
                            .await?;
                    } else {
                        warn!(
                            "Newer Join response not for our prefix {:?} from {:?}",
                            section_auth, sender,
                        );
                    }
                }
                JoinResponse::Redirect(section_auth) => {
                    if section_auth.section_key() == section_key {
                        continue;
                    }

                    // Ignore already used recipients
                    let new_recipients: Vec<(XorName, SocketAddr)> = section_auth
                        .elders
                        .iter()
                        .filter(|(_, addr)| !used_recipient.contains(addr))
                        .map(|(name, addr)| (*name, *addr))
                        .collect();

                    if new_recipients.is_empty() {
                        debug!("Joining redirected to the same set of peers we already contacted - ignoring response");
                        continue;
                    } else {
                        info!(
                            "Joining redirected to another set of peers: {:?}",
                            new_recipients,
                        );
                    }

                    let prefix = section_auth.prefix;

                    if relocate_payload.is_some() || prefix.matches(&self.node.name()) {
                        info!(
                            "Newer Join response for our prefix {:?} from {:?}",
                            section_auth, sender
                        );
                        section_key = section_auth.section_key();
                        let join_request = JoinRequest {
                            section_key,
                            relocate_payload: relocate_payload.clone(),
                            resource_proof_response: None,
                        };

                        recipients = new_recipients;
                        self.send_join_requests(join_request, &recipients, section_key)
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
                    let recipients = &[(dest_info.dest, sender)];
                    self.send_join_requests(join_request, recipients, section_key)
                        .await?;
                }
            }
        }
    }

    async fn send_join_requests(
        &mut self,
        join_request: JoinRequest,
        recipients: &[(XorName, SocketAddr)],
        section_key: bls::PublicKey,
    ) -> Result<()> {
        info!("Sending {:?} to {:?}", join_request, recipients);

        let variant = Variant::JoinRequest(Box::new(join_request));
        let message = RoutingMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted,
            variant,
            section_key,
        )?;

        let _ = self
            .send_tx
            .send((
                MessageType::Routing {
                    msg: message,
                    dest_info: DestInfo {
                        dest: recipients[0].0,
                        dest_section_pk: section_key,
                    },
                },
                recipients.to_vec(),
            ))
            .await;

        Ok(())
    }

    async fn receive_join_response(
        &mut self,
        expected_genesis_key: Option<&bls::PublicKey>,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<(JoinResponse, SocketAddr, DestInfo)> {
        let destination = match relocate_payload {
            Some(payload) => *payload.details.destination()?,
            None => self.node.name(),
        };

        while let Some((message, sender)) = self.recv_rx.next().await {
            // we are interested only in `JoinResponse` type of messages
            let (routing_msg, dest_info, join_response) = match message {
                MessageType::Node { .. }
                | MessageType::Client { .. }
                | MessageType::SectionInfo { .. } => continue,
                MessageType::Routing { msg, dest_info } => {
                    if let Variant::JoinResponse(resp) = &msg.variant {
                        let join_response = resp.clone();
                        (msg, dest_info, *join_response)
                    } else {
                        self.backlog_message(msg, sender, dest_info);
                        continue;
                    }
                }
            };

            match join_response {
                JoinResponse::Rejected(JoinRejectionReason::NodeNotReachable(_))
                | JoinResponse::Rejected(JoinRejectionReason::JoinsDisallowed) => {
                    return Ok((join_response, sender, dest_info));
                }
                JoinResponse::Retry(ref section_auth)
                | JoinResponse::Redirect(ref section_auth) => {
                    if !section_auth.prefix.matches(&destination) {
                        error!("Invalid JoinResponse bad prefix: {:?}", join_response);
                        continue;
                    }

                    if section_auth.elders.is_empty() {
                        error!(
                            "Invalid JoinResponse, empty list of Elders: {:?}",
                            join_response
                        );
                        continue;
                    }

                    if !self.verify_message(&routing_msg, None) {
                        continue;
                    }

                    return Ok((join_response, sender, dest_info));
                }
                JoinResponse::ResourceChallenge { .. } => {
                    if relocate_payload.is_some() {
                        warn!("Ignoring ResourceChallenge received when relocating");
                        continue;
                    }

                    if !self.verify_message(&routing_msg, None) {
                        continue;
                    }

                    return Ok((join_response, sender, dest_info));
                }
                JoinResponse::Approval {
                    genesis_key,
                    ref section_auth,
                    ref member_info,
                    ..
                } => {
                    if member_info.value.peer.name() != &self.node.name() {
                        trace!("Ignore NodeApproval not for us");
                        continue;
                    }

                    if let Some(expected_genesis_key) = expected_genesis_key {
                        if expected_genesis_key != &genesis_key {
                            trace!("Genesis key doesn't match");
                            continue;
                        }
                    }

                    let trusted_key = if let Some(payload) = relocate_payload {
                        Some(&payload.relocate_details()?.destination_key)
                    } else {
                        None
                    };

                    if !self.verify_message(&routing_msg, trusted_key) {
                        continue;
                    }

                    trace!(
                        "This node has been approved to join the network at {:?}!",
                        section_auth.value.prefix,
                    );

                    return Ok((join_response, sender, dest_info));
                }
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
        dkg::test_utils::*,
        error::Error as RoutingError,
        messages::RoutingMsgUtils,
        section::test_utils::*,
        section::{MemberInfoUtils, SectionAuthorityProviderUtils},
        ELDER_SIZE, MIN_ADULT_AGE, MIN_AGE,
    };
    use anyhow::{anyhow, Error, Result};
    use assert_matches::assert_matches;
    use futures::{
        future::{self, Either},
        pin_mut,
    };
    use secured_linked_list::SecuredLinkedList;
    use sn_messaging::{node::MemberInfo, SectionAuthorityProvider};
    use std::collections::BTreeMap;
    use tokio::task;

    #[tokio::test]
    async fn join_as_adult() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (section_auth, mut nodes, sk_set) =
            gen_section_authority_provider(Prefix::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let bootstrap_addr = bootstrap_node.addr;

        let sk = sk_set.secret_key();
        let pk = sk.public_key();

        // Node in first section has to have an age higher than MIN_ADULT_AGE
        // Otherwise during the bootstrap process, node will change its id and age.
        let node_age = MIN_AGE + 2;
        let node = Node::new(
            ed25519::gen_keypair(&Prefix::default().range_inclusive(), node_age),
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
            // Receive JoinRequest
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;

            let bootstrap_addrs: Vec<SocketAddr> =
                recipients.iter().map(|(_name, addr)| *addr).collect();
            assert_eq!(bootstrap_addrs, [bootstrap_addr]);

            let (message, dest_info) = assert_matches!(message, MessageType::Routing { msg, dest_info } =>
                (msg, dest_info));

            assert_eq!(dest_info.dest, *peer.name());
            assert_matches!(message.variant, Variant::JoinRequest(request) => {
                assert!(request.resource_proof_response.is_none());
                assert!(request.relocate_payload.is_none());
            });

            // Send JoinResponse::Retry with section auth provider info
            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Retry(section_auth.clone()))),
                &bootstrap_node,
                section_auth.section_key(),
                *peer.name(),
            )?;

            // Receive the second JoinRequest with correct section info
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
            assert_matches!(message.variant, Variant::JoinRequest(request) => {
                assert_eq!(request.section_key, pk);
                assert!(request.relocate_payload.is_none());
            });

            // Send JoinResponse::Approval
            let section_auth = proven(sk, section_auth.clone())?;
            let member_info = proven(sk, MemberInfo::joined(peer))?;
            let proof_chain = SecuredLinkedList::new(pk);
            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Approval {
                    genesis_key: pk,
                    section_auth: section_auth.clone(),
                    member_info,
                    section_chain: proof_chain,
                })),
                &bootstrap_node,
                section_auth.value.section_key(),
                *peer.name(),
            )?;

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
    async fn join_receive_redirect_response() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (section_auth, mut nodes, sk_set) =
            gen_section_authority_provider(Prefix::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let pk_set = sk_set.public_keys();

        let node = Node::new(
            ed25519::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let name = node.name();
        let state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.run(vec![bootstrap_node.addr], None, None);
        let test_task = async move {
            // Receive JoinRequest
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;

            assert_eq!(
                recipients
                    .into_iter()
                    .map(|peer| peer.1)
                    .collect::<Vec<_>>(),
                vec![bootstrap_node.addr]
            );

            assert_matches!(message, MessageType::Routing { msg, .. } =>
                assert_matches!(msg.variant, Variant::JoinRequest{..}));

            // Send JoinResponse::Redirect
            let new_bootstrap_addrs: BTreeMap<_, _> = (0..ELDER_SIZE)
                .map(|_| (XorName::random(), gen_addr()))
                .collect();

            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Redirect(SectionAuthorityProvider {
                    prefix: Prefix::default(),
                    public_key_set: pk_set.clone(),
                    elders: new_bootstrap_addrs.clone(),
                }))),
                &bootstrap_node,
                section_auth.section_key(),
                name,
            )?;
            task::yield_now().await;

            // Receive new JoinRequest with redirected bootstrap contacts
            let (message, recipients) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;

            assert_eq!(
                recipients
                    .into_iter()
                    .map(|peer| peer.1)
                    .collect::<Vec<_>>(),
                new_bootstrap_addrs
                    .iter()
                    .map(|(_, addr)| *addr)
                    .collect::<Vec<_>>()
            );

            let (message, dest_info) = assert_matches!(message, MessageType::Routing { msg, dest_info } =>
                (msg, dest_info));

            assert_eq!(dest_info.dest_section_pk, pk_set.public_key());
            assert_matches!(message.variant, Variant::JoinRequest(req) => {
                assert_eq!(req.section_key, pk_set.public_key());
            });

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
    async fn join_invalid_redirect_response() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (section_auth, mut nodes, sk_set) =
            gen_section_authority_provider(Prefix::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);
        let pk_set = sk_set.public_keys();

        let node = Node::new(
            ed25519::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );
        let node_name = node.name();
        let state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.run(vec![bootstrap_node.addr], None, None);
        let test_task = async {
            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;

            assert_matches!(message, MessageType::Routing { msg, .. } =>
                    assert_matches!(msg.variant, Variant::JoinRequest{..}));

            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Redirect(SectionAuthorityProvider {
                    prefix: Prefix::default(),
                    public_key_set: pk_set.clone(),
                    elders: BTreeMap::new(),
                }))),
                &bootstrap_node,
                section_auth.section_key(),
                node_name,
            )?;
            task::yield_now().await;

            let addrs = (0..ELDER_SIZE)
                .map(|_| (XorName::random(), gen_addr()))
                .collect();

            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Redirect(SectionAuthorityProvider {
                    prefix: Prefix::default(),
                    public_key_set: pk_set.clone(),
                    elders: addrs,
                }))),
                &bootstrap_node,
                section_auth.section_key(),
                node_name,
            )?;
            task::yield_now().await;

            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;

            assert_matches!(message, MessageType::Routing { msg, .. } =>
                        assert_matches!(msg.variant, Variant::JoinRequest{..}));

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
    async fn join_disallowed_response() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let (section_auth, mut nodes, _) =
            gen_section_authority_provider(Prefix::default(), ELDER_SIZE);
        let bootstrap_node = nodes.remove(0);

        let node = Node::new(
            ed25519::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );

        let node_name = node.name();
        let state = State::new(node, send_tx, recv_rx);

        let bootstrap_task = state.run(vec![bootstrap_node.addr], None, None);
        let test_task = async {
            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("JoinRequest was not received"))?;

            assert_matches!(message, MessageType::Routing { msg, .. } =>
                            assert_matches!(msg.variant, Variant::JoinRequest{..}));

            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Rejected(
                    JoinRejectionReason::JoinsDisallowed,
                ))),
                &bootstrap_node,
                section_auth.section_key(),
                node_name,
            )?;

            Ok(())
        };

        let (join_result, test_result) = future::join(bootstrap_task, test_task).await;

        if let Err(RoutingError::TryJoinLater) = join_result {
        } else {
            return Err(anyhow!("Not getting an execpted network rejection."));
        }

        test_result
    }

    #[tokio::test]
    async fn join_invalid_retry_prefix_response() -> Result<()> {
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let (recv_tx, recv_rx) = mpsc::channel(1);
        let recv_rx = MessageReceiver::Deserialized(recv_rx);

        let bootstrap_node = Node::new(
            ed25519::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
            gen_addr(),
        );

        let node = Node::new(
            ed25519::gen_keypair(&Prefix::default().range_inclusive(), MIN_ADULT_AGE),
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
            assert_matches!(message.variant, Variant::JoinRequest(_));

            // Send `Retry` with bad prefix
            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Retry(
                    gen_section_authority_provider(bad_prefix, ELDER_SIZE).0,
                ))),
                &bootstrap_node,
                section_key,
                node_name,
            )?;
            task::yield_now().await;

            // Send `Retry` with good prefix
            send_response(
                &recv_tx,
                Variant::JoinResponse(Box::new(JoinResponse::Retry(
                    gen_section_authority_provider(good_prefix, ELDER_SIZE).0,
                ))),
                &bootstrap_node,
                section_key,
                node_name,
            )?;

            let (message, _) = send_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("RoutingMsg was not received"))?;

            let message = assert_matches!(message, MessageType::Routing{ msg, .. } => msg);
            assert_matches!(message.variant, Variant::JoinRequest(_));

            Ok(())
        };

        pin_mut!(join_task);
        pin_mut!(test_task);

        match future::select(join_task, test_task).await {
            Either::Left(_) => unreachable!(),
            Either::Right((output, _)) => output,
        }
    }

    // test helper
    fn send_response(
        recv_tx: &mpsc::Sender<(MessageType, SocketAddr)>,
        variant: Variant,
        bootstrap_node: &Node,
        section_key: bls::PublicKey,
        node_name: XorName,
    ) -> Result<()> {
        let message = RoutingMsg::single_src(
            bootstrap_node,
            DstLocation::DirectAndUnrouted,
            variant,
            section_key,
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

        Ok(())
    }
}

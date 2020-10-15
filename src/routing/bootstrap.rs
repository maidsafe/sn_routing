// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Comm;
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
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::mpsc, task};
use xor_name::Prefix;

/// Bootstrap into the network as an infant node.
pub(crate) async fn infant(
    node: Node,
    comm: &Comm,
    bootstrap_addr: SocketAddr,
) -> Result<(Node, Section)> {
    let local_set = task::LocalSet::new();
    let (message_tx, message_rx) = mpsc::channel(1);
    let incoming_connections = comm.listen()?;
    let _ = local_set.spawn_local(receive_messages(incoming_connections, message_tx));

    let mut state = State::new(node, comm, message_rx)?;
    let section = local_set
        .run_until(state.run(vec![bootstrap_addr], None))
        .await?;

    Ok((state.node, section))
}

/// Re-bootstrap as a relocated node.
pub(crate) async fn relocate(
    node: Node,
    comm: &Comm,
    message_rx: mpsc::Receiver<(Message, SocketAddr)>,
    bootstrap_addrs: Vec<SocketAddr>,
    relocate_details: SignedRelocateDetails,
) -> Result<(Node, Section)> {
    let mut state = State::new(node, comm, message_rx)?;
    let section = state.run(bootstrap_addrs, Some(relocate_details)).await?;
    Ok((state.node, section))
}

struct State<'a> {
    comm: &'a Comm,
    message_rx: mpsc::Receiver<(Message, SocketAddr)>,
    node: Node,
}

impl<'a> State<'a> {
    fn new(
        node: Node,
        comm: &'a Comm,
        message_rx: mpsc::Receiver<(Message, SocketAddr)>,
    ) -> Result<Self> {
        Ok(Self {
            comm,
            message_rx,
            node,
        })
    }

    async fn run(
        &mut self,
        bootstrap_addrs: Vec<SocketAddr>,
        relocate_details: Option<SignedRelocateDetails>,
    ) -> Result<Section> {
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

    async fn bootstrap(
        &mut self,
        mut bootstrap_addrs: Vec<SocketAddr>,
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<(EldersInfo, bls::PublicKey)> {
        loop {
            self.send_bootstrap_request(&bootstrap_addrs, relocate_details)
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
        &self,
        recipients: &[SocketAddr],
        relocate_details: Option<&SignedRelocateDetails>,
    ) -> Result<()> {
        let destination = match relocate_details {
            Some(details) => *details.destination(),
            None => self.node.name(),
        };

        let message = Message::single_src(
            &self.node.keypair,
            self.node.age,
            DstLocation::Direct,
            Variant::BootstrapRequest(destination),
            None,
            None,
        )?;

        debug!("{} Sending BootstrapRequest to {:?}", self.node, recipients);

        self.comm
            .send_message_to_targets(recipients, recipients.len(), message.to_bytes())
            .await?;

        Ok(())
    }

    async fn receive_bootstrap_response(&mut self) -> Result<(BootstrapResponse, SocketAddr)> {
        while let Some((message, sender)) = self.message_rx.recv().await {
            match message.variant() {
                Variant::BootstrapResponse(response) => {
                    if !self.verify_message(&message, None) {
                        continue;
                    }

                    return Ok((response.clone(), sender));
                }
                _ => {
                    trace!(
                        "{} Useless message {:?} from {}",
                        self.node,
                        message,
                        sender,
                    );
                }
            }
        }

        error!("{} Message sender unexpectedly closed", self.node);
        Err(Error::InvalidState)
    }

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

        let mut rng = crate::rng::new();
        let new_keypair = crypto::keypair_within_range(&mut rng, &name_prefix.range_inclusive());
        let new_name = crypto::name(&new_keypair.public);
        let age = relocate_details.relocate_details().age;
        let relocate_payload =
            RelocatePayload::new(relocate_details, &new_name, &self.node.keypair)?;

        info!("{} Changing name to {}.", self.node, new_name);
        self.node.keypair = Arc::new(new_keypair);
        self.node.age = age;

        Ok(relocate_payload)
    }

    async fn join(
        &mut self,
        mut elders_info: EldersInfo,
        mut section_key: bls::PublicKey,
        relocate_payload: Option<RelocatePayload>,
    ) -> Result<Section> {
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
                    return Ok(Section::new(section_chain, elders_info));
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
        &self,
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
        let message = Message::single_src(
            &self.node.keypair,
            self.node.age,
            DstLocation::Direct,
            variant,
            None,
            None,
        )?;

        self.comm
            .send_message_to_targets(&recipients, recipients.len(), message.to_bytes())
            .await?;

        Ok(())
    }

    async fn receive_join_response(
        &mut self,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<(JoinResponse, SocketAddr)> {
        while let Some((message, sender)) = self.message_rx.recv().await {
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

                _ => {
                    trace!(
                        "{} Useless message {:?} from {}",
                        self.node,
                        message,
                        sender,
                    );
                }
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
                warn!(
                    "{} Verification of {:?} failed: {}",
                    self.node, message, error
                );
                false
            }
        }
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

async fn receive_messages(
    mut incoming_connections: qp2p::IncomingConnections,
    tx: mpsc::Sender<(Message, SocketAddr)>,
) {
    while let Some(mut incoming_messages) = incoming_connections.next().await {
        let mut tx = tx.clone();
        let _ = task::spawn_local(async move {
            while let Some(message) = incoming_messages.next().await {
                match message {
                    qp2p::Message::UniStream { bytes, src, .. } => {
                        match Message::from_bytes(&bytes) {
                            Ok(message) => {
                                let _ = tx.send((message, src)).await;
                            }
                            Err(error) => debug!("Failed to deserialize message: {}", error),
                        }
                    }
                    qp2p::Message::BiStream { .. } => {
                        trace!("Ignore bi-stream messages during bootstrap");
                    }
                }
            }
        });
    }
}

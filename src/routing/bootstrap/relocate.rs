// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{send_message, verify_message};
use crate::{
    ed25519,
    error::{Error, Result},
    messages::RoutingMsgUtils,
    node::Node,
    peer::PeerUtils,
    relocation::{RelocatePayloadUtils, SignedRelocateDetailsUtils},
    routing::comm::Comm,
    section::{SectionAuthorityProviderUtils, SectionUtils},
};
use sn_data_types::PublicKey;
use sn_messaging::{
    node::{
        JoinAsRelocatedRequest, JoinAsRelocatedResponse, RelocatePayload, RoutingMsg, Section,
        SignedRelocateDetails, Variant,
    },
    DestInfo, DstLocation, MessageType,
};
use std::{collections::HashSet, net::SocketAddr};
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

/// Re-join as a relocated node.
pub(crate) struct JoinAsRelocated<'a> {
    // Communication api for outgoing messages.
    comm: &'a Comm,
    // Receiver for incoming join response messages.
    recv_rx: mpsc::Receiver<(RoutingMsg, SocketAddr)>,
    node: Node,
}

impl<'a> JoinAsRelocated<'a> {
    pub fn new(
        comm: &'a Comm,
        node: Node,
        recv_rx: mpsc::Receiver<(RoutingMsg, SocketAddr)>,
    ) -> Self {
        Self {
            comm,
            recv_rx,
            node,
        }
    }

    // Send `JoinAsRelocatedRequest` and wait for the response. If the response is:
    // - `Retry`: repeat with the new info, which shall include the relocation payload.
    // - `Redirect`: repeat with the new set of addresses.
    // - `ResourceChallenge`: ignore it as it's an invalid/unexpected type of response.
    // - `Approval`: returns the `Section` to use by this node, completing the bootstrap.
    //
    // NOTE: It's not guaranteed this function ever returns. This can happen due to messages being
    // lost in transit or other reasons. It's the responsibility of the caller to handle this case,
    // for example by using a timeout.
    pub async fn run(
        mut self,
        bootstrap_addrs: Vec<SocketAddr>,
        genesis_key: bls::PublicKey,
        relocate_details: SignedRelocateDetails,
    ) -> Result<(Node, Section)> {
        let mut section_key = relocate_details.destination_key()?;
        let dest_xorname = *relocate_details.destination()?;

        // We send a first join request to obtain the section prefix, which
        // we will then use to generate the relocation payload and send the
        // `JoinAsRelocatedRequest` again with it.
        // TODO: include the section Prefix in the RelocationDetails so we save one request.
        let mut relocate_payload = None;
        let join_request = JoinAsRelocatedRequest {
            section_key,
            relocate_payload: None,
        };

        let mut recipients: Vec<(XorName, SocketAddr)> = bootstrap_addrs
            .iter()
            .map(|addr| (dest_xorname, *addr))
            .collect();

        self.send_join_requests(join_request, &recipients, section_key)
            .await?;

        // Avoid sending more than one request to the same peer.
        let mut used_recipient = HashSet::<SocketAddr>::new();
        loop {
            used_recipient.extend(recipients.iter().map(|(_, addr)| addr));

            let (response, sender) = self
                .receive_join_response(&genesis_key, relocate_payload.as_ref())
                .await?;

            match response {
                JoinAsRelocatedResponse::Approval {
                    section_auth,
                    section_chain,
                    ..
                } => {
                    return Ok((
                        self.node,
                        Section::new(genesis_key, section_chain, section_auth)?,
                    ));
                }
                JoinAsRelocatedResponse::Retry(section_auth) => {
                    if section_auth.section_key() == section_key {
                        continue;
                    }

                    let new_recipients: Vec<(XorName, SocketAddr)> = section_auth
                        .elders
                        .iter()
                        .map(|(name, addr)| (*name, *addr))
                        .collect();

                    // if we are relocating, and we didn't generate
                    // the relocation payload yet, we do it now
                    if relocate_payload.is_none() {
                        relocate_payload = Some(self.build_relocation_payload(
                            &section_auth.prefix,
                            relocate_details.clone(),
                        )?);
                    }

                    info!(
                        "Newer Join response for our prefix {:?} from {:?}",
                        section_auth, sender
                    );
                    section_key = section_auth.section_key();
                    let join_request = JoinAsRelocatedRequest {
                        section_key,
                        relocate_payload: relocate_payload.clone(),
                    };

                    recipients = new_recipients;
                    self.send_join_requests(join_request, &recipients, section_key)
                        .await?;
                }
                JoinAsRelocatedResponse::Redirect(section_auth) => {
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

                    // if we are relocating, and we didn't generate
                    // the relocation payload yet, we do it now
                    if relocate_payload.is_none() {
                        relocate_payload = Some(self.build_relocation_payload(
                            &section_auth.prefix,
                            relocate_details.clone(),
                        )?);
                    }

                    info!(
                        "Newer Join response for our prefix {:?} from {:?}",
                        section_auth, sender
                    );
                    section_key = section_auth.section_key();
                    let join_request = JoinAsRelocatedRequest {
                        section_key,
                        relocate_payload: relocate_payload.clone(),
                    };

                    recipients = new_recipients;
                    self.send_join_requests(join_request, &recipients, section_key)
                        .await?;
                }
                JoinAsRelocatedResponse::NodeNotReachable(addr) => {
                    error!(
                        "Node cannot join as relocated since it is not externally reachable: {}",
                        addr
                    );
                    return Err(Error::NodeNotReachable(addr));
                }
            }
        }
    }

    // Change our name to fit the destination section and apply the new age.
    fn build_relocation_payload(
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

    async fn send_join_requests(
        &mut self,
        join_request: JoinAsRelocatedRequest,
        recipients: &[(XorName, SocketAddr)],
        section_key: bls::PublicKey,
    ) -> Result<()> {
        info!("Sending {:?} to {:?}", join_request, recipients);

        let variant = Variant::JoinAsRelocatedRequest(Box::new(join_request));
        let message = RoutingMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted,
            variant,
            section_key,
        )?;

        send_message(
            self.comm,
            MessageType::Routing {
                msg: message,
                dest_info: DestInfo {
                    dest: recipients[0].0,
                    dest_section_pk: section_key,
                },
            },
            recipients.to_vec(),
        )
        .await;

        Ok(())
    }

    async fn receive_join_response(
        &mut self,
        expected_genesis_key: &bls::PublicKey,
        relocate_payload: Option<&RelocatePayload>,
    ) -> Result<(JoinAsRelocatedResponse, SocketAddr)> {
        let destination = match relocate_payload {
            Some(payload) => *payload.details.destination()?,
            None => self.node.name(),
        };

        while let Some((routing_msg, sender)) = self.recv_rx.recv().await {
            // we are interested only in `JoinAsRelocatedResponse` type of messages
            if let Variant::JoinAsRelocatedResponse(join_response) = &routing_msg.variant {
                match **join_response {
                    JoinAsRelocatedResponse::NodeNotReachable(_) => {
                        return Ok((*join_response.clone(), sender))
                    }
                    JoinAsRelocatedResponse::Retry(ref section_auth)
                    | JoinAsRelocatedResponse::Redirect(ref section_auth) => {
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

                        if !verify_message(&routing_msg, None) {
                            continue;
                        }

                        return Ok((*join_response.clone(), sender));
                    }
                    JoinAsRelocatedResponse::Approval {
                        ref section_auth,
                        ref member_info,
                        ref section_chain,
                    } => {
                        if member_info.value.peer.name() != &self.node.name() {
                            trace!("Ignore NodeApproval not for us");
                            continue;
                        }

                        if expected_genesis_key != section_chain.root_key() {
                            trace!("Genesis key doesn't match");
                            continue;
                        }

                        let trusted_key = if let Some(payload) = relocate_payload {
                            Some(&payload.relocate_details()?.destination_key)
                        } else {
                            None
                        };

                        if !verify_message(&routing_msg, trusted_key) {
                            continue;
                        }

                        trace!(
                            "This node has been approved to join the network at {:?}!",
                            section_auth.value.prefix,
                        );

                        return Ok((*join_response.clone(), sender));
                    }
                }
            }
        }

        error!("RoutingMsg sender unexpectedly closed");
        // TODO: consider more specific error here (e.g. `BootstrapInterrupted`)
        Err(Error::InvalidState)
    }
}

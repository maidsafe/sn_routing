// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Base;
use crate::{
    chain::{
        AccumulatingEvent, Chain, EldersChange, EldersInfo, Proof, ProofSet, SectionKeyInfo,
        SendAckMessagePayload,
    },
    error::RoutingError,
    event::Event,
    id::PublicId,
    messages::{DirectMessage, MessageContent, RoutingMessage},
    outbox::EventBox,
    parsec::{self, Block, Observation, ParsecMap},
    quic_p2p::NodeInfo,
    routing_table::{Authority, Prefix},
    state_machine::Transition,
    types::MessageId,
    xor_name::XorName,
};
use log::LogLevel;
use maidsafe_utilities::serialisation::{deserialise, serialise};

/// Common functionality for node states post resource proof.
pub trait Approved: Base {
    fn parsec_map_mut(&mut self) -> &mut ParsecMap;
    fn chain_mut(&mut self) -> &mut Chain;
    fn send_event(&mut self, event: Event, outbox: &mut dyn EventBox);
    fn set_pfx_successfully_polled(&mut self, val: bool);
    fn is_pfx_successfully_polled(&self) -> bool;

    /// Handles an accumulated `AddElder` event.
    fn handle_add_elder_event(
        &mut self,
        new_pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `RemoveElder` event.
    fn handle_remove_elder_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `Online` event.
    fn handle_online_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError>;

    /// Handles an accumulated `Offline` event.
    fn handle_offline_event(&mut self, pub_id: PublicId) -> Result<(), RoutingError>;

    /// Handles an accumulated `OurMerge` event.
    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError>;

    /// Handles an accumulated `NeighbourMerge` event.
    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError>;

    /// Handles an accumulated `SectionInfo` event.
    fn handle_section_info_event(
        &mut self,
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
        neighbour_change: EldersChange,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError>;

    /// Handle an accumulated `TheirKeyInfo` event
    fn handle_their_key_info_event(&mut self, key_info: SectionKeyInfo)
        -> Result<(), RoutingError>;

    /// Handle an accumulated `SendAckMessage` event
    fn handle_send_ack_message_event(
        &mut self,
        ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError>;

    fn handle_parsec_request(
        &mut self,
        msg_version: u64,
        par_request: parsec::Request,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let log_ident = self.log_ident();
        let (response, poll) =
            self.parsec_map_mut()
                .handle_request(msg_version, par_request, pub_id, &log_ident);

        if let Some(response) = response {
            self.send_direct_message(&pub_id, response);
        }

        if poll {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn handle_parsec_response(
        &mut self,
        msg_version: u64,
        par_response: parsec::Response,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let log_ident = self.log_ident();
        if self
            .parsec_map_mut()
            .handle_response(msg_version, par_response, pub_id, &log_ident)
        {
            self.parsec_poll(outbox)
        } else {
            Ok(Transition::Stay)
        }
    }

    fn parsec_poll(&mut self, outbox: &mut dyn EventBox) -> Result<Transition, RoutingError> {
        while let Some(block) = self.parsec_map_mut().poll() {
            let parsec_version = self.parsec_map_mut().last_version();
            match block.payload() {
                Observation::Accusation { .. } => {
                    // FIXME: Handle properly
                    unreachable!("...")
                }
                Observation::Genesis {
                    group,
                    related_info,
                } => {
                    // FIXME: Validate with Chain info.

                    trace!(
                        "{} Parsec Genesis {}: group {:?} - related_info {}",
                        self,
                        parsec_version,
                        group,
                        related_info.len()
                    );

                    for pub_id in group {
                        // Establish connection with the genesis peer, if not already connected.
                        if let Err(error) = self.send_connection_request(
                            *pub_id,
                            Authority::Node(*self.name()),
                            Authority::Node(*pub_id.name()),
                            outbox,
                        ) {
                            debug!(
                                "{} - Failed to send connection request to genesis peer {}: {:?}",
                                self, pub_id, error
                            );
                        }

                        // Notify upper layers about the new node.
                        self.send_event(Event::NodeAdded(*pub_id.name()), outbox);
                    }

                    self.chain_mut()
                        .handle_genesis_event(&group, &related_info)?;
                    self.set_pfx_successfully_polled(true);

                    continue;
                }
                Observation::OpaquePayload(event) => {
                    if let Some(proof) = block.proofs().iter().next().map(|p| Proof {
                        pub_id: *p.public_id(),
                        sig: *p.signature(),
                    }) {
                        trace!(
                            "{} Parsec OpaquePayload {}: {} - {:?}",
                            self,
                            parsec_version,
                            proof.pub_id(),
                            event
                        );
                        self.chain_mut().handle_opaque_event(event, proof)?;
                    }
                }
                Observation::Add { peer_id, .. } => {
                    let event = AccumulatingEvent::AddElder(*peer_id).into_network_event();
                    let proof_set = to_proof_set(&block);
                    trace!("{} Parsec Add {}: - {}", self, parsec_version, peer_id);
                    self.chain_mut().handle_churn_event(&event, proof_set)?;
                }
                Observation::Remove { peer_id, .. } => {
                    let event = AccumulatingEvent::RemoveElder(*peer_id).into_network_event();
                    let proof_set = to_proof_set(&block);
                    trace!("{} Parsec Remove {}: - {}", self, parsec_version, peer_id);
                    self.chain_mut().handle_churn_event(&event, proof_set)?;
                }
                obs @ Observation::StartDkg(_) | obs @ Observation::DkgMessage(_) => {
                    log_or_panic!(
                        LogLevel::Error,
                        "parsec_poll polled internal Observation {}: {:?}",
                        parsec_version,
                        obs
                    );
                }
                Observation::DkgResult { .. } => unreachable!("..."),
            }

            match self.chain_poll(outbox)? {
                Transition::Stay => (),
                transition => return Ok(transition),
            }
        }

        Ok(Transition::Stay)
    }

    fn chain_poll(&mut self, outbox: &mut dyn EventBox) -> Result<Transition, RoutingError> {
        let mut our_pfx = *self.chain_mut().our_prefix();
        while let Some((event, neighbour_change)) = self.chain_mut().poll()? {
            trace!("{} Handle accumulated event: {:?}", self, event);

            match event {
                AccumulatingEvent::AddElder(pub_id) => {
                    self.handle_add_elder_event(pub_id, outbox)?;
                }
                AccumulatingEvent::RemoveElder(pub_id) => {
                    self.handle_remove_elder_event(pub_id, outbox)?;
                }
                AccumulatingEvent::Online(info) => {
                    self.handle_online_event(info, outbox)?;
                }
                AccumulatingEvent::Offline(pub_id) => {
                    self.handle_offline_event(pub_id)?;
                }
                AccumulatingEvent::OurMerge => self.handle_our_merge_event()?,
                AccumulatingEvent::NeighbourMerge(_) => self.handle_neighbour_merge_event()?,
                AccumulatingEvent::SectionInfo(elders_info) => {
                    match self.handle_section_info_event(
                        elders_info,
                        our_pfx,
                        neighbour_change,
                        outbox,
                    )? {
                        Transition::Stay => (),
                        transition => return Ok(transition),
                    }
                }
                AccumulatingEvent::TheirKeyInfo(key_info) => {
                    self.handle_their_key_info_event(key_info)?
                }
                AccumulatingEvent::AckMessage(_payload) => {
                    // Update their_knowledge is handled within the chain.
                }
                AccumulatingEvent::SendAckMessage(payload) => {
                    self.handle_send_ack_message_event(payload)?
                }
                AccumulatingEvent::ParsecPrune => {
                    info!(
                        "{} Handling chain {:?} not yet implemented, ignoring.",
                        self, event
                    );
                }
            }

            our_pfx = *self.chain_mut().our_prefix();
        }

        Ok(Transition::Stay)
    }

    fn send_connection_request(
        &mut self,
        their_pub_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        _: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if their_pub_id == *self.id() {
            debug!("{} - Not sending connection request to ourselves.", self);
            return Ok(());
        }

        if self.peer_map().has(&their_pub_id) {
            debug!(
                "{} - Not sending connection request to {} - already connected.",
                self, their_pub_id
            );
            return Ok(());
        }

        let conn_info = serialise(&self.our_connection_info()?)?;
        let content = MessageContent::ConnectionRequest {
            conn_info,
            pub_id: *self.full_id().public_id(),
            msg_id: MessageId::new(),
        };

        debug!("{} - Sending connection request to {}.", self, their_pub_id);

        self.send_routing_message(RoutingMessage { src, dst, content })
            .map_err(|err| {
                debug!(
                    "{} - Failed to send connection request to {}: {:?}.",
                    self, their_pub_id, err
                );
                err
            })
    }

    fn handle_connection_request(
        &mut self,
        encrypted_their_conn_info: &[u8],
        their_pub_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        _: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if src.single_signing_name() != Some(their_pub_id.name()) {
            // Connection request not from the source node.
            return Err(RoutingError::InvalidSource);
        }

        if dst.single_signing_name() != Some(self.name()) {
            // Connection request not for us.
            return Err(RoutingError::InvalidDestination);
        }

        let their_conn_info: NodeInfo = deserialise(encrypted_their_conn_info)?;

        debug!(
            "{} - Received connection request from {:?}.",
            self, their_pub_id
        );

        self.peer_map_mut().insert(their_pub_id, their_conn_info);
        self.send_direct_message(&their_pub_id, DirectMessage::ConnectionResponse);

        Ok(())
    }
}

fn to_proof_set(block: &Block) -> ProofSet {
    let sigs = block
        .proofs()
        .iter()
        .map(|proof| (*proof.public_id(), *proof.signature()))
        .collect();
    ProofSet { sigs }
}

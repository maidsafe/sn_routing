// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{approved::Approved, Command, Context, NodeInfo, State};
use crate::{
    error::{Error, Result},
    event::{Connected, Event},
    messages::{BootstrapResponse, JoinRequest, Message, Variant, VerifyStatus},
    peer::Peer,
    relocation::RelocatePayload,
    section::{EldersInfo, SharedState},
    DstLocation, MIN_AGE,
};
use std::{net::SocketAddr, time::Duration};
use xor_name::Prefix;

/// Time after which an attempt to joining a section is cancelled (and possibly retried).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

// The joining stage - node is waiting to be approved by the section.
pub(crate) struct Joining {
    pub node_info: NodeInfo,
    // EldersInfo of the section we are joining.
    elders_info: EldersInfo,
    // PublicKey of the section we are joining.
    section_key: bls::PublicKey,
    // Whether we are joining as infant or relocating.
    join_type: JoinType,
    timer_token: u64,
}

impl Joining {
    pub fn new(
        cx: &mut Context,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
        relocate_payload: Option<RelocatePayload>,
        node_info: NodeInfo,
    ) -> Result<Self> {
        let join_type = match relocate_payload {
            Some(payload) => JoinType::Relocate(payload),
            None => JoinType::First,
        };

        let mut stage = Self {
            node_info,
            elders_info,
            section_key,
            join_type,
            timer_token: 0,
        };
        stage.send_join_requests(cx)?;

        Ok(stage)
    }

    pub fn handle_message(
        &mut self,
        cx: &mut Context,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<()> {
        trace!("Got {:?}", msg);

        if !self.in_dst_location(msg.dst()) {
            return Ok(());
        }

        match msg.variant() {
            Variant::BootstrapResponse(BootstrapResponse::Join {
                elders_info,
                section_key,
            }) => {
                verify_message(&msg, None)?;
                self.handle_bootstrap_response(
                    cx,
                    msg.src().to_sender_node(sender)?,
                    elders_info.clone(),
                    *section_key,
                )
            }
            Variant::NodeApproval(payload) => {
                let trusted_key = match &self.join_type {
                    JoinType::Relocate(payload) => {
                        Some(&payload.relocate_details().destination_key)
                    }
                    JoinType::First { .. } => None,
                };
                verify_message(&msg, trusted_key)?;

                // Transition from Joining to Approved
                let connect_type = self.connect_type();
                let section_chain = msg.proof_chain()?.clone();

                info!(
                    "This node has been approved to join the network at {:?}!",
                    payload.value.prefix,
                );

                let shared_state = SharedState::new(section_chain, payload.clone());
                let state = Approved::new(shared_state, None, self.node_info.clone())?;
                let state = State::Approved(state);
                cx.push(Command::Transition(Box::new(state)));

                self.node_info.send_event(Event::Connected(connect_type));

                Ok(())
            }
            _ => {
                debug!("Useless message from {:?}: {:?}", sender, msg);
                Ok(())
            }
        }
    }

    pub fn handle_timeout(&mut self, cx: &mut Context, token: u64) -> Result<()> {
        if token == self.timer_token {
            debug!("Timeout when trying to join a section");
            // Try again
            self.send_join_requests(cx)?;
        }

        Ok(())
    }

    fn handle_bootstrap_response(
        &mut self,
        cx: &mut Context,
        sender: Peer,
        new_elders_info: EldersInfo,
        new_section_key: bls::PublicKey,
    ) -> Result<()> {
        if new_section_key == self.section_key {
            return Ok(());
        }

        if new_elders_info.prefix.matches(&self.node_info.name()) {
            info!(
                "Newer Join response for our prefix {:?} from {:?}",
                new_elders_info, sender
            );
            self.elders_info = new_elders_info;
            self.section_key = new_section_key;
            self.send_join_requests(cx)?;
        } else {
            warn!(
                "Newer Join response not for our prefix {:?} from {:?}",
                new_elders_info, sender,
            );
        }

        Ok(())
    }

    // The EldersInfo of the section we are joining.
    pub fn target_section_elders_info(&self) -> &EldersInfo {
        &self.elders_info
    }

    // Are we relocating or joining for the first time?
    fn connect_type(&self) -> Connected {
        match &self.join_type {
            JoinType::First { .. } => Connected::First,
            JoinType::Relocate(payload) => Connected::Relocate {
                previous_name: payload.relocate_details().pub_id,
            },
        }
    }

    fn send_join_requests(&mut self, cx: &mut Context) -> Result<()> {
        let (relocate_payload, age) = match &self.join_type {
            JoinType::First { .. } => (None, MIN_AGE),
            JoinType::Relocate(payload) => (Some(payload), payload.relocate_details().age),
        };

        let recipients: Vec<_> = self
            .elders_info
            .elders
            .values()
            .map(Peer::addr)
            .copied()
            .collect();

        let join_request = JoinRequest {
            section_key: self.section_key,
            relocate_payload: relocate_payload.cloned(),
        };

        info!("Sending {:?} to {:?}", join_request, recipients);

        let variant = Variant::JoinRequest(Box::new(join_request));
        let message = Message::single_src(
            &self.node_info.keypair,
            age,
            DstLocation::Direct,
            variant,
            None,
            None,
        )?;

        cx.send_message_to_targets(&recipients, recipients.len(), message.to_bytes());
        self.timer_token = cx.schedule_timeout(JOIN_TIMEOUT);

        Ok(())
    }

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        match dst {
            DstLocation::Node(name) => *name == self.node_info.name(),
            DstLocation::Section(_) => false,
            DstLocation::Direct => true,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum JoinType {
    // Node joining the network for the first time.
    First,
    // Node being relocated.
    Relocate(RelocatePayload),
}

fn verify_message(msg: &Message, trusted_key: Option<&bls::PublicKey>) -> Result<()> {
    // The message verification will use only those trusted keys whose prefix is compatible with
    // the message source. By using empty prefix, we make sure `trusted_key` is always used.
    let prefix = Prefix::default();

    msg.verify(trusted_key.map(|key| (&prefix, key)))
        .and_then(|status| match (status, trusted_key) {
            (VerifyStatus::Full, _) | (VerifyStatus::Unknown, None) => Ok(()),
            (VerifyStatus::Unknown, Some(_)) => Err(Error::UntrustedMessage),
        })
        .map_err(|error| {
            warn!("Verification of {:?} failed: {}", msg, error);
            error
        })
}

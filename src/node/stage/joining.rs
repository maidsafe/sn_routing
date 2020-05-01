// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    core::Core,
    error::Result,
    event::Connected,
    id::P2pNode,
    messages::{self, BootstrapResponse, JoinRequest, Message, MessageHash, Variant, VerifyStatus},
    relocation::RelocatePayload,
    section::{EldersInfo, SectionKeyInfo},
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use std::{net::SocketAddr, time::Duration};

/// Time after which an attempt to joining a section is cancelled (and possibly retried).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(600);

// The joining stage - node is waiting to be approved by the section.
pub struct Joining {
    // EldersInfo of the section we are joining.
    elders_info: EldersInfo,
    // Whether we are joining as infant or relocating.
    join_type: JoinType,
}

impl Joining {
    pub fn new(
        core: &mut Core,
        elders_info: EldersInfo,
        relocate_payload: Option<RelocatePayload>,
    ) -> Self {
        let join_type = match relocate_payload {
            Some(payload) => JoinType::Relocate(payload),
            None => {
                let timeout_token = core.timer.schedule(JOIN_TIMEOUT);
                JoinType::First { timeout_token }
            }
        };

        let stage = Self {
            elders_info,
            join_type,
        };
        stage.send_join_requests(core);
        stage
    }

    // Returns whether the timeout was handled.
    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) -> bool {
        let join_token = match self.join_type {
            JoinType::First { timeout_token } => timeout_token,
            JoinType::Relocate(_) => return false,
        };

        if join_token == token {
            debug!("Timeout when trying to join a section.");

            for addr in self
                .elders_info
                .elders
                .values()
                .map(|node| *node.peer_addr())
            {
                core.transport.disconnect(addr);
            }

            true
        } else {
            false
        }
    }

    pub fn should_handle_message(&self, msg: &Message) -> bool {
        match msg.variant {
            Variant::NodeApproval(_)
            | Variant::BootstrapResponse(BootstrapResponse::Join(_))
            | Variant::Bounce { .. } => true,
            Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::AckMessage { .. }
            | Variant::GenesisUpdate(_)
            | Variant::Relocate(_)
            | Variant::MessageSignature(_)
            | Variant::BootstrapRequest(_)
            | Variant::BootstrapResponse(_)
            | Variant::JoinRequest(_)
            | Variant::MemberKnowledge { .. }
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Ping => false,
        }
    }

    pub fn handle_bootstrap_response(
        &mut self,
        core: &mut Core,
        sender: P2pNode,
        new_elders_info: EldersInfo,
    ) -> Result<()> {
        if new_elders_info.version <= self.elders_info.version {
            return Ok(());
        }

        if new_elders_info.prefix.matches(core.name()) {
            info!(
                "Newer Join response for our prefix {:?} from {:?}",
                new_elders_info, sender
            );
            self.elders_info = new_elders_info;
            self.send_join_requests(core);
        } else {
            log_or_panic!(
                log::Level::Error,
                "Newer Join response not for our prefix {:?} from {:?}",
                new_elders_info,
                sender,
            );
        }

        Ok(())
    }

    pub fn unhandled_message(
        &mut self,
        core: &mut Core,
        sender: Option<SocketAddr>,
        msg: Message,
        msg_bytes: Bytes,
    ) {
        match msg.variant {
            Variant::MemberKnowledge { .. }
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Ping => (),
            Variant::NodeApproval(_)
            | Variant::BootstrapResponse(BootstrapResponse::Join(_))
            | Variant::Bounce { .. } => unreachable!(),
            _ => {
                let sender = sender.expect("sender missing");

                debug!(
                    "Unhandled message - bouncing: {:?}, hash: {:?}",
                    msg,
                    MessageHash::from_bytes(&msg_bytes)
                );

                let variant = Variant::Bounce {
                    elders_version: None,
                    message: msg_bytes,
                };

                core.send_direct_message(&sender, variant)
            }
        }
    }

    pub fn verify_message(&self, msg: &Message) -> Result<bool> {
        match (&msg.variant, &self.join_type) {
            (Variant::NodeApproval(_), JoinType::Relocate(payload)) => {
                let details = payload.relocate_details();
                let key_info = &details.destination_key_info;
                verify_message_full(msg, Some(key_info))
            }
            (Variant::NodeApproval(_), JoinType::First { .. }) => {
                // We don't have any trusted keys to verify this message, but we still need to
                // handle it.
                Ok(true)
            }
            (Variant::BootstrapResponse(BootstrapResponse::Join(_)), _)
            | (Variant::Bounce { .. }, _) => verify_message_full(msg, None),
            _ => unreachable!("unexpected message to verify: {:?}", msg),
        }
    }

    // The EldersInfo of the section we are joining.
    pub fn target_section_elders_info(&self) -> &EldersInfo {
        &self.elders_info
    }

    // Are we relocating or joining for the first time?
    pub fn connect_type(&self) -> Connected {
        match self.join_type {
            JoinType::First { .. } => Connected::First,
            JoinType::Relocate(_) => Connected::Relocate,
        }
    }

    fn send_join_requests(&self, core: &mut Core) {
        let relocate_payload = match &self.join_type {
            JoinType::First { .. } => None,
            JoinType::Relocate(payload) => Some(payload),
        };

        for dst in self.elders_info.elders.values() {
            let join_request = JoinRequest {
                elders_version: self.elders_info.version,
                relocate_payload: relocate_payload.cloned(),
            };

            let variant = Variant::JoinRequest(Box::new(join_request));

            info!("Sending JoinRequest to {}", dst);
            core.send_direct_message(dst.peer_addr(), variant);
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum JoinType {
    // Node joining the network for the first time.
    First { timeout_token: u64 },
    // Node being relocated.
    Relocate(RelocatePayload),
}

fn verify_message_full(msg: &Message, key_info: Option<&SectionKeyInfo>) -> Result<bool> {
    msg.verify(as_iter(key_info))
        .and_then(VerifyStatus::require_full)
        .map_err(|error| {
            messages::log_verify_failure(msg, &error, as_iter(key_info));
            error
        })?;

    Ok(true)
}

fn as_iter(
    key_info: Option<&SectionKeyInfo>,
) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
    key_info
        .into_iter()
        .map(|key_info| (key_info.prefix(), key_info))
}

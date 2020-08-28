// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    core::Core,
    error::{Result, RoutingError},
    event::Connected,
    id::P2pNode,
    messages::{
        self, BootstrapResponse, JoinRequest, Message, MessageStatus, QueuedMessage, Variant,
        VerifyStatus,
    },
    relocation::RelocatePayload,
    section::EldersInfo,
};

use std::{mem, net::SocketAddr, time::Duration};
use xor_name::Prefix;

/// Time after which an attempt to joining a section is cancelled (and possibly retried).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

// The joining stage - node is waiting to be approved by the section.
pub(crate) struct Joining {
    // EldersInfo of the section we are joining.
    elders_info: EldersInfo,
    // PublicKey of the section we are joining.
    section_key: bls::PublicKey,
    // Whether we are joining as infant or relocating.
    join_type: JoinType,
    // Token for the join request timeout.
    timer_token: u64,
    // Message we can't handle until we are joined.
    msg_backlog: Vec<QueuedMessage>,
}

impl Joining {
    pub fn new(
        core: &mut Core,
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
        relocate_payload: Option<RelocatePayload>,
        msg_backlog: Vec<QueuedMessage>,
    ) -> Self {
        let join_type = match relocate_payload {
            Some(payload) => JoinType::Relocate(payload),
            None => JoinType::First,
        };
        let timer_token = core.timer.schedule(JOIN_TIMEOUT);

        let stage = Self {
            elders_info,
            section_key,
            join_type,
            timer_token,
            msg_backlog,
        };
        stage.send_join_requests(core);
        stage
    }

    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) {
        if token == self.timer_token {
            debug!("Timeout when trying to join a section");
            // Try again
            self.send_join_requests(core);
            self.timer_token = core.timer.schedule(JOIN_TIMEOUT);
        }
    }

    pub fn decide_message_status(&self, msg: &Message) -> Result<MessageStatus> {
        match msg.variant() {
            Variant::NodeApproval(_) => {
                let trusted_key = match &self.join_type {
                    JoinType::Relocate(payload) => {
                        Some(&payload.relocate_details().destination_key)
                    }
                    JoinType::First { .. } => None,
                };
                verify_message(msg, trusted_key)?;
                Ok(MessageStatus::Useful)
            }

            Variant::BootstrapResponse(BootstrapResponse::Join { .. }) => {
                verify_message(msg, None)?;
                Ok(MessageStatus::Useful)
            }

            Variant::NeighbourInfo { .. }
            | Variant::UserMessage(_)
            | Variant::Sync { .. }
            | Variant::Relocate(_)
            | Variant::RelocatePromise(_)
            | Variant::MessageSignature(_)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::BouncedUnknownMessage { .. }
            | Variant::DKGMessage { .. }
            | Variant::DKGOldElders { .. }
            | Variant::Vote { .. } => Ok(MessageStatus::Unknown),

            Variant::BootstrapRequest(_)
            | Variant::BootstrapResponse(_)
            | Variant::JoinRequest(_)
            | Variant::Ping => Ok(MessageStatus::Useless),
        }
    }

    pub fn handle_unknown_message(&mut self, sender: SocketAddr, msg: Message) {
        self.msg_backlog.push(msg.into_queued(Some(sender)));
    }

    pub fn handle_bootstrap_response(
        &mut self,
        core: &mut Core,
        sender: P2pNode,
        new_elders_info: EldersInfo,
        new_section_key: bls::PublicKey,
    ) -> Result<()> {
        if new_section_key == self.section_key {
            return Ok(());
        }

        if new_elders_info.prefix.matches(core.name()) {
            info!(
                "Newer Join response for our prefix {:?} from {:?}",
                new_elders_info, sender
            );
            self.elders_info = new_elders_info;
            self.section_key = new_section_key;
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

    // Remove and return the message backlog.
    pub fn take_message_backlog(&mut self) -> Vec<QueuedMessage> {
        mem::take(&mut self.msg_backlog)
    }

    fn send_join_requests(&self, core: &mut Core) {
        let relocate_payload = match &self.join_type {
            JoinType::First { .. } => None,
            JoinType::Relocate(payload) => Some(payload),
        };

        for dst in self.elders_info.elders.values() {
            let join_request = JoinRequest {
                section_key: self.section_key,
                relocate_payload: relocate_payload.cloned(),
            };

            info!("Sending {:?} to {}", join_request, dst);
            let variant = Variant::JoinRequest(Box::new(join_request));
            core.send_direct_message(dst.peer_addr(), variant);
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
            (VerifyStatus::Unknown, Some(_)) => Err(RoutingError::UntrustedMessage),
        })
        .map_err(|error| {
            messages::log_verify_failure(msg, &error, trusted_key.map(|key| (&prefix, key)));
            error
        })
}

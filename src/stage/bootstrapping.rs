// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::joining::{JoinType, Joining, JOIN_TIMEOUT};
use crate::{
    chain::EldersInfo,
    error::Result,
    id::{FullId, P2pNode},
    messages::{BootstrapResponse, Message, Variant, VerifyStatus},
    relocation::{RelocatePayload, SignedRelocateDetails},
    states::Core,
    time::Duration,
    xor_space::Prefix,
};
use fxhash::FxHashSet;
use std::{collections::HashMap, iter, net::SocketAddr};

/// Time after which bootstrap is cancelled (and possibly retried).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

// The bootstrapping stage - node is trying to find the section to join.
pub struct Bootstrapping {
    // Using `FxHashSet` for deterministic iteration order.
    pending_requests: FxHashSet<SocketAddr>,
    timeout_tokens: HashMap<u64, SocketAddr>,
    relocate_details: Option<SignedRelocateDetails>,
}

impl Bootstrapping {
    pub fn new(relocate_details: Option<SignedRelocateDetails>) -> Self {
        Self {
            pending_requests: Default::default(),
            timeout_tokens: Default::default(),
            relocate_details,
        }
    }

    pub fn handle_timeout(&mut self, core: &mut Core, token: u64) {
        let peer_addr = if let Some(peer_addr) = self.timeout_tokens.remove(&token) {
            peer_addr
        } else {
            return;
        };

        debug!("Timeout when trying to bootstrap against {}.", peer_addr);

        if !self.pending_requests.remove(&peer_addr) {
            return;
        }

        core.transport.disconnect(peer_addr);

        if self.pending_requests.is_empty() {
            // Rebootstrap
            core.transport.bootstrap();
        }
    }

    pub fn handle_bootstrap_response(
        &mut self,
        core: &mut Core,
        sender: P2pNode,
        response: BootstrapResponse,
    ) -> Result<Option<Joining>> {
        // Ignore messages from peers we didn't send `BootstrapRequest` to.
        if !self.pending_requests.contains(sender.peer_addr()) {
            debug!(
                "Ignoring BootstrapResponse from unexpected peer: {}",
                sender,
            );
            core.transport.disconnect(*sender.peer_addr());
            return Ok(None);
        }

        match response {
            BootstrapResponse::Join(elders_info) => {
                info!(
                    "Joining a section {:?} (given by {:?})",
                    elders_info, sender
                );

                let join_type = self.join_section(core, &elders_info)?;
                let stage = Joining {
                    elders_info,
                    join_type,
                };
                stage.send_join_requests(core);
                Ok(Some(stage))
            }
            BootstrapResponse::Rebootstrap(new_conn_infos) => {
                info!(
                    "Bootstrapping redirected to another set of peers: {:?}",
                    new_conn_infos
                );
                self.reconnect_to_new_section(core, new_conn_infos);
                Ok(None)
            }
        }
    }

    pub fn send_bootstrap_request(&mut self, core: &mut Core, dst: SocketAddr) {
        if !self.pending_requests.insert(dst) {
            return;
        }

        let token = core.timer.schedule(BOOTSTRAP_TIMEOUT);
        let _ = self.timeout_tokens.insert(token, dst);

        let destination = match &self.relocate_details {
            Some(details) => *details.destination(),
            None => *core.name(),
        };

        debug!("Sending BootstrapRequest to {}.", dst);
        core.send_direct_message(&dst, Variant::BootstrapRequest(destination));
    }

    fn reconnect_to_new_section(&mut self, core: &mut Core, new_conn_infos: Vec<SocketAddr>) {
        for addr in self.pending_requests.drain() {
            core.transport.disconnect(addr);
        }

        self.timeout_tokens.clear();

        for conn_info in new_conn_infos {
            self.send_bootstrap_request(core, conn_info);
        }
    }

    fn join_section(&mut self, core: &mut Core, elders_info: &EldersInfo) -> Result<JoinType> {
        let relocate_details = self.relocate_details.take();
        let destination = match &relocate_details {
            Some(details) => *details.destination(),
            None => *core.name(),
        };
        let old_full_id = core.full_id.clone();

        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            elders_info.prefix().bit_count() + extra_split_count,
            destination,
        );

        if !name_prefix.matches(core.name()) {
            let new_full_id = FullId::within_range(&mut core.rng, &name_prefix.range_inclusive());
            info!("Changing name to {}.", new_full_id.public_id().name());
            core.full_id = new_full_id;
        }

        if let Some(details) = relocate_details {
            let relocate_payload =
                RelocatePayload::new(details, core.full_id.public_id(), &old_full_id)?;

            Ok(JoinType::Relocate(relocate_payload))
        } else {
            let timeout_token = core.timer.schedule(JOIN_TIMEOUT);
            Ok(JoinType::First { timeout_token })
        }
    }

    pub fn verify_message(&self, msg: &Message) -> Result<bool> {
        msg.verify(iter::empty())
            .and_then(VerifyStatus::require_full)?;
        Ok(true)
    }
}

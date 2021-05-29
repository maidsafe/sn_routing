// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::{
    error::Result,
    peer::PeerUtils,
    relocation::{
        self, RelocateAction, RelocateDetailsUtils, RelocateState, SignedRelocateDetailsUtils,
    },
    routing::command::Command,
    section::{MemberInfoUtils, SectionAuthorityProviderUtils, SectionPeersUtils, SectionUtils},
    Event, ELDER_SIZE,
};
use sn_messaging::node::{
    Peer, Proposal, RelocateDetails, RelocatePromise, RoutingMsg, SignedRelocateDetails,
};
use tokio::sync::mpsc;
use xor_name::XorName;

// Relocation
impl Core {
    pub(crate) fn relocate_peers(
        &self,
        churn_name: &XorName,
        churn_signature: &bls::Signature,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        // Do not carry out relocation when there is not enough elder nodes.
        if self.section.authority_provider().elder_count() < ELDER_SIZE {
            return Ok(commands);
        }

        // Consider: Set <= 4, as to not carry out relocations in first 16 sections.
        // TEMP: Do not carry out relocations in the first section
        if self.section.prefix().bit_count() < 1 {
            return Ok(commands);
        }

        let relocations =
            relocation::actions(&self.section, &self.network, churn_name, churn_signature);

        for (info, action) in relocations {
            let peer = info.peer;

            // The newly joined node is not being relocated immediately.
            if peer.name() == churn_name {
                continue;
            }

            debug!(
                "Relocating {:?} to {} (on churn of {})",
                peer,
                action.destination(),
                churn_name
            );

            commands.extend(self.propose(Proposal::Offline(info.relocate(*action.destination())))?);

            match action {
                RelocateAction::Instant(details) => {
                    commands.extend(self.send_relocate(&peer, details)?)
                }
                RelocateAction::Delayed(promise) => {
                    commands.extend(self.send_relocate_promise(&peer, promise)?)
                }
            }
        }

        Ok(commands)
    }

    pub(crate) fn relocate_rejoining_peer(&self, peer: &Peer, age: u8) -> Result<Vec<Command>> {
        let details =
            RelocateDetails::with_age(&self.section, &self.network, peer, *peer.name(), age);

        trace!(
            "Relocating {:?} to {} with age {} due to rejoin",
            peer,
            details.destination,
            details.age
        );

        self.send_relocate(peer, details)
    }

    pub(crate) fn handle_relocate(
        &mut self,
        details: SignedRelocateDetails,
    ) -> Result<Option<Command>> {
        if details.relocate_details()?.pub_id != self.node.name() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return Ok(None);
        }

        debug!(
            "Received Relocate message to join the section at {}",
            details.relocate_details()?.destination
        );

        match self.relocate_state {
            Some(RelocateState::InProgress(_)) => {
                trace!("Ignore Relocate - relocation already in progress");
                return Ok(None);
            }
            Some(RelocateState::Delayed(_)) => (),
            None => {
                self.send_event(Event::RelocationStarted {
                    previous_name: self.node.name(),
                });
            }
        }

        let (message_tx, message_rx) = mpsc::channel(1);
        self.relocate_state = Some(RelocateState::InProgress(message_tx));

        let bootstrap_addrs = self.section.authority_provider().addresses();

        Ok(Some(Command::Relocate {
            bootstrap_addrs,
            details,
            message_rx,
        }))
    }

    pub(crate) fn handle_relocate_promise(
        &mut self,
        promise: RelocatePromise,
        msg: RoutingMsg,
    ) -> Result<Vec<Command>> {
        let mut commands = vec![];

        if promise.name == self.node.name() {
            // Store the `RelocatePromise` message and send it back after we are demoted.
            // Keep it around even if we are not elder anymore, in case we need to resend it.
            match self.relocate_state {
                None => {
                    trace!(
                        "Received RelocatePromise to section at {}",
                        promise.destination
                    );
                    self.relocate_state = Some(RelocateState::Delayed(msg.clone()));
                    self.send_event(Event::RelocationStarted {
                        previous_name: self.node.name(),
                    });
                }
                Some(RelocateState::InProgress(_)) => {
                    trace!("ignore RelocatePromise - relocation already in progress");
                }
                Some(RelocateState::Delayed(_)) => {
                    trace!("ignore RelocatePromise - already have one");
                }
            }

            // We are no longer elder. Send the promise back already.
            if !self.is_elder() {
                commands.push(self.send_message_to_our_elders(msg));
            }

            return Ok(commands);
        }

        if self.section.is_elder(&promise.name) {
            error!(
                "ignore returned RelocatePromise from {} - node is still elder",
                promise.name
            );
            return Ok(commands);
        }

        if let Some(info) = self.section.members().get(&promise.name) {
            let details = RelocateDetails::new(
                &self.section,
                &self.network,
                &info.peer,
                promise.destination,
            );
            commands.extend(self.send_relocate(&info.peer, details)?);
        } else {
            error!(
                "ignore returned RelocatePromise from {} - unknown node",
                promise.name
            );
        }

        Ok(commands)
    }
}

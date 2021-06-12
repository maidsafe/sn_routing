// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod anti_entropy;
mod api;
mod connectivity;
mod delivery_group;
mod messaging;

use super::{command::Command, enduser_registry::EndUserRegistry, split_barrier::SplitBarrier};
use crate::{
    dkg::{DkgVoter, ProposalAggregator},
    error::Result,
    event::{Elders, Event, NodeElderChange},
    message_filter::MessageFilter,
    messages::RoutingMsgUtils,
    network::NetworkUtils,
    node::Node,
    relocation::RelocateState,
    section::{SectionAuthorityProviderUtils, SectionKeyShare, SectionKeysProvider, SectionUtils},
};
use itertools::Itertools;
use resource_proof::ResourceProof;
use secured_linked_list::SecuredLinkedList;
use sn_messaging::node::SignatureAggregator;
use sn_messaging::{
    node::{Network, Proposal, Proven, RoutingMsg, Section, Variant},
    DestInfo, DstLocation, MessageId, SectionAuthorityProvider,
};
use std::collections::BTreeSet;
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

pub const RESOURCE_PROOF_DATA_SIZE: usize = 64;
pub const RESOURCE_PROOF_DIFFICULTY: u8 = 2;
const KEY_CACHE_SIZE: u8 = 5;

// State + logic of a routing node.
pub(crate) struct Core {
    node: Node,
    section: Section,
    network: Network,
    section_keys_provider: SectionKeysProvider,
    message_aggregator: SignatureAggregator,
    proposal_aggregator: ProposalAggregator,
    split_barrier: SplitBarrier,
    // Voter for Dkg
    dkg_voter: DkgVoter,
    relocate_state: Option<RelocateState>,
    msg_filter: MessageFilter,
    pub(super) event_tx: mpsc::Sender<Event>,
    joins_allowed: bool,
    resource_proof: ResourceProof,
    end_users: EndUserRegistry,
}

impl Core {
    // Creates `Core` for a regular node.
    pub fn new(
        node: Node,
        section: Section,
        section_key_share: Option<SectionKeyShare>,
        event_tx: mpsc::Sender<Event>,
    ) -> Self {
        let section_keys_provider = SectionKeysProvider::new(KEY_CACHE_SIZE, section_key_share);

        Self {
            node,
            section,
            network: Network::new(),
            section_keys_provider,
            proposal_aggregator: ProposalAggregator::default(),
            split_barrier: SplitBarrier::new(),
            message_aggregator: SignatureAggregator::default(),
            dkg_voter: DkgVoter::default(),
            relocate_state: None,
            msg_filter: MessageFilter::new(),
            event_tx,
            joins_allowed: true,
            resource_proof: ResourceProof::new(RESOURCE_PROOF_DATA_SIZE, RESOURCE_PROOF_DIFFICULTY),
            end_users: EndUserRegistry::new(),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ////////////////////////////////////////////////////////////////////////////

    pub async fn add_to_filter(&mut self, msg_id: &MessageId) -> bool {
        self.msg_filter.add_to_filter(msg_id).await
    }

    async fn check_for_entropy(
        &self,
        msg: &RoutingMsg,
        dest_info: DestInfo,
    ) -> Result<(Vec<Command>, bool)> {
        if !self.is_elder() {
            // Adult nodes do need to carry out entropy checking, however the message shall always
            // be handled.
            return Ok((vec![], true));
        }

        let (actions, can_be_executed) =
            anti_entropy::process(&self.node, &self.section, msg, dest_info)?;
        let mut commands = vec![];

        for msg in actions.send {
            commands.extend(self.relay_message(&msg).await?);
        }

        Ok((commands, can_be_executed))
    }

    pub(crate) fn state_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            is_elder: self.is_elder(),
            last_key: *self.section.chain().last_key(),
            prefix: *self.section.prefix(),
            elders: self.section().authority_provider().names(),
        }
    }

    pub(crate) fn update_section_knowledge(
        &mut self,
        section_auth: Proven<SectionAuthorityProvider>,
        section_chain: SecuredLinkedList,
    ) {
        let prefix = section_auth.value.prefix;
        if self
            .network
            .update_section(section_auth, None, &section_chain)
        {
            info!("Neighbour section knowledge updated: {:?}", prefix);
        } else {
            warn!("Neighbour section update failed");
        }
    }

    pub(crate) async fn update_state(&mut self, old: StateSnapshot) -> Result<Vec<Command>> {
        let mut commands = vec![];
        let new = self.state_snapshot();

        self.section_keys_provider
            .finalise_dkg(self.section.chain().last_key());

        if new.prefix != old.prefix {
            info!("Split");
        }

        if new.last_key != old.last_key {
            self.msg_filter.reset().await;

            if new.is_elder {
                info!(
                    "Section updated: prefix: ({:b}), key: {:?}, elders: {}",
                    new.prefix,
                    new.last_key,
                    self.section.authority_provider().peers().format(", ")
                );

                if self.section_keys_provider.has_key_share() {
                    commands.extend(self.promote_and_demote_elders()?);
                    // Whenever there is an elders change, casting a round of joins_allowed
                    // proposals to sync.
                    commands.extend(self.propose(Proposal::JoinsAllowed(self.joins_allowed))?);
                }

                self.print_network_stats();

                // Sending SectionKnowledge to other sections for new SAP.
                let section_auth = self.section.proven_authority_provider();
                let variant = Variant::SectionKnowledge {
                    src_info: (section_auth.clone(), self.section.chain().clone()),
                    msg: None,
                };
                for sap in self.network.all() {
                    let msg = RoutingMsg::single_src(
                        &self.node,
                        DstLocation::DirectAndUnrouted,
                        variant.clone(),
                        section_auth.value.section_key(),
                    )?;
                    let targets: Vec<_> = sap
                        .elders()
                        .iter()
                        .map(|(name, addr)| (*name, *addr))
                        .collect();
                    let len = targets.len();
                    let dest_info = DestInfo {
                        dest: XorName::random(),
                        dest_section_pk: sap.section_key(),
                    };
                    trace!("Sending updated SectionInfo to all known sections");
                    commands.push(Command::send_message_to_nodes(targets, len, msg, dest_info));
                }
            }

            if new.is_elder || old.is_elder {
                commands.extend(self.send_sync(self.section.clone(), self.network.clone())?);
            }

            let current: BTreeSet<_> = self.section.authority_provider().names();
            let added = current.difference(&old.elders).copied().collect();
            let removed = old.elders.difference(&current).copied().collect();
            let remaining = old.elders.intersection(&current).copied().collect();

            let elders = Elders {
                prefix: new.prefix,
                key: new.last_key,
                remaining,
                added,
                removed,
            };

            let self_status_change = if !old.is_elder && new.is_elder {
                info!("Promoted to elder");
                NodeElderChange::Promoted
            } else if old.is_elder && !new.is_elder {
                info!("Demoted");
                self.network = Network::new();
                self.section_keys_provider = SectionKeysProvider::new(KEY_CACHE_SIZE, None);
                NodeElderChange::Demoted
            } else {
                NodeElderChange::None
            };

            let sibling_elders = if new.prefix != old.prefix {
                self.network.get(&new.prefix.sibling()).map(|sec_auth| {
                    let current: BTreeSet<_> = sec_auth.names();
                    let added = current.difference(&old.elders).copied().collect();
                    let removed = old.elders.difference(&current).copied().collect();
                    let remaining = old.elders.intersection(&current).copied().collect();
                    Elders {
                        prefix: new.prefix.sibling(),
                        key: sec_auth.section_key(),
                        remaining,
                        added,
                        removed,
                    }
                })
            } else {
                None
            };

            let event = if let Some(sibling_elders) = sibling_elders {
                Event::SectionSplit {
                    elders,
                    sibling_elders,
                    self_status_change,
                }
            } else {
                Event::EldersChanged {
                    elders,
                    self_status_change,
                }
            };

            self.send_event(event).await;
        }

        if !new.is_elder {
            commands.extend(self.return_relocate_promise());
        }

        Ok(commands)
    }

    pub(crate) fn section_key_by_name(&self, name: &XorName) -> bls::PublicKey {
        if self.section.prefix().matches(name) {
            *self.section.chain().last_key()
        } else if let Ok(key) = self.network.key_by_name(name) {
            key
        } else if self.section.prefix().sibling().matches(name) {
            // For sibling with unknown key, use the previous key in our chain under the assumption
            // that it's the last key before the split and therefore the last key of theirs we know.
            // In case this assumption is not correct (because we already progressed more than one
            // key since the split) then this key would be unknown to them and they would send
            // us back their whole section chain. However, this situation should be rare.
            *self.section.chain().prev_key()
        } else {
            *self.section.chain().root_key()
        }
    }

    pub(crate) fn print_network_stats(&self) {
        self.network
            .network_stats(self.section.authority_provider())
            .print()
    }
}

pub(crate) struct StateSnapshot {
    is_elder: bool,
    last_key: bls::PublicKey,
    prefix: Prefix,
    elders: BTreeSet<XorName>,
}

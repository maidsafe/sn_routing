// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::super::Core;
use crate::{
    agreement::DkgKeyUtils,
    error::Result,
    messages::RoutingMsgUtils,
    network::NetworkUtils,
    peer::PeerUtils,
    relocation::RelocateState,
    routing::command::Command,
    section::{ElderCandidatesUtils, SectionAuthorityProviderUtils, SectionUtils},
};
use secured_linked_list::SecuredLinkedList;
use sn_messaging::{
    node::{
        DkgKey, ElderCandidates, MemberInfo, Network, Peer, PlainMessage, Proposal, Proven,
        RelocateDetails, RelocatePromise, RoutingMsg, Section, Variant,
    },
    DestInfo, DstLocation,
};
use std::{cmp::Ordering, iter, net::SocketAddr, slice};
use xor_name::XorName;

// RoutingMsg sending
impl Core {
    // Send NodeApproval to a joining node which makes them a section member
    pub(crate) fn send_node_approval(
        &self,
        member_info: Proven<MemberInfo>,
        their_knowledge: Option<bls::PublicKey>,
    ) -> Result<Command> {
        info!(
            "Our section with {:?} has approved peer {:?}.",
            self.section.prefix(),
            member_info.value.peer
        );

        let addr = *member_info.value.peer.addr();
        let name = *member_info.value.peer.name();

        // Attach proof chain that includes the key the approved node knows (if any), the key its
        // `MemberInfo` is signed with and the last key of our section chain.
        let proof_chain = self.section.chain().minimize(
            iter::once(self.section.chain().last_key())
                .chain(their_knowledge.as_ref())
                .chain(iter::once(&member_info.proof.public_key)),
        )?;

        let variant = Variant::NodeApproval {
            genesis_key: *self.section.genesis_key(),
            section_auth: self.section.proven_authority_provider().clone(),
            member_info,
        };

        let message = RoutingMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted,
            variant,
            Some(proof_chain),
        )?;

        Ok(Command::send_message_to_node(
            (name, addr),
            message,
            DestInfo {
                dest: name,
                dest_section_pk: *self.section.chain().last_key(),
            },
        ))
    }

    pub(crate) fn send_sync(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        let send = |variant, recipients: Vec<(XorName, SocketAddr)>| -> Result<_> {
            trace!("Send {:?} to {:?}", variant, recipients);

            let message =
                RoutingMsg::single_src(&self.node, DstLocation::DirectAndUnrouted, variant, None)?;
            let dest_info = DestInfo {
                dest: XorName::random(),
                dest_section_pk: *self.section.chain().last_key(),
            };
            Ok(Command::send_message_to_nodes(
                recipients.clone(),
                recipients.len(),
                message,
                dest_info,
            ))
        };

        let mut commands = vec![];

        let (elders, non_elders): (Vec<_>, _) = section
            .active_members()
            .filter(|peer| peer.name() != &self.node.name())
            .map(|peer| (*peer.name(), *peer.addr()))
            .partition(|peer| section.is_elder(&peer.0));

        // Send the trimmed state to non-elders. The trimmed state contains only the knowledge of
        // own section.
        let variant = Variant::Sync {
            section: section.clone(),
            network: Network::new(),
        };
        commands.push(send(variant, non_elders)?);

        // Send the full state to elders.
        // The full state contains the whole section chain.
        let variant = Variant::Sync { section, network };
        commands.push(send(variant, elders)?);

        Ok(commands)
    }

    pub(crate) fn send_sync_to_adults(&mut self) -> Result<Vec<Command>> {
        let send = |variant, recipients: Vec<_>| -> Result<_> {
            trace!("Send {:?} to {:?}", variant, recipients);

            let message =
                RoutingMsg::single_src(&self.node, DstLocation::DirectAndUnrouted, variant, None)?;

            Ok(Command::send_message_to_nodes(
                recipients.clone(),
                recipients.len(),
                message,
                DestInfo {
                    dest: XorName::random(),
                    dest_section_pk: *self.section_chain().last_key(),
                },
            ))
        };

        let mut commands = vec![];

        let adults: Vec<_> = self
            .section
            .live_adults()
            .map(|peer| (*peer.name(), *peer.addr()))
            .collect();

        let variant = Variant::Sync {
            section: self.section.clone(),
            network: Network::new(),
        };

        commands.push(send(variant, adults)?);

        Ok(commands)
    }

    pub(crate) fn send_relocate(
        &self,
        recipient: &Peer,
        details: RelocateDetails,
    ) -> Result<Vec<Command>> {
        // We need to construct a proof that would be trusted by the destination section.
        let known_key = self
            .network
            .key_by_name(&details.destination)
            .unwrap_or_else(|| self.section.chain().root_key());

        let src = details.pub_id;
        let dst = DstLocation::Node(details.pub_id);
        let variant = Variant::Relocate(details);

        self.send_message_for_dst_accumulation(
            src,
            dst,
            variant,
            Some(known_key),
            slice::from_ref(recipient),
        )
    }

    pub(crate) fn send_relocate_promise(
        &self,
        recipient: &Peer,
        promise: RelocatePromise,
    ) -> Result<Vec<Command>> {
        // Note: this message is first sent to a single node who then sends it back to the section
        // where it needs to be handled by all the elders. This is why the destination is
        // `Section`, not `Node`.
        let src = promise.name;
        let dst = DstLocation::Section(promise.name);
        let variant = Variant::RelocatePromise(promise);

        self.send_message_for_dst_accumulation(src, dst, variant, None, slice::from_ref(recipient))
    }

    pub(crate) fn return_relocate_promise(&self) -> Option<Command> {
        // TODO: keep sending this periodically until we get relocated.
        if let Some(RelocateState::Delayed(msg)) = &self.relocate_state {
            Some(self.send_message_to_our_elders(msg.clone()))
        } else {
            None
        }
    }

    pub(crate) fn send_dkg_start(&self, elder_candidates: ElderCandidates) -> Result<Vec<Command>> {
        // Send to all participants.
        let recipients: Vec<_> = elder_candidates.peers().collect();
        self.send_dkg_start_to(elder_candidates, &recipients)
    }

    pub(crate) fn send_dkg_start_to(
        &self,
        elder_candidates: ElderCandidates,
        recipients: &[Peer],
    ) -> Result<Vec<Command>> {
        let src_prefix = elder_candidates.prefix;
        let generation = self.section.chain().main_branch_len() as u64;
        let dkg_key = DkgKey::new(&elder_candidates, generation);

        trace!(
            "Send DkgStart for {:?} with {:?} to {:?}",
            elder_candidates,
            dkg_key,
            recipients
        );

        let variant = Variant::DkgStart {
            dkg_key,
            elder_candidates,
        };

        self.send_message_for_dst_accumulation(
            src_prefix.name(),
            DstLocation::DirectAndUnrouted,
            variant,
            None,
            recipients,
        )
    }

    pub(crate) fn create_aggregate_at_src_proposal(
        &self,
        dst: DstLocation,
        variant: Variant,
        proof_chain_first_key: Option<&bls::PublicKey>,
    ) -> Result<Proposal> {
        let proof_chain = self.create_proof_chain(proof_chain_first_key)?;
        let dst_key = if let Some(name) = dst.name() {
            *self.section_key_by_name(&name)
        } else {
            // NOTE: `dst` is `Direct`. We use this when we want the message to accumulate at the
            // destination and also be handled only there. We only do this if the recipient is in
            // our section, so it's OK to use our latest key as the `dst_key`.
            *self.section.chain().last_key()
        };

        let message = PlainMessage {
            src: self.section.prefix().name(),
            dst,
            dst_key,
            variant,
        };

        let proposal = Proposal::AccumulateAtSrc {
            message: Box::new(message),
            proof_chain,
        };
        trace!("Created aggregate at source proposal {:?}", proposal);
        Ok(proposal)
    }

    pub(crate) fn send_message_for_dst_accumulation(
        &self,
        src: XorName,
        dst: DstLocation,
        variant: Variant,
        additional_proof_chain_key: Option<&bls::PublicKey>,
        recipients: &[Peer],
    ) -> Result<Vec<Command>> {
        let proof_chain = self.create_proof_chain(additional_proof_chain_key)?;
        let key_share = self.section_keys_provider.key_share().map_err(|err| {
            trace!(
                "Can't create message {:?} for accumulation at dst {:?}: {}",
                variant,
                dst,
                err
            );
            err
        })?;
        let message = RoutingMsg::for_dst_accumulation(key_share, src, dst, variant, proof_chain)?;

        trace!(
            "Send {:?} for accumulation at dst to {:?}",
            message,
            recipients
        );

        Ok(self.send_or_handle(message, recipients))
    }

    // Send the message to all `recipients`. If one of the recipients is us, don't send it over the
    // network but handle it directly.
    pub(crate) fn send_or_handle(&self, message: RoutingMsg, recipients: &[Peer]) -> Vec<Command> {
        let mut commands = vec![];
        let mut others = Vec::new();
        let mut handle = false;

        trace!("Send {:?} to {:?}", message, recipients);

        for recipient in recipients {
            if recipient.name() == &self.node.name() {
                handle = true;
            } else {
                others.push((*recipient.name(), *recipient.addr()));
            }
        }

        if !others.is_empty() {
            let count = others.len();
            let dest_section_pk = *self.section_key_by_name(&others[0].0);
            commands.push(Command::send_message_to_nodes(
                others,
                count,
                message.clone(),
                DestInfo {
                    dest: XorName::random(), // will be updated when sending
                    dest_section_pk,
                },
            ));
        }

        if handle {
            commands.push(Command::HandleMessage {
                sender: Some(self.node.addr),
                message,
                dest_info: DestInfo {
                    dest: self.node.name(),
                    dest_section_pk: *self.section_chain().last_key(),
                },
            });
        }

        commands
    }

    pub(crate) fn create_proof_chain(
        &self,
        additional_key: Option<&bls::PublicKey>,
    ) -> Result<SecuredLinkedList> {
        // The last key of the proof chain is the last section key for which we also have the
        // secret key share. Ideally this is our current section key unless we haven't observed the
        // DKG completion yet.
        let last_key = self
            .section_keys_provider
            .key_share()?
            .public_key_set
            .public_key();

        // Only include `additional_key` if it is older than `last_key` because `last_key` must be
        // the actual last key of the resulting proof chain because it's the key that will be used
        // to sign the message.
        let additional_key = additional_key
            .filter(|key| self.section.chain().cmp_by_position(key, &last_key) == Ordering::Less);

        Ok(self
            .section
            .chain()
            .minimize(iter::once(&last_key).chain(additional_key))?)
    }

    pub(crate) fn send_direct_message(
        &self,
        recipient: (XorName, SocketAddr),
        variant: Variant,
        dst_pk: bls::PublicKey,
    ) -> Result<Command> {
        let message =
            RoutingMsg::single_src(&self.node, DstLocation::DirectAndUnrouted, variant, None)?;
        Ok(Command::send_message_to_node(
            recipient,
            message,
            DestInfo {
                dest: recipient.0,
                dest_section_pk: dst_pk,
            },
        ))
    }

    // TODO: consider changing this so it sends only to a subset of the elders
    // (say 1/3 of the ones closest to our name or so)
    pub(crate) fn send_message_to_our_elders(&self, msg: RoutingMsg) -> Command {
        let targets: Vec<_> = self
            .section
            .authority_provider()
            .elders()
            .iter()
            .map(|(name, address)| (*name, *address))
            .collect();

        let dest_section_pk = *self.section_chain().last_key();

        let dest_info = DestInfo {
            dest: self.section.prefix().name(),
            dest_section_pk,
        };

        Command::send_message_to_nodes(targets.clone(), targets.len(), msg, dest_info)
    }
}

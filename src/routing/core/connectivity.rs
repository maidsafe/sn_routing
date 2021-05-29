// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::{
    agreement::{DkgCommands, DkgFailureProofSetUtils},
    error::Result,
    peer::PeerUtils,
    routing::command::Command,
    section::{MemberInfoUtils, SectionAuthorityProviderUtils, SectionPeersUtils, SectionUtils},
    Error,
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use sn_messaging::{
    node::{DkgFailureProof, DkgFailureProofSet, DkgKey, ElderCandidates, Proposal, Variant},
    DstLocation,
};
use std::{collections::BTreeSet, iter, net::SocketAddr, slice};
use xor_name::XorName;

impl Core {
    pub(crate) fn handle_dkg_start(
        &mut self,
        dkg_key: DkgKey,
        elder_candidates: ElderCandidates,
    ) -> Result<Vec<Command>> {
        trace!("Received DkgStart for {:?}", elder_candidates);
        self.dkg_voter
            .start(&self.node.keypair, dkg_key, elder_candidates)
            .into_commands(&self.node, *self.section_chain().last_key())
    }

    pub(crate) fn handle_dkg_message(
        &mut self,
        dkg_key: DkgKey,
        message: DkgMessage,
        sender: XorName,
    ) -> Result<Vec<Command>> {
        trace!("handle DKG message {:?} from {}", message, sender);

        self.dkg_voter
            .process_message(&self.node.keypair, &dkg_key, message)
            .into_commands(&self.node, *self.section_chain().last_key())
    }

    pub(crate) fn handle_dkg_failure_observation(
        &mut self,
        dkg_key: DkgKey,
        non_participants: &BTreeSet<XorName>,
        proof: DkgFailureProof,
    ) -> Result<Vec<Command>> {
        self.dkg_voter
            .process_failure(&dkg_key, non_participants, proof)
            .into_commands(&self.node, *self.section_chain().last_key())
    }

    pub(crate) fn handle_dkg_failure_agreement(
        &self,
        sender: &XorName,
        proofs: &DkgFailureProofSet,
    ) -> Result<Vec<Command>> {
        let sender = &self
            .section
            .members()
            .get(sender)
            .ok_or(Error::InvalidSrcLocation)?
            .peer;

        let generation = self.section.chain().main_branch_len() as u64;
        let elder_candidates = self
            .section
            .promote_and_demote_elders(&self.node.name())
            .into_iter()
            .find(|elder_candidates| proofs.verify(elder_candidates, generation));
        let elder_candidates = if let Some(elder_candidates) = elder_candidates {
            elder_candidates
        } else {
            trace!("Ignore DKG failure agreement with invalid proofs or outdated participants",);
            return Ok(vec![]);
        };

        if proofs.non_participants.is_empty() {
            // The DKG failure is a corrupted one due to lagging.
            trace!(
                "Received DKG failure agreement - restarting: {:?}",
                elder_candidates
            );

            self.send_dkg_start_to(elder_candidates, slice::from_ref(sender))
        } else {
            // The DKG failure is regarding non_participants, i.e. potential unresponsive node.
            trace!(
                "Received DKG failure agreement of non_participants {:?} , DKG generation({}) {:?}",
                proofs.non_participants,
                generation,
                elder_candidates
            );
            self.cast_offline_proposals(&proofs.non_participants)
        }
    }

    pub(crate) fn handle_connectivity_complaint(
        &mut self,
        sender: XorName,
        elder_name: XorName,
    ) -> Result<Vec<Command>> {
        self.connectivity_complaints
            .add_complaint(sender, elder_name);

        let weighing_adults: BTreeSet<XorName> = self
            .section
            .members()
            .joined()
            .map(|info| *info.peer.name())
            .collect();
        if self
            .connectivity_complaints
            .is_complained(elder_name, &weighing_adults)
        {
            self.propose_offline(elder_name)
        } else {
            Ok(vec![])
        }
    }

    fn complain_connectivity(&self, name: XorName) -> Result<Vec<Command>> {
        if !self.is_elder() {
            // When self is not an elder, then the peer has to be an elder, and we shall complaint
            // the lost to other elders.
            let variant = Variant::ConnectivityComplaint(name);
            let recipients: Vec<_> = self
                .section
                .proven_authority_provider()
                .value
                .peers()
                .filter(|peer| *peer.name() != name)
                .collect();
            trace!(
                "Casting connectivity complaint against {:?} {:?}",
                name,
                recipients
            );

            return self.send_message_for_dst_accumulation(
                self.node.name(),
                DstLocation::DirectAndUnrouted,
                variant,
                None,
                &recipients,
            );
        }

        self.propose_offline(name)
    }

    pub fn handle_connection_lost(&self, addr: SocketAddr) -> Result<Vec<Command>> {
        let name = if let Some(peer) = self.section.find_joined_member_by_addr(&addr) {
            debug!("Lost connection to known peer {}", peer);
            *peer.name()
        } else {
            if let Some(end_user) = self.get_enduser_by_addr(&addr) {
                debug!("Lost connection to client {:?}", end_user);
            } else {
                debug!("Lost connection to unknown peer {}", addr);
            }
            return Ok(vec![]);
        };

        self.complain_connectivity(name)
    }

    pub fn handle_peer_lost(&self, addr: &SocketAddr) -> Result<Vec<Command>> {
        let name = if let Some(peer) = self.section.find_joined_member_by_addr(addr) {
            debug!("Lost known peer {}", peer);
            *peer.name()
        } else {
            trace!("Lost unknown peer {}", addr);
            return Ok(vec![]);
        };

        self.complain_connectivity(name)
    }

    pub fn propose_offline(&self, name: XorName) -> Result<Vec<Command>> {
        self.cast_offline_proposals(&iter::once(name).collect())
    }

    fn cast_offline_proposals(&self, names: &BTreeSet<XorName>) -> Result<Vec<Command>> {
        // Don't send the `Offline` proposal to the peer being lost as that send would fail,
        // triggering a chain of further `Offline` proposals.
        let elders: Vec<_> = self
            .section
            .authority_provider()
            .peers()
            .filter(|peer| !names.contains(peer.name()))
            .collect();
        let mut result: Vec<Command> = Vec::new();
        for name in names.iter() {
            if let Some(info) = self.section.members().get(name) {
                let info = info.clone().leave()?;
                if let Ok(commands) = self.send_proposal(&elders, Proposal::Offline(info)) {
                    result.extend(commands);
                }
            }
        }
        Ok(result)
    }
}

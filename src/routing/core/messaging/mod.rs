// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod handling;
mod sending;

use super::Core;
use crate::{
    agreement::{ProofShare, Proposal},
    error::Result,
    messages::{Message, Variant},
    peer::Peer,
    routing::command::Command,
    section::SectionKeyShare,
};
use sn_messaging::DstLocation;
use std::net::SocketAddr;
use xor_name::XorName;

impl Core {
    // Send proposal to all our elders.
    pub(crate) fn propose(&self, proposal: Proposal) -> Result<Vec<Command>> {
        let elders: Vec<_> = self.section.authority_provider().peers().collect();
        self.send_proposal(&elders, proposal)
    }

    // Send `proposal` to `recipients`.
    pub(crate) fn send_proposal(
        &self,
        recipients: &[Peer],
        proposal: Proposal,
    ) -> Result<Vec<Command>> {
        let key_share = self.section_keys_provider.key_share().map_err(|err| {
            trace!("Can't propose {:?}: {}", proposal, err);
            err
        })?;
        self.send_proposal_with(recipients, proposal, key_share)
    }

    pub(crate) fn send_proposal_with(
        &self,
        recipients: &[Peer],
        proposal: Proposal,
        key_share: &SectionKeyShare,
    ) -> Result<Vec<Command>> {
        trace!(
            "Propose {:?}, key_share: {:?}, aggregators: {:?}",
            proposal,
            key_share,
            recipients,
        );

        let proof_share = proposal.prove(
            key_share.public_key_set.clone(),
            key_share.index,
            &key_share.secret_key_share,
        )?;

        // Broadcast the proposal to the rest of the section elders.
        let variant = Variant::Propose {
            content: proposal,
            proof_share,
        };
        let message = Message::single_src(&self.node, DstLocation::Direct, variant, None)?;

        Ok(self.send_or_handle(message, recipients))
    }

    // ------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------

    pub(crate) fn check_lagging(
        &self,
        peer: (SocketAddr, XorName),
        proof_share: &ProofShare,
    ) -> Result<Option<Command>> {
        let public_key = proof_share.public_key_set.public_key();

        if self.section.chain().has_key(&public_key)
            && public_key != *self.section.chain().last_key()
        {
            // The key is recognized as non-last, indicating the peer is lagging.
            Ok(Some(self.send_direct_message(
                peer,
                // TODO: consider sending only those parts of section that are new
                // since `public_key` was the latest key.
                Variant::Sync {
                    section: self.section.clone(),
                    network: self.network.clone(),
                },
                proof_share.public_key_set.public_key(),
            )?))
        } else {
            Ok(None)
        }
    }
}

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::{
    messages::{MessageStatus, RoutingMsgUtils, SrcAuthorityUtils},
    section::{SectionAuthorityProviderUtils, SectionUtils},
    Result,
};
use bls_signature_aggregator::ProofShare;
use sn_messaging::{
    node::{Proposal, RelocatePromise, RoutingMsg, Variant},
    DstLocation,
};
use xor_name::XorName;

// Decisions
impl Core {
    pub(crate) fn decide_message_status(&self, msg: &RoutingMsg) -> Result<MessageStatus> {
        match msg.variant() {
            Variant::SectionKnowledge { .. } | Variant::ConnectivityComplaint(_) => {
                if !self.is_elder() {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::UserMessage(_) => {
                // If elder, always handle UserMessage, otherwise
                // handle it only if addressed directly to us as a node.
                if !self.is_elder() && *msg.dst() != DstLocation::Node(self.node.name()) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::JoinRequest(req) => {
                // Ignore `JoinRequest` if we are not elder unless the join request
                // is outdated in which case we reply with `BootstrapResponse::Join`
                // with the up-to-date info (see `handle_join_request`).
                if !self.is_elder() && req.section_key == *self.section.chain().last_key() {
                    // Note: We don't bounce this message because the current bounce-resend
                    // mechanism wouldn't preserve the original SocketAddr which is needed for
                    // properly handling this message.
                    // This is OK because in the worst case the join request just timeouts and the
                    // joining node sends it again.
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::DkgStart {
                elder_candidates, ..
            } => {
                if !elder_candidates.elders.contains_key(&self.node.name()) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::NodeApproval { .. } | Variant::JoinRetry { .. } => {
                // Skip validation of these. We will validate them inside the bootstrap task.
                return Ok(MessageStatus::Useful);
            }
            Variant::Sync { section, .. } => {
                // Ignore `Sync` not for our section.
                if !section.prefix().matches(&self.node.name()) {
                    return Ok(MessageStatus::Useless);
                }
            }
            Variant::Propose {
                content,
                proof_share,
                ..
            } => {
                if let Some(status) =
                    self.decide_propose_status(&msg.src.name(), content, proof_share)
                {
                    return Ok(status);
                }
            }
            Variant::RelocatePromise(promise) => {
                if let Some(status) = self.decide_relocate_promise_status(promise) {
                    return Ok(status);
                }
            }
            Variant::Relocate(_)
            | Variant::BouncedUntrustedMessage { .. }
            | Variant::DkgMessage { .. }
            | Variant::DkgFailureObservation { .. }
            | Variant::DkgFailureAgreement { .. }
            | Variant::SectionKnowledgeQuery { .. }
            | Variant::ResourceChallenge { .. } => {}
        }

        if self.verify_message(msg)? {
            Ok(MessageStatus::Useful)
        } else {
            Ok(MessageStatus::Untrusted)
        }
    }

    // Decide how to handle a `Propose` message.
    pub(crate) fn decide_propose_status(
        &self,
        sender: &XorName,
        proposal: &Proposal,
        proof_share: &ProofShare,
    ) -> Option<MessageStatus> {
        match proposal {
            Proposal::SectionInfo(section_auth)
                if section_auth.prefix == *self.section.prefix()
                    || section_auth.prefix.is_extension_of(self.section.prefix()) =>
            {
                // This `SectionInfo` is proposed by the DKG participants and is signed by the new
                // key created by the DKG so we don't know it yet. We only require the sender of the
                // proposal to be one of the DKG participants.
                if section_auth.contains_elder(sender) {
                    None
                } else {
                    Some(MessageStatus::Useless)
                }
            }
            _ => {
                // Any other proposal needs to be signed by a known key.
                if self
                    .section
                    .chain()
                    .has_key(&proof_share.public_key_set.public_key())
                {
                    None
                } else {
                    Some(MessageStatus::Untrusted)
                }
            }
        }
    }

    // Decide how to handle a `RelocatePromise` message.
    pub(crate) fn decide_relocate_promise_status(
        &self,
        promise: &RelocatePromise,
    ) -> Option<MessageStatus> {
        if promise.name == self.node.name() {
            // Promise to relocate us.
            if self.relocate_state.is_some() {
                // Already received a promise or already relocating. discard.
                return Some(MessageStatus::Useless);
            }
        } else {
            // Promise returned from a node to be relocated, to be exchanged for the actual
            // `Relocate` message.
            if !self.is_elder() || self.section.is_elder(&promise.name) {
                // If we are not elder, maybe we just haven't processed our promotion yet.
                // If they are still elder, maybe we just haven't processed their demotion yet.
                // If otherwise they are still elder, maybe we just haven't processed their demotion yet.
                return Some(MessageStatus::Useless);
            }
        }

        None
    }
}

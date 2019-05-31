// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::OnlinePayload;
use crate::{id::PublicId, utils::LogIdent, utils::XorTargetInterval};
use log::LogLevel;
use std::collections::BTreeSet;

/// A candidate (if any) may be in different stages of the resource proof process.
/// When we consensus to accept them for resource proof, move to `AcceptedForResourceProof`
/// with the value all elder expect to get from `CandidateInfo`.
/// If we consensus to refuse them: reset to None.
/// If we consensus to accept them: move to ApprovedWaitingSectionInfo until we are available to
/// accept a new candidate, at which point reset to None.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum Candidate {
    /// No-one is currently in the resource proof process.
    /// We can take on a new candidate on consensus of an `ExpectCandidate` event.
    None,
    /// We accepted a candidate to perform resource proof in this section. We are waiting for
    /// them to send their `CandidateInfo` before starting the actual resource proof.
    AcceptedForResourceProof {
        target_interval: XorTargetInterval,
        old_public_id: PublicId,
    },
    /// We consensused the candidate online. We are waiting for the SectionInfo to consensus
    /// and this new node to start handling events before allowing a new candidate.
    ApprovedWaitingSectionInfo { new_pub_id: PublicId },
}

impl Candidate {
    /// Return true if no candidate info
    pub fn is_none(&self) -> bool {
        *self == Candidate::None
    }

    /// Forget about the current candidate.
    pub fn reset(&mut self) {
        *self = Candidate::None;
    }

    /// Forget about the current candidate if it is a member of the given section.
    pub fn reset_if_member_of(&mut self, members: &BTreeSet<PublicId>) {
        if let Candidate::ApprovedWaitingSectionInfo { ref new_pub_id } = self {
            if members.contains(new_pub_id) {
                *self = Candidate::None;
            }
        }
    }

    /// Our section decided that the candidate should be resource proofed next.
    /// Pre-condition: is_none.
    pub fn accept_for_resource_proof(
        &mut self,
        old_public_id: PublicId,
        target_interval: XorTargetInterval,
    ) {
        if !self.is_none() {
            log_or_panic!(
                LogLevel::Error,
                "accept_as_candidate when processing one already"
            );
        }

        *self = Candidate::AcceptedForResourceProof {
            old_public_id: old_public_id,
            target_interval: target_interval,
        };
    }

    /// Try to accept as memeber.
    /// If the candidate was already purged or is unexpected, return false.
    /// Otherwise marks the candidate as `ApprovedWaitingSectionInfo`.
    pub fn try_accept_as_member(&mut self, online_payload: &OnlinePayload) -> bool {
        if self.old_public_id() == Some(&online_payload.old_public_id) {
            // Known candidate was accepted.
            // Ignore any information that could be different stored in candidate.
            // Do not accept candidate until we complete our current one.
            *self = Candidate::ApprovedWaitingSectionInfo {
                new_pub_id: online_payload.new_public_id,
            };
            true
        } else {
            // Unkwown candidate, Candidate was purged before: refuse it.
            false
        }
    }

    /// Return the target interval if we are resource proofing for that old PublicId.
    pub fn matching_target_interval(&self, old_public_id: &PublicId) -> Option<&XorTargetInterval> {
        if self.old_public_id() == Some(old_public_id) {
            self.target_interval()
        } else {
            None
        }
    }

    /// The public id of the candidate we are resource proofing.
    pub fn old_public_id(&self) -> Option<&PublicId> {
        match self {
            Candidate::None | Candidate::ApprovedWaitingSectionInfo { .. } => None,
            Candidate::AcceptedForResourceProof { old_public_id, .. } => Some(old_public_id),
        }
    }

    /// The target interval of the candidate we are resource proofing.
    fn target_interval(&self) -> Option<&XorTargetInterval> {
        match self {
            Candidate::None | Candidate::ApprovedWaitingSectionInfo { .. } => None,
            Candidate::AcceptedForResourceProof {
                target_interval, ..
            } => Some(target_interval),
        }
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_status(&self, log_ident: &LogIdent) {
        let log_prefix = format!("{} Shared Candidate Status - ", log_ident);
        match self {
            Candidate::None => trace!("{}No candidate is currently being handled.", log_prefix),
            Candidate::AcceptedForResourceProof {
                ref old_public_id, ..
            } => trace!(
                "{}{} Accepted as candidate.",
                log_prefix,
                old_public_id.name()
            ),
            Candidate::ApprovedWaitingSectionInfo { new_pub_id } => trace!(
                "{}{} has not been included in our SectionInfo yet.",
                log_prefix,
                new_pub_id
            ),
        }
    }
}

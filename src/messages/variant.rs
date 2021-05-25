// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Message, VerifyStatus};
use crate::{
    agreement::{DkgFailureProof, DkgFailureProofSet, DkgKey, ProofShare, Proposal, Proven},
    crypto::Signature,
    error::{Error, Result},
    network::Network,
    relocation::{RelocateDetails, RelocatePayload, RelocatePromise},
    section::{ElderCandidates, MemberInfo, Section, SectionAuthorityProvider, SectionChain},
};
use bls_dkg::key_gen::message::Message as DkgMessage;
use bytes::Bytes;
use hex_fmt::HexFmt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sn_messaging::DestInfo;
use std::{
    collections::{BTreeSet, VecDeque},
    fmt::{self, Debug, Formatter},
};
use xor_name::XorName;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
/// Message variant
pub(crate) enum Variant {
    /// Inform other sections about our section or vice-versa.
    SectionKnowledge {
        /// `SectionAuthorityProvider` and `SectionChain` of the sender's section, with the proof chain.
        src_info: (Proven<SectionAuthorityProvider>, SectionChain),
        /// Message
        msg: Option<Box<Message>>,
        // Nonce that is derived from the incoming message that triggered sending this
        // message. It's purpose is to make sure that `OtherSection`s that are identical
        // but triggered by different messages are not filtered out.
        // nonce: MessageHash,
    },
    /// User-facing message
    UserMessage(Bytes),
    /// Message sent to newly joined node containing the necessary info to become a member of our
    /// section.
    NodeApproval {
        genesis_key: bls::PublicKey,
        section_auth: Proven<SectionAuthorityProvider>,
        member_info: Proven<MemberInfo>,
    },
    /// Message sent to all members to update them about the state of our section.
    Sync {
        // Information about our section.
        section: Section,
        // Information about the rest of the network that we know of.
        network: Network,
    },
    /// Send from a section to the node to be immediately relocated.
    Relocate(RelocateDetails),
    /// Send:
    /// - from a section to a current elder to be relocated after they are demoted.
    /// - from the node to be relocated back to its section after it was demoted.
    RelocatePromise(RelocatePromise),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `GetSectionResponse::Succcess` to its `GetSectionQuery`.
    JoinRequest(Box<JoinRequest>),
    /// Response to outdated JoinRequest
    JoinRetry {
        section_auth: SectionAuthorityProvider,
        section_key: bls::PublicKey,
    },
    /// Sent from a node that can't establish the trust of the contained message to its original
    /// source in order for them to provide new proof that the node would trust.
    BouncedUntrustedMessage {
        msg: Box<Message>,
        dest_info: DestInfo,
    },
    /// Sent to the new elder candidates to start the DKG process.
    DkgStart {
        /// The identifier of the DKG session to start.
        dkg_key: DkgKey,
        /// The DKG particpants.
        elder_candidates: ElderCandidates,
    },
    /// Message exchanged for DKG process.
    DkgMessage {
        /// The identifier of the DKG session this message is for.
        dkg_key: DkgKey,
        /// The DKG message.
        message: DkgMessage,
    },
    /// Broadcasted to the other DKG participants when a DKG failure is observed.
    DkgFailureObservation {
        dkg_key: DkgKey,
        proof: DkgFailureProof,
        non_participants: BTreeSet<XorName>,
    },
    /// Sent to the current elders by the DKG participants when at least majority of them observe
    /// a DKG failure.
    DkgFailureAgreement(DkgFailureProofSet),
    /// Message containing a single `Proposal` to be aggregated in the proposal aggregator.
    Propose {
        content: Proposal,
        proof_share: ProofShare,
    },
    /// Challenge sent from existing elder nodes to the joining peer for resource proofing.
    ResourceChallenge {
        data_size: usize,
        difficulty: u8,
        nonce: [u8; 32],
        nonce_signature: Signature,
    },
    /// Message sent by a node to indicate it received a message from a node which was ahead in knowledge.
    /// A reply is expected with a `SectionKnowledge` message.
    SectionKnowledgeQuery {
        last_known_key: Option<bls::PublicKey>,
        msg: Box<Message>,
    },
    /// A follow-up reply will be sent by src with SectionKnowledge.
    // DstOutdated,
    /// Direct complaint sent from an adult to elders regarding the connectivity issue of an elder.
    ConnectivityComplaint(XorName),
}

impl Variant {
    pub(crate) fn verify<'a, I>(
        &self,
        _proof_chain: Option<&SectionChain>,
        _trusted_keys: I,
    ) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        let _proof_chain = match self {
            Self::NodeApproval {
                section_auth: _,
                member_info: _,
                ..
            } => {
                // TODO: Attach SectionChain with Variant::NodeApproval
                // let proof_chain = proof_chain.ok_or(Error::InvalidMessage)?;
                //
                // if !section_auth.verify(proof_chain) {
                //     return Err(Error::InvalidMessage);
                // }
                //
                // if !member_info.verify(proof_chain) {
                //     return Err(Error::InvalidMessage);
                // }
                //
                // proof_chain
                return Ok(VerifyStatus::Full);
            }
            Self::Sync { section, .. } => {
                section.chain();
                return Ok(VerifyStatus::Full);
            }
            _ => return Ok(VerifyStatus::Full),
        };

        // TODO: Attach SectionChain with Variant::NodeApproval
        // if proof_chain.check_trust(trusted_keys) {
        //     Ok(VerifyStatus::Full)
        // } else {
        //     Ok(VerifyStatus::Unknown)
        // }
    }
}

impl Debug for Variant {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::SectionKnowledge { .. } => f.debug_struct("SectionKnowledge").finish(),
            Self::UserMessage(payload) => write!(f, "UserMessage({:10})", HexFmt(payload)),
            Self::NodeApproval {
                genesis_key,
                section_auth,
                member_info,
            } => f
                .debug_struct("NodeApproval")
                .field("genesis_key", genesis_key)
                .field("section_auth", section_auth)
                .field("member_info", member_info)
                .finish(),
            Self::Sync { section, network } => f
                .debug_struct("Sync")
                .field("section_auth", section.authority_provider())
                .field("section_key", section.chain().last_key())
                .field(
                    "other_prefixes",
                    &format_args!("({:b})", network.prefixes().format(", ")),
                )
                .finish(),
            Self::Relocate(payload) => write!(f, "Relocate({:?})", payload),
            Self::RelocatePromise(payload) => write!(f, "RelocatePromise({:?})", payload),
            Self::JoinRequest(payload) => write!(f, "JoinRequest({:?})", payload),
            Self::JoinRetry {
                section_auth,
                section_key,
            } => f
                .debug_struct("JoinRetry")
                .field("section_auth", section_auth)
                .field("section_key", section_key)
                .finish(),
            Self::BouncedUntrustedMessage { msg, dest_info } => f
                .debug_struct("BouncedUntrustedMessage")
                .field("message", msg)
                .field("dest_info", dest_info)
                .finish(),
            Self::DkgStart {
                dkg_key,
                elder_candidates,
            } => f
                .debug_struct("DkgStart")
                .field("dkg_key", dkg_key)
                .field("elder_candidates", elder_candidates)
                .finish(),
            Self::DkgMessage { dkg_key, message } => f
                .debug_struct("DkgMessage")
                .field("dkg_key", &dkg_key)
                .field("message", message)
                .finish(),
            Self::DkgFailureObservation {
                dkg_key,
                proof,
                non_participants,
            } => f
                .debug_struct("DkgFailureObservation")
                .field("dkg_key", dkg_key)
                .field("proof", proof)
                .field("non_participants", non_participants)
                .finish(),
            Self::DkgFailureAgreement(proofs) => {
                f.debug_tuple("DkgFailureAgreement").field(proofs).finish()
            }
            Self::Propose {
                content,
                proof_share,
            } => f
                .debug_struct("Propose")
                .field("content", content)
                .field("proof_share", proof_share)
                .finish(),
            Self::ResourceChallenge {
                data_size,
                difficulty,
                ..
            } => f
                .debug_struct("ResourceChallenge")
                .field("data_size", data_size)
                .field("difficulty", difficulty)
                .finish(),
            Self::ConnectivityComplaint(name) => write!(f, "ConnectivityComplaint({:?})", name),
            Self::SectionKnowledgeQuery { .. } => write!(f, "SectionKnowledgeQuery"),
        }
    }
}

/// Joining peer's proof of resolvement of given resource proofing challenge.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ResourceProofResponse {
    pub(crate) solution: u64,
    pub(crate) data: VecDeque<u8>,
    pub(crate) nonce: [u8; 32],
    pub(crate) nonce_signature: Signature,
}

/// Request to join a section
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct JoinRequest {
    /// The public key of the section to join.
    pub section_key: bls::PublicKey,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
    /// Proof of the resouce proofing.
    pub resource_proof_response: Option<ResourceProofResponse>,
}

impl Debug for JoinRequest {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("JoinRequest")
            .field("section_key", &self.section_key)
            .field(
                "relocate_payload",
                &self
                    .relocate_payload
                    .as_ref()
                    .map(|payload| payload.relocate_details()),
            )
            .field(
                "resource_proof_response",
                &self
                    .resource_proof_response
                    .as_ref()
                    .map(|proof| proof.solution),
            )
            .finish()
    }
}

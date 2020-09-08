// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AccumulatingMessage, Message, MessageHash, VerifyStatus};
use crate::{
    consensus::{DkgKey, ProofShare, Proven, Vote},
    error::{Error, Result},
    relocation::{RelocateDetails, RelocatePayload, RelocatePromise},
    section::{EldersInfo, SectionProofChain, SharedState, TrustStatus},
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};
use xor_name::XorName;

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
/// Message variant
pub(crate) enum Variant {
    /// Inform neighbours about our new section.
    NeighbourInfo {
        /// `EldersInfo` of the sender's section, with the proof chain.
        elders_info: Proven<EldersInfo>,
        /// Nonce that is derived from the incoming message that triggered sending this
        /// `NeighbourInfo`. It's purpose is to make sure that `NeighbourInfo`s that are identical
        /// but triggered by different messages are not filtered out.
        nonce: MessageHash,
    },
    /// User-facing message
    UserMessage(Bytes),
    /// Message sent to newly joined node containing the necessary info to become a member of our
    /// section.
    NodeApproval(Proven<EldersInfo>),
    /// Message sent to all members to update them about the state of our section.
    Sync(SharedState),
    /// Send from a section to the node to be immediately relocated.
    Relocate(RelocateDetails),
    /// Send:
    /// - from a section to a current elder to be relocated after they are demoted.
    /// - from the node to be relocated back to its section after it was demoted.
    RelocatePromise(RelocatePromise),
    /// Sent from members of a section message's source location to the first hop. The
    /// message will only be relayed once enough signatures have been accumulated.
    MessageSignature(Box<AccumulatingMessage>),
    /// Sent from a newly connected peer to the bootstrap node to request connection infos of
    /// members of the section matching the given name.
    BootstrapRequest(XorName),
    /// Sent from the bootstrap node to a peer in response to `BootstrapRequest`. It can either
    /// accept the peer into the section, or redirect it to another set of bootstrap peers
    BootstrapResponse(BootstrapResponse),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `BootstrapResponse::Join` to its `BootstrapRequest`.
    JoinRequest(Box<JoinRequest>),
    /// Message sent to a disconnected peer to trigger lost peer detection.
    Ping,
    /// Sent from a node that can't establish the trust of the contained message to its original
    /// source in order for them to provide new proof that the node would trust.
    BouncedUntrustedMessage(Box<Message>),
    /// Sent from a node that doesn't know how to handle `message` to its elders in order for them
    /// to decide what to do with it (resend with more info or discard).
    BouncedUnknownMessage {
        /// The last section key of the sender.
        src_key: bls::PublicKey,
        /// The serialized original message.
        message: Bytes,
    },
    /// Sent to the new elder candidates to start the DKG process.
    DKGStart {
        /// The identifier of the DKG session to start.
        dkg_key: DkgKey,
        /// The DKG particpants.
        elders_info: EldersInfo,
    },
    /// Message exchanged for DKG process.
    DKGMessage {
        /// The identifier of the DKG session this message is for.
        dkg_key: DkgKey,
        /// The serialized DKG message.
        message: Bytes,
    },
    /// Message to notify current elders about the DKG result.
    DKGResult {
        /// The identifier of the DKG session the result is for.
        dkg_key: DkgKey,
        /// The result of the DKG.
        result: Result<bls::PublicKey, ()>,
    },
    /// Message containing a single `Vote` to be accumulated in the vote accumulator.
    Vote {
        content: Vote,
        proof_share: ProofShare,
    },
}

impl Variant {
    pub(crate) fn verify<'a, I>(
        &self,
        proof_chain: Option<&SectionProofChain>,
        trusted_keys: I,
    ) -> Result<VerifyStatus>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        match self {
            Self::NodeApproval(elders_info) => {
                let proof_chain = proof_chain.ok_or(Error::InvalidMessage)?;

                if !elders_info.verify(proof_chain) {
                    return Err(Error::UntrustedMessage);
                }

                match proof_chain.check_trust(trusted_keys) {
                    TrustStatus::Trusted => Ok(VerifyStatus::Full),
                    TrustStatus::Unknown => Ok(VerifyStatus::Unknown),
                    TrustStatus::Invalid => Err(Error::UntrustedMessage),
                }
            }
            Self::NeighbourInfo { elders_info, .. } => {
                let proof_chain = proof_chain.ok_or(Error::InvalidMessage)?;

                if !elders_info.verify(proof_chain) {
                    return Err(Error::UntrustedMessage);
                }

                match proof_chain.check_trust(trusted_keys) {
                    TrustStatus::Trusted => Ok(VerifyStatus::Full),
                    TrustStatus::Unknown => Ok(VerifyStatus::Unknown),
                    TrustStatus::Invalid => Err(Error::UntrustedMessage),
                }
            }
            _ => Ok(VerifyStatus::Full),
        }
    }
}

impl Debug for Variant {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NeighbourInfo { elders_info, nonce } => f
                .debug_struct("NeighbourInfo")
                .field("elders_info", elders_info)
                .field("nonce", nonce)
                .finish(),
            Self::UserMessage(payload) => write!(f, "UserMessage({:10})", HexFmt(payload)),
            Self::NodeApproval(payload) => write!(f, "NodeApproval({:?})", payload),
            Self::Sync(shared_state) => f
                .debug_struct("Sync")
                .field("elders_info", shared_state.sections.our())
                .field("section_key", shared_state.our_history.last_key())
                .finish(),
            Self::Relocate(payload) => write!(f, "Relocate({:?})", payload),
            Self::RelocatePromise(payload) => write!(f, "RelocatePromise({:?})", payload),
            Self::MessageSignature(payload) => write!(f, "MessageSignature({:?})", payload.content),
            Self::BootstrapRequest(payload) => write!(f, "BootstrapRequest({})", payload),
            Self::BootstrapResponse(payload) => write!(f, "BootstrapResponse({:?})", payload),
            Self::JoinRequest(payload) => write!(f, "JoinRequest({:?})", payload),
            Self::Ping => write!(f, "Ping"),
            Self::BouncedUntrustedMessage(message) => f
                .debug_tuple("BouncedUntrustedMessage")
                .field(message)
                .finish(),
            Self::BouncedUnknownMessage { src_key, message } => f
                .debug_struct("BouncedUnknownMessage")
                .field("src_key", src_key)
                .field("message_hash", &MessageHash::from_bytes(message))
                .finish(),
            Self::DKGStart {
                dkg_key,
                elders_info,
            } => f
                .debug_struct("DKGStart")
                .field("dkg_key", dkg_key)
                .field("elders_info", elders_info)
                .finish(),
            Self::DKGMessage { dkg_key, message } => f
                .debug_struct("DKGMessage")
                .field("dkg_key", &dkg_key)
                .field("message_hash", &MessageHash::from_bytes(message))
                .finish(),
            Self::DKGResult { dkg_key, result } => f
                .debug_struct("DKGResult")
                .field("dkg_key", dkg_key)
                .field("result", result)
                .finish(),
            Self::Vote {
                content,
                proof_share,
            } => f
                .debug_struct("Vote")
                .field("content", content)
                .field("proof_share", proof_share)
                .finish(),
        }
    }
}

/// Response to a BootstrapRequest
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub enum BootstrapResponse {
    /// This response means that the new peer is clear to join the section. The connection infos of
    /// the section elders and the section key are provided.
    Join {
        elders_info: EldersInfo,
        section_key: bls::PublicKey,
    },
    /// The new peer should retry bootstrapping with another section. The set of connection infos
    /// of the members of that section is provided.
    Rebootstrap(Vec<SocketAddr>),
}

/// Request to join a section
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct JoinRequest {
    /// The public key of the section to join
    pub section_key: bls::PublicKey,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
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
            .finish()
    }
}

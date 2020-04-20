// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AccumulatingMessage, MessageHash};
use crate::{
    chain::GenesisPfxInfo,
    parsec,
    relocation::{RelocateDetails, RelocatePayload},
    section::EldersInfo,
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Message variant
pub enum Variant {
    /// Inform neighbours about our new section.
    NeighbourInfo(EldersInfo),
    /// User-facing message
    UserMessage(Vec<u8>),
    /// Approves the joining node as a routing node.
    /// Section X -> Node joining X
    NodeApproval(Box<GenesisPfxInfo>),
    /// Acknowledgement that the src section knows that the dst section is at the specified
    /// version.
    /// Section X -> Section Y
    AckMessage {
        /// The prefix of our section when we acknowledge their version.
        src_prefix: Prefix<XorName>,
        /// The version acknowledged.
        ack_version: u64,
    },
    /// Update sent to Adults and Infants by Elders
    GenesisUpdate(Box<GenesisPfxInfo>),
    /// Send from a section to the node being relocated.
    Relocate(Box<RelocateDetails>),
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
    /// Sent from Adults and Infants to Elders. Updates Elders about the sender's knowledge of its
    /// own section.
    MemberKnowledge(MemberKnowledge),
    /// Parsec request message
    ParsecRequest(u64, parsec::Request),
    /// Parsec response message
    ParsecResponse(u64, parsec::Response),
    /// Message sent to a disconnected peer to trigger lost peer detection.
    Ping,
    /// Response to a message that the recipient cannot handle at this time but might be able to
    /// handle it later. For example, an adult receiving a message intended for elders will be
    /// able to handle it after being promoted.
    Bounce {
        /// Elders version of the section of the message recipient according to their knowledge.
        /// `None` if the recipient is not yet member of any section.
        elders_version: Option<u64>,
        /// The original message, serialized.
        message: Bytes,
    },
}

impl Debug for Variant {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NeighbourInfo(payload) => write!(f, "NeighbourInfo({:?})", payload),
            Self::UserMessage(payload) => write!(f, "UserMessage({})", HexFmt(payload)),
            Self::NodeApproval(payload) => write!(f, "NodeApproval({:?})", payload),
            Self::AckMessage {
                src_prefix,
                ack_version,
            } => f
                .debug_struct("AckMessage")
                .field("src_prefix", src_prefix)
                .field("ack_version", ack_version)
                .finish(),
            Self::GenesisUpdate(payload) => write!(f, "GenesisUpdate({:?})", payload),
            Self::Relocate(payload) => write!(f, "Relocate({:?})", payload),
            Self::MessageSignature(payload) => write!(f, "MessageSignature({:?})", payload.content),
            Self::BootstrapRequest(payload) => write!(f, "BootstrapRequest({})", payload),
            Self::BootstrapResponse(payload) => write!(f, "BootstrapResponse({:?})", payload),
            Self::JoinRequest(payload) => write!(f, "JoinRequest({:?})", payload),
            Self::MemberKnowledge(payload) => write!(f, "MemberKnowledge({:?})", payload),
            Self::ParsecRequest(version, _) => write!(f, "ParsecRequest({}, ..)", version),
            Self::ParsecResponse(version, _) => write!(f, "ParsecResponse({}, ..)", version),
            Self::Ping => write!(f, "Ping"),
            Self::Bounce {
                elders_version,
                message,
            } => f
                .debug_struct("Bounce")
                .field("elders_version", elders_version)
                .field("message_hash", &MessageHash::from_bytes(message))
                .finish(),
        }
    }
}

/// Response to a BootstrapRequest
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub enum BootstrapResponse {
    /// This response means that the new peer is clear to join the section. The connection infos of
    /// the section elders and the section prefix are provided.
    Join(EldersInfo),
    /// The new peer should retry bootstrapping with another section. The set of connection infos
    /// of the members of that section is provided.
    Rebootstrap(Vec<SocketAddr>),
}

/// Request to join a section
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The section version to join
    pub elders_version: u64,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
}

impl Debug for JoinRequest {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("JoinRequest")
            .field("elders_version", &self.elders_version)
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

/// Node's knowledge about its own section.
#[derive(Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub struct MemberKnowledge {
    pub elders_version: u64,
    pub parsec_version: u64,
}

impl MemberKnowledge {
    pub fn update(&mut self, other: MemberKnowledge) {
        self.elders_version = self.elders_version.max(other.elders_version);
        self.parsec_version = self.parsec_version.max(other.parsec_version);
    }
}

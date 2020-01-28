// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::SignedRoutingMessage;
use crate::{
    chain::{EldersInfo, GenesisPfxInfo},
    parsec,
    relocation::{RelocateDetails, RelocatePayload},
    xor_space::{Prefix, XorName},
    ConnectionInfo,
};
use serde::Serialize;
use std::fmt::{self, Debug, Formatter};

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
/// Body of RoutingMessage
pub enum RoutingVariant {
    /// Inform neighbours about our new section.
    NeighbourInfo(EldersInfo),
    /// User-facing message
    UserMessage(Vec<u8>),
    /// Approves the joining node as a routing node.
    ///
    /// Sent from Group Y to the joining node.
    NodeApproval(GenesisPfxInfo),
    /// Acknowledgement of a consensused section info.
    AckMessage {
        /// The prefix of our section when we acknowledge their EldersInfo of version ack_version.
        src_prefix: Prefix<XorName>,
        /// The version acknowledged.
        ack_version: u64,
    },
    /// Update sent to Adults and Infants by Elders
    GenesisUpdate(GenesisPfxInfo),
    /// Send to a node being relocated from its own section.
    Relocate(Box<RelocateDetails>),
}

/// Body of DirectVariant
#[derive(Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum DirectVariant {
    /// Sent from members of a section or group message's source location to the first hop. The
    /// message will only be relayed once enough signatures have been accumulated.
    MessageSignature(Box<SignedRoutingMessage>),
    /// Sent from a newly connected peer to the bootstrap node to request connection infos of
    /// members of the section matching the given name.
    BootstrapRequest(XorName),
    /// Sent from the bootstrap node to a peer in response to `BootstrapRequest`. It can either
    /// accept the peer into the section, or redirect it to another set of bootstrap peers
    BootstrapResponse(BootstrapResponse),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `BootstrapResponse::Join` to its `BootstrapRequest`.
    JoinRequest(Box<JoinRequest>),
    /// Sent from members of a section to a joining node in response to `ConnectionRequest`
    /// (which is a routing message)
    ConnectionResponse,
    /// Sent from Adults and Infants to Elders. Updates Elders about the sender's knowledge of its
    /// own section.
    MemberKnowledge(MemberKnowledge),
    /// Parsec request message
    ParsecRequest(u64, parsec::Request),
    /// Parsec response message
    ParsecResponse(u64, parsec::Response),
}

/// Response to a BootstrapRequest
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub enum BootstrapResponse {
    /// This response means that the new peer is clear to join the section. The connection infos of
    /// the section elders and the section prefix are provided.
    Join(EldersInfo),
    /// The new peer should retry bootstrapping with another section. The set of connection infos
    /// of the members of that section is provided.
    Rebootstrap(Vec<ConnectionInfo>),
}

/// Request to join a section
#[derive(Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct JoinRequest {
    /// The section version to join
    pub elders_version: u64,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
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

impl Debug for RoutingVariant {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::RoutingVariant::*;
        match self {
            NeighbourInfo(info) => write!(formatter, "NeighbourInfo({:?})", info),
            UserMessage(content) => write!(formatter, "UserMessage({:?})", content,),
            NodeApproval(gen_info) => write!(formatter, "NodeApproval({:?})", gen_info),
            AckMessage {
                src_prefix,
                ack_version,
            } => write!(formatter, "AckMessage({:?}, {})", src_prefix, ack_version),
            GenesisUpdate(info) => write!(formatter, "GenesisUpdate({:?})", info),
            Relocate(payload) => write!(formatter, "Relocate({:?})", payload),
        }
    }
}

impl Debug for DirectVariant {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::DirectVariant::*;
        match self {
            MessageSignature(msg) => write!(formatter, "MessageSignature({:?})", msg),
            BootstrapRequest(name) => write!(formatter, "BootstrapRequest({})", name),
            BootstrapResponse(response) => write!(formatter, "BootstrapResponse({:?})", response),
            JoinRequest(join_request) => write!(
                formatter,
                "JoinRequest({}, {:?})",
                join_request.elders_version,
                join_request
                    .relocate_payload
                    .as_ref()
                    .map(|payload| payload.relocate_details())
            ),
            ConnectionResponse => write!(formatter, "ConnectionResponse"),
            ParsecRequest(v, _) => write!(formatter, "ParsecRequest({}, _)", v),
            ParsecResponse(v, _) => write!(formatter, "ParsecResponse({}, _)", v),
            MemberKnowledge(payload) => write!(formatter, "{:?}", payload),
        }
    }
}

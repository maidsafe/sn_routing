// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AccumulatingMessage, Message, MessageHash};
use crate::{
    consensus::{GenesisPrefixInfo, ParsecRequest, ParsecResponse},
    id::PublicId,
    relocation::{RelocateDetails, RelocatePayload},
    section::EldersInfo,
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
};
use xor_name::XorName;

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
/// Message variant
pub enum Variant {
    /// Inform neighbours about our new section.
    NeighbourInfo {
        /// `EldersInfo` of the neighbour section.
        elders_info: EldersInfo,
        /// Nonce that is derived from the incoming message that triggered sending this
        /// `NeighbourInfo`. It's purpose is to make sure that `NeighbourInfo`s that are identical
        /// but triggered by different messages are not filtered out.
        nonce: MessageHash,
    },
    /// User-facing message
    UserMessage(Vec<u8>),
    /// Approves the joining node as a routing node.
    /// Section X -> Node joining X
    NodeApproval(GenesisPrefixInfo),
    /// Update sent to Adults and Infants by Elders
    GenesisUpdate(GenesisPrefixInfo),
    /// Send from a section to the node being relocated.
    Relocate(RelocateDetails),
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
    /// Sent from Adults and Infants to Elders. Used to "poke" the elders to trigger them to send
    /// ParsecRequest back.
    ParsecPoke(u64),
    /// Parsec request message
    ParsecRequest(u64, ParsecRequest),
    /// Parsec response message
    ParsecResponse(u64, ParsecResponse),
    /// Message sent to a disconnected peer to trigger lost peer detection.
    Ping,
    /// Sent from a node that can't establish the trust of the contained message to its original
    /// source in order for them to provide new proof that the node would trust.
    BouncedUntrustedMessage(Box<Message>),
    /// Sent from a node that doesn't know how to handle `message` to its elders in order for them
    /// to decide what to do with it (resend with more info or discard).
    BouncedUnknownMessage {
        /// The original message, serialized.
        message: Bytes,
        /// The latest parsec version of the recipient of `message`.
        parsec_version: u64,
    },
    /// Message exchanged for DKG process.
    DKGMessage {
        /// The identifier of the key_gen instance this message is about.
        /// Currently just using the participants.
        /// TODO: may need to consider using other unique identifying approach.
        participants: BTreeSet<PublicId>,
        /// The parsec version this DKG message related to.
        parsec_version: u64,
        /// The serialized DKG message.
        message: Bytes,
    },
    /// Message of notify sibling that DKG completed during split
    DKGSibling {
        /// Participants of the DKG
        participants: BTreeSet<PublicId>,
        /// Parsec version of the DKG
        parsec_version: u64,
        /// Public key set that got consensused
        public_key_set: bls::PublicKeySet,
    },
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
            Self::GenesisUpdate(payload) => write!(f, "GenesisUpdate({:?})", payload),
            Self::Relocate(payload) => write!(f, "Relocate({:?})", payload),
            Self::MessageSignature(payload) => write!(f, "MessageSignature({:?})", payload.content),
            Self::BootstrapRequest(payload) => write!(f, "BootstrapRequest({})", payload),
            Self::BootstrapResponse(payload) => write!(f, "BootstrapResponse({:?})", payload),
            Self::JoinRequest(payload) => write!(f, "JoinRequest({:?})", payload),
            Self::ParsecPoke(version) => write!(f, "ParsecPoke({})", version),
            Self::ParsecRequest(version, _) => write!(f, "ParsecRequest({}, ..)", version),
            Self::ParsecResponse(version, _) => write!(f, "ParsecResponse({}, ..)", version),
            Self::Ping => write!(f, "Ping"),
            Self::BouncedUntrustedMessage(message) => f
                .debug_tuple("BouncedUntrustedMessage")
                .field(message)
                .finish(),
            Self::BouncedUnknownMessage {
                message,
                parsec_version,
            } => f
                .debug_struct("BouncedUnknownMessage")
                .field("message_hash", &MessageHash::from_bytes(message))
                .field("parsec_version", parsec_version)
                .finish(),
            Self::DKGMessage {
                participants,
                parsec_version,
                message,
            } => f
                .debug_struct("DKGMessage")
                .field("participants", participants)
                .field("parsec_version", parsec_version)
                .field("message_hash", &MessageHash::from_bytes(message))
                .finish(),
            Self::DKGSibling {
                participants,
                parsec_version,
                public_key_set,
            } => f
                .debug_struct("DKGMessage")
                .field("participants", participants)
                .field("parsec_version", parsec_version)
                .field("public_key_set", public_key_set)
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
pub struct JoinRequest {
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

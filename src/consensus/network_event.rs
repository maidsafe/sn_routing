// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{DkgResultWrapper, Observation, ParsecNetworkEvent},
    id::{P2pNode, PublicId},
    relocation::RelocateDetails,
    section::{EldersInfo, SectionMap},
    Prefix, XorName,
};
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct AckMessagePayload {
    /// The name of the section that message was for. This is important as we may get a message
    /// when we are still pre-split, think it is for us, but it was not.
    /// (i.e sent to 00, and we are 01, but lagging at 0 we are valid destination).
    pub dst_name: XorName,
    /// The prefix of our section when we acknowledge their SectionInfo of version ack_version.
    pub src_prefix: Prefix<XorName>,
    /// The key acknowledged.
    pub ack_key: bls::PublicKey,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct SendAckMessagePayload {
    /// The prefix acknowledged.
    pub ack_prefix: Prefix<XorName>,
    /// The key acknowledged.
    pub ack_key: bls::PublicKey,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct EventSigPayload {
    /// The public key share for that signature share
    pub pub_key_share: bls::PublicKeyShare,
    /// The signature share signing the SectionInfo.
    pub sig_share: bls::SignatureShare,
}

impl EventSigPayload {
    #[cfg_attr(feature = "mock_base", allow(clippy::trivially_copy_pass_by_ref))]
    pub fn new(key_share: &bls::SecretKeyShare, section_key: &bls::PublicKey) -> Self {
        let sig_share = key_share.sign(&section_key.to_bytes()[..]);
        let pub_key_share = key_share.public_key_share();

        Self {
            pub_key_share,
            sig_share,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct OnlinePayload {
    // Identifier of the joining node.
    pub p2p_node: P2pNode,
    // The age the node should have after joining.
    pub age: u8,
    // The key of the destination section that the joining node knows, if any.
    pub their_knowledge: Option<bls::PublicKey>,
}

/// Routing Network events
// TODO: Box `SectionInfo`?
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum AccumulatingEvent {
    /// Genesis event. This is output-only event.
    Genesis {
        group: BTreeSet<PublicId>,
        related_info: Vec<u8>,
    },

    /// Vote to start a DKG instance. This is input-only event.
    StartDkg(BTreeSet<PublicId>),

    /// Result of a DKG. This is output-only event.
    DkgResult {
        participants: BTreeSet<PublicId>,
        dkg_result: DkgResultWrapper,
    },

    /// Voted for node that is about to join our section
    Online(OnlinePayload),
    /// Voted for node we no longer consider online.
    Offline(PublicId),

    SectionInfo(EldersInfo, bls::PublicKey),

    // Voted for received message with info to update neighbour_info.
    NeighbourInfo(EldersInfo),

    // Voted for received message with keys to update their_keys
    TheirKeyInfo {
        prefix: Prefix<XorName>,
        key: bls::PublicKey,
    },

    // Voted for received AckMessage to update their_knowledge
    AckMessage(AckMessagePayload),

    // Voted for sending AckMessage (Require 100% consensus)
    SendAckMessage(SendAckMessagePayload),

    // Prune the gossip graph.
    ParsecPrune,

    // Voted for node to be relocated out of our section.
    Relocate(RelocateDetails),

    // Voted to initiate the relocation if value <= 0, otherwise re-vote with value - 1.
    RelocatePrepare(RelocateDetails, i32),

    // Opaque user-defined event.
    User(Vec<u8>),
}

impl AccumulatingEvent {
    pub fn from_network_event(event: NetworkEvent) -> (Self, Option<EventSigPayload>) {
        (event.payload, event.signature)
    }

    pub fn into_network_event(self) -> NetworkEvent {
        NetworkEvent {
            payload: self,
            signature: None,
        }
    }

    pub fn into_network_event_with(self, signature: Option<EventSigPayload>) -> NetworkEvent {
        NetworkEvent {
            payload: self,
            signature,
        }
    }
}

impl Debug for AccumulatingEvent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::Genesis {
                group,
                related_info,
            } => write!(
                formatter,
                "Genesis {{ group: {:?}, related_info: {:?} }}",
                group,
                HexFmt(related_info)
            ),
            Self::StartDkg(participants) => write!(formatter, "StartDkg({:?})", participants),
            Self::DkgResult { participants, .. } => write!(
                formatter,
                "DkgResult {{ participants: {:?}, .. }}",
                participants
            ),
            Self::Online(payload) => write!(formatter, "Online({:?})", payload),
            Self::Offline(id) => write!(formatter, "Offline({})", id),
            Self::SectionInfo(info, _) => write!(formatter, "SectionInfo({:?})", info),
            Self::NeighbourInfo(info) => write!(formatter, "NeighbourInfo({:?})", info),
            Self::TheirKeyInfo { prefix, key } => write!(
                formatter,
                "TheirKeyInfo {{ prefix: {:?}, key: {:?} }}",
                prefix, key
            ),
            Self::AckMessage(payload) => write!(formatter, "AckMessage({:?})", payload),
            Self::SendAckMessage(payload) => write!(formatter, "SendAckMessage({:?})", payload),
            Self::ParsecPrune => write!(formatter, "ParsecPrune"),
            Self::Relocate(payload) => write!(formatter, "Relocate({:?})", payload),
            Self::RelocatePrepare(payload, count_down) => {
                write!(formatter, "RelocatePrepare({:?}, {})", payload, count_down)
            }
            Self::User(payload) => write!(formatter, "User({:<8})", HexFmt(payload)),
        }
    }
}

/// Trait for AccumulatingEvent payloads.
pub trait IntoAccumulatingEvent {
    fn into_accumulating_event(self) -> AccumulatingEvent;
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NetworkEvent {
    pub payload: AccumulatingEvent,
    pub signature: Option<EventSigPayload>,
}

impl NetworkEvent {
    /// Convert `NetworkEvent` into a Parsec Observation
    pub fn into_obs(self) -> Observation<Self, PublicId> {
        match self {
            Self {
                payload: AccumulatingEvent::StartDkg(participants),
                ..
            } => parsec::Observation::StartDkg(participants),
            event => parsec::Observation::OpaquePayload(event),
        }
    }
}

impl ParsecNetworkEvent for NetworkEvent {}

impl Debug for NetworkEvent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        if self.signature.is_some() {
            write!(formatter, "{:?}(signature)", self.payload)
        } else {
            self.payload.fmt(formatter)
        }
    }
}

// Neighbour section elders that got removed/demoted.
#[derive(Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NeighbourEldersRemoved(pub BTreeSet<P2pNode>);

impl NeighbourEldersRemoved {
    pub fn builder(sections: &SectionMap) -> NeighbourEldersRemovedBuilder {
        NeighbourEldersRemovedBuilder(sections.other_elders().cloned().collect())
    }
}

pub struct NeighbourEldersRemovedBuilder(BTreeSet<P2pNode>);

impl NeighbourEldersRemovedBuilder {
    pub fn build(mut self, sections: &SectionMap) -> NeighbourEldersRemoved {
        for p2p_node in sections.other_elders() {
            let _ = self.0.remove(p2p_node);
        }

        NeighbourEldersRemoved(self.0)
    }
}

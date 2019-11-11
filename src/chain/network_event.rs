// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{EldersInfo, Proof, SectionKeyInfo};
use crate::{
    crypto::Digest256,
    id::{FullId, P2pNode, PublicId},
    parsec,
    relocation::RelocateDetails,
    routing_table::Prefix,
    BlsPublicKeyShare, BlsSignatureShare, RoutingError, XorName,
};
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct AckMessagePayload {
    /// The prefix of our section when we acknowledge their SectionInfo of version ack_version.
    pub src_prefix: Prefix<XorName>,
    /// The version acknowledged.
    pub ack_version: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct SendAckMessagePayload {
    /// The prefix acknowledged.
    pub ack_prefix: Prefix<XorName>,
    /// The version acknowledged.
    pub ack_version: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct EventSigPayload {
    /// The public key share for that signature share
    pub pub_key_share: BlsPublicKeyShare,
    /// The signature share signing the SectionInfo.
    pub sig_share: BlsSignatureShare,
}

impl EventSigPayload {
    pub fn new<T: Serialize>(full_id: &FullId, payload: &T) -> Result<Self, RoutingError> {
        let proof = Proof::new(full_id, payload)?;

        Ok(Self {
            pub_key_share: BlsPublicKeyShare(proof.pub_id),
            sig_share: proof.sig,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct OnlinePayload {
    pub p2p_node: P2pNode,
    pub age: u8,
}

/// Routing Network events
// TODO: Box `SectionInfo`?
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum AccumulatingEvent {
    /// Vote to start a DKG instance
    StartDkg(BTreeSet<PublicId>),

    /// Voted for node that is about to join our section
    Online(OnlinePayload),
    /// Voted for node we no longer consider online.
    Offline(PublicId),

    OurMerge,
    NeighbourMerge(Digest256),
    SectionInfo(EldersInfo),

    // Voted for received message with info to update neighbour_info.
    NeighbourInfo(EldersInfo),

    // Voted for received message with keys to update their_keys
    TheirKeyInfo(SectionKeyInfo),

    // Voted for received AckMessage to update their_knowledge
    AckMessage(AckMessagePayload),

    // Voted for sending AckMessage (Require 100% consensus)
    SendAckMessage(SendAckMessagePayload),

    // Prune the gossip graph.
    ParsecPrune,

    // Voted for node to be relocated out of our section.
    Relocate(RelocateDetails),

    // Opaque user-defined event.
    User(Vec<u8>),
}

impl AccumulatingEvent {
    pub fn from_network_event(event: NetworkEvent) -> (AccumulatingEvent, Option<EventSigPayload>) {
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
            AccumulatingEvent::StartDkg(participants) => {
                write!(formatter, "StartDkg({:?})", participants)
            }
            AccumulatingEvent::Online(payload) => write!(formatter, "Online({:?})", payload),
            AccumulatingEvent::Offline(id) => write!(formatter, "Offline({})", id),
            AccumulatingEvent::OurMerge => write!(formatter, "OurMerge"),
            AccumulatingEvent::NeighbourMerge(digest) => {
                write!(formatter, "NeighbourMerge({:.14?})", HexFmt(digest))
            }
            AccumulatingEvent::SectionInfo(info) => write!(formatter, "SectionInfo({:?})", info),
            AccumulatingEvent::NeighbourInfo(info) => {
                write!(formatter, "NeighbourInfo({:?})", info)
            }
            AccumulatingEvent::TheirKeyInfo(payload) => {
                write!(formatter, "TheirKeyInfo({:?})", payload)
            }
            AccumulatingEvent::AckMessage(payload) => {
                write!(formatter, "AckMessage({:?})", payload)
            }
            AccumulatingEvent::SendAckMessage(payload) => {
                write!(formatter, "SendAckMessage({:?})", payload)
            }
            AccumulatingEvent::ParsecPrune => write!(formatter, "ParsecPrune"),
            AccumulatingEvent::Relocate(payload) => write!(formatter, "Relocate({:?})", payload),
            AccumulatingEvent::User(payload) => write!(formatter, "User({:<8})", HexFmt(payload)),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NetworkEvent {
    pub payload: AccumulatingEvent,
    pub signature: Option<EventSigPayload>,
}

impl NetworkEvent {
    /// Convert `NetworkEvent` into a Parsec Observation
    pub fn into_obs(self) -> parsec::Observation<NetworkEvent, PublicId> {
        match self {
            NetworkEvent {
                payload: AccumulatingEvent::StartDkg(participants),
                ..
            } => parsec::Observation::StartDkg(participants),
            event => parsec::Observation::OpaquePayload(event),
        }
    }
}

impl parsec::NetworkEvent for NetworkEvent {}

impl Debug for NetworkEvent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        if self.signature.is_some() {
            write!(formatter, "{:?}(signature)", self.payload)
        } else {
            self.payload.fmt(formatter)
        }
    }
}

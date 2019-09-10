// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Proof, SectionInfo, SectionKeyInfo};
use crate::id::{FullId, PublicId};
use crate::parsec;
use crate::routing_table::Prefix;
use crate::sha3::Digest256;
use crate::types::MessageId;
use crate::{Authority, BlsPublicKeyShare, BlsSignatureShare, RoutingError, XorName};
use hex_fmt::HexFmt;
use maidsafe_utilities::serialisation::serialise;
use std::fmt::{self, Debug, Formatter};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct ExpectCandidatePayload {
    /// The joining node's current public ID.
    pub old_public_id: PublicId,
    /// The joining node's current authority.
    pub old_client_auth: Authority<XorName>,
    /// The message's unique identifier.
    pub message_id: MessageId,
    // The routing_msg.dst
    pub dst_name: XorName,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct OnlinePayload {
    /// The joining node's new public ID.
    pub new_public_id: PublicId,
    /// The joining node's previous public ID.
    pub old_public_id: PublicId,
    /// The joining node's current authority.
    pub client_auth: Authority<XorName>,
}

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
pub struct SectionInfoSigPayload {
    /// The public key share for that signature share
    pub pub_key_share: BlsPublicKeyShare,
    /// The signature share signing the SectionInfo.
    pub sig_share: BlsSignatureShare,
}

impl SectionInfoSigPayload {
    pub fn new(
        info: &SectionInfo,
        full_id: &FullId,
    ) -> Result<SectionInfoSigPayload, RoutingError> {
        let proof = Proof::new(*full_id.public_id(), full_id.signing_private_key(), &info)?;

        Ok(SectionInfoSigPayload {
            pub_key_share: BlsPublicKeyShare(proof.pub_id),
            sig_share: proof.sig,
        })
    }
}

/// Routing Network events
// TODO: Box `SectionInfo`?
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum AccumulatingEvent {
    /// Add new elder once we agreed to add a candidate
    AddElder(PublicId, Authority<XorName>),
    /// Remove elder once we agreed to remove the peer
    RemoveElder(PublicId),

    /// Voted for candidate that pass resource proof
    Online(OnlinePayload),
    /// Voted for candidate we no longer consider online.
    Offline(PublicId),

    OurMerge,
    NeighbourMerge(Digest256),
    SectionInfo(SectionInfo),

    /// Voted for received ExpectCandidate Message.
    ExpectCandidate(ExpectCandidatePayload),

    // Voted for timeout expired for this candidate old_public_id.
    PurgeCandidate(PublicId),

    // Voted for received message with keys to we can update their_keys
    TheirKeyInfo(SectionKeyInfo),

    // Voted for received AckMessage to update their_knowledge
    AckMessage(AckMessagePayload),

    // Voted for sending AckMessage (Require 100% consensus)
    SendAckMessage(SendAckMessagePayload),

    // Prune the gossip graph.
    ParsecPrune,
}

impl AccumulatingEvent {
    pub fn from_network_event(
        event: NetworkEvent,
    ) -> (AccumulatingEvent, Option<SectionInfoSigPayload>) {
        (event.payload, event.signature)
    }

    pub fn into_network_event(self) -> NetworkEvent {
        NetworkEvent {
            payload: self,
            signature: None,
        }
    }

    pub fn into_network_event_with(self, signature: Option<SectionInfoSigPayload>) -> NetworkEvent {
        NetworkEvent {
            payload: self,
            signature,
        }
    }

    pub fn section_info(&self) -> Option<&SectionInfo> {
        match *self {
            AccumulatingEvent::SectionInfo(ref self_si) => Some(self_si),
            _ => None,
        }
    }
}

impl Debug for AccumulatingEvent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            AccumulatingEvent::AddElder(ref id, _) => write!(formatter, "AddElder({}, _)", id),
            AccumulatingEvent::RemoveElder(ref id) => write!(formatter, "RemoveElder({})", id),
            AccumulatingEvent::Online(ref payload) => write!(
                formatter,
                "Online(new:{}, old:{})",
                payload.new_public_id, payload.old_public_id
            ),
            AccumulatingEvent::Offline(ref id) => write!(formatter, "Offline({})", id),
            AccumulatingEvent::OurMerge => write!(formatter, "OurMerge"),
            AccumulatingEvent::NeighbourMerge(ref digest) => {
                write!(formatter, "NeighbourMerge({:.14?})", HexFmt(digest))
            }
            AccumulatingEvent::SectionInfo(ref sec_info) => {
                write!(formatter, "SectionInfo({:?})", sec_info)
            }
            AccumulatingEvent::ExpectCandidate(ref vote) => {
                write!(formatter, "ExpectCandidate({:?})", vote)
            }
            AccumulatingEvent::PurgeCandidate(ref id) => {
                write!(formatter, "PurgeCandidate({})", id)
            }
            AccumulatingEvent::TheirKeyInfo(ref payload) => {
                write!(formatter, "TheirKeyInfo({:?})", payload)
            }
            AccumulatingEvent::AckMessage(ref payload) => {
                write!(formatter, "AckMessage({:?})", payload)
            }
            AccumulatingEvent::SendAckMessage(ref payload) => {
                write!(formatter, "SendAckMessage({:?})", payload)
            }
            AccumulatingEvent::ParsecPrune => write!(formatter, "ParsecPrune"),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NetworkEvent {
    pub payload: AccumulatingEvent,
    pub signature: Option<SectionInfoSigPayload>,
}

impl NetworkEvent {
    /// Returns the payload if this is a `SectionInfo` event.
    pub fn section_info(&self) -> Option<&SectionInfo> {
        self.payload.section_info()
    }

    /// Convert `NetworkEvent` into a Parsec Observation
    pub fn into_obs(self) -> Result<parsec::Observation<NetworkEvent, PublicId>, RoutingError> {
        Ok(match self {
            NetworkEvent {
                payload: AccumulatingEvent::AddElder(id, auth),
                ..
            } => parsec::Observation::Add {
                peer_id: id,
                related_info: serialise(&auth)?,
            },
            NetworkEvent {
                payload: AccumulatingEvent::RemoveElder(id),
                ..
            } => parsec::Observation::Remove {
                peer_id: id,
                related_info: Default::default(),
            },
            event => parsec::Observation::OpaquePayload(event),
        })
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

// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{ProofSet, ProvingSection, SectionInfo};
use crate::id::PublicId;
use crate::parsec;
use crate::sha3::Digest256;
use crate::types::MessageId;
use crate::{Authority, RoutingError, XorName};
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

/// Routing Network events
// TODO: Box `SectionInfo`?
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum NetworkEvent {
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

    /// A list of proofs for a neighbour section, starting from the current section.
    ProvingSections(Vec<ProvingSection>, SectionInfo),

    AckMessage(SectionInfo),
}

impl NetworkEvent {
    /// Checks if the given `SectionInfo` is a valid successor of `self`.
    pub fn proves_successor_info(&self, their_si: &SectionInfo, proofs: &ProofSet) -> bool {
        match *self {
            NetworkEvent::SectionInfo(ref self_si) => self_si.proves_successor(their_si, proofs),
            _ => false,
        }
    }

    /// Returns the payload if this is a `SectionInfo` event.
    pub fn section_info(&self) -> Option<&SectionInfo> {
        match *self {
            NetworkEvent::SectionInfo(ref self_si) => Some(self_si),
            _ => None,
        }
    }

    /// Convert `NetworkEvent` into a Parsec Observation
    pub fn into_obs(self) -> Result<parsec::Observation<NetworkEvent, PublicId>, RoutingError> {
        Ok(match self {
            NetworkEvent::AddElder(id, auth) => parsec::Observation::Add {
                peer_id: id,
                related_info: serialise(&auth)?,
            },
            NetworkEvent::RemoveElder(id) => parsec::Observation::Remove {
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
        match self {
            NetworkEvent::AddElder(ref id, _) => write!(formatter, "AddElder({}, _)", id),
            NetworkEvent::RemoveElder(ref id) => write!(formatter, "RemoveElder({})", id),
            NetworkEvent::Online(ref payload) => write!(
                formatter,
                "Online(new:{}, old:{})",
                payload.new_public_id, payload.old_public_id
            ),
            NetworkEvent::Offline(ref id) => write!(formatter, "Offline({})", id),
            NetworkEvent::OurMerge => write!(formatter, "OurMerge"),
            NetworkEvent::NeighbourMerge(ref digest) => {
                write!(formatter, "NeighbourMerge({:.14?})", HexFmt(digest))
            }
            NetworkEvent::SectionInfo(ref sec_info) => {
                write!(formatter, "SectionInfo({:?})", sec_info)
            }
            NetworkEvent::ExpectCandidate(ref vote) => {
                write!(formatter, "ExpectCandidate({:?})", vote)
            }
            NetworkEvent::PurgeCandidate(ref id) => write!(formatter, "PurgeCandidate({})", id),
            NetworkEvent::ProvingSections(_, ref sec_info) => {
                write!(formatter, "ProvingSections(_, {:?})", sec_info)
            }
            NetworkEvent::AckMessage(ref sec_info) => {
                write!(formatter, "AckMessage(_, {:?})", sec_info)
            }
        }
    }
}

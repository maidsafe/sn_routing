// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DkgResultWrapper, Observation, ParsecNetworkEvent, ProofShare};
use crate::{
    error::Result,
    id::{P2pNode, PublicId},
    messages::MessageHash,
    relocation::RelocateDetails,
    section::{EldersInfo, SectionKeyShare},
    Prefix, XorName,
};
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
};

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
    /// Genesis event. This is output-only unsigned event.
    Genesis {
        group: BTreeSet<PublicId>,
        related_info: Vec<u8>,
    },

    /// Vote to start a DKG instance. This is input-only unsigned event.
    StartDkg(BTreeSet<PublicId>),

    /// Result of a DKG. This is output-only unsigned event.
    DkgResult {
        participants: BTreeSet<PublicId>,
        dkg_result: DkgResultWrapper,
    },

    /// Voted for node that is about to join our section
    Online(OnlinePayload),
    /// Voted for node we no longer consider online.
    Offline(PublicId),

    SectionInfo(EldersInfo, bls::PublicKey),

    // Voted for received message with info about a neighbour section.
    NeighbourInfo(EldersInfo, bls::PublicKey),

    // Voted to send info about our section to a neighbour section.
    SendNeighbourInfo {
        dst: XorName,
        // Hash of the incoming message that triggered this vote. It's purpose is to make the votes
        // triggered by different message unique.
        nonce: MessageHash,
    },

    // Voted to update their section key.
    TheirKey {
        prefix: Prefix<XorName>,
        key: bls::PublicKey,
    },

    // Voted to update their knowledge of our section.
    TheirKnowledge {
        prefix: Prefix<XorName>,
        knowledge: u64,
    },

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
    pub fn needs_signature(&self) -> bool {
        match self {
            Self::Genesis { .. } | Self::StartDkg(_) | Self::DkgResult { .. } => false,
            _ => true,
        }
    }

    /// Sign and convert this event into `NetworkEvent`.
    ///
    /// # Panics
    ///
    /// Panics if `self.needs_signature()` is `false`
    pub fn into_signed_network_event(
        self,
        section_key_share: &SectionKeyShare,
    ) -> Result<NetworkEvent> {
        let signature_share = self.sign(&section_key_share.secret_key_share)?;
        let proof_share = ProofShare {
            public_key_set: section_key_share.public_key_set.clone(),
            index: section_key_share.index,
            signature_share,
        };

        Ok(NetworkEvent {
            payload: self,
            proof_share: Some(proof_share),
        })
    }

    /// Convert this event into unsigned `NetworkEvent`.
    ///
    /// # Panics
    ///
    /// Panics if `self.needs_signature()` is `true`
    #[cfg(all(test, feature = "mock"))]
    pub fn into_unsigned_network_event(self) -> NetworkEvent {
        assert!(!self.needs_signature());

        NetworkEvent {
            payload: self,
            proof_share: None,
        }
    }

    /// Create a signature share of this event using `secret key share`.
    ///
    /// # Panics
    ///
    /// Panics if `self.needs_signature()` is `false`
    pub fn sign(&self, secret_key_share: &bls::SecretKeyShare) -> Result<bls::SignatureShare> {
        assert!(self.needs_signature());

        let bytes = self.serialise_for_signing()?;
        Ok(secret_key_share.sign(&bytes))
    }

    pub fn verify(&self, proof_share: &ProofShare) -> bool {
        self.needs_signature()
            && self
                .serialise_for_signing()
                .map(|bytes| proof_share.verify(&bytes))
                .unwrap_or(false)
    }

    fn serialise_for_signing(&self) -> Result<Vec<u8>> {
        match self {
            Self::SectionInfo(_, section_key) | Self::NeighbourInfo(_, section_key) => {
                Ok(section_key.to_bytes().to_vec())
            }
            Self::TheirKey { prefix, key } => Ok(bincode::serialize(&(prefix, key))?),
            // TODO: serialise these variants properly
            Self::Online(_)
            | Self::Offline(_)
            | Self::SendNeighbourInfo { .. }
            | Self::TheirKnowledge { .. }
            | Self::ParsecPrune
            | Self::Relocate(_)
            | Self::RelocatePrepare(..)
            | Self::User(_) => Ok(vec![]),
            Self::Genesis { .. } | Self::StartDkg(_) | Self::DkgResult { .. } => unreachable!(),
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
                "Genesis {{ group: {:?}, related_info: {:10} }}",
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
            Self::SectionInfo(info, _) => write!(formatter, "SectionInfo({:?}, ..)", info),
            Self::NeighbourInfo(elders_info, _) => {
                write!(formatter, "NeighbourInfo({:?}, ..)", elders_info)
            }
            Self::SendNeighbourInfo { dst, nonce } => write!(
                formatter,
                "SendNeighbourInfo {{ dst: {:?}, nonce: {:?} }}",
                dst, nonce
            ),
            Self::TheirKey { prefix, key } => formatter
                .debug_struct("TheirKey")
                .field("prefix", prefix)
                .field("key", key)
                .finish(),
            Self::TheirKnowledge { prefix, knowledge } => write!(
                formatter,
                "TheirKnowledge {{ prefix: {:?}, knowledge: {} }}",
                prefix, knowledge
            ),
            Self::ParsecPrune => write!(formatter, "ParsecPrune"),
            Self::Relocate(payload) => write!(formatter, "Relocate({:?})", payload),
            Self::RelocatePrepare(payload, count_down) => {
                write!(formatter, "RelocatePrepare({:?}, {})", payload, count_down)
            }
            Self::User(payload) => write!(formatter, "User({:<8})", HexFmt(payload)),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NetworkEvent {
    pub payload: AccumulatingEvent,
    pub proof_share: Option<ProofShare>,
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
        if let Some(share) = self.proof_share.as_ref() {
            write!(formatter, "{:?} (sig #{})", self.payload, share.index)
        } else {
            self.payload.fmt(formatter)
        }
    }
}

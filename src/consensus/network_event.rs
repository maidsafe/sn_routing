// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Observation, ParsecNetworkEvent, ProofShare};
use crate::{
    error::Result,
    id::{P2pNode, PublicId},
    messages::MessageHash,
    relocation::RelocateDetails,
    section::{member_info, EldersInfo, MemberState, SectionKeyShare},
    Prefix, XorName,
};
use hex_fmt::HexFmt;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
};

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

    /// Voted for node that is about to join our section
    Online {
        /// Identifier of the joining node.
        p2p_node: P2pNode,
        /// Previous name if relocated.
        previous_name: Option<XorName>,
        /// The age the node should have after joining.
        age: u8,
        /// The key of the destination section that the joining node knows, if any.
        their_knowledge: Option<bls::PublicKey>,
    },
    /// Voted for node we no longer consider online.
    Offline(XorName),

    // Vote to update the elders info of a section.
    SectionInfo(EldersInfo),

    // Voted to send info about our section to a neighbour section.
    SendNeighbourInfo {
        dst: XorName,
        // Hash of the incoming message that triggered this vote. It's purpose is to make the votes
        // triggered by different message unique.
        nonce: MessageHash,
    },

    // Voted to update our section key.
    OurKey {
        // In case of split, this prefix is used to differentiate the subsections. Not part of
        // the proof.
        prefix: Prefix,
        key: bls::PublicKey,
    },

    // Voted to update their section key.
    TheirKey {
        prefix: Prefix,
        key: bls::PublicKey,
    },

    // Voted to update their knowledge of our section.
    TheirKnowledge {
        prefix: Prefix,
        knowledge: u64,
    },

    // Prune the gossip graph.
    ParsecPrune,

    // Voted for node to be relocated out of our section.
    Relocate(RelocateDetails),

    // Opaque user-defined event.
    User(Vec<u8>),
}

impl AccumulatingEvent {
    pub fn needs_signature(&self) -> bool {
        match self {
            Self::Genesis { .. } => false,
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

    fn serialise_for_signing(&self) -> Result<Vec<u8>, bincode::Error> {
        match self {
            Self::OurKey { prefix: _, key } => {
                // Note: the prefix is only needed to differentiate between the two subsections in
                // case of split but it isn't part of the proven data.
                bincode::serialize(key)
            }
            Self::TheirKey { prefix, key } => bincode::serialize(&(prefix, key)),
            Self::TheirKnowledge { prefix, knowledge } => bincode::serialize(&(prefix, knowledge)),
            Self::SectionInfo(info) => bincode::serialize(info),
            Self::Online {
                p2p_node,
                previous_name: _,
                age: _,
                their_knowledge: _,
            } => bincode::serialize(&member_info::to_sign(p2p_node.name(), MemberState::Joined)),
            Self::Offline(name) => {
                bincode::serialize(&member_info::to_sign(name, MemberState::Left))
            }
            Self::Relocate(details) => {
                // Note: signing the same fields as for `Offline` because we need to update the
                // members map the same way as if the node went offline. The relocate details
                // will be signed using a different vote, but that is not implemented yet.
                bincode::serialize(&member_info::to_sign(
                    details.pub_id.name(),
                    MemberState::Left,
                ))
            }

            // TODO: serialise these variants properly
            Self::SendNeighbourInfo { .. } | Self::ParsecPrune | Self::User(_) => Ok(vec![]),
            Self::Genesis { .. } => unreachable!(),
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
            Self::Online {
                p2p_node,
                previous_name,
                age,
                their_knowledge,
            } => formatter
                .debug_struct("Online")
                .field("p2p_node", p2p_node)
                .field("previous_name", previous_name)
                .field("age", age)
                .field("their_knowledge", their_knowledge)
                .finish(),

            Self::Offline(id) => write!(formatter, "Offline({})", id),
            Self::SectionInfo(info) => write!(formatter, "SectionInfo({:?})", info),
            Self::SendNeighbourInfo { dst, nonce } => write!(
                formatter,
                "SendNeighbourInfo {{ dst: {:?}, nonce: {:?} }}",
                dst, nonce
            ),
            Self::OurKey { prefix, key } => formatter
                .debug_struct("OurKey")
                .field("prefix", prefix)
                .field("key", key)
                .finish(),
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
        parsec::Observation::OpaquePayload(self)
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

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
    id::PublicId,
    section::{MemberInfo, SectionKeyShare},
    XorName,
};
use hex_fmt::HexFmt;
use serde::Serialize;
use std::fmt::{self, Debug, Formatter};

/// Routing Network events
// TODO: Box `SectionInfo`?
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum AccumulatingEvent {
    /// Voted for node that is about to join our section
    Online {
        member_info: MemberInfo,
        /// Previous name if relocated.
        previous_name: Option<XorName>,
        /// The key of the destination section that the joining node knows, if any.
        their_knowledge: Option<bls::PublicKey>,
    },
    /// Voted for node we no longer consider online.
    Offline(MemberInfo),

    // Prune the gossip graph.
    ParsecPrune,

    // Opaque user-defined event.
    User(Vec<u8>),
}

impl AccumulatingEvent {
    /// Sign and convert this event into `NetworkEvent`.
    ///
    /// # Panics
    ///
    /// Panics if `self.needs_signature()` is `false`
    pub fn into_network_event(self, section_key_share: &SectionKeyShare) -> Result<NetworkEvent> {
        let signature_share = self.sign(&section_key_share.secret_key_share)?;
        let proof_share = ProofShare {
            public_key_set: section_key_share.public_key_set.clone(),
            index: section_key_share.index,
            signature_share,
        };

        Ok(NetworkEvent {
            payload: self,
            proof_share,
        })
    }

    /// Create a signature share of this event using `secret key share`.
    ///
    /// # Panics
    ///
    /// Panics if `self.needs_signature()` is `false`
    pub fn sign(&self, secret_key_share: &bls::SecretKeyShare) -> Result<bls::SignatureShare> {
        let bytes = self.serialise_for_signing()?;
        Ok(secret_key_share.sign(&bytes))
    }

    pub fn verify(&self, proof_share: &ProofShare) -> bool {
        self.serialise_for_signing()
            .map(|bytes| proof_share.verify(&bytes))
            .unwrap_or(false)
    }

    fn serialise_for_signing(&self) -> Result<Vec<u8>, bincode::Error> {
        match self {
            Self::Online {
                member_info,
                previous_name: _,
                their_knowledge: _,
            } => bincode::serialize(member_info),
            Self::Offline(member_info) => bincode::serialize(member_info),
            // TODO: serialise these variants properly
            Self::ParsecPrune | Self::User(_) => Ok(vec![]),
        }
    }
}

impl Debug for AccumulatingEvent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::Online {
                member_info,
                previous_name,
                their_knowledge,
            } => formatter
                .debug_struct("Online")
                .field("member_info", member_info)
                .field("previous_name", previous_name)
                .field("their_knowledge", their_knowledge)
                .finish(),

            Self::Offline(member_info) => write!(formatter, "Offline({:?})", member_info),
            Self::ParsecPrune => write!(formatter, "ParsecPrune"),
            Self::User(payload) => write!(formatter, "User({:<8})", HexFmt(payload)),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NetworkEvent {
    pub payload: AccumulatingEvent,
    pub proof_share: ProofShare,
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
        write!(
            formatter,
            "{:?} (sig #{})",
            self.payload, self.proof_share.index
        )
    }
}

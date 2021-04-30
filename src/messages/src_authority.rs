// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{PublicKey, Signature as SimpleSignature},
    error::{Error, Result},
    peer::Peer,
};
use bls_signature_aggregator::{Proof, ProofShare};
use serde::{Deserialize, Serialize};
use sn_messaging::SrcLocation;
use std::net::SocketAddr;
use xor_name::XorName;

/// Source authority of a message.
/// Src of message and authority to send it. Authority is validated by the signature.
/// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
/// agains the pub key and we know th epub key then we are good. If the proof is not recognised we
/// ask for a longer chain that can be recognised). Therefore we don't need to sign this field.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SrcAuthority {
    /// Authority of a single peer.
    Node {
        /// Public key of the source peer.
        public_key: PublicKey,
        /// ed-25519 signature of the message corresponding to the public key of the source peer.
        signature: SimpleSignature,
    },
    /// Authority of a single peer that uses it's BLS Keyshare to sign the message.
    BlsShare {
        /// Name in the source section
        src_name: XorName,
        /// Proof Share signed by the peer's BLS KeyShare
        proof_share: ProofShare,
    },
    /// Authority of a whole section.
    Section {
        /// Name in the source section.
        src_name: XorName,
        /// BLS proof of the message corresponding to the source section.
        proof: Proof,
    },
}

impl SrcAuthority {
    pub(crate) fn src_location(&self) -> SrcLocation {
        match self {
            Self::Node { public_key, .. } => {
                SrcLocation::Node(XorName::from(sn_data_types::PublicKey::from(*public_key)))
            }
            Self::BlsShare { src_name, .. } => SrcLocation::Section(*src_name),
            Self::Section { src_name, .. } => SrcLocation::Section(*src_name),
        }
    }

    pub(crate) fn is_section(&self) -> bool {
        matches!(self, Self::Section { .. })
    }

    pub(crate) fn name(&self) -> XorName {
        match self {
            Self::Node { public_key, .. } => {
                XorName::from(sn_data_types::PublicKey::from(*public_key))
            }
            Self::BlsShare { src_name, .. } => *src_name,
            Self::Section { src_name, .. } => *src_name,
        }
    }

    // If this location is `Node`, returns the corresponding `Peer` with `addr`. Otherwise error.
    pub(crate) fn peer(&self, addr: SocketAddr) -> Result<Peer> {
        match self {
            Self::Node { public_key, .. } => Ok(Peer::new(
                XorName::from(sn_data_types::PublicKey::from(*public_key)),
                addr,
            )),
            Self::Section { .. } | Self::BlsShare { .. } => Err(Error::InvalidSrcLocation),
        }
    }
}

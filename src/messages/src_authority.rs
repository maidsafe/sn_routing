// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::{name, PublicKey, Signature as SimpleSignature},
    error::{Error, Result},
    peer::Peer,
};
use bls_signature_aggregator::ProofShare;
use serde::{Deserialize, Serialize};
use sn_messaging::SrcLocation;
use std::net::SocketAddr;
use xor_name::{Prefix, XorName};

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
        /// Age of the source peer.
        age: u8,
        /// ed-25519 signature of the message corresponding to the public key of the source peer.
        signature: SimpleSignature,
    },
    /// Authority of a single peer that uses it's BLS Keyshare to sign the message.
    BlsShare {
        /// Section name at the time
        src_section: XorName,
        /// Public key of the source peer.
        public_key: PublicKey,
        /// Age of the source peer.
        age: u8,
        /// Proof Share signed by the peer's BLS KeyShare
        proof_share: ProofShare,
    },
    /// Authority of a whole section.
    Section {
        /// Prefix of the source section.
        prefix: Prefix,
        /// BLS signature of the message corresponding to the source section public key.
        signature: bls::Signature,
    },
}

impl SrcAuthority {
    pub(crate) fn src_location(&self) -> SrcLocation {
        match self {
            Self::Node { public_key, .. } => SrcLocation::Node(name(public_key)),
            Self::BlsShare { public_key, .. } => SrcLocation::Node(name(public_key)),
            Self::Section { prefix, .. } => SrcLocation::Section(prefix.name()),
        }
    }

    pub(crate) fn is_section(&self) -> bool {
        matches!(self, Self::Section { .. })
    }

    pub(crate) fn to_node_name(&self) -> Result<XorName> {
        match self {
            Self::Node { public_key, .. } => Ok(name(public_key)),
            Self::BlsShare { public_key, .. } => Ok(name(public_key)),
            Self::Section { .. } => Err(Error::InvalidSrcLocation),
        }
    }

    // If this location is `Node`, returns the corresponding `Peer` with `addr`. Otherwise error.
    pub(crate) fn to_node_peer(&self, addr: SocketAddr) -> Result<Peer> {
        match self {
            Self::Section { .. } => Err(Error::InvalidSrcLocation),
            Self::Node {
                public_key, age, ..
            }
            | Self::BlsShare {
                public_key, age, ..
            } => Ok(Peer::new(name(public_key), addr, *age)),
        }
    }

    // If this is `Section`, returns the prefix.
    pub(crate) fn as_section_prefix(&self) -> Result<&Prefix> {
        match self {
            Self::Section { prefix, .. } => Ok(prefix),
            Self::Node { .. } | Self::BlsShare { .. } => Err(Error::InvalidSrcLocation),
        }
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::Signature as SimpleSignature,
    error::{Result, RoutingError},
    id::{P2pNode, PublicId},
    location::SrcLocation,
};

use std::net::SocketAddr;
use xor_name::Prefix;

/// Source authority of a message.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Src of message and authority to send it. Authority is validated by the signature.
/// Messages do not need to sign this field as it is all verifiable (i.e. if the sig validates
/// agains the pub key and we know th epub key then we are good. If the proof is not recodnised we
/// ask for a longer chain that can be recodnised). Therefor we don't need to sign this field.
pub enum SrcAuthority {
    /// Authority of a single node.
    Node {
        /// Id of the source node.
        public_id: PublicId,
        /// ed-25519 signature of the message corresponding to the public key of the source node.
        signature: SimpleSignature,
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
            Self::Node { public_id, .. } => SrcLocation::Node(*public_id.name()),
            Self::Section { prefix, .. } => SrcLocation::Section(*prefix),
        }
    }

    pub(crate) fn check_is_section(&self) -> Result<()> {
        if self.is_section() {
            Ok(())
        } else {
            Err(RoutingError::BadLocation)
        }
    }

    pub(crate) fn is_section(&self) -> bool {
        matches!(self, Self::Section { .. })
    }

    pub(crate) fn as_node(&self) -> Result<&PublicId> {
        match self {
            Self::Node { public_id, .. } => Ok(public_id),
            Self::Section { .. } => Err(RoutingError::BadLocation),
        }
    }

    // If this is `Section`, returns the prefix.
    pub(crate) fn as_section_prefix(&self) -> Result<&Prefix> {
        match self {
            Self::Section { prefix, .. } => Ok(prefix),
            Self::Node { .. } => Err(RoutingError::BadLocation),
        }
    }

    pub(crate) fn to_sender_node(&self, sender: Option<SocketAddr>) -> Result<P2pNode> {
        let pub_id = *self.as_node()?;
        let conn_info = sender.ok_or(RoutingError::InvalidSource)?;
        Ok(P2pNode::new(pub_id, conn_info))
    }
}

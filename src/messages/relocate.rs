// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{MessageContent, RoutingMessage, SecurityMetadata, SignedRoutingMessage};
use crate::{id::PublicId, routing_table::Authority, xor_name::XorName};

/// Details of a relocation: which node to relocate, where to relocate it to and what age it should
/// get once relocated.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct RelocateDetails {
    /// Public id of the node to relocate.
    pub pub_id: PublicId,
    /// Relocation destination - the node will be relocated to a section whose prefix matches this
    /// name.
    pub destination: XorName,
    /// The age the node will have post-relocation.
    pub age: u8,
}

/// Relocation details that are signed so the destination section can prove the relocation is
/// genuine.
pub struct SignedRelocateDetails {
    content: RelocateDetails,
    src: Authority<XorName>,
    dst: Authority<XorName>,
    security_metadata: SecurityMetadata,
}

impl SignedRelocateDetails {
    pub fn new(
        content: RelocateDetails,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        security_metadata: SecurityMetadata,
    ) -> Self {
        Self {
            content,
            src,
            dst,
            security_metadata,
        }
    }

    pub fn content(&self) -> &RelocateDetails {
        &self.content
    }
}

impl From<SignedRelocateDetails> for SignedRoutingMessage {
    fn from(details: SignedRelocateDetails) -> Self {
        Self::from_parts(
            RoutingMessage {
                content: MessageContent::Relocate(details.content),
                src: details.src,
                dst: details.dst,
            },
            details.security_metadata,
        )
    }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Variant;
use crate::{
    crypto::signing::Signature,
    error::RoutingError,
    id::{FullId, PublicId},
};
use bincode::serialize;
use serde::Serialize;
use std::fmt::{self, Debug, Formatter};

#[derive(Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignedDirectMessage {
    content: Variant,
    src_id: PublicId,
    signature: Signature,
}

impl SignedDirectMessage {
    /// Create new `SignedDirectMessage` with `content` and signed by `src_full_id`.
    pub fn new(content: Variant, src_full_id: &FullId) -> Result<Self, RoutingError> {
        let serialised = serialize(&content)?;
        let signature = src_full_id.sign(&serialised);

        Ok(Self {
            content,
            src_id: *src_full_id.public_id(),
            signature,
        })
    }

    /// Verify the message signature.
    pub fn verify(&self) -> Result<(), RoutingError> {
        let serialised = serialize(&self.content)?;

        if self.src_id.verify(&serialised, &self.signature) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    /// Verify the message signature and return its content and the sender id.
    /// Consume the message in the process.
    pub fn open(self) -> Result<(Variant, PublicId), RoutingError> {
        self.verify()?;
        Ok((self.content, self.src_id))
    }

    /// Content of the message.
    #[cfg(all(test, feature = "mock_base"))]
    pub fn content(&self) -> &Variant {
        &self.content
    }
}

impl Debug for SignedDirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedDirectMessage {{ content: {:?}, src_id: {:?}, signature: {:?} }}",
            self.content, self.src_id, self.signature
        )
    }
}

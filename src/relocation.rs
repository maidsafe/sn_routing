// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Relocation related types and utilities.

use crate::{
    chain::{AccumulatingEvent, IntoAccumulatingEvent, SectionProofChain},
    crypto::{self, signing::Signature},
    error::RoutingError,
    id::{FullId, PublicId},
    xor_name::{XorName, XOR_NAME_LEN},
    BlsSignature,
};
use maidsafe_utilities::serialisation::serialise;
use std::fmt;

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

impl IntoAccumulatingEvent for RelocateDetails {
    fn into_accumulating_event(self) -> AccumulatingEvent {
        AccumulatingEvent::Relocate(self)
    }
}

/// Relocation details that are signed so the destination section can prove the relocation is
/// genuine.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignedRelocateDetails {
    content: RelocateDetails,
    proof: SectionProofChain,
    signature: BlsSignature,
}

impl SignedRelocateDetails {
    pub fn new(
        content: RelocateDetails,
        proof: SectionProofChain,
        signature: BlsSignature,
    ) -> Self {
        Self {
            content,
            proof,
            signature,
        }
    }

    pub fn content(&self) -> &RelocateDetails {
        &self.content
    }

    pub fn proof(&self) -> &SectionProofChain {
        &self.proof
    }

    // TODO: remove this `allow(unused)` when the Relocate signature issue is solved.
    #[allow(unused)]
    pub fn verify(&self) -> bool {
        serialise(&self.content)
            .map(|bytes| self.proof.last_public_key().verify(&self.signature, bytes))
            .unwrap_or(false)
    }
}

impl fmt::Debug for SignedRelocateDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedRelocateDetails {{ content: {:?}, .. }}",
            self.content
        )
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct RelocatePayload {
    pub details: SignedRelocateDetails,
    /// The new id (`PublicId`) of the node signed using its old id, to prove the node identity.
    pub signature_of_new_id_with_old_id: Signature,
}

impl RelocatePayload {
    pub fn new(
        details: SignedRelocateDetails,
        new_pub_id: &PublicId,
        old_full_id: &FullId,
    ) -> Result<Self, RoutingError> {
        let new_id_serialised = serialise(new_pub_id)?;
        let signature_of_new_id_with_old_id = old_full_id.sign(&new_id_serialised);

        Ok(Self {
            details,
            signature_of_new_id_with_old_id,
        })
    }

    pub fn verify_identity(&self, new_pub_id: &PublicId) -> bool {
        let new_id_serialised = match serialise(new_pub_id) {
            Ok(buf) => buf,
            Err(_) => return false,
        };

        self.details
            .content()
            .pub_id
            .verify(&new_id_serialised, &self.signature_of_new_id_with_old_id)
    }
}

pub fn compute_destination(relocated_name: &XorName, trigger_name: &XorName) -> XorName {
    let mut buffer = [0; 2 * XOR_NAME_LEN];
    buffer[..XOR_NAME_LEN].copy_from_slice(&relocated_name.0);
    buffer[XOR_NAME_LEN..].copy_from_slice(&trigger_name.0);

    XorName(crypto::sha3_256(&buffer))
}

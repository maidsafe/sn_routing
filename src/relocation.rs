// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Relocation related types and utilities.

use crate::{
    crypto::{self, Signature},
    error::RoutingError,
    id::{FullId, PublicId},
    messages::{Message, Variant},
};

use bincode::serialize;
use serde::{de::Error as SerdeDeError, Deserialize, Deserializer, Serialize, Serializer};
use xor_name::XorName;

/// Relocation check - returns whether a member with the given age is a candidate for relocation on
/// a churn event with the given signature.
pub fn check(age: u8, churn_signature: &bls::Signature) -> bool {
    // Evaluate the formula: `signature % 2^age == 0` Which is the same as checking the signature
    // has at least `age` trailing zero bits.
    trailing_zeros(&churn_signature.to_bytes()[..]) >= age as u32
}

// Returns the number of trailing zero bits of the byte slice.
fn trailing_zeros(bytes: &[u8]) -> u32 {
    let mut output = 0;

    for &byte in bytes.iter().rev() {
        if byte == 0 {
            output += 8;
        } else {
            output += byte.trailing_zeros();
            break;
        }
    }

    output
}

/// Compute the destination for the node with `relocating_name` to be relocated to. `churn_name` is
/// the name of the joined/left node that triggered the relocation.
pub fn compute_destination(relocating_name: &XorName, churn_name: &XorName) -> XorName {
    let combined_name = xor(relocating_name, churn_name);
    XorName(crypto::sha3_256(&combined_name.0))
}

// TODO: move this to the xor-name crate as `BitXor` impl.
fn xor(lhs: &XorName, rhs: &XorName) -> XorName {
    let mut output = XorName::default();
    for (o, (l, r)) in output.0.iter_mut().zip(lhs.0.iter().zip(rhs.0.iter())) {
        *o = l ^ r;
    }

    output
}

/// Details of a relocation: which node to relocate, where to relocate it to and what age it should
/// get once relocated.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct RelocateDetails {
    /// Public id of the node to relocate.
    pub pub_id: PublicId,
    /// Relocation destination - the node will be relocated to a section whose prefix matches this
    /// name.
    pub destination: XorName,
    /// The BLS key of the destination section used by the relocated node to verify messages.
    pub destination_key: bls::PublicKey,
    /// The age the node will have post-relocation.
    pub age: u8,
}

/// SignedRoutingMessage with Relocate message content.
#[derive(Clone, Eq, PartialEq, Hash)]
pub(crate) struct SignedRelocateDetails {
    /// Signed message whose content is Variant::Relocate
    signed_msg: Message,
}

impl SignedRelocateDetails {
    pub fn new(signed_msg: Message) -> Result<Self, RoutingError> {
        if let Variant::Relocate(_) = signed_msg.variant() {
            Ok(Self { signed_msg })
        } else {
            Err(RoutingError::InvalidMessage)
        }
    }

    // FIXME: need a non-panicking version of this, because when we receive it from another node,
    // we can't be sure it's well formed.
    pub fn relocate_details(&self) -> &RelocateDetails {
        if let Variant::Relocate(details) = &self.signed_msg.variant() {
            details
        } else {
            panic!("SignedRelocateDetails always contain Variant::Relocate")
        }
    }

    pub fn signed_msg(&self) -> &Message {
        &self.signed_msg
    }

    pub fn destination(&self) -> &XorName {
        &self.relocate_details().destination
    }
}

impl Serialize for SignedRelocateDetails {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        self.signed_msg.serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for SignedRelocateDetails {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let signed_msg = Deserialize::deserialize(deserialiser)?;
        Self::new(signed_msg).map_err(|err| {
            D::Error::custom(format!(
                "failed to construct SignedRelocateDetails: {:?}",
                err
            ))
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct RelocatePayload {
    /// The Relocate Signed message.
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
        let new_id_serialised = serialize(new_pub_id)?;
        let signature_of_new_id_with_old_id = old_full_id.sign(&new_id_serialised);

        Ok(Self {
            details,
            signature_of_new_id_with_old_id,
        })
    }

    pub fn verify_identity(&self, new_pub_id: &PublicId) -> bool {
        let new_id_serialised = match serialize(new_pub_id) {
            Ok(buf) => buf,
            Err(_) => return false,
        };

        self.details
            .relocate_details()
            .pub_id
            .verify(&new_id_serialised, &self.signature_of_new_id_with_old_id)
    }

    pub fn relocate_details(&self) -> &RelocateDetails {
        self.details.relocate_details()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct RelocatePromise {
    pub name: XorName,
    pub destination: XorName,
}

/// Action to relocate a node.
pub(crate) enum RelocateAction {
    /// Relocate the node instantly.
    Instant(RelocateDetails),
    /// Relocate the node after they are no longer our elder.
    Delayed(RelocatePromise),
}

impl RelocateAction {
    pub fn destination(&self) -> &XorName {
        match self {
            Self::Instant(details) => &details.destination,
            Self::Delayed(promise) => &promise.destination,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_slice_trailing_zeros() {
        assert_eq!(trailing_zeros(&[0]), 8);
        assert_eq!(trailing_zeros(&[1]), 0);
        assert_eq!(trailing_zeros(&[2]), 1);
        assert_eq!(trailing_zeros(&[4]), 2);
        assert_eq!(trailing_zeros(&[8]), 3);
        assert_eq!(trailing_zeros(&[0, 0]), 16);
        assert_eq!(trailing_zeros(&[1, 0]), 8);
        assert_eq!(trailing_zeros(&[2, 0]), 9);
    }
}

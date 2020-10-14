// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Relocation related types and utilities.

use crate::{
    consensus::Proven,
    crypto::{self, Keypair, Signature, Verifier},
    error::Error,
    messages::{Message, Variant},
    network::Network,
    section::{MemberInfo, Section},
};

use serde::{de::Error as SerdeDeError, Deserialize, Deserializer, Serialize, Serializer};
use xor_name::XorName;

/// Find all nodes to relocate after a churn even and create the relocate actions for them.
pub(crate) fn actions(
    section: &Section,
    network: &Network,
    churn_name: &XorName,
    churn_signature: &bls::Signature,
) -> Vec<(MemberInfo, RelocateAction)> {
    section
        .members()
        .proven_joined()
        .filter(|info| check(info.value.peer.age(), churn_signature))
        .map(|info| {
            (
                info.value,
                RelocateAction::new(section, network, info, churn_name),
            )
        })
        .collect()
}

/// Details of a relocation: which node to relocate, where to relocate it to and what age it should
/// get once relocated.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct RelocateDetails {
    /// Public id of the node to relocate.
    pub pub_id: XorName,
    /// Relocation destination - the node will be relocated to a section whose prefix matches this
    /// name.
    pub destination: XorName,
    /// The BLS key of the destination section used by the relocated node to verify messages.
    pub destination_key: bls::PublicKey,
    /// The age the node will have post-relocation.
    pub age: u8,
}

impl RelocateDetails {
    pub(crate) fn new(
        section: &Section,
        network: &Network,
        info: &MemberInfo,
        destination: XorName,
    ) -> Self {
        let destination_key = *network
            .key_by_name(&destination)
            .unwrap_or_else(|| section.chain().first_key());

        Self {
            pub_id: *info.peer.name(),
            destination,
            destination_key,
            age: info.peer.age().saturating_add(1),
        }
    }
}

/// SignedSNRoutingMessage with Relocate message content.
#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct SignedRelocateDetails {
    /// Signed message whose content is Variant::Relocate
    signed_msg: Message,
}

impl SignedRelocateDetails {
    pub fn new(signed_msg: Message) -> Result<Self, Error> {
        if let Variant::Relocate(_) = signed_msg.variant() {
            Ok(Self { signed_msg })
        } else {
            Err(Error::InvalidMessage)
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

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RelocatePayload {
    /// The Relocate Signed message.
    pub details: SignedRelocateDetails,
    /// The new name of the node signed using its old public_key, to prove the node identity.
    pub signature_of_new_name_with_old_key: Signature,
}

impl RelocatePayload {
    pub fn new(
        details: SignedRelocateDetails,
        new_name: &XorName,
        old_keypair: &Keypair,
    ) -> Result<Self, Error> {
        let signature_of_new_name_with_old_key = crypto::sign(&new_name.0, old_keypair);

        Ok(Self {
            details,
            signature_of_new_name_with_old_key,
        })
    }

    pub fn verify_identity(&self, new_name: &XorName) -> bool {
        let pub_key = if let Ok(pub_key) = crypto::pub_key(&self.details.relocate_details().pub_id)
        {
            pub_key
        } else {
            return false;
        };

        pub_key
            .verify(&new_name.0, &self.signature_of_new_name_with_old_key)
            .is_ok()
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
    pub fn new(
        section: &Section,
        network: &Network,
        info: &Proven<MemberInfo>,
        churn_name: &XorName,
    ) -> Self {
        let destination = destination(info.value.peer.name(), churn_name);

        if section.is_elder(info.value.peer.name()) {
            RelocateAction::Delayed(RelocatePromise {
                name: *info.value.peer.name(),
                destination,
            })
        } else {
            RelocateAction::Instant(RelocateDetails::new(
                section,
                network,
                &info.value,
                destination,
            ))
        }
    }

    pub fn destination(&self) -> &XorName {
        match self {
            Self::Instant(details) => &details.destination,
            Self::Delayed(promise) => &promise.destination,
        }
    }
}

// Compute the destination for the node with `relocating_name` to be relocated to. `churn_name` is
// the name of the joined/left node that triggered the relocation.
fn destination(relocating_name: &XorName, churn_name: &XorName) -> XorName {
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

// Relocation check - returns whether a member with the given age is a candidate for relocation on
// a churn event with the given signature.
fn check(age: u8, churn_signature: &bls::Signature) -> bool {
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

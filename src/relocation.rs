// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Relocation related types and utilities.

use crate::{
    crypto::{self, signing::Signature},
    error::RoutingError,
    id::{FullId, PublicId},
    messages::{Message, Variant},
};

use bincode::serialize;
use serde::{de::Error as SerdeDeError, Deserialize, Deserializer, Serialize, Serializer};
use xor_name::{Prefix, XorName, XOR_NAME_LEN};

#[cfg(feature = "mock_base")]
pub use self::overrides::Overrides;

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
pub struct SignedRelocateDetails {
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
pub struct RelocatePayload {
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

#[cfg(not(feature = "mock_base"))]
pub fn compute_destination(
    _src_prefix: &Prefix,
    relocated_name: &XorName,
    trigger_name: &XorName,
) -> XorName {
    compute_destination_without_override(relocated_name, trigger_name)
}

#[cfg(feature = "mock_base")]
pub fn compute_destination(
    src_prefix: &Prefix,
    relocated_name: &XorName,
    trigger_name: &XorName,
) -> XorName {
    self::overrides::get(
        src_prefix,
        compute_destination_without_override(relocated_name, trigger_name),
    )
}

fn compute_destination_without_override(
    relocated_name: &XorName,
    trigger_name: &XorName,
) -> XorName {
    let mut buffer = [0; 2 * XOR_NAME_LEN];
    buffer[..XOR_NAME_LEN].copy_from_slice(&relocated_name.0);
    buffer[XOR_NAME_LEN..].copy_from_slice(&trigger_name.0);

    XorName(crypto::sha3_256(&buffer))
}

#[cfg(feature = "mock_base")]
mod overrides {
    use crate::{Prefix, XorName};
    use std::{
        cell::RefCell,
        collections::{hash_map::Entry, HashMap, HashSet},
    };

    /// Mechanism for overriding relocation destinations. Useful for tests.
    pub struct Overrides {
        prefixes: HashSet<Prefix>,
    }

    impl Overrides {
        /// Create new instance of relocation overrides.
        /// The overrides set by this instance are automatically `clear`ed when this instance goes
        /// out of scope.
        pub fn new() -> Self {
            Self {
                prefixes: HashSet::new(),
            }
        }

        /// Override relocation destination for the given source prefix - that is, any node to be
        /// relocated from that prefix will be relocated to the given destination.
        /// The override applies only to the exact prefix, not to its parents / children.
        pub fn set(&mut self, src_prefix: Prefix, dst: XorName) {
            let _ = self.prefixes.insert(src_prefix);

            OVERRIDES.with(|map| {
                map.borrow_mut().entry(src_prefix).or_default().next = Some(dst);
            })
        }

        /// Suppress relocations from the given source prefix.
        pub fn suppress(&mut self, src_prefix: Prefix) {
            self.set(src_prefix, src_prefix.name())
        }

        /// Suppress relocations from the given source prefix and its parent prefixes.
        pub fn suppress_self_and_parents(&mut self, mut src_prefix: Prefix) {
            self.suppress(src_prefix);

            while !src_prefix.is_empty() {
                src_prefix = src_prefix.popped();
                self.suppress(src_prefix);
            }
        }

        /// Clear all relocation overrides set by this instance.
        pub fn clear(&mut self) {
            OVERRIDES.with(|map| {
                let mut map = map.borrow_mut();

                for prefix in self.prefixes.drain() {
                    if let Some(info) = map.get_mut(&prefix) {
                        info.next = None;
                    }
                }
            });
        }
    }

    impl Default for Overrides {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for Overrides {
        fn drop(&mut self) {
            self.clear();
        }
    }

    #[derive(Default)]
    struct OverrideInfo {
        // If `Some`, the relocation destinations are overridden with this name, otherwise they are
        // not.
        next: Option<XorName>,
        // Map of original relocation destinations to the overridden ones. As this map is shared
        // among all nodes in the network, this assures that every node will pick the same
        // destination name for a given relocated node no matter when the calculation is performed.
        used: HashMap<XorName, XorName>,
    }

    impl OverrideInfo {
        fn get(&mut self, original_dst: XorName) -> XorName {
            match self.used.entry(original_dst) {
                Entry::Vacant(entry) => {
                    if let Some(next) = self.next {
                        *entry.insert(next)
                    } else {
                        original_dst
                    }
                }
                Entry::Occupied(entry) => *entry.get(),
            }
        }
    }

    pub(super) fn get(src_prefix: &Prefix, original_dst: XorName) -> XorName {
        OVERRIDES.with(|map| {
            if let Some(info) = map.borrow_mut().get_mut(src_prefix) {
                info.get(original_dst)
            } else {
                original_dst
            }
        })
    }

    thread_local! {
        static OVERRIDES: RefCell<HashMap<Prefix, OverrideInfo>> = RefCell::new(HashMap::new());
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::rng;
        use rand::Rng;

        #[test]
        fn multiple_instances() {
            let mut rng = rng::new();

            let p0 = Prefix::default().pushed(false);
            let p1 = Prefix::default().pushed(true);

            let a_orig: XorName = rng.gen();
            let b_orig: XorName = rng.gen();
            let a_overriden0: XorName = rng.gen();
            let a_overriden1: XorName = rng.gen();

            assert_eq!(get(&p0, a_orig), a_orig);
            assert_eq!(get(&p1, a_orig), a_orig);

            {
                let mut overrides = Overrides::new();
                overrides.set(p0, a_overriden0);
                assert_eq!(get(&p0, a_orig), a_overriden0);
                assert_eq!(get(&p1, a_orig), a_orig);

                {
                    let mut overrides = Overrides::new();
                    overrides.set(p1, a_overriden1);
                    assert_eq!(get(&p0, a_orig), a_overriden0);
                    assert_eq!(get(&p1, a_orig), a_overriden1);
                }

                assert_eq!(get(&p0, a_orig), a_overriden0);
                assert_eq!(get(&p1, a_orig), a_overriden1);
                assert_eq!(get(&p1, b_orig), b_orig);
            }

            assert_eq!(get(&p0, a_orig), a_overriden0);
            assert_eq!(get(&p1, a_orig), a_overriden1);
            assert_eq!(get(&p0, b_orig), b_orig);
            assert_eq!(get(&p1, b_orig), b_orig);
        }
    }
}

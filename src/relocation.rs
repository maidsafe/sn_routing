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
    routing_table::Prefix,
    xor_name::{XorName, XOR_NAME_LEN},
    BlsSignature,
};
use maidsafe_utilities::serialisation::serialise;
use std::fmt;

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

#[cfg(not(feature = "mock_base"))]
pub fn compute_destination(
    _src_prefix: &Prefix<XorName>,
    relocated_name: &XorName,
    trigger_name: &XorName,
) -> XorName {
    compute_destination_without_override(relocated_name, trigger_name)
}

#[cfg(feature = "mock_base")]
pub fn compute_destination(
    src_prefix: &Prefix<XorName>,
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
        prefixes: HashSet<Prefix<XorName>>,
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
        pub fn set(&mut self, src_prefix: Prefix<XorName>, dst: XorName) {
            let rc = if self.prefixes.insert(src_prefix) {
                1
            } else {
                0
            };

            OVERRIDES.with(|map| {
                let _ = map
                    .borrow_mut()
                    .entry(src_prefix)
                    .and_modify(|info| {
                        info.next = dst;
                        info.rc += rc;
                    })
                    .or_insert_with(|| OverrideInfo {
                        next: dst,
                        used: HashMap::new(),
                        rc,
                    });
            })
        }

        /// Suppress relocations from the given source prefix.
        pub fn suppress(&mut self, src_prefix: Prefix<XorName>) {
            self.set(src_prefix, src_prefix.name())
        }

        /// Clear all relocation overrides set by this instance.
        pub fn clear(&mut self) {
            OVERRIDES.with(|map| {
                let mut map = map.borrow_mut();

                for prefix in self.prefixes.drain() {
                    match map.entry(prefix) {
                        Entry::Occupied(mut entry) => {
                            if entry.get().rc <= 1 {
                                let _ = entry.remove();
                            } else {
                                entry.get_mut().rc -= 1;
                            }
                        }
                        Entry::Vacant(_) => panic!("Unexpected missing overrides for {:?}", prefix),
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

    struct OverrideInfo {
        // Name that will be used as the next relocation destination.
        next: XorName,
        // Map of original relocation destinations to the overridden ones. As this map is shared
        // among all nodes in the network, this assures that every node will pick the same
        // destination name for a given relocated node no matter when the calculation is performed.
        used: HashMap<XorName, XorName>,
        // Reference counter (number of `Overrides` instances that share this entry).
        rc: usize,
    }

    impl OverrideInfo {
        fn get(&mut self, original_dst: XorName) -> XorName {
            *self.used.entry(original_dst).or_insert(self.next)
        }
    }

    pub(super) fn get(src_prefix: &Prefix<XorName>, original_dst: XorName) -> XorName {
        OVERRIDES.with(|map| {
            if let Some(info) = map.borrow_mut().get_mut(src_prefix) {
                info.get(original_dst)
            } else {
                original_dst
            }
        })
    }

    thread_local! {
        static OVERRIDES: RefCell<HashMap<Prefix<XorName>, OverrideInfo>> = RefCell::new(HashMap::new());
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

            let original: XorName = rng.gen();
            let overriden0: XorName = rng.gen();
            let overriden1: XorName = rng.gen();

            assert_eq!(get(&p0, original), original);
            assert_eq!(get(&p1, original), original);

            {
                let mut overrides = Overrides::new();
                overrides.set(p0, overriden0);
                assert_eq!(get(&p0, original), overriden0);
                assert_eq!(get(&p1, original), original);

                {
                    let mut overrides = Overrides::new();
                    overrides.set(p1, overriden1);
                    assert_eq!(get(&p0, original), overriden0);
                    assert_eq!(get(&p1, original), overriden1);
                }

                assert_eq!(get(&p0, original), overriden0);
                assert_eq!(get(&p1, original), original);
            }

            assert_eq!(get(&p0, original), original);
            assert_eq!(get(&p1, original), original);
        }
    }
}

// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::NO_OWNER_PUB_KEY;
use error::RoutingError;
use maidsafe_utilities::serialisation::{serialise, serialised_size};
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use utils;
use xor_name::XorName;

/// Maximum allowed size for a Structured Data to grow to
pub const MAX_STRUCTURED_DATA_SIZE_IN_BYTES: u64 = 102400;

/// Mutable structured data.
///
/// These types may be stored unsigned with previous and current owner keys
/// set to the same keys. Updates require a signature to validate.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub struct StructuredData {
    type_tag: u64,
    name: XorName,
    data: Vec<u8>,
    version: u64,
    owners: BTreeSet<PublicKey>,
    signatures: BTreeMap<PublicKey, Signature>,
}

impl StructuredData {
    /// Creates a new `StructuredData`.
    pub fn new(type_tag: u64,
               name: XorName,
               version: u64,
               data: Vec<u8>,
               owners: BTreeSet<PublicKey>)
               -> Result<StructuredData, RoutingError> {
        if owners.len() > 1 {
            return Err(RoutingError::InvalidOwners);
        }

        Ok(StructuredData {
            type_tag: type_tag,
            name: name,
            data: data,
            version: version,
            owners: owners,
            signatures: BTreeMap::new(),
        })
    }

    /// Replaces this data item with the given updated version if the update is valid, otherwise
    /// returns an error.
    ///
    /// To transfer ownership, the current owner signs over the data and increase `version` by one.
    pub fn replace_with_other(&mut self, other: StructuredData) -> Result<(), RoutingError> {
        self.validate_self_against_successor(&other)?;

        self.type_tag = other.type_tag;
        self.name = other.name;
        self.data = other.data;
        self.version = other.version;
        self.owners = other.owners;
        self.signatures = other.signatures;
        Ok(())
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Deletes the data by clearing all its fields, if the `other` data would be a valid
    /// successor.
    pub fn delete_if_valid_successor(&mut self,
                                     other: &StructuredData)
                                     -> Result<(), RoutingError> {
        self.validate_self_against_successor(other)?;
        self.data.clear();
        self.version += 1;
        self.owners.clear();
        self.signatures.clear();
        Ok(())
    }

    /// Check whether the data has been deleted
    pub fn is_deleted(&self) -> bool {
        self.data.is_empty() && self.owners.is_empty() && self.signatures.is_empty()
    }

    /// Verifies that `other` is a valid update for `self`; returns an error otherwise.
    ///
    /// An update is valid if it doesn't change type tag or identifier (these are immutable),
    /// increases the version by 1 and is signed by (more than 50% of) the owners.
    pub fn validate_self_against_successor(&self,
                                           other: &StructuredData)
                                           -> Result<(), RoutingError> {
        if other.owners.len() > 1 || other.signatures.len() > 1 ||
           self.owners.contains(&NO_OWNER_PUB_KEY) {
            return Err(RoutingError::InvalidOwners);
        }

        // TODO(dirvine) Increase error types to be more descriptive  :07/07/2015
        if other.type_tag != self.type_tag || other.name != self.name ||
           other.version != self.version + 1 {
            return Err(RoutingError::UnknownMessageType);
        }
        let data = other.data_to_sign()?;
        super::verify_signatures(&self.owners, &data, &other.signatures)
    }

    fn data_to_sign(&self) -> Result<Vec<u8>, RoutingError> {
        // Seems overkill to use serialisation here, but done to ensure cross platform signature
        // handling is OK
        let sd = SerialisableStructuredData {
            type_tag: self.type_tag.to_string().as_bytes().to_vec(),
            name: self.name,
            data: &self.data,
            version: self.version.to_string().as_bytes().to_vec(),
            owners: &self.owners,
        };

        serialise(&sd).map_err(From::from)
    }

    /// Adds a signature with the given `keys.1` to the `signatures` and returns
    /// the number of signatures that are still required. If more than 50% of the owners
    /// have signed, 0 is returned and validation is complete.
    pub fn add_signature(&mut self, keys: &(PublicKey, SecretKey)) -> Result<usize, RoutingError> {
        if !self.signatures.is_empty() {
            return Err(RoutingError::InvalidOwners);
        }
        let data = self.data_to_sign()?;
        let sig = sign::sign_detached(&data, &keys.1);
        let _ = self.signatures.insert(keys.0, sig);
        Ok(((self.owners.len() / 2) + 1).saturating_sub(self.signatures.len()))
    }

    /// Overwrite any existing signatures with the new signatures provided.
    pub fn replace_signatures(&mut self, new_signatures: BTreeMap<PublicKey, Signature>) {
        self.signatures = new_signatures;
    }

    /// Get the type_tag
    pub fn get_type_tag(&self) -> u64 {
        self.type_tag
    }

    /// Get the serialised data
    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Get the version
    pub fn get_version(&self) -> u64 {
        self.version
    }

    /// Get the current owner keys
    pub fn get_owners(&self) -> &BTreeSet<PublicKey> {
        &self.owners
    }

    /// Get previous owner signatures
    pub fn get_signatures(&self) -> &BTreeMap<PublicKey, Signature> {
        &self.signatures
    }

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        serialised_size(self) <= MAX_STRUCTURED_DATA_SIZE_IN_BYTES
    }
}

impl Debug for StructuredData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "StructuredData {{ type_tag: {}, name: {}, version: {}, data: {}, \
                owners: {:?}, signatures: {:?} }}",
               self.type_tag,
               self.name(),
               self.version,
               utils::format_binary_array(&self.data[..]),
               self.owners,
               self.signatures)
    }
}

#[derive(RustcEncodable)]
struct SerialisableStructuredData<'a> {
    type_tag: Vec<u8>,
    name: XorName,
    data: &'a [u8],
    version: Vec<u8>,
    owners: &'a BTreeSet<PublicKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use data;
    use rand;
    use rust_sodium::crypto::sign;
    use std::collections::BTreeSet;
    use xor_name::XorName;

    #[test]
    fn single_owner() {
        let keys = sign::gen_keypair();
        let mut owner_keys = BTreeSet::new();
        owner_keys.insert(keys.0);

        match StructuredData::new(0, rand::random(), 0, vec![], owner_keys.clone()) {
            Ok(mut structured_data) => {
                let data = match structured_data.data_to_sign() {
                    Ok(data) => data,
                    Err(error) => panic!("Error: {:?}", error),
                };
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                structured_data.get_signatures())
                    .is_err());
                assert_eq!(structured_data.add_signature(&keys).unwrap(), 0);
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                structured_data.get_signatures())
                    .is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn single_owner_other_signature() {
        let keys = sign::gen_keypair();
        let other_keys = sign::gen_keypair();
        let mut owner_keys = BTreeSet::new();
        owner_keys.insert(keys.0);

        match StructuredData::new(0, rand::random(), 0, vec![], owner_keys.clone()) {
            Ok(mut structured_data) => {
                assert_eq!(structured_data.add_signature(&other_keys).unwrap(), 0);
                let data = match structured_data.data_to_sign() {
                    Ok(data) => data,
                    Err(error) => panic!("Error: {:?}", error),
                };
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                structured_data.get_signatures())
                    .is_err());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn transfer_ownership() {
        let keys = sign::gen_keypair();
        let other_keys = sign::gen_keypair();
        let mut owner = BTreeSet::new();
        owner.insert(keys.0);
        let mut new_owner = BTreeSet::new();
        new_owner.insert(other_keys.0);
        let name: XorName = rand::random();

        let mut sd = unwrap!(StructuredData::new(0, name, 0, vec![], owner));
        let mut sd_new = unwrap!(StructuredData::new(0, name, 1, vec![], new_owner.clone()));
        assert_eq!(sd_new.add_signature(&keys).unwrap(), 0);
        assert!(sd.replace_with_other(sd_new).is_ok());

        let mut sd_fail = unwrap!(StructuredData::new(0, name, 2, vec![], new_owner));
        assert_eq!(sd_fail.add_signature(&keys).unwrap(), 0);
        assert!(sd.replace_with_other(sd_fail).is_err());
    }
}

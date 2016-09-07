// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use maidsafe_utilities::serialisation::serialise;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;
use data::DataIdentifier;
use error::RoutingError;
use append_types::{AppendedData, Filter};

/// Maximum allowed size for a public appendable data to grow to
pub const MAX_PUB_APPENDABLE_DATA_SIZE_IN_BYTES: usize = 102400;

/// Public appendable data.
///
/// These types may be stored unsigned with previous and current owner keys
/// set to the same keys. Updates require a signature to validate.
///
/// Data can be appended by any key that is not excluded by the filter.
// TODO: Deduplicate the logic shared with `PrivAppendableData` and `StructuredData`.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub struct PubAppendableData {
    /// The name of this data chunk.
    pub name: XorName,
    /// The version, i.e. the number of times this has been updated by a `Post` request.
    pub version: u64,
    /// The keys of the current owners that have the right to modify this data.
    pub current_owner_keys: Vec<PublicKey>,
    /// The keys of the owners of the chunk's previous version.
    pub previous_owner_keys: Vec<PublicKey>,
    /// The filter defining who is allowed to append items.
    pub filter: Filter,
    /// A collection of previously deleted data items.
    pub deleted_data: BTreeSet<AppendedData>,
    /// The signatures of the above fields by the previous owners, confirming the last update.
    pub previous_owner_signatures: Vec<Signature>,
    /// The collection of appended data items. These are not signed by the owners, as they change
    /// even between `Post`s.
    pub data: BTreeSet<AppendedData>,
}

impl PubAppendableData {
    /// Creates a new `PubAppendableData` signed with `signing_key`.
    pub fn new(name: XorName,
               version: u64,
               current_owner_keys: Vec<PublicKey>,
               previous_owner_keys: Vec<PublicKey>,
               filter: Filter,
               signing_key: Option<&SecretKey>)
               -> Result<PubAppendableData, RoutingError> {

        let mut pub_appendable_data = PubAppendableData {
            name: name,
            version: version,
            current_owner_keys: current_owner_keys,
            previous_owner_keys: previous_owner_keys,
            filter: filter,
            deleted_data: BTreeSet::new(),
            previous_owner_signatures: vec![],
            data: BTreeSet::new(),
        };

        if let Some(key) = signing_key {
            let _ = try!(pub_appendable_data.add_signature(key));
        }
        Ok(pub_appendable_data)
    }

    /// Updates this data item with the given updated version if the update is valid, otherwise
    /// returns an error.
    ///
    /// This allows types to be created and `previous_owner_signatures` added one by one.
    /// To transfer ownership, the current owner signs over the data; the previous owners field
    /// must have the previous owners of `version - 1` as the current owners of that last version.
    ///
    /// The `data` will contain the union of the data items, _excluding_ the `deleted_data` as
    /// given in the update.
    pub fn update_with_other(&mut self, other: PubAppendableData) -> Result<(), RoutingError> {
        try!(self.validate_self_against_successor(&other));

        self.name = other.name;
        self.version = other.version;
        self.previous_owner_keys = other.previous_owner_keys;
        self.current_owner_keys = other.current_owner_keys;
        self.filter = other.filter;
        self.deleted_data = other.deleted_data;
        self.previous_owner_signatures = other.previous_owner_signatures;
        self.data.extend(other.data);
        for ad in &self.deleted_data {
            let _ = self.data.remove(ad);
        }
        Ok(())
    }

    /// Deletes the given data item and returns `true` if it was there.
    pub fn delete(&mut self, appended_data: AppendedData) -> bool {
        let removed = self.data.remove(&appended_data);
        let _ = self.deleted_data.insert(appended_data);
        removed
    }

    /// Inserts the given data item, or returns `false` if it cannot be added because it has
    /// recently been deleted.
    pub fn append(&mut self, appended_data: AppendedData) -> bool {
        if match self.filter {
            Filter::WhiteList(ref white_list) => !white_list.contains(&appended_data.sign_key),
            Filter::BlackList(ref black_list) => black_list.contains(&appended_data.sign_key),
        } || self.deleted_data.contains(&appended_data) {
            return false;
        }
        let _ = self.data.insert(appended_data);
        true
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::PubAppendable(self.name)
    }

    /// Verifies that `other` is a valid update for `self`; returns an error otherwise.
    ///
    /// An update is valid if it doesn't change the name, increases the version by 1 and is signed
    /// by (more than 50% of) the owners.
    ///
    /// In case of an ownership transfer, the `previous_owner_keys` in `other` must match the
    /// `current_owner_keys` in `self`.
    pub fn validate_self_against_successor(&self,
                                           other: &PubAppendableData)
                                           -> Result<(), RoutingError> {
        let owner_keys_to_match = if other.previous_owner_keys.is_empty() {
            &other.current_owner_keys
        } else {
            &other.previous_owner_keys
        };

        if other.name != self.name || other.version != self.version + 1 ||
           *owner_keys_to_match != self.current_owner_keys {
            return Err(RoutingError::UnknownMessageType);
        }
        other.verify_previous_owner_signatures(owner_keys_to_match)
    }

    /// Confirms *unique and valid* owner_signatures are more than 50% of total owners.
    fn verify_previous_owner_signatures(&self,
                                        owner_keys: &[PublicKey])
                                        -> Result<(), RoutingError> {
        // Refuse any duplicate previous_owner_signatures (people can have many owner keys)
        // Any duplicates invalidates this type.
        for (i, sig) in self.previous_owner_signatures.iter().enumerate() {
            for sig_check in &self.previous_owner_signatures[..i] {
                if sig == sig_check {
                    return Err(RoutingError::DuplicateSignatures);
                }
            }
        }

        // Refuse when not enough previous_owner_signatures found
        if self.previous_owner_signatures.len() < (owner_keys.len() + 1) / 2 {
            return Err(RoutingError::NotEnoughSignatures);
        }

        let data = try!(self.data_to_sign());
        // Count valid previous_owner_signatures and refuse if quantity is not enough

        let check_all_keys = |&sig| {
            owner_keys.iter()
                .any(|pub_key| sign::verify_detached(&sig, &data, pub_key))
        };

        if self.previous_owner_signatures
            .iter()
            .filter(|&sig| check_all_keys(sig))
            .count() < (owner_keys.len() / 2 + owner_keys.len() % 2) {
            return Err(RoutingError::NotEnoughSignatures);
        }
        Ok(())
    }

    fn data_to_sign(&self) -> Result<Vec<u8>, RoutingError> {
        // Seems overkill to use serialisation here, but done to ensure cross platform signature
        // handling is OK
        let sd = SerialisablePubAppendableData {
            name: self.name,
            previous_owner_keys: &self.previous_owner_keys,
            current_owner_keys: &self.current_owner_keys,
            version: self.version.to_string().as_bytes().to_vec(),
            filter: &self.filter,
            deleted_data: &self.deleted_data,
        };

        serialise(&sd).map_err(From::from)
    }

    /// Adds a signature with the given `secret_key` to the `previous_owner_signatures` and returns
    /// the number of signatures that are still required. If more than 50% of the previous owners
    /// have signed, 0 is returned and validation is complete.
    pub fn add_signature(&mut self, secret_key: &SecretKey) -> Result<usize, RoutingError> {
        let data = try!(self.data_to_sign());
        let sig = sign::sign_detached(&data, secret_key);
        self.previous_owner_signatures.push(sig);
        let owner_keys = if self.previous_owner_keys.is_empty() {
            &self.current_owner_keys
        } else {
            &self.previous_owner_keys
        };
        Ok(((owner_keys.len() / 2) + 1).saturating_sub(self.previous_owner_signatures.len()))
    }

    /// Overwrite any existing signatures with the new signatures provided.
    pub fn replace_signatures(&mut self, new_signatures: Vec<Signature>) {
        self.previous_owner_signatures = new_signatures;
    }

    /// Get the data
    pub fn get_data(&self) -> &BTreeSet<AppendedData> {
        &self.data
    }

    /// Get the previous owner keys
    pub fn get_previous_owner_keys(&self) -> &Vec<PublicKey> {
        &self.previous_owner_keys
    }

    /// Get the version
    pub fn get_version(&self) -> u64 {
        self.version
    }

    /// Get the current owner keys
    pub fn get_owner_keys(&self) -> &Vec<PublicKey> {
        &self.current_owner_keys
    }

    /// Get previous owner signatures
    pub fn get_previous_owner_signatures(&self) -> &Vec<Signature> {
        &self.previous_owner_signatures
    }
}

impl Debug for PubAppendableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let previous_owner_keys: Vec<String> = self.previous_owner_keys
            .iter()
            .map(|pub_key| ::utils::format_binary_array(&pub_key.0))
            .collect();
        let current_owner_keys: Vec<String> = self.current_owner_keys
            .iter()
            .map(|pub_key| ::utils::format_binary_array(&pub_key.0))
            .collect();
        let previous_owner_signatures: Vec<String> = self.previous_owner_signatures
            .iter()
            .map(|signature| ::utils::format_binary_array(&signature.0[..]))
            .collect();
        write!(formatter,
               "PubAppendableData {{ name: {}, previous_owner_keys: {:?}, \
                version: {}, current_owner_keys: {:?}, previous_owner_signatures: {:?} }}",
               self.name(),
               previous_owner_keys,
               self.version,
               current_owner_keys,
               previous_owner_signatures)
        // TODO(afck): Print `data` and `deleted_data`.
    }
}

#[derive(RustcEncodable)]
struct SerialisablePubAppendableData<'a> {
    name: XorName,
    previous_owner_keys: &'a [PublicKey],
    current_owner_keys: &'a [PublicKey],
    version: Vec<u8>,
    filter: &'a Filter,
    deleted_data: &'a BTreeSet<AppendedData>,
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;

    use rust_sodium::crypto::sign;
    use xor_name::XorName;
    use append_types::Filter;

    #[test]
    fn single_owner() {
        let keys = sign::gen_keypair();
        let owner_keys = vec![keys.0];

        match PubAppendableData::new(rand::random(),
                                     0,
                                     owner_keys.clone(),
                                     vec![],
                                     Filter::white_list(None),
                                     Some(&keys.1)) {
            Ok(pub_appendable_data) => {
                assert_eq!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn single_owner_unsigned() {
        let keys = sign::gen_keypair();
        let owner_keys = vec![keys.0];

        match PubAppendableData::new(rand::random(),
                                     0,
                                     vec![],
                                     owner_keys.clone(),
                                     Filter::white_list(None),
                                     None) {
            Ok(pub_appendable_data) => {
                assert_eq!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn single_owner_other_signing_key() {
        let keys = sign::gen_keypair();
        let owner_keys = vec![keys.0];
        let other_keys = sign::gen_keypair();

        match PubAppendableData::new(rand::random(),
                                     0,
                                     owner_keys.clone(),
                                     vec![],
                                     Filter::white_list(None),
                                     Some(&other_keys.1)) {
            Ok(pub_appendable_data) => {
                assert_eq!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn single_owner_other_signature() {
        let keys = sign::gen_keypair();
        let owner_keys = vec![keys.0];
        let other_keys = sign::gen_keypair();

        match PubAppendableData::new(rand::random(),
                                     0,
                                     vec![],
                                     owner_keys.clone(),
                                     Filter::white_list(None),
                                     None) {
            Ok(mut pub_appendable_data) => {
                assert_eq!(pub_appendable_data.add_signature(&other_keys.1).ok(),
                           Some(0));
                assert_eq!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn three_owners() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();

        let owner_keys = vec![keys1.0, keys2.0, keys3.0];

        match PubAppendableData::new(rand::random(),
                                     0,
                                     owner_keys.clone(),
                                     vec![],
                                     Filter::white_list(None),
                                     None) {
            Ok(mut pub_appendable_data) => {
                // After one signature, one more is required to reach majority.
                assert_eq!(unwrap!(pub_appendable_data.add_signature(&keys1.1)), 1);
                assert!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).is_err());
                // Two out of three is enough.
                assert_eq!(unwrap!(pub_appendable_data.add_signature(&keys2.1)), 0);
                assert!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Three out of three is also fine.
                assert_eq!(unwrap!(pub_appendable_data.add_signature(&keys3.1)), 0);
                assert!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn four_owners() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();
        let keys4 = sign::gen_keypair();

        let owner_keys = vec![keys1.0, keys2.0, keys3.0, keys4.0];

        match PubAppendableData::new(rand::random(),
                                     0,
                                     owner_keys.clone(),
                                     vec![],
                                     Filter::white_list(None),
                                     Some(&keys1.1)) {
            Ok(mut pub_appendable_data) => {
                // Two signatures are not enough because they don't have a strict majority.
                assert_eq!(unwrap!(pub_appendable_data.add_signature(&keys2.1)), 1);
                assert!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Three out of four is enough.
                assert_eq!(unwrap!(pub_appendable_data.add_signature(&keys3.1)), 0);
                assert!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Four out of four is also fine.
                assert_eq!(unwrap!(pub_appendable_data.add_signature(&keys4.1)), 0);
                assert!(pub_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn transfer_owners() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();
        let new_owner = sign::gen_keypair();

        let identifier: XorName = rand::random();

        // Owned by keys1 keys2 and keys3
        match PubAppendableData::new(identifier,
                                     0,
                                     vec![keys1.0, keys2.0, keys3.0],
                                     vec![],
                                     Filter::white_list(None),
                                     Some(&keys1.1)) {
            Ok(mut orig_pub_appendable_data) => {
                assert_eq!(orig_pub_appendable_data.add_signature(&keys2.1).ok(),
                           Some(0));
                // Transfer ownership and update to new owner
                match PubAppendableData::new(identifier,
                                             1,
                                             vec![new_owner.0],
                                             vec![keys1.0, keys2.0, keys3.0],
                                             Filter::white_list(None),
                                             Some(&keys1.1)) {
                    Ok(mut new_pub_appendable_data) => {
                        assert_eq!(new_pub_appendable_data.add_signature(&keys2.1).ok(),
                                   Some(0));
                        match orig_pub_appendable_data.update_with_other(new_pub_appendable_data) {
                            Ok(()) => (),
                            Err(e) => panic!("Error {:?}", e),
                        }
                        // transfer ownership back to keys1 only
                        match PubAppendableData::new(identifier,
                                                     2,
                                                     vec![keys1.0],
                                                     vec![new_owner.0],
                                                     Filter::white_list(None),
                                                     Some(&new_owner.1)) {
                            Ok(another_new_pub_appendable_data) => {
                                match orig_pub_appendable_data.update_with_other(
                                        another_new_pub_appendable_data) {
                                    Ok(()) => (),
                                    Err(e) => panic!("Error {:?}", e),
                                }
                            }
                            Err(error) => panic!("Error: {:?}", error),
                        }
                    }
                    Err(error) => panic!("Error: {:?}", error),
                }
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }
}

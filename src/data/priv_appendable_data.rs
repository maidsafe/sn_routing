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

use maidsafe_utilities::serialisation::{deserialise, serialise, serialised_size};
use rust_sodium::crypto::{box_, sealedbox};
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use rustc_serialize::{Decodable, Decoder};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;
use super::{AppendWrapper, AppendedData, DataIdentifier, Filter, NO_OWNER_PUB_KEY,
            verify_signatures};
use error::RoutingError;

/// Maximum allowed size for a private appendable data to grow to
pub const MAX_PRIV_APPENDABLE_DATA_SIZE_IN_BYTES: u64 = 102400;

/// Maximum size of a serialised `PrivAppendedData` item, in bytes.
pub const MAX_PRIV_APPENDED_DATA_BYTES: usize = 220;

/// A private appended data item: an encrypted `AppendedData`.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcEncodable, Debug)]
pub struct PrivAppendedData(pub Vec<u8>);

impl PrivAppendedData {
    /// Creates a new `PrivAppendedData` encrypted with `encrypting_key`.
    pub fn new(appended_data: &AppendedData,
               encrypt_pub_key: &box_::PublicKey)
               -> Result<PrivAppendedData, RoutingError> {
        let encoded_appended_data = try!(serialise(&appended_data));
        let encrypted_appended_data = sealedbox::seal(&encoded_appended_data, encrypt_pub_key);
        Ok(PrivAppendedData(encrypted_appended_data))
    }

    /// Returns `AppendedData` decrypted from this item.
    pub fn open(&self,
                pub_key: &box_::PublicKey,
                secret_key: &box_::SecretKey)
                -> Result<AppendedData, RoutingError> {
        let decipher_result = try!(sealedbox::open(&self.0, pub_key, secret_key)
            .map_err(|()| RoutingError::AsymmetricDecryptionFailure));
        Ok(try!(deserialise(&decipher_result)))
    }
}

impl Decodable for PrivAppendedData {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let data: Vec<u8> = try!(Decodable::decode(d));
        if data.len() > MAX_PRIV_APPENDED_DATA_BYTES {
            return Err(d.error("wrong private appended data size"));
        }
        Ok(PrivAppendedData(data))
    }
}

/// Private appendable data.
///
/// These types may be stored unsigned with previous and current owner keys
/// set to the same keys. Updates require a signature to validate.
///
/// Data can be appended by any key that is not excluded by the filter.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub struct PrivAppendableData {
    /// The name of this data chunk.
    pub name: XorName,
    /// The version, i.e. the number of times this has been updated by a `Post` request.
    pub version: u64,
    /// The filter defining who is allowed to append items.
    pub filter: Filter,
    /// The key to use for encrypting appended data items.
    pub encrypt_key: box_::PublicKey,
    /// A collection of previously deleted data items.
    pub deleted_data: BTreeSet<PrivAppendedData>,
    /// The pub_keys of the current owners of the chunk's.
    pub owners: BTreeSet<PublicKey>,
    /// The pub_keys and signatures of the owners of the chunk's current version.
    pub signatures: BTreeMap<PublicKey, Signature>,
    /// The collection of appended data items. These are not signed by the owners, as they change
    /// even between `Post`s.
    pub data: BTreeSet<PrivAppendedData>, // Unsigned
}

impl PrivAppendableData {
    /// Creates a new `PubAppendableData` signed with `signing_key`.
    #[cfg_attr(feature="clippy", allow(too_many_arguments))]
    pub fn new(name: XorName,
               version: u64,
               owners: BTreeSet<PublicKey>,
               deleted_data: BTreeSet<PrivAppendedData>,
               filter: Filter,
               encrypt_key: box_::PublicKey)
               -> Result<PrivAppendableData, RoutingError> {
        if owners.len() > 1 {
            return Err(RoutingError::InvalidOwners);
        }

        Ok(PrivAppendableData {
            name: name,
            version: version,
            filter: filter,
            encrypt_key: encrypt_key,
            deleted_data: deleted_data,
            owners: owners,
            signatures: BTreeMap::new(),
            data: BTreeSet::new(),
        })
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
    pub fn update_with_other(&mut self, other: PrivAppendableData) -> Result<(), RoutingError> {
        try!(self.validate_self_against_successor(&other));

        self.name = other.name;
        self.version = other.version;
        self.filter = other.filter;
        self.encrypt_key = other.encrypt_key;
        self.deleted_data = other.deleted_data;
        self.signatures = other.signatures;
        self.owners = other.owners;
        self.data.extend(other.data);
        for ad in &self.deleted_data {
            let _ = self.data.remove(ad);
        }
        Ok(())
    }

    /// Verifies that `other` is a valid update for `self`; returns an error otherwise.
    ///
    /// An update is valid if it doesn't change the name, increases the version by 1 and is signed
    /// by (more than 50% of) the owners.
    ///
    /// In case of an ownership transfer, the other's `signatures` are from `owners` in `self`.
    pub fn validate_self_against_successor(&self,
                                           other: &PrivAppendableData)
                                           -> Result<(), RoutingError> {
        if other.owners.len() > 1 ||
           other.signatures.len() > 1 ||
           self.owners.contains(&NO_OWNER_PUB_KEY) {
            return Err(RoutingError::InvalidOwners);
        }

        if other.name != self.name || other.version != self.version + 1 {
            return Err(RoutingError::UnknownMessageType);
        }
        let data = try!(other.data_to_sign());
        verify_signatures(&self.owners, &data, &other.signatures)
    }

    /// Inserts the given data item, or returns `false` if it cannot be added because it has
    /// recently been deleted.
    pub fn append(&mut self, priv_appended_data: PrivAppendedData, sign_key: &PublicKey) -> bool {
        if match self.filter {
            Filter::WhiteList(ref white_list) => !white_list.contains(sign_key),
            Filter::BlackList(ref black_list) => black_list.contains(sign_key),
        } || self.deleted_data.contains(&priv_appended_data) {
            return false;
        }
        let _ = self.data.insert(priv_appended_data);
        true
    }

    /// Inserts the given wrapper item, or returns `false` if cannot
    pub fn apply_wrapper(&mut self, wrapper: AppendWrapper) -> bool {
        if !wrapper.verify_signature() || &self.version != wrapper.version() {
            return false;
        }
        match wrapper.priv_appended_data() {
            None => false,
            Some(priv_appended_data) => self.append(priv_appended_data.clone(), wrapper.sign_key()),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::PrivAppendable(self.name)
    }

    fn data_to_sign(&self) -> Result<Vec<u8>, RoutingError> {
        // Seems overkill to use serialisation here, but done to ensure cross platform signature
        // handling is OK
        let sd = SerialisablePrivAppendableData {
            name: self.name,
            version: self.version.to_string().as_bytes().to_vec(),
            filter: &self.filter,
            encrypt_key: &self.encrypt_key,
            owners: &self.owners,
            deleted_data: &self.deleted_data,
        };

        serialise(&sd).map_err(From::from)
    }

    /// Adds a signature with the given `keys.1` to the `signatures` and returns
    /// the number of signatures that are still required. If more than 50% of the owners
    /// have signed, 0 is returned and validation is complete.
    pub fn add_signature(&mut self, keys: (&PublicKey, &SecretKey)) -> Result<usize, RoutingError> {
        if !self.signatures.is_empty() {
            return Err(RoutingError::InvalidOwners);
        }
        let data = try!(self.data_to_sign());
        let sig = sign::sign_detached(&data, keys.1);
        let _ = self.signatures.insert(*keys.0, sig);
        Ok(((self.owners.len() / 2) + 1).saturating_sub(self.signatures.len()))
    }

    /// Overwrite any existing signatures with the new signatures provided.
    pub fn replace_signatures(&mut self, new_signatures: BTreeMap<PublicKey, Signature>) {
        self.signatures = new_signatures;
    }

    /// Get the data
    pub fn get_data(&self) -> &BTreeSet<PrivAppendedData> {
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
        serialised_size(self) <= MAX_PRIV_APPENDABLE_DATA_SIZE_IN_BYTES
    }
}

impl Debug for PrivAppendableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let previous_owner_keys: Vec<String> = self.signatures
            .iter()
            .map(|(pub_key, _)| ::utils::format_binary_array(&pub_key.0))
            .collect();
        let current_owner_keys: Vec<String> = self.owners
            .iter()
            .map(|pub_key| ::utils::format_binary_array(&pub_key.0))
            .collect();
        let previous_owner_signatures: Vec<String> = self.signatures
            .iter()
            .map(|(_, sig)| ::utils::format_binary_array(&sig.0[..]))
            .collect();
        write!(formatter,
               "PrivAppendableData {{ name: {}, previous_owner_keys: {:?}, \
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
struct SerialisablePrivAppendableData<'a> {
    name: XorName,
    version: Vec<u8>,
    filter: &'a Filter,
    encrypt_key: &'a box_::PublicKey,
    owners: &'a BTreeSet<PublicKey>,
    deleted_data: &'a BTreeSet<PrivAppendedData>,
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;

    use std::collections::BTreeSet;
    use maidsafe_utilities::serialisation::serialise;
    use rust_sodium::crypto::{box_, sign};
    use xor_name::XorName;
    use data::{AppendWrapper, AppendedData, DataIdentifier, Filter};

    #[test]
    fn serialised_priv_appended_data_size() {
        let keys = sign::gen_keypair();
        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let appended_data = unwrap!(AppendedData::new(pointer, keys.0, &keys.1));
        let encrypt_keys = box_::gen_keypair();
        let priv_appended_data = unwrap!(PrivAppendedData::new(&appended_data, &encrypt_keys.0));
        let serialised = unwrap!(serialise(&priv_appended_data));
        assert_eq!(MAX_PRIV_APPENDED_DATA_BYTES, serialised.len());
    }

    #[test]
    fn single_owner() {
        let keys = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let owner_keys = vec![keys.0];

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      owner_keys.clone(),
                                      vec![],
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      Some(&keys.1)) {
            Ok(priv_appendable_data) => {
                assert_eq!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
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
        let encrypt_keys = box_::gen_keypair();

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      vec![],
                                      owner_keys.clone(),
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      None) {
            Ok(priv_appendable_data) => {
                assert_eq!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
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
        let encrypt_keys = box_::gen_keypair();

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      owner_keys.clone(),
                                      vec![],
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      Some(&other_keys.1)) {
            Ok(priv_appendable_data) => {
                assert_eq!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
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
        let encrypt_keys = box_::gen_keypair();

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      vec![],
                                      owner_keys.clone(),
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      None) {
            Ok(mut priv_appendable_data) => {
                assert_eq!(priv_appendable_data.add_signature(&other_keys.1).ok(),
                           Some(0));
                assert_eq!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    // TODO: this test is disabled as the feature of multi-sig is disabled
    #[ignore]
    #[test]
    fn three_owners() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();

        let owner_keys = vec![keys1.0, keys2.0, keys3.0];

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      owner_keys.clone(),
                                      vec![],
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      None) {
            Ok(mut priv_appendable_data) => {
                // After one signature, one more is required to reach majority.
                assert_eq!(unwrap!(priv_appendable_data.add_signature(&keys1.1)), 1);
                assert!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys)
                    .is_err());
                // Two out of three is enough.
                assert_eq!(unwrap!(priv_appendable_data.add_signature(&keys2.1)), 0);
                assert!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Three out of three is also fine.
                assert_eq!(unwrap!(priv_appendable_data.add_signature(&keys3.1)), 0);
                assert!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    // TODO: this test is disabled as the feature of multi-sig is disabled
    #[ignore]
    #[test]
    fn four_owners() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();
        let keys4 = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();

        let owner_keys = vec![keys1.0, keys2.0, keys3.0, keys4.0];

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      owner_keys.clone(),
                                      vec![],
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      Some(&keys1.1)) {
            Ok(mut priv_appendable_data) => {
                // Two signatures are not enough because they don't have a strict majority.
                assert_eq!(unwrap!(priv_appendable_data.add_signature(&keys2.1)), 1);
                assert!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Three out of four is enough.
                assert_eq!(unwrap!(priv_appendable_data.add_signature(&keys3.1)), 0);
                assert!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Four out of four is also fine.
                assert_eq!(unwrap!(priv_appendable_data.add_signature(&keys4.1)), 0);
                assert!(priv_appendable_data.verify_previous_owner_signatures(&owner_keys).is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    // TODO: this test is disabled as the feature of multi-sig is disabled
    #[ignore]
    #[test]
    fn transfer_owner_attack() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let new_owner = sign::gen_keypair();
        let attacker = sign::gen_keypair();

        let name: XorName = rand::random();
        let owner_keys = vec![keys1.0, keys2.0, keys3.0];
        let attacker_keys = vec![keys1.0, keys2.0, keys3.0, attacker.0];

        let mut orig_priv_appendable_data = unwrap!(PrivAppendableData::new(name,
                                      0,
                                      owner_keys.clone(),
                                      vec![],
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      Some(&keys1.1)));
        assert_eq!(orig_priv_appendable_data.add_signature(&keys2.1).ok(),
                   Some(0));

        let mut new_priv_appendable_data = unwrap!(PrivAppendableData::new(name,
                                              1,
                                              vec![new_owner.0],
                                              owner_keys.clone(),
                                              BTreeSet::new(),
                                              Filter::white_list(None),
                                              encrypt_keys.0,
                                              Some(&keys1.1)));
        assert_eq!(new_priv_appendable_data.add_signature(&attacker.1).ok(),
                   Some(0));
        assert!(new_priv_appendable_data.verify_previous_owner_signatures(&owner_keys).is_err());
        assert!(new_priv_appendable_data.verify_previous_owner_signatures(&attacker_keys).is_ok());
        // Shall throw error of NotEnoughSignatures
        assert!(orig_priv_appendable_data.update_with_other(new_priv_appendable_data.clone())
            .is_err());

        assert_eq!(new_priv_appendable_data.add_signature(&attacker.1).ok(),
                   Some(0));
        // Shall throw error of DuplicateSignatures
        assert!(new_priv_appendable_data.verify_previous_owner_signatures(&attacker_keys).is_err());
    }

    // TODO: this test is disabled as the feature of multi-sig is disabled
    #[ignore]
    #[test]
    fn update_with_wrong_info() {
        let keys1 = sign::gen_keypair();
        let keys2 = sign::gen_keypair();
        let keys3 = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let new_owner = sign::gen_keypair();

        let name: XorName = rand::random();
        let owner_keys = vec![keys1.0, keys2.0, keys3.0];

        let mut orig_priv_appendable_data = unwrap!(PrivAppendableData::new(name,
                                      0,
                                      owner_keys.clone(),
                                      vec![],
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0,
                                      Some(&keys1.1)));
        assert_eq!(orig_priv_appendable_data.add_signature(&keys2.1).ok(),
                   Some(0));

        // Update with wrong version
        let mut wrong_version = unwrap!(PrivAppendableData::new(name,
                                                                2,
                                                                vec![new_owner.0],
                                                                owner_keys.clone(),
                                                                BTreeSet::new(),
                                                                Filter::white_list(None),
                                                                encrypt_keys.0,
                                                                Some(&keys1.1)));
        assert_eq!(wrong_version.add_signature(&keys2.1).ok(), Some(0));
        // Shall throw error of UnknownMessageType
        assert!(orig_priv_appendable_data.update_with_other(wrong_version).is_err());

        // Update with owner_keys in different order
        let mut wrong_order = unwrap!(PrivAppendableData::new(name,
                                                              1,
                                                              vec![new_owner.0],
                                                              vec![keys3.0, keys2.0, keys1.0],
                                                              BTreeSet::new(),
                                                              Filter::white_list(None),
                                                              encrypt_keys.0,
                                                              Some(&keys1.1)));
        assert_eq!(wrong_order.add_signature(&keys2.1).ok(), Some(0));
        // Shall throw error of UnknownMessageType
        assert!(orig_priv_appendable_data.update_with_other(wrong_order).is_err());

        // Update with wrong identifier
        let mut wrong_name = unwrap!(PrivAppendableData::new(rand::random(),
                                                             1,
                                                             vec![new_owner.0],
                                                             owner_keys,
                                                             BTreeSet::new(),
                                                             Filter::white_list(None),
                                                             encrypt_keys.0,
                                                             Some(&keys1.1)));
        assert_eq!(wrong_name.add_signature(&keys2.1).ok(), Some(0));
        // Shall throw error of UnknownMessageType
        assert!(orig_priv_appendable_data.update_with_other(wrong_name).is_err());
    }

    #[test]
    fn appending_with_white_list() {
        let keys = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let owner_keys = vec![keys.0];

        let white_key = sign::gen_keypair();
        let black_key = sign::gen_keypair();

        let mut priv_appendable_data = unwrap!(PrivAppendableData::new(rand::random(),
                                            0,
                                            owner_keys.clone(),
                                            vec![],
                                            BTreeSet::new(),
                                            Filter::white_list(vec![white_key.0]),
                                            encrypt_keys.0,
                                            Some(&keys.1)));

        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let appended_data = unwrap!(AppendedData::new(pointer, keys.0, &keys.1));
        let priv_appended_data = unwrap!(PrivAppendedData::new(&appended_data, &encrypt_keys.0));

        assert!(!priv_appendable_data.append(priv_appended_data.clone(), &black_key.0));
        assert!(priv_appendable_data.append(priv_appended_data, &white_key.0));
    }

    #[test]
    fn appending_with_black_list() {
        let keys = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let owner_keys = vec![keys.0];

        let white_key = sign::gen_keypair();
        let black_key = sign::gen_keypair();

        let mut priv_appendable_data = unwrap!(PrivAppendableData::new(rand::random(),
                                            0,
                                            owner_keys.clone(),
                                            vec![],
                                            BTreeSet::new(),
                                            Filter::black_list(vec![black_key.0]),
                                            encrypt_keys.0,
                                            Some(&keys.1)));

        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let appended_data = unwrap!(AppendedData::new(pointer, keys.0, &keys.1));
        let priv_appended_data = unwrap!(PrivAppendedData::new(&appended_data, &encrypt_keys.0));

        assert!(!priv_appendable_data.append(priv_appended_data.clone(), &black_key.0));
        assert!(priv_appendable_data.append(priv_appended_data, &white_key.0));
    }

    #[test]
    fn apply_wrapper() {
        let keys = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let name: XorName = rand::random();

        let mut priv_appendable_data = unwrap!(PrivAppendableData::new(name,
                                                                       0,
                                                                       vec![keys.0],
                                                                       vec![],
                                                                       BTreeSet::new(),
                                                                       Filter::black_list(None),
                                                                       encrypt_keys.0,
                                                                       Some(&keys.1)));

        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let appended_data = unwrap!(AppendedData::new(pointer, keys.0, &keys.1));
        let priv_appended_data = unwrap!(PrivAppendedData::new(&appended_data, &encrypt_keys.0));

        // apply correct wrapper
        let append_wrapper = unwrap!(AppendWrapper::new_priv(name,
                                                             priv_appended_data.clone(),
                                                             (&keys.0, &keys.1),
                                                             0));
        assert!(priv_appendable_data.apply_wrapper(append_wrapper));

        // apply wrapper with incorrect version
        let append_wrapper =
            unwrap!(AppendWrapper::new_priv(name, priv_appended_data, (&keys.0, &keys.1), 1));
        assert!(!priv_appendable_data.apply_wrapper(append_wrapper));
    }
}

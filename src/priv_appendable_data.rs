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

use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sealedbox};
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use rustc_serialize::{Decoder, Decodable};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;
use data::DataIdentifier;
use error::RoutingError;
use append_types::{AppendedData, AppendWrapper, Filter};

/// Maximum allowed size for a private appendable data to grow to
pub const MAX_PRIV_APPENDABLE_DATA_SIZE_IN_BYTES: usize = 102400;

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
    /// The keys of the current owners that have the right to modify this data.
    pub current_owner_keys: Vec<PublicKey>,
    /// The keys of the owners of the chunk's previous version.
    pub previous_owner_keys: Vec<PublicKey>,
    /// The filter defining who is allowed to append items.
    pub filter: Filter,
    /// The key to use for encrypting appended data items.
    pub encrypt_key: box_::PublicKey,
    /// A collection of previously deleted data items.
    pub deleted_data: BTreeSet<PrivAppendedData>,
    /// The signatures of the above fields by the previous owners, confirming the last update.
    pub previous_owner_signatures: Vec<Signature>, // All the above fields
    /// The collection of appended data items. These are not signed by the owners, as they change
    /// even between `Post`s.
    pub data: BTreeSet<PrivAppendedData>, // Unsigned
}

impl PrivAppendableData {
    /// Creates a new `PubAppendableData` signed with `signing_key`.
    #[cfg_attr(feature="clippy", allow(too_many_arguments))]
    pub fn new(name: XorName,
               version: u64,
               current_owner_keys: Vec<PublicKey>,
               previous_owner_keys: Vec<PublicKey>,
               deleted_data: BTreeSet<PrivAppendedData>,
               filter: Filter,
               encrypt_key: box_::PublicKey,
               signing_key: Option<&SecretKey>)
               -> Result<PrivAppendableData, RoutingError> {

        let mut priv_appendable_data = PrivAppendableData {
            name: name,
            version: version,
            current_owner_keys: current_owner_keys,
            previous_owner_keys: previous_owner_keys,
            filter: filter,
            encrypt_key: encrypt_key,
            deleted_data: deleted_data,
            previous_owner_signatures: vec![],
            data: BTreeSet::new(),
        };

        if let Some(key) = signing_key {
            let _ = try!(priv_appendable_data.add_signature(key));
        }
        Ok(priv_appendable_data)
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
        self.previous_owner_keys = other.previous_owner_keys;
        self.current_owner_keys = other.current_owner_keys;
        self.filter = other.filter;
        self.encrypt_key = other.encrypt_key;
        self.deleted_data = other.deleted_data;
        self.previous_owner_signatures = other.previous_owner_signatures;
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
    /// In case of an ownership transfer, the `previous_owner_keys` in `other` must match the
    /// `current_owner_keys` in `self`.
    pub fn validate_self_against_successor(&self,
                                           other: &PrivAppendableData)
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
        if !wrapper.verify_signature() && &self.version != wrapper.version() {
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

    /// Confirms *unique and valid* owner_signatures are more than 50% of total owners.
    #[allow(unused)]
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
        let sd = SerialisablePrivAppendableData {
            name: self.name,
            previous_owner_keys: &self.previous_owner_keys,
            current_owner_keys: &self.current_owner_keys,
            version: self.version.to_string().as_bytes().to_vec(),
            filter: &self.filter,
            encrypt_key: &self.encrypt_key,
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
    pub fn get_data(&self) -> &BTreeSet<PrivAppendedData> {
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

impl Debug for PrivAppendableData {
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
    previous_owner_keys: &'a [PublicKey],
    current_owner_keys: &'a [PublicKey],
    version: Vec<u8>,
    filter: &'a Filter,
    encrypt_key: &'a box_::PublicKey,
    deleted_data: &'a BTreeSet<PrivAppendedData>,
}

#[cfg(test)]
mod test {
    extern crate rand;
    use super::*;

    use std::collections::BTreeSet;
    use data::DataIdentifier;
    use maidsafe_utilities::serialisation::serialise;
    use rust_sodium::crypto::{box_, sign};
    use append_types::{AppendedData, Filter};

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
}

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
use rust_sodium::crypto::box_;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;
use data::DataIdentifier;
use error::RoutingError;
use append_types::{AppendedData, Filter};

/// Maximum allowed size for a private appendable data to grow to
pub const MAX_PRIV_APPENDABLE_DATA_SIZE_IN_BYTES: usize = 102400;

/// Size of a serialised priv_appended_data item.
pub const SERIALISED_PRIV_APPENDED_DATA_SIZE: usize = 260;

/// A private appended data item.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable, Debug)]
pub struct PrivAppendedData {
    pub encrypt_key: box_::PublicKey, // Recommended to be a part of a throwaway keypair
    pub nonce: box_::Nonce,
    pub encrypted_appended_data: Vec<u8>, // Encrypted AppendedData
}

impl PrivAppendedData {
    /// Creates a new `PrivAppendedData` encrypted with `encrypting_key`.
    pub fn new(appended_data: &AppendedData,
               encrypt_pub_key: &box_::PublicKey,
               encrypt_secret_key: &box_::SecretKey)
               -> Result<PrivAppendedData, RoutingError> {
        let encoded_appended_data = try!(serialise(&appended_data));
        let nonce = box_::gen_nonce();
        let encrypted_appended_data = box_::seal(&encoded_appended_data,
                                                 &nonce,
                                                 encrypt_pub_key,
                                                 encrypt_secret_key);
        Ok(PrivAppendedData {
            encrypt_key: *encrypt_pub_key,
            nonce: nonce,
            encrypted_appended_data: encrypted_appended_data,
        })
    }

    /// Returns `AppendedData` decrypted from this item.
    pub fn open(&self, encrypt_secret_key: &box_::SecretKey) -> Result<AppendedData, RoutingError> {
        let decipher_result = try!(box_::open(&self.encrypted_appended_data,
                                              &self.nonce,
                                              &self.encrypt_key,
                                              encrypt_secret_key).map_err(|()|
                                                  RoutingError::AsymmetricDecryptionFailure));
        Ok(try!(deserialise(&decipher_result)))
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
    name: XorName,
    version: u64,
    current_owner_keys: Vec<PublicKey>,
    previous_owner_keys: Vec<PublicKey>,
    filter: Filter,
    encrypt_key: box_::PublicKey,
    deleted_data: BTreeSet<PrivAppendedData>,
    previous_owner_signatures: Vec<Signature>, // All the above fields
    data: BTreeSet<PrivAppendedData>, // Unsigned
}

impl PrivAppendableData {
    /// Creates a new `PubAppendableData` signed with `signing_key`.
    pub fn new(name: XorName,
               version: u64,
               current_owner_keys: Vec<PublicKey>,
               previous_owner_keys: Vec<PublicKey>,
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
            deleted_data: BTreeSet::new(),
            previous_owner_signatures: vec![],
            data: BTreeSet::new(),
        };

        if let Some(key) = signing_key {
            let _ = try!(priv_appendable_data.add_signature(key));
        }
        Ok(priv_appendable_data)
    }

    /// Deletes the given data item and returns `true` if it was there.
    pub fn delete(&mut self, appended_data: PrivAppendedData) -> bool {
        let removed = self.data.remove(&appended_data);
        if removed {
            let _ = self.deleted_data.insert(appended_data);
        }
        removed
    }

    /// Inserts the given data item, or returns `false` if it cannot be added because it has
    /// recently been deleted.
    pub fn append(&mut self,
                  priv_appended_data: PrivAppendedData,
                  encrypt_secret_key: &box_::SecretKey)
                  -> bool {
        if self.deleted_data.contains(&priv_appended_data) {
            return false;
        }
        let appended_data = match priv_appended_data.open(encrypt_secret_key) {
            Ok(appended_data) => appended_data,
            Err(_) => return false,
        };
        let signed_data = match serialise(&(appended_data.pointer(), appended_data.sign_key())) {
            Ok(result) => result,
            Err(_) => return false,
        };
        if sign::verify_detached(appended_data.signature(),
                                 &signed_data,
                                 appended_data.sign_key()) {
            match self.filter.clone() {
                Filter::WhiteList(white_list) => {
                    if !white_list.contains(appended_data.sign_key()) {
                        return false;
                    }
                }
                Filter::BlackList(black_list) => {
                    if black_list.contains(appended_data.sign_key()) {
                        return false;
                    }
                }
            }
        }
        let _ = self.data.insert(priv_appended_data);
        self.version += 1;
        true
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

    /// Return data size.
    pub fn payload_size(&self) -> usize {
        self.data.len() * SERIALISED_PRIV_APPENDED_DATA_SIZE
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
        let priv_appended_data = unwrap!(PrivAppendedData::new(&appended_data,
                                                               &encrypt_keys.0,
                                                               &encrypt_keys.1));
        let serialised = unwrap!(serialise(&priv_appended_data));
        assert_eq!(SERIALISED_PRIV_APPENDED_DATA_SIZE, serialised.len());
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
                                      Filter::WhiteList(vec![]),
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
                                      Filter::WhiteList(vec![]),
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
                                      Filter::WhiteList(vec![]),
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
                                      Filter::WhiteList(vec![]),
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
                                      Filter::WhiteList(vec![]),
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
                                      Filter::WhiteList(vec![]),
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
}

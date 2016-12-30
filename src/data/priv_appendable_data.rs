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

use error::RoutingError;
use maidsafe_utilities::serialisation::{deserialise, serialise, serialised_size};
use rust_sodium::crypto::{box_, sealedbox};
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use rustc_serialize::{Decodable, Decoder};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use super::{AppendWrapper, AppendedData, DataIdentifier, Filter, NO_OWNER_PUB_KEY};
use xor_name::XorName;

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
        let encoded_appended_data = serialise(&appended_data)?;
        let encrypted_appended_data = sealedbox::seal(&encoded_appended_data, encrypt_pub_key);
        Ok(PrivAppendedData(encrypted_appended_data))
    }

    /// Returns `AppendedData` decrypted from this item.
    pub fn open(&self,
                pub_key: &box_::PublicKey,
                secret_key: &box_::SecretKey)
                -> Result<AppendedData, RoutingError> {
        let decipher_result = sealedbox::open(&self.0, pub_key, secret_key)
            .map_err(|()| RoutingError::AsymmetricDecryptionFailure)?;
        Ok(deserialise(&decipher_result)?)
    }
}

impl Decodable for PrivAppendedData {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let data: Vec<u8> = Decodable::decode(d)?;
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
    #[cfg_attr(feature="cargo-clippy", allow(too_many_arguments))]
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
        self.validate_self_against_successor(&other)?;

        self.name = other.name;
        self.version = other.version;
        self.filter = other.filter;
        self.encrypt_key = other.encrypt_key;
        self.deleted_data = other.deleted_data;
        self.signatures = other.signatures;
        self.owners = other.owners;
        self.data.extend(other.data);
        for ad in &self.deleted_data {
            if self.data.contains(ad) {
                let _remove = self.data.remove(ad);
            }
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
        if other.owners.len() > 1 || other.signatures.len() > 1 ||
           self.owners.contains(&NO_OWNER_PUB_KEY) {
            return Err(RoutingError::InvalidOwners);
        }

        if other.name != self.name || other.version != self.version + 1 {
            return Err(RoutingError::UnknownMessageType);
        }
        let data = other.data_to_sign()?;
        super::verify_signatures(&self.owners, &data, &other.signatures)
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
        self.data
            .insert(priv_appended_data)
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
    pub fn add_signature(&mut self, keys: &(PublicKey, SecretKey)) -> Result<usize, RoutingError> {
        if !self.signatures.is_empty() {
            return Err(RoutingError::InvalidOwners);
        }
        let data = self.data_to_sign()?;
        let sig = sign::sign_detached(&data, &keys.1);
        if self.signatures.insert(keys.0, sig).is_none() {
            return Ok(((self.owners.len() / 2) + 1).saturating_sub(self.signatures.len()));
        }
        Err(RoutingError::FailedSignature)
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
        write!(formatter,
               "PrivAppendableData {{ name: {}, version: {}, owners: {:?}, signatures: {:?} }}",
               self.name(),
               self.version,
               self.owners,
               self.signatures)
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
mod tests {
    use data::{self, AppendWrapper, AppendedData, DataIdentifier, Filter};
    use maidsafe_utilities::serialisation::serialise;
    use rand;
    use rust_sodium::crypto::{box_, sign};
    use std::collections::BTreeSet;
    use super::*;
    use xor_name::XorName;

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
        let mut owner_keys = BTreeSet::new();
        owner_keys.insert(keys.0);

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      owner_keys.clone(),
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0) {
            Ok(mut priv_appendable_data) => {
                let data = match priv_appendable_data.data_to_sign() {
                    Ok(data) => data,
                    Err(error) => panic!("Error: {:?}", error),
                };
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                priv_appendable_data.get_signatures())
                    .is_err());
                assert!(priv_appendable_data.add_signature(&keys).is_ok());
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                priv_appendable_data.get_signatures())
                    .is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn single_owner_other_signature() {
        let keys = sign::gen_keypair();
        let other_keys = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();
        let mut owner_keys = BTreeSet::new();
        owner_keys.insert(keys.0);

        match PrivAppendableData::new(rand::random(),
                                      0,
                                      owner_keys.clone(),
                                      BTreeSet::new(),
                                      Filter::white_list(None),
                                      encrypt_keys.0) {
            Ok(mut priv_appendable_data) => {
                assert!(priv_appendable_data.add_signature(&other_keys).is_ok());
                let data = match priv_appendable_data.data_to_sign() {
                    Ok(data) => data,
                    Err(error) => panic!("Error: {:?}", error),
                };
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                priv_appendable_data.get_signatures())
                    .is_err());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn appending_with_white_list() {
        let keys = sign::gen_keypair();
        let encrypt_keys = box_::gen_keypair();

        let white_key = sign::gen_keypair();
        let black_key = sign::gen_keypair();

        let mut priv_appendable_data = unwrap!(PrivAppendableData::new(rand::random(),
                                            0,
                                            BTreeSet::new(),
                                            BTreeSet::new(),
                                            Filter::white_list(vec![white_key.0]),
                                            encrypt_keys.0));

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

        let white_key = sign::gen_keypair();
        let black_key = sign::gen_keypair();

        let mut priv_appendable_data = unwrap!(PrivAppendableData::new(rand::random(),
                                            0,
                                            BTreeSet::new(),
                                            BTreeSet::new(),
                                            Filter::black_list(vec![black_key.0]),
                                            encrypt_keys.0));

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
                                                                       BTreeSet::new(),
                                                                       BTreeSet::new(),
                                                                       Filter::black_list(None),
                                                                       encrypt_keys.0));

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

    #[test]
    fn transfer_ownership() {
        let keys = sign::gen_keypair();
        let other_keys = sign::gen_keypair();
        let mut owner = BTreeSet::new();
        owner.insert(keys.0);
        let mut new_owner = BTreeSet::new();
        new_owner.insert(other_keys.0);
        let name: XorName = rand::random();
        let encrypt_keys = box_::gen_keypair();

        let mut ad = unwrap!(PrivAppendableData::new(name,
                                                     0,
                                                     owner,
                                                     BTreeSet::new(),
                                                     Filter::black_list(None),
                                                     encrypt_keys.0));
        let mut ad_new = unwrap!(PrivAppendableData::new(name,
                                                         1,
                                                         new_owner.clone(),
                                                         BTreeSet::new(),
                                                         Filter::black_list(None),
                                                         encrypt_keys.0));
        assert!(ad_new.add_signature(&keys).is_ok());
        assert!(ad.update_with_other(ad_new).is_ok());

        let mut ad_fail = unwrap!(PrivAppendableData::new(name,
                                                          2,
                                                          new_owner.clone(),
                                                          BTreeSet::new(),
                                                          Filter::black_list(None),
                                                          encrypt_keys.0));
        assert!(ad_fail.add_signature(&keys).is_ok());
        assert!(ad.update_with_other(ad_fail).is_err());
    }
}

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
use maidsafe_utilities::serialisation::{serialise, serialised_size};
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use super::{AppendWrapper, AppendedData, DataIdentifier, Filter, NO_OWNER_PUB_KEY};
use xor_name::XorName;

/// Maximum allowed size for a public appendable data to grow to
pub const MAX_PUB_APPENDABLE_DATA_SIZE_IN_BYTES: u64 = 102400;

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
    /// The filter defining who is allowed to append items.
    pub filter: Filter,
    /// A collection of previously deleted data items.
    pub deleted_data: BTreeSet<AppendedData>,
    /// The pub_keys of the current owners of the chunk's.
    pub owners: BTreeSet<PublicKey>,
    /// The pub_keys and signatures of the owners of the chunk's current version.
    pub signatures: BTreeMap<PublicKey, Signature>,
    /// The collection of appended data items. These are not signed by the owners, as they change
    /// even between `Post`s.
    pub data: BTreeSet<AppendedData>,
}

impl PubAppendableData {
    /// Creates a new `PubAppendableData` signed with `signing_key`.
    pub fn new(name: XorName,
               version: u64,
               owners: BTreeSet<PublicKey>,
               deleted_data: BTreeSet<AppendedData>,
               filter: Filter)
               -> Result<PubAppendableData, RoutingError> {
        if owners.len() > 1 {
            return Err(RoutingError::InvalidOwners);
        }

        Ok(PubAppendableData {
            name: name,
            version: version,
            filter: filter,
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
    pub fn update_with_other(&mut self, other: PubAppendableData) -> Result<(), RoutingError> {
        self.validate_self_against_successor(&other)?;

        self.name = other.name;
        self.version = other.version;
        self.filter = other.filter;
        self.deleted_data = other.deleted_data;
        self.owners = other.owners;
        self.signatures = other.signatures;
        self.data.extend(other.data);
        for ad in &self.deleted_data {
            let _ = self.data.remove(ad);
        }
        Ok(())
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

    /// Inserts the given wrapper item, or returns `false` if cannot
    pub fn apply_wrapper(&mut self, wrapper: AppendWrapper) -> bool {
        if !wrapper.verify_signature() || &self.version != wrapper.version() {
            return false;
        }
        match wrapper.pub_appended_data() {
            None => false,
            Some(pub_appended_data) => self.append(pub_appended_data.clone()),
        }
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

    fn data_to_sign(&self) -> Result<Vec<u8>, RoutingError> {
        // Seems overkill to use serialisation here, but done to ensure cross platform signature
        // handling is OK
        let sd = SerialisablePubAppendableData {
            name: self.name,
            owners: &self.owners,
            version: self.version.to_string().as_bytes().to_vec(),
            filter: &self.filter,
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
        let _ = self.signatures.insert(keys.0, sig);
        Ok(((self.owners.len() / 2) + 1).saturating_sub(self.signatures.len()))
    }

    /// Overwrite any existing signatures with the new signatures provided.
    pub fn replace_signatures(&mut self, new_signatures: BTreeMap<PublicKey, Signature>) {
        self.signatures = new_signatures;
    }

    /// Get the data
    pub fn get_data(&self) -> &BTreeSet<AppendedData> {
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
        serialised_size(self) <= MAX_PUB_APPENDABLE_DATA_SIZE_IN_BYTES
    }
}

impl Debug for PubAppendableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "PubAppendableData {{ name: {}, version: {}, owners: {:?}, signatures: {:?} }}",
               self.name(),
               self.version,
               self.owners,
               self.signatures)
        // TODO(afck): Print `data` and `deleted_data`.
    }
}

#[derive(RustcEncodable)]
struct SerialisablePubAppendableData<'a> {
    name: XorName,
    owners: &'a BTreeSet<PublicKey>,
    version: Vec<u8>,
    filter: &'a Filter,
    deleted_data: &'a BTreeSet<AppendedData>,
}

#[cfg(test)]
mod test {
    use data::{self, AppendWrapper, AppendedData, DataIdentifier, Filter};
    use rand;
    use rust_sodium::crypto::sign;
    use std::collections::BTreeSet;
    use super::*;
    use xor_name::XorName;

    #[test]
    fn single_owner() {
        let keys = sign::gen_keypair();
        let mut owner_keys = BTreeSet::new();
        owner_keys.insert(keys.0);

        match PubAppendableData::new(rand::random(),
                                     0,
                                     owner_keys.clone(),
                                     BTreeSet::new(),
                                     Filter::white_list(None)) {
            Ok(mut pub_appendable_data) => {
                let data = match pub_appendable_data.data_to_sign() {
                    Ok(data) => data,
                    Err(error) => panic!("Error: {:?}", error),
                };
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                pub_appendable_data.get_signatures())
                    .is_err());
                assert_eq!(pub_appendable_data.add_signature(&keys).unwrap(), 0);
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                pub_appendable_data.get_signatures())
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

        match PubAppendableData::new(rand::random(),
                                     0,
                                     owner_keys.clone(),
                                     BTreeSet::new(),
                                     Filter::white_list(None)) {
            Ok(mut pub_appendable_data) => {
                assert_eq!(pub_appendable_data.add_signature(&other_keys).unwrap(), 0);
                let data = match pub_appendable_data.data_to_sign() {
                    Ok(data) => data,
                    Err(error) => panic!("Error: {:?}", error),
                };
                assert!(data::verify_signatures(&owner_keys,
                                                &data,
                                                pub_appendable_data.get_signatures())
                    .is_err());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn appending_with_white_list() {
        let black_key = sign::gen_keypair();
        let white_key = sign::gen_keypair();

        let mut pub_appendable_data = unwrap!(PubAppendableData::new(rand::random(),
                                              0,
                                              BTreeSet::new(),
                                              BTreeSet::new(),
                                              Filter::white_list(vec![white_key.0]),));

        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let black_appended_data = unwrap!(AppendedData::new(pointer, black_key.0, &black_key.1));
        let white_appended_data = unwrap!(AppendedData::new(pointer, white_key.0, &white_key.1));

        assert!(!pub_appendable_data.append(black_appended_data));
        assert!(pub_appendable_data.append(white_appended_data));
    }

    #[test]
    fn appending_with_black_list() {
        let black_key = sign::gen_keypair();
        let white_key = sign::gen_keypair();

        let mut pub_appendable_data = unwrap!(PubAppendableData::new(rand::random(),
                                              0,
                                              BTreeSet::new(),
                                              BTreeSet::new(),
                                              Filter::black_list(vec![black_key.0])));

        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let black_appended_data = unwrap!(AppendedData::new(pointer, black_key.0, &black_key.1));
        let white_appended_data = unwrap!(AppendedData::new(pointer, white_key.0, &white_key.1));

        assert!(!pub_appendable_data.append(black_appended_data));
        assert!(pub_appendable_data.append(white_appended_data));
    }

    #[test]
    fn apply_wrapper() {
        let keys = sign::gen_keypair();
        let name: XorName = rand::random();

        let mut pub_appendable_data = unwrap!(PubAppendableData::new(name,
                                                                     0,
                                                                     BTreeSet::new(),
                                                                     BTreeSet::new(),
                                                                     Filter::black_list(None)));
        let pointer = DataIdentifier::Structured(rand::random(), 10000);
        let appended_data = unwrap!(AppendedData::new(pointer, keys.0, &keys.1));

        // apply correct wrapper
        let append_wrapper = AppendWrapper::new_pub(name, appended_data.clone(), 0);
        assert!(pub_appendable_data.apply_wrapper(append_wrapper));

        // apply wrapper with incorrect version
        let append_wrapper = AppendWrapper::new_pub(name, appended_data, 1);
        assert!(!pub_appendable_data.apply_wrapper(append_wrapper));
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

        let mut ad = unwrap!(PubAppendableData::new(name,
                                                    0,
                                                    owner,
                                                    BTreeSet::new(),
                                                    Filter::black_list(None)));
        let mut ad_new = unwrap!(PubAppendableData::new(name,
                                                        1,
                                                        new_owner.clone(),
                                                        BTreeSet::new(),
                                                        Filter::black_list(None)));
        assert_eq!(ad_new.add_signature(&keys).unwrap(), 0);
        assert!(ad.update_with_other(ad_new).is_ok());

        let mut ad_fail = unwrap!(PubAppendableData::new(name,
                                                         2,
                                                         new_owner.clone(),
                                                         BTreeSet::new(),
                                                         Filter::black_list(None)));
        assert_eq!(ad_fail.add_signature(&keys).unwrap(), 0);
        assert!(ad.update_with_other(ad_fail).is_err());
    }
}

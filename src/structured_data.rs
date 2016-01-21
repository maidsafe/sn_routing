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

/// Maximum allowed size for a Structured Data to grow to
pub const MAX_STRUCTURED_DATA_SIZE_IN_BYTES: usize = 102400;

use xor_name::XorName;

/// Mutable structured data.
///
/// The name is computed from the type tag and identifier, so these two fields are immutable.
///
/// These types may be stored unsigned with previous and current owner keys
/// set to the same keys. Updates require a signature to validate.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub struct StructuredData {
    type_tag: u64,
    identifier: XorName,
    data: Vec<u8>,
    previous_owner_keys: Vec<::sodiumoxide::crypto::sign::PublicKey>,
    version: u64,
    current_owner_keys: Vec<::sodiumoxide::crypto::sign::PublicKey>,
    previous_owner_signatures: Vec<::sodiumoxide::crypto::sign::Signature>,
}


impl StructuredData {
    /// Creates a new `StructuredData` signed with `signing_key`.
    pub fn new(type_tag: u64,
               identifier: XorName,
               version: u64,
               data: Vec<u8>,
               current_owner_keys: Vec<::sodiumoxide::crypto::sign::PublicKey>,
               previous_owner_keys: Vec<::sodiumoxide::crypto::sign::PublicKey>,
               signing_key: Option<&::sodiumoxide::crypto::sign::SecretKey>)
               -> Result<StructuredData, ::error::RoutingError> {

        let mut structured_data = StructuredData {
            type_tag: type_tag,
            identifier: identifier,
            data: data,
            previous_owner_keys: previous_owner_keys,
            version: version,
            current_owner_keys: current_owner_keys,
            previous_owner_signatures: vec![],
        };

        if let Some(key) = signing_key {
            let _ = try!(structured_data.add_signature(key));
        }
        Ok(structured_data)
    }

    /// This is a static function that computes the name of a `StructuredData` given its type tag
    /// and identifier. To request the data with that type tag and identifier, a `Get` request
    /// needs to be sent to that name's `NaeManager`.
    pub fn compute_name(type_tag: u64, identifier: &XorName) -> XorName {
        let type_tag_as_string = type_tag.to_string();

        let chain = identifier.0
                              .iter()
                              .cloned()
                              .chain(type_tag_as_string.as_bytes().iter().cloned())
                              .map(|a| a);

        XorName(::sodiumoxide::crypto::hash::sha512::hash(&chain.collect::<Vec<_>>()[..]).0)
    }

    /// Replaces this data item with the given updated version if the update is valid, otherwise
    /// returns an error.
    ///
    /// This allows types to be created and `previous_owner_signatures` added one by one.
    /// To transfer ownership, the current owner signs over the data; the previous owners field
    /// must have the previous owners of `version - 1` as the current owners of that last version.
    pub fn replace_with_other(&mut self,
                              other: StructuredData)
                              -> Result<(), ::error::RoutingError> {
        try!(self.validate_self_against_successor(&other));

        self.type_tag = other.type_tag;
        self.identifier = other.identifier;
        self.data = other.data;
        self.previous_owner_keys = other.previous_owner_keys;
        self.version = other.version;
        self.current_owner_keys = other.current_owner_keys;
        self.previous_owner_signatures = other.previous_owner_signatures;
        Ok(())
    }

    /// Returns the name, computed from the type tag and identifier.
    pub fn name(&self) -> XorName {
        StructuredData::compute_name(self.type_tag, &self.identifier)
    }

    /// Verifies that `other` is a valid update for `self`; returns an error otherwise.
    ///
    /// An update is valid if it doesn't change type tag or identifier (these are immutable),
    /// increases the version by 1 and is signed by (more than 50% of) the owners.
    ///
    /// In case of an ownership transfer, the `previous_owner_keys` in `other` must match the
    /// `current_owner_keys` in `self`.
    pub fn validate_self_against_successor(&self,
                                           other: &StructuredData)
                                           -> Result<(), ::error::RoutingError> {
        let owner_keys_to_match = if other.previous_owner_keys.is_empty() {
            &other.current_owner_keys
        } else {
            &other.previous_owner_keys
        };

        // TODO(dirvine) Increase error types to be more descriptive  :07/07/2015
        if other.type_tag != self.type_tag || other.identifier != self.identifier ||
           other.version != self.version + 1 ||
           *owner_keys_to_match != self.current_owner_keys {
            return Err(::error::RoutingError::UnknownMessageType);
        }
        other.verify_previous_owner_signatures(owner_keys_to_match)
    }

    /// Confirms *unique and valid* owner_signatures are more than 50% of total owners.
    fn verify_previous_owner_signatures(&self,
                                        owner_keys: &[::sodiumoxide::crypto::sign::PublicKey])
                                        -> Result<(), ::error::RoutingError> {
        // Refuse any duplicate previous_owner_signatures (people can have many owner keys)
        // Any duplicates invalidates this type.
        for (i, sig) in self.previous_owner_signatures.iter().enumerate() {
            for sig_check in &self.previous_owner_signatures[..i] {
                if sig == sig_check {
                    return Err(::error::RoutingError::DuplicateSignatures);
                }
            }
        }

        // Refuse when not enough previous_owner_signatures found
        if self.previous_owner_signatures.len() < (owner_keys.len() + 1) / 2 {
            return Err(::error::RoutingError::NotEnoughSignatures);
        }

        let data = try!(self.data_to_sign());
        // Count valid previous_owner_signatures and refuse if quantity is not enough

        let check_all_keys = |&sig| {
            owner_keys.iter()
                      .any(|ref pub_key| {
                          ::sodiumoxide::crypto::sign::verify_detached(&sig, &data, pub_key)
                      })
        };

        if self.previous_owner_signatures
               .iter()
               .filter(|&sig| check_all_keys(sig))
               .count() < (owner_keys.len() / 2 + owner_keys.len() % 2) {
            return Err(::error::RoutingError::NotEnoughSignatures);
        }
        Ok(())
    }

    fn data_to_sign(&self) -> Result<Vec<u8>, ::error::RoutingError> {
        // Seems overkill to use serialisation here, but done to ensure cross platform signature
        // handling is OK
        let mut enc = ::cbor::Encoder::from_memory();
        try!(enc.encode(self.type_tag.to_string().as_bytes()));
        try!(enc.encode(&[self.identifier]));
        try!(enc.encode(&self.data));
        try!(enc.encode(&self.previous_owner_keys));
        try!(enc.encode(&self.current_owner_keys));
        try!(enc.encode(self.version.to_string().as_bytes()));
        Ok(enc.into_bytes())
    }

    /// Adds a signature with the given `secret_key` to the `previous_owner_signatures` and returns
    /// the number of signatures that are still required. If more than 50% of the previous owners
    /// have signed, 0 is returned and validation is complete.
    pub fn add_signature(&mut self,
                         secret_key: &::sodiumoxide::crypto::sign::SecretKey)
                         -> Result<usize, ::error::RoutingError> {
        let data = try!(self.data_to_sign());
        let sig = ::sodiumoxide::crypto::sign::sign_detached(&data, secret_key);
        self.previous_owner_signatures.push(sig);
        let owner_keys = if self.previous_owner_keys.is_empty() {
            &self.current_owner_keys
        } else {
            &self.previous_owner_keys
        };
        Ok(((owner_keys.len() / 2) + 1).saturating_sub(self.previous_owner_signatures.len()))
    }

    /// Overwrite any existing signatures with the new signatures provided.
    pub fn replace_signatures(&mut self,
                              new_signatures: Vec<::sodiumoxide::crypto::sign::Signature>) {
        self.previous_owner_signatures = new_signatures;
    }

    /// Get the type_tag
    pub fn get_type_tag(&self) -> u64 {
        self.type_tag.clone()
    }

    /// Get the identifier
    pub fn get_identifier(&self) -> &XorName {
        &self.identifier
    }

    /// Get the serialised data
    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Get the previous owner keys
    pub fn get_previous_owner_keys(&self) -> &Vec<::sodiumoxide::crypto::sign::PublicKey> {
        &self.previous_owner_keys
    }

    /// Get the version
    pub fn get_version(&self) -> u64 {
        self.version
    }

    /// Get the current owner keys
    pub fn get_owner_keys(&self) -> &Vec<::sodiumoxide::crypto::sign::PublicKey> {
        &self.current_owner_keys
    }

    /// Get previous owner signatures
    pub fn get_previous_owner_signatures(&self) -> &Vec<::sodiumoxide::crypto::sign::Signature> {
        &self.previous_owner_signatures
    }

    /// Return data size.
    pub fn payload_size(&self) -> usize {
        self.data.len()
    }
}

impl ::std::fmt::Debug for StructuredData {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        try!(write!(formatter,
                    " type_tag: {:?} , name: {:?} , version: {:?} , data: {:?}",
                    self.type_tag,
                    self.name(),
                    self.version,
                    ::utils::format_binary_array(&self.data[..])));

        let prev_owner_keys: Vec<String> = self.previous_owner_keys
                                               .iter()
                                               .map(|pub_key| ::utils::format_binary_array(&pub_key.0))
                                               .collect();
        try!(write!(formatter, " , previous_owner_keys : ("));
        for itr in &prev_owner_keys {
            try!(write!(formatter, "{:?} ", itr));
        }
        try!(write!(formatter, ")"));

        let current_owner_keys: Vec<String> = self.current_owner_keys
                                                  .iter()
                                                  .map(|pub_key| ::utils::format_binary_array(&pub_key.0))
                                                  .collect();
        try!(write!(formatter, " , current_owner_keys : ("));
        for itr in &current_owner_keys {
            try!(write!(formatter, "{:?} ", itr));
        }
        try!(write!(formatter, ") "));

        let prev_owner_signatures: Vec<String> = self.previous_owner_signatures
                                                     .iter()
                                                     .map(|signature| {
                                                         ::utils::format_binary_array(&signature.0[..])
                                                     })
                                                     .collect();
        try!(write!(formatter, " , prev_owner_signatures : ("));
        for itr in &prev_owner_signatures {
            try!(write!(formatter, "{:?} ", itr));
        }
        write!(formatter, ") ")
    }
}


#[cfg(test)]
mod test {
    extern crate rand;

    use xor_name::XorName;

    #[test]
    fn single_owner() {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];

        match super::StructuredData::new(0,
                                         rand::random(),
                                         0,
                                         vec![],
                                         owner_keys.clone(),
                                         vec![],
                                         Some(&keys.1)) {
            Ok(structured_data) => {
                assert_eq!(structured_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn single_owner_unsigned() {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];

        match super::StructuredData::new(0,
                                         rand::random(),
                                         0,
                                         vec![],
                                         owner_keys.clone(),
                                         vec![],
                                         None) {
            Ok(structured_data) => {
                assert_eq!(structured_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn single_owner_other_signing_key() {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        let other_keys = ::sodiumoxide::crypto::sign::gen_keypair();

        match super::StructuredData::new(0,
                                         rand::random(),
                                         0,
                                         vec![],
                                         owner_keys.clone(),
                                         vec![],
                                         Some(&other_keys.1)) {
            Ok(structured_data) => {
                assert_eq!(structured_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn single_owner_other_signature() {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        let other_keys = ::sodiumoxide::crypto::sign::gen_keypair();

        match super::StructuredData::new(0,
                                         rand::random(),
                                         0,
                                         vec![],
                                         owner_keys.clone(),
                                         vec![],
                                         None) {
            Ok(mut structured_data) => {
                assert_eq!(structured_data.add_signature(&other_keys.1).ok(), Some(0));
                assert_eq!(structured_data.verify_previous_owner_signatures(&owner_keys).ok(),
                           Some(()))
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn three_owners() {
        let keys1 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys2 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys3 = ::sodiumoxide::crypto::sign::gen_keypair();

        let owner_keys = vec![keys1.0, keys2.0, keys3.0];

        match super::StructuredData::new(0,
                                         rand::random(),
                                         0,
                                         vec![],
                                         owner_keys.clone(),
                                         vec![],
                                         None) {
            Ok(mut structured_data) => {
                // After one signature, one more is required to reach majority.
                assert_eq!(structured_data.add_signature(&keys1.1).unwrap(), 1);
                assert!(structured_data.verify_previous_owner_signatures(&owner_keys).is_err());
                // Two out of three is enough.
                assert_eq!(structured_data.add_signature(&keys2.1).unwrap(), 0);
                assert!(structured_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Three out of three is also fine.
                assert_eq!(structured_data.add_signature(&keys3.1).unwrap(), 0);
                assert!(structured_data.verify_previous_owner_signatures(&owner_keys).is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn four_owners() {
        let keys1 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys2 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys3 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys4 = ::sodiumoxide::crypto::sign::gen_keypair();

        let owner_keys = vec![keys1.0, keys2.0, keys3.0, keys4.0];

        match super::StructuredData::new(0,
                                         rand::random(),
                                         0,
                                         vec![],
                                         owner_keys.clone(),
                                         vec![],
                                         Some(&keys1.1)) {
            Ok(mut structured_data) => {
                // Two signatures are not enough because they don't have a strict majority.
                assert_eq!(structured_data.add_signature(&keys2.1).unwrap(), 1);
                assert!(structured_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Three out of four is enough.
                assert_eq!(structured_data.add_signature(&keys3.1).unwrap(), 0);
                assert!(structured_data.verify_previous_owner_signatures(&owner_keys).is_ok());
                // Four out of four is also fine.
                assert_eq!(structured_data.add_signature(&keys4.1).unwrap(), 0);
                assert!(structured_data.verify_previous_owner_signatures(&owner_keys).is_ok());
            }
            Err(error) => panic!("Error: {:?}", error),
        }
    }

    #[test]
    fn transfer_owners() {
        let keys1 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys2 = ::sodiumoxide::crypto::sign::gen_keypair();
        let keys3 = ::sodiumoxide::crypto::sign::gen_keypair();
        let new_owner = ::sodiumoxide::crypto::sign::gen_keypair();

        let identifier: XorName = rand::random();

        // Owned by keys1 keys2 and keys3
        match super::StructuredData::new(0,
                                         identifier.clone(),
                                         0,
                                         vec![],
                                         vec![keys1.0, keys2.0, keys3.0],
                                         vec![],
                                         Some(&keys1.1)) {
            Ok(mut orig_structured_data) => {
                assert_eq!(orig_structured_data.add_signature(&keys2.1).ok(), Some(0));
                // Transfer ownership and update to new owner
                match super::StructuredData::new(0,
                                                 identifier.clone(),
                                                 1,
                                                 vec![],
                                                 vec![new_owner.0],
                                                 vec![keys1.0, keys2.0, keys3.0],
                                                 Some(&keys1.1)) {
                    Ok(mut new_structured_data) => {
                        assert_eq!(new_structured_data.add_signature(&keys2.1).ok(), Some(0));
                        match orig_structured_data.replace_with_other(new_structured_data) {
                            Ok(()) => println!("All good"),
                            Err(e) => panic!("Error {:?}", e),
                        }
                        // transfer ownership back to keys1 only
                        match super::StructuredData::new(0,
                                                         identifier,
                                                         2,
                                                         vec![],
                                                         vec![keys1.0],
                                                         vec![new_owner.0],
                                                         Some(&new_owner.1)) {
                            Ok(another_new_structured_data) => {
                                match orig_structured_data.replace_with_other(another_new_structured_data) {
                                    Ok(()) => println!("All good"),
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

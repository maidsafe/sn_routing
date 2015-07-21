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

use rustc_serialize::{Encodable, Encoder, Decoder};
use cbor;
use error::RoutingError;
use NameType;
use sodiumoxide::crypto;

/// StructuredData
/// These types may be stored unsigned with previous and current owner keys
/// set to the same keys. Updates though require a signature to validate
#[derive(Debug, Eq, PartialEq, Clone, RustcDecodable, RustcEncodable)]
pub struct StructuredData {
    type_tag: u64,
    identifier: NameType,
    data: Vec<u8>,
    previous_owner_keys: Vec<crypto::sign::PublicKey>,
    version: u64,
    current_owner_keys: Vec<crypto::sign::PublicKey>,
    previous_owner_signatures: Vec<crypto::sign::Signature>
}


impl StructuredData {

    /// Constructor
    pub fn new(type_tag: u64,
               identifier: NameType,
               data: Vec<u8>,
               previous_owner_keys: Vec<crypto::sign::PublicKey>,
               version: u64,
               current_owner_keys: Vec<crypto::sign::PublicKey>,
               previous_owner_signatures: Vec<crypto::sign::Signature>) -> StructuredData {

        StructuredData {
                   type_tag: type_tag,
                   identifier: identifier,
                   data: data,
                   previous_owner_keys: previous_owner_keys,
                   version: version,
                   current_owner_keys : current_owner_keys,
                   previous_owner_signatures: previous_owner_signatures
                 }
    }
    /// replace this data item with an updated version if such exists, otherwise fail.
    /// This is done this way to allow types to be created and previous_owner_signatures added one by one
    /// To transfer ownership the current owner signs over the data, the previous owners field
    /// must have the previous owners of version - 1 as the current owners of that last version.
    pub fn replace_with_other(&mut self, other: StructuredData) -> Result<(), RoutingError> {
        // TODO(dirvine) Increase error types to be more descriptive  :07/07/2015
        if      other.type_tag != self.type_tag     ||
                other.identifier != self.identifier ||
                other.version != self.version + 1   ||
                other.previous_owner_keys != self.current_owner_keys  {
            return Err(RoutingError::UnknownMessageType)
        }
        try!(other.verify_previous_owner_signatures());

                   self.type_tag = other.type_tag;
                   self.identifier = other.identifier;
                   self.data = other.data;
                   self.previous_owner_keys = other.previous_owner_keys;
                   self.version = other.version;
                   self.current_owner_keys  = other.current_owner_keys;
                   self.previous_owner_signatures = other.previous_owner_signatures;
                   Ok(())
    }

    /// Returns name and validates invariants
    pub fn name(&self) -> NameType {
        let type_tag_as_string = self.type_tag.to_string();

        let chain = self.identifier.0.iter()
                    .chain(type_tag_as_string.as_bytes().iter())
                    .map(|a|*a);

        NameType(crypto::hash::sha512::hash(&chain.collect::<Vec<_>>()[..]).0)
    }

    /// Confirms *unique and valid* previous_owner_signatures are at least 50% of total owners
    fn verify_previous_owner_signatures(&self) -> Result<(), RoutingError> {
         // Refuse any duplicate previous_owner_signatures (people can have many owner keys)
         // Any duplicates invalidates this type
         if self.previous_owner_signatures.iter().filter(|&sig| self.previous_owner_signatures.iter()
                                  .any(|ref sig_check| NameType(sig.0) == NameType(sig_check.0)))
                                  .count() > (self.previous_owner_keys.len() + 1) /2 {

            return Err(RoutingError::DuplicateSignatures);
         }


         // Refuse when not enough previous_owner_signatures found
         if self.previous_owner_signatures.len() < (self.previous_owner_keys.len()  + 1 ) / 2 {
             return Err(RoutingError::NotEnoughSignatures);
         }

         let data = try!(self.data_to_sign());
         // Count valid previous_owner_signatures and refuse if quantity is not enough
         if self.previous_owner_signatures.iter()
                        .filter(|&sig| self.previous_owner_keys
                          .iter()
                          .any(|ref pub_key| crypto::sign::verify_detached(&sig, &data, &pub_key)))
                            .count() < self.previous_owner_keys.len() / 2 {
            return Err(RoutingError::NotEnoughSignatures);
         }
         Ok(())
    }

    fn data_to_sign(&self) -> Result<Vec<u8>, RoutingError> {
        // seems overkill to use serialisation here, but done
        // to ensure cross platform signature handling is OK
        let mut enc = cbor::Encoder::from_memory();
        try!(enc.encode(self.type_tag.to_string().as_bytes()));
        try!(enc.encode(&[self.identifier]));
        try!(enc.encode(&self.data));
        try!(enc.encode(&self.previous_owner_keys));
        try!(enc.encode(&self.current_owner_keys));
        try!(enc.encode(self.version.to_string().as_bytes()));
        Ok(enc.into_bytes())
    }

    /// Returns number of previous_owner_signatures still required (if any, 0 means this is complete)
    pub fn add_signature(&mut self, secret_key: &crypto::sign::SecretKey) -> Result<isize, RoutingError> {
        let data = try!(self.data_to_sign());
        let sig = crypto::sign::sign_detached(&data, secret_key);
        self.previous_owner_signatures.push(sig);
        Ok(((self.previous_owner_keys.len() + 1) as isize / 2) -
             self.previous_owner_signatures.len() as isize)
    }

    /// Overwrite any existing signatures with the new signatures provided
    pub fn replace_signatures(&mut self, new_signatures : Vec<crypto::sign::Signature>) {
        self.previous_owner_signatures = new_signatures;
    }

    /// Get the type_tag
    pub fn get_type_tag(&self) -> u64 {
        self.type_tag.clone()
    }

    /// Get the identifier
    pub fn get_identifier(&self) -> &NameType {
        &self.identifier
    }

    /// Get the serialised data
    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Get the previous owner keys
    pub fn get_previous_owner_keys(&self) -> &Vec<crypto::sign::PublicKey> {
        &self.previous_owner_keys
    }

    /// Get the version
    pub fn get_version(&self) -> &u64 {
        &self.version
    }

    /// Get the current owner keys
    pub fn get_owner_keys(&self) -> &Vec<crypto::sign::PublicKey> {
        &self.current_owner_keys
    }

    /// Get previous owner signatures
    pub fn get_previous_owner_signatures(&self) -> &Vec<crypto::sign::Signature> {
        &self.previous_owner_signatures
    }

    pub fn payload_size(&self) -> usize {
        self.data.len()
    }
}


#[cfg(test)]
mod test {
    use sodiumoxide::crypto;
    use super::StructuredData;
    use test_utils::Random;
    use NameType;

    #[test]
    fn single_owner() {
        let keys = crypto::sign::gen_keypair();

        let mut structured_data =   StructuredData::new(0,
                                Random::generate_random(),
                                //crypto::hash::sha512::hash("test_identity".to_string().as_bytes()),
                                vec![],
                                vec![keys.0],
                                0,
                                vec![],
                                vec![]);
        assert_eq!(structured_data.verify_previous_owner_signatures().ok(), None);
        assert_eq!(structured_data.add_signature(&keys.1).ok(), Some(0));
        assert_eq!(structured_data.verify_previous_owner_signatures().ok(), Some(()));
    }

    #[test]
    fn three_owners() {
        let keys1 = crypto::sign::gen_keypair();
        let keys2 = crypto::sign::gen_keypair();
        let keys3 = crypto::sign::gen_keypair();

        let mut structured_data =   StructuredData::new(0,
                                Random::generate_random(),
                                //crypto::hash::sha512::hash("test_identity".to_string().as_bytes()),
                                vec![],
                                vec![keys1.0, keys2.0, keys3.0],
                                0,
                                vec![],
                                vec![]);
        assert_eq!(structured_data.add_signature(&keys1.1).ok(), Some(1));
        assert_eq!(structured_data.verify_previous_owner_signatures().ok(), None);
        assert_eq!(structured_data.add_signature(&keys2.1).ok(), Some(0));
        assert_eq!(structured_data.verify_previous_owner_signatures().ok(), Some(()));
    }

    #[test]
    fn transfer_owners() {
        let keys1       = crypto::sign::gen_keypair();
        let keys2       = crypto::sign::gen_keypair();
        let keys3       = crypto::sign::gen_keypair();
        let new_owner   = crypto::sign::gen_keypair();

        let identifier : NameType = Random::generate_random();

        // Owned by keys1 keys2 and keys3
        let mut orig_structured_data =   StructuredData::new(0,
                                identifier.clone(),
                                vec![],
                                vec![keys1.0, keys2.0, keys3.0],
                                0,
                                vec![keys1.0, keys2.0, keys3.0],
                                vec![]);
        assert_eq!(orig_structured_data.add_signature(&keys1.1).ok(), Some(1));
        assert_eq!(orig_structured_data.add_signature(&keys2.1).ok(), Some(0));
        assert_eq!(orig_structured_data.verify_previous_owner_signatures().ok(), Some(()));
        // Transfer ownership and update to new owner
        let mut new_structured_data =   StructuredData::new(0,
                                identifier.clone(),
                                vec![],
                                vec![keys1.0, keys2.0, keys3.0],
                                1,
                                vec![new_owner.0],
                                vec![]);
        assert_eq!(new_structured_data.add_signature(&keys1.1).ok(), Some(1));
        assert_eq!(new_structured_data.add_signature(&keys2.1).ok(), Some(0));
        assert_eq!(new_structured_data.verify_previous_owner_signatures().ok(), Some(()));
        match orig_structured_data.replace_with_other(new_structured_data) {
            Ok(()) => println!("All good"),
            Err(e) => panic!("Error {}", e),
        }
        // transfer ownership back to keys1 only
        let mut another_new_structured_data =   StructuredData::new(0,
                                identifier,
                                vec![],
                                vec![new_owner.0],
                                2,
                                vec![keys1.0],
                                vec![]);
        assert_eq!(another_new_structured_data.add_signature(&new_owner.1).ok(), Some(0));
        assert_eq!(another_new_structured_data.verify_previous_owner_signatures().ok(), Some(()));
        match orig_structured_data.replace_with_other(another_new_structured_data) {
            Ok(()) => println!("All good"),
            Err(e) => panic!("Error {}", e),
        }


    }

}

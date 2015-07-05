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
use std::str;

/// StructuredData
#[derive(Clone, RustcDecodable, RustcEncodable)]
pub struct StructuredData {
    type_tag: u64,
    identifier: crypto::hash::sha512::Digest,
    data: Vec<u8>,
    owner_keys: Vec<crypto::sign::PublicKey>,
    version: u64,
    previous_owner_keys: Vec<crypto::sign::PublicKey>,
    signatures: Vec<crypto::sign::Signature>
}


impl StructuredData {
    
    /// Constructor
    pub fn new(type_tag: u64,
               identifier: crypto::hash::sha512::Digest,
               data: Vec<u8>, 
               owner_keys: Vec<crypto::sign::PublicKey>, 
               version: u64, previous_owner_keys: Vec<crypto::sign::PublicKey>, 
               signatures: Vec<crypto::sign::Signature>) -> StructuredData {
        
        StructuredData { 
                   type_tag: type_tag,
                   identifier: identifier,
                   data: data,
                   owner_keys: owner_keys,
                   version: version,
                   previous_owner_keys : previous_owner_keys,
                   signatures: signatures
                 }
    }
    /// replace this data item with an updated version if such exists, otherwise fail.
    /// Returns the replaced (new) StructuredData 
    /// This is done this way to allow types to be created and signatures added one by one
    pub fn replace_with_other(self, other: StructuredData) -> Result<StructuredData, RoutingError> {
        if try!(other.name()) != try!(self.name()) { return Err(RoutingError::UnknownMessageType)}
        if other.version != self.version + 1 { return Err(RoutingError::UnknownMessageType)}
        if other.previous_owner_keys != self.owner_keys || other.owner_keys != self.owner_keys { 
            return Err(RoutingError::UnknownMessageType)
        }
        try!(other.verify_signatures());
        
        Ok(StructuredData { 
                   type_tag: other.type_tag,
                   identifier: other.identifier,
                   data: other.data,
                   owner_keys: other.owner_keys,
                   version: other.version,
                   previous_owner_keys : other.previous_owner_keys,
                   signatures: other.signatures
                 })
    }

    /// Returns name and validates invariants
    pub fn name(&self) -> Result<NameType, RoutingError> {
        let test = try!(str::from_utf8(&self.identifier.0)).to_owned() + &self.type_tag.to_string();
        Ok(NameType::new(crypto::hash::sha512::hash(&test.as_bytes()).0))
    }
    
    /// Confirms *unique and valid* signatures are at least 50% of total owners 
    pub fn verify_signatures(&self) -> Result<(), RoutingError> {
         // Refuse any duplicate signatures (people can have many owner keys)
         // Any duplicates invalidates this type
         if self.signatures.iter().filter(|&sig| self.signatures.iter()
                                  .any(|ref sig_check| NameType(sig.0) == NameType(sig_check.0)))
                                  .count() > 0 {
                                        
            return Err(RoutingError::DuplicateSignatures); 
         }
         // Refuse when not enough signatures found
         if self.signatures.len() < (self.owner_keys.len()  + 1 ) / 2 { 
             return Err(RoutingError::NotEnoughSignatures); 
         } 
         
         let data = try!(self.data_to_sign());
         // Count valid signatures and refuse if quantity is not enough  
         if self.signatures.iter()
                        .filter(|&sig| self.owner_keys
                          .iter()
                          .any(|ref pub_key| crypto::sign::verify_detached(&sig, &data, &pub_key)))
                            .count() < self.owner_keys.len() / 2 { 
            return Err(RoutingError::NotEnoughSignatures); 
         }
         Ok(()) 
    }
    
    fn data_to_sign(&self)->Result<Vec<u8>, RoutingError> {
        // seems overkill to use serialisation here, but done
        // to ensure cross platform signature handling is OK
        let mut enc = cbor::Encoder::from_memory();
        try!(enc.encode(self.type_tag.to_string().as_bytes()));
        try!(enc.encode(&self.identifier[..])); 
        try!(enc.encode(&self.data));
        try!(enc.encode(&self.owner_keys)); 
        try!(enc.encode(&self.previous_owner_keys)); 
        try!(enc.encode(self.version.to_string().as_bytes()));
        Ok(enc.as_bytes().into_iter().map(|&x| x).collect())
    }

    /// Returns number of signatures still required (if any, 0 means this is complete)
    pub fn add_signature(mut self, secret_key: &crypto::sign::SecretKey) -> Result<isize, RoutingError> {
        let data = try!(self.data_to_sign());
        let sig = crypto::sign::sign_detached(&data, secret_key);
        self.signatures.push(sig);
        Ok(((self.owner_keys.len() + 1) as isize / 2) - self.signatures.len() as isize)
    }
}


#[cfg(test)]
mod test {
    use sodiumoxide::crypto;
    use super::StructuredData;
    // use error::RoutingError;

    #[test]
    fn single_owner() {
        let keys = crypto::sign::gen_keypair();

        let structured_data =   StructuredData::new(0, 
                                crypto::hash::sha512::hash("test_identity".to_string().as_bytes()),
                                vec![], 
                                vec![keys.0], 
                                0,
                                vec![], 
                                vec![]);
        match structured_data.verify_signatures() {
            Ok(()) => panic!("Should not verifiy signature"),
            Err(e) => println!("Passed with error {}", e),
            }
        
        match structured_data.add_signature(&keys.1) {
            Ok(o) => println!("Added sig, {} remaining", o),
            Err(e) => panic!("Error {}" , e),    
        }

    }

    #[test]
    fn dual_owners() {
        let keys1 = crypto::sign::gen_keypair();
        let keys2 = crypto::sign::gen_keypair();
        let structured_data =   StructuredData::new(0, 
                                crypto::hash::sha512::hash("test_identity".to_string().as_bytes()),
                                vec![], 
                                vec![keys1.0, keys2.0], 
                                0,
                                vec![], 
                                vec![]);
       { 
        match structured_data.add_signature(&keys1.1.clone()) {
            Err(ref e) => println!("Added sig, {} remaining", e),
            Ok(o) => panic!("Error should not pass with {} sigs remaining", o),    
        }
       }
        // match structured_data.add_signature(&keys2.1.clone()) {
        //     Ok(o) => println!("Added sig, {} remaining", o),
        //     Err(ref e) => panic!("Error {}" , e),    
        // }
    
    }
}


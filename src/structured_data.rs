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
use error::{RoutingError, DataError};
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
               signatures: Vec<crypto::sign::Signature>) -> Result<StructuredData, RoutingError> {
        
        Ok(StructuredData { 
                   type_tag: type_tag,
                   identifier: identifier,
                   data: data,
                   owner_keys: owner_keys,
                   version: version,
                   previous_owner_keys : previous_owner_keys,
                   signatures: signatures
                 })
    }

    /// Returns name and validates invariants
    pub fn name(&self) -> Result<NameType, RoutingError> {
        let test = try!(str::from_utf8(&self.identifier.0)).to_owned() + &self.type_tag.to_string();
        Ok(NameType::new(crypto::hash::sha512::hash(&test.as_bytes()).0))
    }
    
    /// Return an error if there are any problems 
    pub fn verify_signatures(&self) -> Result<(), RoutingError> {
         if self.signatures.len() < self.owner_keys.len() / 2 { 
             return Err(RoutingError::NotEnoughSignatures); 
         } 
         // TODO(dirvine) Check all sigs are unique  :05/07/2015
         let data = try!(self.data_to_sign());
         if self.signatures.iter()
                      .filter(|&sig| self.owner_keys.iter()
                        .any(|ref pub_key| crypto::sign::verify_detached(&sig, &data, &pub_key)))
                        .count() < self.owner_keys.len() / 2 { 
                            return Err(RoutingError::NotEnoughSignatures); 
         }
         Ok(()) 
    }
    
    fn data_to_sign(&self)->Result<Vec<u8>, RoutingError> {
        let mut enc = cbor::Encoder::from_memory();

        try!(enc.encode(self.type_tag.to_string().as_bytes()));
        try!(enc.encode(&self.identifier[..])); 
        try!(enc.encode(&self.data));
        try!(enc.encode(&self.owner_keys)); 
        try!(enc.encode(self.version.to_string().as_bytes()));
        Ok(enc.as_bytes().into_iter().map(|&x| x).collect())
    }

    /// Returns number of signatures still required (if any, 0 means this is complete)
    pub fn add_signatures(mut self, secret_key: &crypto::sign::SecretKey) -> Result<(), RoutingError> {
        let data = try!(self.data_to_sign());
        let sig = crypto::sign::sign_detached(&data, secret_key);
        self.signatures.push(sig);
        Ok(())
    }
}


#[cfg(test)]
mod test {
    // use super::*;

    #[test]
    fn works() {
    }
}


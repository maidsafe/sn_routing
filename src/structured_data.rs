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

use cbor;
use cbor::{Encoder, Decoder, DirectDecoder, Cbor, CborBytes, CborTagEncode};
use rustc_serialize::{Decodable, Encodable};
use rustc_serialize;
use rustc_serialize::json::{self, Json, ToJson};
use std::collections::BTreeMap;
// use helper::*;
use error::{RoutingError, DataError};
use NameType;
use sendable::Sendable;
use std::fmt;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto;

// fn serialise(&self) -> cbor::CborResult<Vec<u8>> {
//     let mut encoder = cbor::Encoder::from_memory();
//     return encoder.encode(&[&self]).map(|()| encoder.into_bytes());
// }
// TODO(dirvine) This ia a huge hack for now, we should sort serialising arrays, 
// it's on the cards but to slow for us. So we will have a hack to do this with for now. 
// It will collide with anyone else though who wants to implement array encode/decode  :21/06/2015
// impl Decodable for [u8; 32] {
//     fn decode<D: Decoder>(d: &mut D)-> Result<[u8; 32], D::Error> {
//         d.read_seq(|decoder, len| {
//         if len != 32 {
//             return Err(decoder.error(&format!("Expecting array of length: {}, but found {}", 32, len)));
//         }
//         let mut arr = [0u8; 32];
//         for (i, val) in arr.iter_mut().enumerate() {
//             *val = try!(decoder.read_seq_elt(i, Decodable::decode));
//         }
//         Ok(arr)
//         })
//     }
// }
//

// ####################### End of hack ################################

fn encode<T: Encodable>(v: T) -> Vec<u8> {
    let mut enc = Encoder::from_memory();
    enc.encode(&[v]).unwrap();
    enc.as_bytes().to_vec()
}

#[derive(Clone, Debug, PartialEq, Eq, RustcEncodable, RustcDecodable)]
pub struct PublicSignKey(pub [u8; crypto::sign::PUBLICKEYBYTES]);

impl PublicSignKey {
   fn new(key: crypto::sign::PublicKey) -> PublicSignKey {
         let mut tmp = [0u8; crypto::sign::PUBLICKEYBYTES];
         tmp.clone_from_slice(&key[..]);
         PublicSignKey(tmp)
       }
   
  fn as_crypto_public_key(&self) -> crypto::sign::PublicKey {
         let mut tmp = [0u8; crypto::sign::PUBLICKEYBYTES];
         tmp.clone_from_slice(&self[..]);
         crypto::sign::PublicKey(tmp)
   }
}

impl ::std::ops::Index<::std::ops::Range<usize>> for PublicSignKey {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
        let &PublicSignKey(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeTo<usize>> for PublicSignKey {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
        let &PublicSignKey(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for PublicSignKey {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
        let &PublicSignKey(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeFull> for PublicSignKey {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
        let &PublicSignKey(ref b) = self;
        b.index(_index)
    }
}


#[derive(RustcEncodable)]
pub struct Signature(pub [u8; crypto::sign::SIGNATUREBYTES]);

impl Signature {
   fn new(key: crypto::sign::Signature) -> Signature {
         let mut tmp = [0u8; crypto::sign::SIGNATUREBYTES];
         tmp.clone_from_slice(&key[..]);
         Signature(tmp)
   }
   
   fn as_crypto_sig(&self) -> crypto::sign::Signature {
         let mut tmp = [0u8; crypto::sign::SIGNATUREBYTES];
         tmp.clone_from_slice(&self[..]);
         crypto::sign::Signature(tmp)
   }
}


impl ::std::ops::Index<::std::ops::Range<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
        let &Signature(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeTo<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
        let &Signature(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for Signature {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
        let &Signature(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeFull> for Signature {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
        let &Signature(ref b) = self;
        b.index(_index)
    }
}

impl Clone for Signature {
      fn clone(&self) -> Self {
        let &Signature(v) = self;
            Signature(v)  
        }

}

impl Decodable for Signature {
    fn decode<D: rustc_serialize::Decoder>(d: &mut D)-> Result<Signature, D::Error> {
        d.read_seq(|decoder, len| {
        if len != crypto::sign::SIGNATUREBYTES {
            return Err(decoder.error(&format!("Expecting array of length: {}, but found {}", crypto::sign::SIGNATUREBYTES, len)));
        }
        let mut arr = [0u8; crypto::sign::SIGNATUREBYTES];
        for (i, val) in arr.iter_mut().enumerate() {
            *val = try!(decoder.read_seq_elt(i, Decodable::decode));
        }
        Ok(Signature(arr))
        })
    }
}


/// FixedStructuredData
#[derive(Clone, RustcDecodable, RustcEncodable)]
pub struct FixedStructuredData {
    type_tag: u64,
    data: Vec<u8>,
    owner_keys: Vec<PublicSignKey>,
    version: u64,
    signatures: Vec<Signature>
}


impl FixedStructuredData {
    /// Constructor
    pub fn new(type_tag: u64, data: Vec<u8>, owner_keys: Vec<PublicSignKey>, version: u64, signatures: Vec<Signature>) -> Result<FixedStructuredData, RoutingError> {
        
        Ok(FixedStructuredData { 
                   type_tag: type_tag,
                   data: data,
                   owner_keys: owner_keys,
                   version: version,
                   signatures: signatures
                 })
    }

    pub fn name(&self) -> Result<NameType, RoutingError> {
        let mut enc = encode(&self.type_tag);
        enc.extend(encode(&self.owner_keys).iter().map(|&x| x));
        Ok(NameType::new(crypto::hash::sha512::hash(&enc).0))
    }

    fn verify_signatures(type_tag: u64, data: &[u8], owner_keys: &[PublicSignKey], version: u64, signatures: &[Signature]) -> Result<(), DataError> {
         if signatures.len() < owner_keys.len() / 2 { return Err(DataError::NotEnoughSignatures); } 
         if signatures.iter().filter(|&sig| owner_keys.iter().any(|ref pub_key| crypto::sign::verify_detached(&sig.as_crypto_sig(), data, &pub_key.as_crypto_public_key()))).count() < owner_keys.len() / 2 { return Err(DataError::NotEnoughSignatures); }
         Ok(()) 
    }
    
    fn add_signatures(type_tag: u64, data: &[u8], owner_keys: &[PublicSignKey], version: u64, signatures: &[Signature]) -> Result<(), DataError> {
         if signatures.len() < owner_keys.len() / 2 { return Err(DataError::NotEnoughSignatures); } 
         if signatures.iter().filter(|&sig| owner_keys.iter().any(|ref pub_key| crypto::sign::verify_detached(&sig.as_crypto_sig(), data, &pub_key.as_crypto_public_key()))).count() < owner_keys.len() / 2 { return Err(DataError::NotEnoughSignatures); }
         Ok(()) 
    }

}



//
//
// impl Encodable for FixedStructuredData {
//     fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
//         cbor::CborTagEncode::new(5483_003, &(&self.type_tag, &self.data, &self.owner_keys, &self.version, &self.signatures)).encode(e)
//     }
// }

// impl Decodable for FixedStructuredData {
//     fn decode<D: Decoder>(d: &mut D) -> Result<FixedStructuredData, D::Error> {
//         try!(d.read_u64());
//         let (type_tag, data, owner_keys, version, signatures) = try!(Decodable::decode(d));
//         let s = FixedStructuredData { 
//                                   type_tag: type_tag,
//                                   data: data,
//                                   owner_keys: owner_keys,
//                                   version: version,
//                                   signatures: signatures
//                                 };
//         Ok(s)
//     }
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn works() {
    }
}


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

#![allow(unused_assignments)]

use sodiumoxide::crypto;
use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use rand::random;
use sodiumoxide;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::asymmetricbox;
use NameType;
use std::fmt;
use error::ResponseError;

pub fn array_as_vector(arr: &[u8]) -> Vec<u8> {
  let mut vector = Vec::new();
  for i in arr.iter() {
    vector.push(*i);
  }
  vector
}

pub fn vector_as_u8_64_array(vector: Vec<u8>) -> [u8;64] {
  let mut arr = [0u8;64];
  for i in (0..64) {
    arr[i] = vector[i];
  }
  arr
}

pub fn vector_as_u8_32_array(vector: Vec<u8>) -> [u8;32] {
  let mut arr = [0u8;32];
  for i in (0..32) {
    arr[i] = vector[i];
  }
  arr
}

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for i in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

pub static GROUP_SIZE: usize = 32;
pub static QUORUM_SIZE: usize = 19;

pub trait Mergeable {
    fn merge<'a, I>(xs: I) -> Option<Self> where I: Iterator<Item=&'a Self>;
}

pub type MessageId = u32;
pub type NodeAddress = NameType; // (Address, NodeTag)
pub type GroupAddress = NameType; // (Address, GroupTag)
pub type SerialisedMessage = Vec<u8>;
pub type IdNode = NameType;
pub type IdNodes = Vec<IdNode>;
pub type Bytes = Vec<u8>;

//#[derive(RustcEncodable, RustcDecodable)]
struct SignedKey {
  sign_public_key: crypto::sign::PublicKey,
  encrypt_public_key: crypto::asymmetricbox::PublicKey,
  signature: crypto::sign::Signature, // detached signature
}

pub enum MessageAction {
  Reply(Vec<u8>),
  SendOn(Vec<NameType>),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct NameAndTypeId {
  pub name : NameType,
  pub type_id : u64
}

impl Encodable for NameAndTypeId {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.name, &self.type_id)).encode(e)
  }
}

impl Decodable for NameAndTypeId {
  fn decode<D: Decoder>(d: &mut D)->Result<NameAndTypeId, D::Error> {
    try!(d.read_u64());
    let (name, type_id) = try!(Decodable::decode(d));
    Ok(NameAndTypeId { name: name, type_id: type_id })
  }
}

pub type FilterType = (NameType, MessageId);

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Signature {
  pub signature : Vec<u8>
}

impl Signature {
  pub fn new(signature : crypto::sign::Signature) -> Signature {
    assert_eq!(signature.0.len(), 64);
    Signature {
      signature : signature.0.to_vec()
    }
  }

  pub fn get_crypto_signature(&self) -> crypto::sign::Signature {
    crypto::sign::Signature(vector_as_u8_64_array(self.signature.clone()))
  }
}

impl Encodable for Signature {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.signature)).encode(e)
  }
}

impl Decodable for Signature {
  fn decode<D: Decoder>(d: &mut D)->Result<Signature, D::Error> {
    try!(d.read_u64());
    let signature = try!(Decodable::decode(d));
    Ok(Signature { signature: signature })
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct PublicSignKey {
  pub public_sign_key : Vec<u8>
}

impl PublicSignKey {
  pub fn new(public_sign_key : crypto::sign::PublicKey) -> PublicSignKey {
    assert_eq!(public_sign_key.0.len(), 32);
    PublicSignKey{
      public_sign_key : public_sign_key.0.to_vec()
    }
  }

  pub fn get_crypto_public_sign_key(&self) -> crypto::sign::PublicKey {
    crypto::sign::PublicKey(vector_as_u8_32_array(self.public_sign_key.clone()))
  }
}

impl fmt::Debug for PublicSignKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicSignKey({:?})", self.public_sign_key.iter().take(6).collect::<Vec<_>>())
    }
}


impl Encodable for PublicSignKey {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.public_sign_key)).encode(e)
  }
}

impl Decodable for PublicSignKey {
  fn decode<D: Decoder>(d: &mut D)->Result<PublicSignKey, D::Error> {
    try!(d.read_u64());
    let public_sign_key = try!(Decodable::decode(d));
    Ok(PublicSignKey { public_sign_key: public_sign_key })
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct PublicKey {
  pub public_key : Vec<u8>
}

impl PublicKey {
  pub fn new(public_key : crypto::asymmetricbox::PublicKey) -> PublicKey {
    PublicKey{
      public_key : public_key.0.to_vec()
    }
  }

  pub fn get_crypto_public_key(&self) -> crypto::asymmetricbox::PublicKey {
    crypto::asymmetricbox::PublicKey(vector_as_u8_32_array(self.public_key.clone()))
  }
}

impl Encodable for PublicKey {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.public_key)).encode(e)
  }
}

impl Decodable for PublicKey {
  fn decode<D: Decoder>(d: &mut D)->Result<PublicKey, D::Error> {
    try!(d.read_u64());
    let public_key = try!(Decodable::decode(d));
    Ok(PublicKey { public_key: public_key })
  }
}

// TODO(Team): Below method should be modified and reused in constructor of Id.
fn calculate_original_name(public_key: &crypto::sign::PublicKey,
                           public_sign_key: &crypto::asymmetricbox::PublicKey,
                           validation_token: &Signature) -> NameType {
    let combined_iter = public_key.0.into_iter().chain(public_sign_key.0.into_iter())
          .chain((&validation_token.signature).into_iter());
    let mut combined: Vec<u8> = Vec::new();
    for iter in combined_iter {
        combined.push(*iter);
    }
    NameType(crypto::hash::sha512::hash(&combined).0)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct PublicId {
  pub public_key: PublicKey,
  pub public_sign_key: PublicSignKey,
  pub validation_token: Signature,
  name: NameType,
}

impl PublicId {
    pub fn new(id : &Id) -> PublicId {
      PublicId {
        public_key : id.get_public_key(),
        public_sign_key : id.get_public_sign_key(),
        validation_token : id.get_validation_token(),
        name : id.get_name().clone(),
      }
    }

    pub fn name(&self) -> NameType {
      self.name.clone()
    }

    pub fn serialised_contents(&self)->Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    // checks if the name is updated to a relocated name
    pub fn is_relocated(&self) -> bool {
        self.name !=  calculate_original_name(&self.public_sign_key.get_crypto_public_sign_key(),
                                              &self.public_key.get_crypto_public_key(),
                                              &self.validation_token)
    }

    // name field is initially same as original_name, this should be replaced by relocated name
    // calculated by the nodes close to original_name by using this method
    pub fn assign_relocated_name(&mut self, relocated_name: NameType) -> bool {
        if self.is_relocated() || self.name == relocated_name {
            return false;
        }
        self.name = relocated_name;
        return true;
    }
}

impl Encodable for PublicId {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.public_key,
                                   &self.public_sign_key,
                                   &self.validation_token,
                                   &self.name)).encode(e)
  }
}

impl Decodable for PublicId {
  fn decode<D: Decoder>(d: &mut D)->Result<PublicId, D::Error> {
    try!(d.read_u64());
    let (public_key, public_sign_key, validation_token, name) = try!(Decodable::decode(d));
    Ok(PublicId { public_key: public_key,
                    public_sign_key : public_sign_key,
                    validation_token: validation_token, name : name})
  }
}

// Note: name field is initially same as original_name, this should be later overwritten by
// relocated name provided by the network using assign_relocated_name method
// TODO (ben 2015-04-01) : implement order based on name
#[derive(Clone)]
pub struct Id {
  public_keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::asymmetricbox::SecretKey),
  validation_token: Signature,
  name: NameType,
}

impl Id {
  pub fn new() -> Id {
    let (pub_sign_key, sec_sign_key) = sodiumoxide::crypto::sign::gen_keypair();
    let (pub_asym_key, sec_asym_key) = sodiumoxide::crypto::asymmetricbox::gen_keypair();

    let sign_key = &pub_sign_key.0;
    let asym_key = &pub_asym_key.0;

    const KEYS_SIZE: usize = sign::PUBLICKEYBYTES + asymmetricbox::PUBLICKEYBYTES;

    let mut keys = [0u8; KEYS_SIZE];

    for i in 0..sign_key.len() {
        keys[i] = sign_key[i];
    }
    for i in 0..asym_key.len() {
        keys[sign::PUBLICKEYBYTES + i] = asym_key[i];
    }

    let validation_token = Signature::new(crypto::sign::sign_detached(&keys, &sec_sign_key));

    let mut combined = [0u8; KEYS_SIZE + sign::SIGNATUREBYTES];

    for i in 0..KEYS_SIZE {
        combined[i] = keys[i];
    }

    for i in 0..sign::SIGNATUREBYTES {
        combined[KEYS_SIZE + i] = validation_token.signature[i];
    }

    let digest = crypto::hash::sha512::hash(&combined);

    Id {
      public_keys : (pub_sign_key, pub_asym_key),
      secret_keys : (sec_sign_key, sec_asym_key),
      validation_token : validation_token,
      name : NameType::new(digest.0),
    }
  }

  pub fn get_name<'a>(&'a self) -> &'a NameType {
      &self.name
  }

  pub fn get_public_key(&self) -> PublicKey {
      PublicKey::new(self.public_keys.1.clone())
  }
  pub fn get_public_sign_key(&self) -> PublicSignKey {
      PublicSignKey::new(self.public_keys.0.clone())
  }
  pub fn get_crypto_public_key(&self) -> crypto::asymmetricbox::PublicKey {
      self.public_keys.1.clone()
  }
  pub fn get_crypto_secret_key(&self) -> crypto::asymmetricbox::SecretKey {
      self.secret_keys.1.clone()
  }
  pub fn get_crypto_public_sign_key(&self) -> crypto::sign::PublicKey {
      self.public_keys.0.clone()
  }
  pub fn get_crypto_secret_sign_key(&self) -> crypto::sign::SecretKey {
      self.secret_keys.0.clone()
  }
  pub fn get_validation_token(&self) -> Signature {
      self.validation_token.clone()
  }
  // checks if the name is updated to a relocated name
  pub fn is_relocated(&self) -> bool {
      self.name !=  calculate_original_name(&self.public_keys.0, &self.public_keys.1, &self.validation_token)
  }

  // name field is initially same as original_name, this should be later overwritten by
  // relocated name provided by the network using this method
  pub fn assign_relocated_name(&mut self, relocated_name: NameType) -> bool {
      if self.is_relocated() || self.name == relocated_name {
          return false;
      }
      self.name = relocated_name;
      return true;
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct AccountTransferInfo {
  pub name : NameType
}

impl Encodable for AccountTransferInfo {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.name)).encode(e)
  }
}

impl Decodable for AccountTransferInfo {
  fn decode<D: Decoder>(d: &mut D)->Result<AccountTransferInfo, D::Error> {
    try!(d.read_u64());
    let name = try!(Decodable::decode(d));
    Ok(AccountTransferInfo { name: name })
  }
}

/// Address of the source of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct SourceAddress {
  pub from_node  : NameType,
  pub from_group : Option<NameType>,
  pub reply_to   : Option<NameType>
}

impl Encodable for SourceAddress {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_102 , &(&self.from_node, &self.from_group, &self.reply_to)).encode(e)
  }
}

impl Decodable for SourceAddress {
  fn decode<D: Decoder>(d: &mut D)->Result<SourceAddress, D::Error> {
    try!(d.read_u64());
    let (from_node, from_group, reply_to) = try!(Decodable::decode(d));
    Ok(SourceAddress { from_node: from_node, from_group: from_group, reply_to: reply_to })
  }
}

/// Address of the destination of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct DestinationAddress {
  pub dest : NameType,
  pub reply_to : Option<NameType>
}

impl Encodable for DestinationAddress {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_101, &(&self.dest, &self.reply_to)).encode(e)
  }
}

impl Decodable for DestinationAddress {
  fn decode<D: Decoder>(d: &mut D)->Result<DestinationAddress, D::Error> {
    try!(d.read_u64());
    let (dest, reply_to) = try!(Decodable::decode(d));
    Ok(DestinationAddress { dest: dest, reply_to: reply_to })
  }
}

impl Encodable for ResponseError {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let mut type_tag;
        match *self {
            ResponseError::NoData => type_tag = "NoData",
            ResponseError::InvalidRequest => type_tag = "InvalidRequest",
        };
        CborTagEncode::new(5483_100, &(&type_tag)).encode(e)
    }
}

impl Decodable for ResponseError {
    fn decode<D: Decoder>(d: &mut D)->Result<ResponseError, D::Error> {
        try!(d.read_u64());
        let mut type_tag : String;
        type_tag = try!(Decodable::decode(d));
        match &type_tag[..] {
            "NoData" => Ok(ResponseError::NoData),
            "InvalidRequest" => Ok(ResponseError::InvalidRequest),
            _ => Err(d.error("Unrecognised ResponseError"))
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
  extern crate cbor;
  use super::*;
  use rand::random;
  use rustc_serialize::{Decodable, Encodable};
  use test_utils::Random;
  use authority::Authority;
  use NameType;

  pub fn generate_address() -> Vec<u8> {
    let mut address: Vec<u8> = vec![];
    for _ in (0..64) {
      address.push(random::<u8>());
    }
    address
  }

  fn test_object<T>(obj_before : T) where T: for<'a> Encodable + Decodable + Eq {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&obj_before]).unwrap();
    let mut d = cbor::Decoder::from_bytes(e.as_bytes());
    let obj_after: T = d.decode().next().unwrap().unwrap();
    assert_eq!(obj_after == obj_before, true)
  }

  #[test]
  fn test_authority() {
    test_object(Authority::ClientManager);
    test_object(Authority::NaeManager);
    test_object(Authority::NodeManager);
    test_object(Authority::ManagedNode);
    test_object(Authority::Client);
    test_object(Authority::Unknown);
  }

  #[test]
  fn test_destination_address() {
    test_object(DestinationAddress { dest: Random::generate_random(), reply_to: None });
  }

  #[test]
  fn test_source_address() {

    test_object(SourceAddress { from_node : Random::generate_random(),
                                from_group : None,
                                reply_to: None });
  }

#[test]
    fn serialisation_public_id() {
        let obj_before = PublicId::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: PublicId = d.decode().next().unwrap().unwrap();
        assert_eq!(obj_before, obj_after);
    }


#[test]
    fn assign_relocated_name_public_id() {
        let before = PublicId::generate_random();
        let original_name = before.name();
        assert!(!before.is_relocated());
        let relocated_name: NameType = Random::generate_random();
        let mut relocated = before.clone();
        assert!(!relocated.assign_relocated_name(original_name.clone()));

        assert!(relocated.assign_relocated_name(relocated_name.clone()));

        assert!(!relocated.assign_relocated_name(relocated_name.clone()));
        assert!(!relocated.assign_relocated_name(Random::generate_random()));
        assert!(!relocated.assign_relocated_name(original_name.clone()));

        assert!(relocated.is_relocated());
        assert_eq!(relocated.name(), relocated_name);
        assert!(before.name()!= relocated.name());
        assert_eq!(before.public_key, relocated.public_key);
        assert_eq!(before.public_sign_key, relocated.public_sign_key);
        assert_eq!(before.validation_token, relocated.validation_token);
    }

#[test]
    fn assign_relocated_name_id() {
        let before = Id::new();
        let original_name = before.get_name();
        assert!(!before.is_relocated());
        let relocated_name: NameType = Random::generate_random();
        let mut relocated = before.clone();
        assert!(!relocated.assign_relocated_name(original_name.clone()));

        assert!(relocated.assign_relocated_name(relocated_name.clone()));

        assert!(!relocated.assign_relocated_name(relocated_name.clone()));
        assert!(!relocated.assign_relocated_name(Random::generate_random()));
        assert!(!relocated.assign_relocated_name(original_name.clone()));


        assert!(relocated.is_relocated());
        assert_eq!(relocated.get_name().clone(), relocated_name);
        assert!(before.get_name()!= relocated.get_name());
        assert_eq!(before.get_public_key(), relocated.get_public_key());
        assert_eq!(before.get_public_sign_key(), relocated.get_public_sign_key());
        assert_eq!(before.get_crypto_public_key().0.to_vec(), relocated.get_crypto_public_key().0.to_vec());
        assert_eq!(before.get_crypto_secret_key().0.to_vec(), relocated.get_crypto_secret_key().0.to_vec());
        assert_eq!(before.get_crypto_public_sign_key().0.to_vec(), relocated.get_crypto_public_sign_key().0.to_vec());
        assert_eq!(before.get_crypto_secret_sign_key().0.to_vec(), relocated.get_crypto_secret_sign_key().0.to_vec());
        assert_eq!(before.get_validation_token(), relocated.get_validation_token());
    }
}

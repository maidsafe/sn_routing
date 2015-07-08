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
use sodiumoxide::crypto::sign::Signature;
use sodiumoxide::crypto::box_;
use std::cmp;
use NameType;
use name_type::closer_to_target;
use std::fmt;
use error::{RoutingError};

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
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

pub static GROUP_SIZE: usize = 8;
pub static QUORUM_SIZE: usize = 6;

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

#[derive(RustcEncodable, RustcDecodable)]
struct SignedKey {
  sign_public_key: crypto::sign::PublicKey,
  encrypt_public_key: crypto::box_::PublicKey,
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

//                        +-> from_node name
//                        |           +-> preserve the message_id when sending on
//                        |           |         +-> destination name
//                        |           |         |
pub type FilterType = (NameType, MessageId, NameType);

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
  pub fn new(public_key : crypto::box_::PublicKey) -> PublicKey {
    PublicKey{
      public_key : public_key.0.to_vec()
    }
  }

  pub fn get_crypto_public_key(&self) -> crypto::box_::PublicKey {
    crypto::box_::PublicKey(vector_as_u8_32_array(self.public_key.clone()))
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

// relocated_name = Hash(original_name + 1st closest node id + 2nd closest node id)
// In case of only one close node provided (in initial network setup scenario),
// relocated_name = Hash(original_name + 1st closest node id)
pub fn calculate_relocated_name(mut close_nodes: Vec<NameType>,
                                original_name: &NameType) -> Result<NameType, RoutingError> {
    if close_nodes.is_empty() {
        return Err(RoutingError::RoutingTableEmpty);
    }
    close_nodes.sort_by(|a, b| if closer_to_target(&a, &b, original_name) {
                                  cmp::Ordering::Less
                                } else {
                                    cmp::Ordering::Greater
                                });
    close_nodes.truncate(2usize);
    close_nodes.insert(0, original_name.clone());

    let mut combined: Vec<u8> = Vec::new();
    for node_id in close_nodes {
      for i in node_id.get_id().iter() {
        combined.push(*i);
      }
    }
    Ok(NameType(crypto::hash::sha512::hash(&combined).0))
}

// A self_relocated id, is purely used for a zero-node to bootstrap a network.
// Such a node will be rejected by the network once routing tables fill up.
pub fn calculate_self_relocated_name(public_key: &crypto::sign::PublicKey,
                           public_sign_key: &crypto::box_::PublicKey,
                           validation_token: &Signature) -> NameType {
    let original_name = calculate_original_name(public_key, public_sign_key,
        validation_token);
    NameType(crypto::hash::sha512::hash(&original_name.0.to_vec()).0)
}

// TODO(Team): Below method should be modified and reused in constructor of Id.
fn calculate_original_name(public_key: &crypto::sign::PublicKey,
                           public_sign_key: &crypto::box_::PublicKey,
                           validation_token: &Signature) -> NameType {
    let combined_iter = public_key.0.into_iter().chain(public_sign_key.0.into_iter())
          .chain((&validation_token[..]).into_iter());
    let mut combined: Vec<u8> = Vec::new();
    for iter in combined_iter {
        combined.push(*iter);
    }
    NameType(crypto::hash::sha512::hash(&combined).0)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
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
        name : id.get_name(),
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

    // checks if the name is equal to the self_relocated name
    pub fn is_self_relocated(&self) -> bool {
        self.name ==  calculate_self_relocated_name(
            &self.public_sign_key.get_crypto_public_sign_key(),
            &self.public_key.get_crypto_public_key(), &self.validation_token)
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

// Note: name field is initially same as original_name, this should be later overwritten by
// relocated name provided by the network using assign_relocated_name method
// TODO (ben 2015-04-01) : implement order based on name
#[derive(Clone)]
pub struct Id {
  public_keys: (crypto::sign::PublicKey, crypto::box_::PublicKey),
  secret_keys: (crypto::sign::SecretKey, crypto::box_::SecretKey),
  validation_token: Signature,
  name: NameType,
}

impl Id {
  pub fn new() -> Id {
    let (pub_sign_key, sec_sign_key) = sodiumoxide::crypto::sign::gen_keypair();
    let (pub_asym_key, sec_asym_key) = sodiumoxide::crypto::box_::gen_keypair();

    let sign_key = &pub_sign_key.0;
    let asym_key = &pub_asym_key.0;

    const KEYS_SIZE: usize = sign::PUBLICKEYBYTES + box_::PUBLICKEYBYTES;

    let mut keys = [0u8; KEYS_SIZE];

    for i in 0..sign_key.len() {
        keys[i] = sign_key[i];
    }
    for i in 0..asym_key.len() {
        keys[sign::PUBLICKEYBYTES + i] = asym_key[i];
    }

    let validation_token = crypto::sign::sign_detached(&keys, &sec_sign_key);

    let combined : Vec<u8> = asym_key.iter().chain(sign_key.iter())
          .chain((&validation_token[..]).iter()).map(|x| *x).collect();


    let digest = crypto::hash::sha512::hash(&combined);

    Id {
      public_keys : (pub_sign_key, pub_asym_key),
      secret_keys : (sec_sign_key, sec_asym_key),
      validation_token : validation_token,
      name : NameType::new(digest.0),
    }
  }
  pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
    self.public_keys.0.clone()
  }

  pub fn with_keys(public_keys: (crypto::sign::PublicKey, crypto::box_::PublicKey),
                   secret_keys: (crypto::sign::SecretKey, crypto::box_::SecretKey)) -> Id {
    let sign_key = &(public_keys.0).0;
    let asym_key = &(public_keys.1).0;

    const KEYS_SIZE: usize = sign::PUBLICKEYBYTES + box_::PUBLICKEYBYTES;

    let mut keys = [0u8; KEYS_SIZE];

    for i in 0..sign_key.len() {
        keys[i] = sign_key[i];
    }
    for i in 0..asym_key.len() {
        keys[sign::PUBLICKEYBYTES + i] = asym_key[i];
    }

    let validation_token = crypto::sign::sign_detached(&keys, &secret_keys.0);

    let combined : Vec<u8> = asym_key.iter().chain(sign_key.iter())
          .chain((&validation_token[..]).iter()).map(|x| *x).collect();


    let digest = crypto::hash::sha512::hash(&combined);

    Id {
      public_keys : public_keys,
      secret_keys : secret_keys,
      validation_token : validation_token,
      name : NameType::new(digest.0),
    }
  }

  pub fn get_name(&self) -> NameType {
      self.name.clone()
  }

  pub fn get_public_key(&self) -> PublicKey {
      PublicKey::new(self.public_keys.1.clone())
  }
  pub fn get_public_sign_key(&self) -> PublicSignKey {
      PublicSignKey::new(self.public_keys.0.clone())
  }
  pub fn get_crypto_public_key(&self) -> crypto::box_::PublicKey {
      self.public_keys.1.clone()
  }
  pub fn get_crypto_secret_key(&self) -> crypto::box_::SecretKey {
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
      self.name !=  calculate_original_name(&self.public_keys.0,
          &self.public_keys.1, &self.validation_token)
  }

  // checks if the name is equal to the self_relocated name
  pub fn is_self_relocated(&self) -> bool {
      self.name ==  calculate_self_relocated_name(&self.public_keys.0,
          &self.public_keys.1, &self.validation_token)
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

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct AccountTransferInfo {
  pub name : NameType
}

/// Address of the source of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct SourceAddress {
  pub from_node   : NameType,
  pub from_group  : Option<NameType>,
  pub reply_to    : Option<NameType>,
  pub relayed_for : Option<NameType>
}


/// Address of the destination of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct DestinationAddress {
  pub dest     : NameType,
  pub relay_to : Option<NameType>
}


#[cfg(test)]
#[allow(deprecated)]
mod test {
  extern crate cbor;
  use super::*;
  use sodiumoxide::crypto;
  use std::cmp;
  use rustc_serialize::{Decodable, Encodable};
  use test_utils::Random;
  use authority::Authority;
  use NameType;
  use name_type::closer_to_target;
  use sodiumoxide::crypto::sign;

  fn test_object<T>(obj_before : T) where T: for<'a> Encodable + Decodable + Eq {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&obj_before]).unwrap();
    let mut d = cbor::Decoder::from_bytes(e.as_bytes());
    let obj_after: T = d.decode().next().unwrap().unwrap();
    assert_eq!(obj_after == obj_before, true)
  }

  #[test]
  fn construct_id_with_keys() {
    let sign_keys = crypto::sign::gen_keypair();
    let asym_keys = crypto::box_::gen_keypair();

    let public_keys = (sign_keys.0, asym_keys.0);
    let secret_keys = (sign_keys.1, asym_keys.1);

    let id = Id::with_keys(public_keys, secret_keys.clone());

    let sign_key = &(public_keys.0).0;
    let asym_key = &(public_keys.1).0;

    const KEYS_SIZE: usize = crypto::sign::PUBLICKEYBYTES + crypto::box_::PUBLICKEYBYTES;

    let mut keys = [0u8; KEYS_SIZE];

    for i in 0..sign_key.len() {
        keys[i] = sign_key[i];
    }
    for i in 0..asym_key.len() {
        keys[crypto::sign::PUBLICKEYBYTES + i] = asym_key[i];
    }

    let validation_token = crypto::sign::sign_detached(&keys, &secret_keys.0);

    let mut combined = [0u8; KEYS_SIZE + crypto::sign::SIGNATUREBYTES];

    for i in 0..KEYS_SIZE {
        combined[i] = keys[i];
    }

    for i in 0..crypto::sign::SIGNATUREBYTES {
        combined[KEYS_SIZE + i] = validation_token.0[i];
    }

    let digest = crypto::hash::sha512::hash(&combined);

    assert_eq!(NameType::new(digest.0), id.get_name());

  }

  #[test]
  fn test_authority() {
    test_object(Authority::ClientManager(Random::generate_random()));
    test_object(Authority::NaeManager(Random::generate_random()));
    test_object(Authority::NodeManager(Random::generate_random()));
    test_object(Authority::ManagedNode);
    test_object(Authority::Client(sign::gen_keypair().0));
    test_object(Authority::Unknown);
  }

  #[test]
  fn test_destination_address() {
    test_object(DestinationAddress { dest: Random::generate_random(), relay_to: None });
  }

  #[test]
  fn test_source_address() {
      test_object(SourceAddress { from_node : Random::generate_random(), from_group : None, reply_to: None, relayed_for : None });
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
    fn test_calculate_relocated_name() {
        let original_name : NameType = Random::generate_random();

        // empty close nodes
        assert!(calculate_relocated_name(Vec::new(), &original_name).is_err());

        // one entry
        let mut close_nodes_one_entry : Vec<NameType> = Vec::new();
        close_nodes_one_entry.push(Random::generate_random());
        let actual_relocated_name_one_entry = calculate_relocated_name(close_nodes_one_entry.clone(),
                                                                       &original_name).unwrap();
        assert!(original_name != actual_relocated_name_one_entry);

        let mut combined_one_node_vec : Vec<NameType> = Vec::new();
        combined_one_node_vec.push(original_name.clone());
        combined_one_node_vec.push(close_nodes_one_entry[0].clone());

        let mut combined_one_node: Vec<u8> = Vec::new();
        for node_id in combined_one_node_vec {
            for i in node_id.get_id().iter() {
                combined_one_node.push(*i);
            }
        }

        let expected_relocated_name_one_node =
              NameType(crypto::hash::sha512::hash(&combined_one_node).0);

        assert_eq!(actual_relocated_name_one_entry, expected_relocated_name_one_node);

        // populated closed nodes
        let mut close_nodes : Vec<NameType> = Vec::new();
        for _ in 0..GROUP_SIZE {
            close_nodes.push(Random::generate_random());
        }
        let actual_relocated_name = calculate_relocated_name(close_nodes.clone(),
                                                             &original_name).unwrap();
        assert!(original_name != actual_relocated_name);

        close_nodes.sort_by(|a, b| if closer_to_target(&a, &b, &original_name) {
                                  cmp::Ordering::Less
                                } else {
                                    cmp::Ordering::Greater
                                });
        let first_closest = close_nodes[0].clone();
        let second_closest = close_nodes[1].clone();
        let mut combined: Vec<u8> = Vec::new();

        for i in original_name.get_id().into_iter() {
            combined.push(*i);
        }
        for i in first_closest.get_id().into_iter() {
            combined.push(*i);
        }
        for i in second_closest.get_id().into_iter() {
            combined.push(*i);
        }

        let expected_relocated_name = NameType(crypto::hash::sha512::hash(&combined).0);
        assert_eq!(expected_relocated_name, actual_relocated_name);

        let mut invalid_combined: Vec<u8> = Vec::new();
        for i in first_closest.get_id().into_iter() {
            invalid_combined.push(*i);
        }
        for i in second_closest.get_id().into_iter() {
            invalid_combined.push(*i);
        }
        for i in original_name.get_id().into_iter() {
            invalid_combined.push(*i);
        }
        let invalid_relocated_name = NameType(crypto::hash::sha512::hash(&invalid_combined).0);
        assert!(invalid_relocated_name != actual_relocated_name);
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
        assert_eq!(relocated.get_name(), relocated_name);
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

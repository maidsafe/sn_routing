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

// Note: name field is initially same as original_name, this should be later overwritten by
// relocated name provided by the network using assign_relocated_name method
// TODO (ben 2015-04-01) : implement order based on name
#[derive(Clone)]
pub struct Id {
  pub public_keys: (crypto::sign::PublicKey, crypto::box_::PublicKey),
  pub secret_keys: (crypto::sign::SecretKey, crypto::box_::SecretKey),
  validation_token: Signature,
  pub name: NameType,
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
// FIXME(dirvine) Do not clone() secure keys (timing attack possible) :08/07/2015
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

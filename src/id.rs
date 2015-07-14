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
  sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
  encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey),
  relocated_name: Option<NameType>
}

impl Id {
  pub fn new() -> Id {
    Id {
    sign_keys: sodiumoxide::crypto::sign::gen_keypair(),
    encrypt_keys: sodiumoxide::crypto::box_::gen_keypair(),
    relocated_name: None,
    }
  }

  // FIXME: We should not copy private nor public keys.
  // Apparently there are attacks that can exploit this.
  pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
    self.sign_keys.0
  }

  pub fn signing_private_key(&self) -> crypto::sign::SecretKey {
    self.sign_keys.1
  }

  pub fn encrypting_public_key(&self) -> crypto::box_::PublicKey {
    self.encrypt_keys.0
  }

  pub fn with_keys(sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
                   encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey)) -> Id {
    Id {
    sign_keys: sodiumoxide::crypto::sign::gen_keypair(),
    encrypt_keys: sodiumoxide::crypto::box_::gen_keypair(),
    relocated_name: None,
    }
  }

  pub fn name(&self) -> Option<NameType> {
    self.relocated_name
  }

  pub fn get_name(&self) -> NameType {
      // This function should not exist, it is here only temporarily
      // to fix compilation.
      unimplemented!()
  }

  pub fn is_self_relocated(&self) -> bool {
      // This function should not exist, it is here only temporarily
      // to fix compilation.
      unimplemented!()
  }
}

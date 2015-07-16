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
use sodiumoxide;
use NameType;

// Note: name field is initially same as original_name, this should be later overwritten by
// relocated name provided by the network using assign_relocated_name method
// TODO (ben 2015-04-01) : implement order based on name
#[derive(Clone)]
pub struct Id {
  sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
  encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey),
  name: NameType
}

impl Id {
    pub fn new() -> Id {
        Id {
          sign_keys : sodiumoxide::crypto::sign::gen_keypair(),
          encrypt_keys : sodiumoxide::crypto::box_::gen_keypair(),
          name : NameType::new([0u8; 64]),
        }
    }

    // FIXME: We should not copy private nor public keys.
    pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
        self.sign_keys.0
    }

    pub fn signing_private_key(&self) -> &crypto::sign::SecretKey {
        &self.sign_keys.1
    }

    pub fn encrypting_public_key(&self) -> crypto::box_::PublicKey {
        self.encrypt_keys.0
    }

    pub fn with_keys(sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
                     encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey))-> Id {
        Id {
          sign_keys : sign_keys,
          encrypt_keys : encrypt_keys,
          name : NameType::new([0u8; 64]),     
        }
    }

    pub fn name(&self) -> NameType {
      self.name
    }

    pub fn get_name(&self) -> NameType {
        // This function should not exist, it is here only temporarily
        // to fix compilation.
        self.name
    }

    pub fn is_self_relocated(&self) -> bool {
        // This function should not exist, it is here only temporarily
        // to fix compilation.
        self.name != NameType::new([1u8; 64])     
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

    // checks if the name is updated to a relocated name
    pub fn is_relocated(&self) -> bool {
        self.name != NameType::new([0u8; 64])     
    }
}


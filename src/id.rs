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
pub struct Id {
  sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
  encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey),
  name: NameType
}

impl Id {
    pub fn new() -> Id {

        let sign_keys =  sodiumoxide::crypto::sign::gen_keypair();
        let name = NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0);
        Id {
          sign_keys : sign_keys,
          encrypt_keys : sodiumoxide::crypto::box_::gen_keypair(),
          name : name,
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
                     encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey)) -> Id {
        let name = NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0);
        Id {
          sign_keys : sign_keys,
          encrypt_keys : encrypt_keys,
          name : name,
        }
    }

    pub fn name(&self) -> NameType {
      self.name
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
        self.name != NameType::new(crypto::hash::sha512::hash(&self.sign_keys.0[..]).0)
    }
}


// #[cfg(test)]
// mod test {
//     use super::*;
//     use sodiumoxide::crypto;
//     use NameType;
//     use test_utils::Random;
//
//     #[test]
//     fn construct_id_with_keys() {
//       let sign_keys = crypto::sign::gen_keypair();
//       let asym_keys = crypto::box_::gen_keypair();
//
//       // let public_keys = (sign_keys.clone().0, asym_keys.clone().0);
//       // let secret_keys = (sign_keys.clone().1, asym_keys.clone().1);
//
//       let id = Id::with_keys(sign_keys.clone(), asym_keys.clone());
//
//       assert_eq!(NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0),
//           id.name());
//       assert_eq!(&sign_keys.0, &id.signing_public_key());
//       // FIXME(ben) 20/07/2015 once PartialEq is implemented for the private key, avoid slice
//       assert_eq!(&sign_keys.1[..], &id.signing_private_key()[..]);
//       assert_eq!(&asym_keys.0, &id.encrypting_public_key());
//     }
//
//     #[test]
//     fn assign_relocated_name_id() {
//         let before = Id::new();
//         let original_name = before.name();
//         assert!(!before.is_relocated());
//         let relocated_name: NameType = Random::generate_random();
//         let mut relocated = before.clone();
//         relocated.assign_relocated_name(original_name.clone());
//
//         assert!(relocated.assign_relocated_name(relocated_name.clone()));
//
//         assert!(!relocated.assign_relocated_name(relocated_name.clone()));
//         assert!(!relocated.assign_relocated_name(Random::generate_random()));
//         assert!(!relocated.assign_relocated_name(original_name.clone()));
//
//
//         assert!(relocated.is_relocated());
//         assert_eq!(relocated.name(), relocated_name);
//         assert!(before.name()!= relocated.name());
//         assert_eq!(before.signing_public_key(), relocated.signing_public_key());
//         assert_eq!(before.encrypting_public_key().0.to_vec(), relocated.encrypting_public_key().0.to_vec());
//         assert_eq!(before.signing_private_key().0.to_vec(), relocated.signing_private_key().0.to_vec());
//         assert_eq!(before.encrypting_public_key().0.to_vec(), relocated.encrypting_public_key().0.to_vec());
//         assert_eq!(before.signing_private_key().0.to_vec(), relocated.signing_private_key().0.to_vec());
//     }
// }

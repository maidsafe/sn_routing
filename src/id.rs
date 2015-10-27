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
/// Id.
pub struct Id {
    sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
    encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey),
    name: NameType,
}

impl Id {

    /// Contruct new Id.
    pub fn new() -> Id {

        let sign_keys =  sodiumoxide::crypto::sign::gen_keypair();
        let name = NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0);
        Id {
            sign_keys: sign_keys,
            encrypt_keys: sodiumoxide::crypto::box_::gen_keypair(),
            name: name,
        }
    }

    // FIXME: We should not copy private nor public keys.
    /// Public signing key.
    pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
        self.sign_keys.0
    }

    /// Secret signing key.
    pub fn signing_private_key(&self) -> &crypto::sign::SecretKey {
        &self.sign_keys.1
    }

    /// Public encryption key.
    pub fn encrypting_public_key(&self) -> crypto::box_::PublicKey {
        self.encrypt_keys.0
    }

    /// Construct with given keys, (Client requirement).
    pub fn with_keys(sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
                     encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey))
                     -> Id {
        let name = NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0);
        Id { sign_keys: sign_keys, encrypt_keys: encrypt_keys, name: name }
    }

    /// Original/relocated name.
    pub fn name(&self) -> NameType {
        self.name
    }

    /// Name field is initially same as original_name, this should be later overwritten by relocated
    /// name provided by the network using this method
    pub fn assign_relocated_name(&mut self, relocated_name: NameType) -> bool {
        if self.is_relocated() || self.name == relocated_name {
            return false;
        }
        self.name = relocated_name;
        return true;
    }

    /// Checks if the name is updated to a relocated name.
    pub fn is_relocated(&self) -> bool {
        self.name != NameType::new(crypto::hash::sha512::hash(&self.sign_keys.0[..]).0)
    }
}


#[cfg(test)]
mod test{
    use rand;

    #[test]
    fn with_keys_and_getters() {
      let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
      let asym_keys = ::sodiumoxide::crypto::box_::gen_keypair();
      let id = ::id::Id::with_keys(sign_keys.clone(), asym_keys.clone());
      let name_id = ::sodiumoxide::crypto::hash::sha512::hash(&sign_keys.0[..]).0;
      let expected_name = ::NameType::new(name_id);

      assert_eq!(expected_name, id.name());
      assert_eq!(&sign_keys.0, &id.signing_public_key());
      // FIXME(ben) 20/07/2015 once PartialEq is implemented for the private key, avoid slice
      assert_eq!(&sign_keys.1[..], &id.signing_private_key()[..]);
      assert_eq!(&asym_keys.0, &id.encrypting_public_key());
    }

    #[test]
    fn is_relocated() {
        let mut id = ::id::Id::new();

        // is not relocated
        assert!(!id.is_relocated());

        // is relocated after changing the name
        id.assign_relocated_name(rand::random());
        assert!(id.is_relocated());
    }

    #[test]
    fn assign_relocated_name() {
      let mut id = ::id::Id::new();
      let original_name = id.name();
      let cloned_original_name = original_name.clone();
      let cloned_signing_public_key = id.signing_public_key().clone().0.to_vec();
      let cloned_encrypting_public_key = id.encrypting_public_key().clone().0.to_vec();
      let cloned_signing_private_key = id.signing_private_key().clone().0.to_vec();

      // will not be relocated with same or equal name
      assert!(!id.assign_relocated_name(original_name));
      assert!(!id.assign_relocated_name(cloned_original_name));

      let relocated_name: ::name_type::NameType = rand::random();

      // is relocated with other name
      assert!(id.assign_relocated_name(relocated_name));

      // will not be relocated with that relocated name again or yet another name
      assert!(!id.assign_relocated_name(relocated_name));
      assert!(!id.assign_relocated_name(rand::random()));

      // assign_relocation_name did change name properly
      assert_eq!(relocated_name, id.name());
      assert!(original_name != relocated_name);

      // assign_relocation_name dit not change any key properties
      assert_eq!(cloned_signing_public_key, id.signing_public_key().0.to_vec());
      assert_eq!(cloned_encrypting_public_key, id.encrypting_public_key().0.to_vec());
      assert_eq!(cloned_signing_private_key, id.signing_private_key().0.to_vec());
    }
}

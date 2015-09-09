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
use rustc_serialize::{Decoder, Encodable, Encoder};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;
use NameType;
use error::RoutingError;
use id::Id;
use utils;
use std::fmt::{Debug, Formatter, Error};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub struct PublicId {
    public_encrypt_key: box_::PublicKey,
    public_sign_key: sign::PublicKey,
    name: NameType,
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str(&format!("PublicId(name:{:?})", self.name))
    }
}

impl PublicId {
    pub fn new(id: &Id) -> PublicId {
        PublicId {
            public_encrypt_key: id.encrypting_public_key().clone(),
            public_sign_key: id.signing_public_key().clone(),
            name: id.name(),
        }
    }

    pub fn name(&self) -> NameType {
        self.name
    }

    pub fn set_name(&mut self, name: NameType) {
        self.name = name;
    }

    pub fn client_name(&self) -> NameType {
        utils::public_key_to_client_name(&self.public_sign_key)
    }

    pub fn serialised_contents(&self) -> Result<Vec<u8>, RoutingError> {
        let mut e = cbor::Encoder::from_memory();
        try!(e.encode(&[&self]));
        Ok(e.into_bytes())
    }

    // name field is initially same as original_name, this should be replaced by relocated name
    // calculated by the nodes close to original_name by using this method
    pub fn assign_relocated_name(&mut self, relocated_name: NameType) {
        self.name = relocated_name;
    }

    pub fn signing_public_key(&self) -> sign::PublicKey {
        self.public_sign_key
    }

    // checks if the name is updated to a relocated name
    pub fn is_relocated(&self) -> bool {
        self.name != utils::public_key_to_client_name(&self.public_sign_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use NameType;
    use test_utils::Random;
    use sodiumoxide::crypto;
    use utils;
    use std::cmp;
    use name_type::closer_to_target;
    use types::GROUP_SIZE;

    #[test]
    fn assign_relocated_name_public_id() {
        let before = PublicId::generate_random();
        let original_name = before.name();
        assert_eq!(original_name,
            NameType::new(crypto::hash::sha512::hash(&before.signing_public_key()[..]).0));
        assert!(!before.is_relocated());
        let relocated_name: NameType = Random::generate_random();
        let mut relocated = before.clone();
        relocated.assign_relocated_name(relocated_name.clone());
        assert!(relocated.is_relocated());
        assert_eq!(before.signing_public_key(), relocated.signing_public_key());
        assert_eq!(relocated.client_name(), original_name);
        assert_eq!(relocated.name(), relocated_name);
    }

    #[test]
    fn calculate_relocated_name() {
        let original_name : NameType = Random::generate_random();

        // empty close nodes
        assert!(utils::calculate_relocated_name(Vec::new(), &original_name).is_err());

        // one entry
        let mut close_nodes_one_entry : Vec<NameType> = Vec::new();
        close_nodes_one_entry.push(Random::generate_random());
        let actual_relocated_name_one_entry = utils::calculate_relocated_name(close_nodes_one_entry.clone(),
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
        let actual_relocated_name = utils::calculate_relocated_name(close_nodes.clone(),
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
}

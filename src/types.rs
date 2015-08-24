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
use sodiumoxide::crypto::sign::Signature;
use sodiumoxide::crypto::sign;
use rustc_serialize::{Decoder, Encodable, Encoder};
use rand::random;
use std::fmt::{Debug, Formatter, Error};

use NameType;
use authority::Authority;

pub fn array_as_vector(arr: &[u8]) -> Vec<u8> {
    let mut vector = Vec::new();
    for i in arr.iter() {
        vector.push(*i);
    }
    vector
}

pub fn vector_as_u8_64_array(vector: Vec<u8>) -> [u8; 64] {
    let mut arr = [0u8;64];
    for i in (0..64) {
        arr[i] = vector[i];
    }
    arr
}

pub fn vector_as_u8_32_array(vector: Vec<u8>) -> [u8; 32] {
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

pub type MessageId = u32;
pub type NodeAddress = NameType; // (Address, NodeTag)
pub type FromAddress = NameType; // (Address, NodeTag)
pub type ToAddress = NameType; // (Address, NodeTag)
pub type GroupAddress = NameType; // (Address, GroupTag)
pub type SerialisedMessage = Vec<u8>;
pub type IdNode = NameType;
pub type IdNodes = Vec<IdNode>;
pub type Bytes = Vec<u8>;

#[derive(RustcEncodable, RustcDecodable)]
struct SignedKey {
    sign_public_key: sign::PublicKey,
    encrypt_public_key: crypto::box_::PublicKey,
}

pub type FilterType = Signature;
pub type ContentFilter = crypto::hash::sha256::Digest;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, RustcEncodable, RustcDecodable)]
pub enum Address {
    Client(crypto::sign::PublicKey),
    Node(NameType),
}

impl Debug for Address {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        match self {
            &Address::Client(ref public_key) => {
                formatter.write_str(&format!("Client({:?})", NameType::new(
                    crypto::hash::sha512::hash(&public_key[..]).0)))
            }
            &Address::Node(ref name) => {
                formatter.write_str(&format!("Node({:?})", name))
            }
        }
    }
}

// #[cfg(test)]
// #[allow(deprecated)]
// mod test {
//     extern crate cbor;
//     use super::*;
//     use sodiumoxide::crypto;
//     use std::cmp;
//     use rustc_serialize::{Decodable, Encodable};
//     use test_utils::Random;
//     use public_id::PublicId;
//     use authority::Authority;
//     use NameType;
//     use name_type::closer_to_target;
//     use sodiumoxide::crypto::sign;
//     use utils;
//
//     fn test_object<T>(obj_before : T) where T: for<'a> Encodable + Decodable + Eq {
//       let mut e = cbor::Encoder::from_memory();
//       e.encode(&[&obj_before]).unwrap();
//       let mut d = cbor::Decoder::from_bytes(e.as_bytes());
//       let obj_after: T = d.decode().next().unwrap().unwrap();
//       assert_eq!(obj_after == obj_before, true)
//     }
//
//     #[test]
//     fn test_authority() {
//       test_object(Authority::ClientManager(Random::generate_random()));
//       test_object(Authority::NaeManager(Random::generate_random()));
//       test_object(Authority::NodeManager(Random::generate_random()));
//       test_object(Authority::ManagedNode);
//       test_object(Authority::Client(sign::gen_keypair().0));
//       test_object(Authority::Unknown);
//     }
//
//     #[test]
//     fn test_destination_address() {
//       test_object(DestinationAddress::Direct(Random::generate_random()));
//     }
//
//     #[test]
//     fn test_source_address() {
//         test_object(SourceAddress::Direct(Random::generate_random()));
//     }
//
//     #[test]
//     fn serialisation_public_id() {
//         let obj_before = PublicId::generate_random();
//
//         let mut e = cbor::Encoder::from_memory();
//         e.encode(&[&obj_before]).unwrap();
//
//         let mut d = cbor::Decoder::from_bytes(e.as_bytes());
//         let obj_after: PublicId = d.decode().next().unwrap().unwrap();
//         assert_eq!(obj_before, obj_after);
//     }
//
//     #[test]
//     fn test_calculate_relocated_name() {
//         let original_name : NameType = Random::generate_random();
//
//         // empty close nodes
//         assert!(utils::calculate_relocated_name(Vec::new(), &original_name).is_err());
//
//         // one entry
//         let mut close_nodes_one_entry : Vec<NameType> = Vec::new();
//         close_nodes_one_entry.push(Random::generate_random());
//         let actual_relocated_name_one_entry = utils::calculate_relocated_name(close_nodes_one_entry.clone(),
//                                                                        &original_name).unwrap();
//         assert!(original_name != actual_relocated_name_one_entry);
//
//         let mut combined_one_node_vec : Vec<NameType> = Vec::new();
//         combined_one_node_vec.push(original_name.clone());
//         combined_one_node_vec.push(close_nodes_one_entry[0].clone());
//
//         let mut combined_one_node: Vec<u8> = Vec::new();
//         for node_id in combined_one_node_vec {
//             for i in node_id.get_id().iter() {
//                 combined_one_node.push(*i);
//             }
//         }
//
//         let expected_relocated_name_one_node =
//               NameType(crypto::hash::sha512::hash(&combined_one_node).0);
//
//         assert_eq!(actual_relocated_name_one_entry, expected_relocated_name_one_node);
//
//         // populated closed nodes
//         let mut close_nodes : Vec<NameType> = Vec::new();
//         for _ in 0..GROUP_SIZE {
//             close_nodes.push(Random::generate_random());
//         }
//         let actual_relocated_name = utils::calculate_relocated_name(close_nodes.clone(),
//                                                                     &original_name).unwrap();
//         assert!(original_name != actual_relocated_name);
//
//         close_nodes.sort_by(|a, b| if closer_to_target(&a, &b, &original_name) {
//                                   cmp::Ordering::Less
//                                 } else {
//                                     cmp::Ordering::Greater
//                                 });
//         let first_closest = close_nodes[0].clone();
//         let second_closest = close_nodes[1].clone();
//         let mut combined: Vec<u8> = Vec::new();
//
//         for i in original_name.get_id().into_iter() {
//             combined.push(*i);
//         }
//         for i in first_closest.get_id().into_iter() {
//             combined.push(*i);
//         }
//         for i in second_closest.get_id().into_iter() {
//             combined.push(*i);
//         }
//
//         let expected_relocated_name = NameType(crypto::hash::sha512::hash(&combined).0);
//         assert_eq!(expected_relocated_name, actual_relocated_name);
//
//         let mut invalid_combined: Vec<u8> = Vec::new();
//         for i in first_closest.get_id().into_iter() {
//             invalid_combined.push(*i);
//         }
//         for i in second_closest.get_id().into_iter() {
//             invalid_combined.push(*i);
//         }
//         for i in original_name.get_id().into_iter() {
//             invalid_combined.push(*i);
//         }
//         let invalid_relocated_name = NameType(crypto::hash::sha512::hash(&invalid_combined).0);
//         assert!(invalid_relocated_name != actual_relocated_name);
//     }
// }

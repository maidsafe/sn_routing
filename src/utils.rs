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

use cbor::{Decoder, Encoder, CborError};
use sodiumoxide;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::Signature;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto;
use std::cmp;
use NameType;
use name_type::closer_to_target;
use std::fmt;
use error::{RoutingError};

use rustc_serialize::{Decodable, Encodable};

pub fn encode<T>(value: &T) -> Result<Vec<u8>, CborError> where T: Encodable {
    let mut enc = Encoder::from_memory();
    try!(enc.encode(&[value]));
    Ok(enc.into_bytes())
}

pub fn decode<T>(bytes: &Vec<u8>) -> Result<T, CborError> where T: Decodable {
    let mut dec = Decoder::from_bytes(&bytes[..]);
    match dec.decode().next() {
        Some(result) => result,
        None => Err(CborError::UnexpectedEOF)
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

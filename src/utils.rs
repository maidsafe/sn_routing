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
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto;
use std::cmp;
use NameType;
use name_type::closer_to_target;
use error::RoutingError;

use rustc_serialize::{Decodable, Encodable};

pub fn encode<T>(value: &T) -> Result<Vec<u8>, CborError>
    where T: Encodable
{
    let mut enc = Encoder::from_memory();
    try!(enc.encode(&[value]));
    Ok(enc.into_bytes())
}

pub fn decode<T>(bytes: &Vec<u8>) -> Result<T, CborError>
    where T: Decodable
{
    let mut dec = Decoder::from_bytes(&bytes[..]);
    match dec.decode().next() {
        Some(result) => result,
        None => Err(CborError::UnexpectedEOF),
    }
}

/// The name client name is the SHA512 of the public signing key
pub fn public_key_to_client_name(key: &sign::PublicKey) -> NameType {
    NameType(crypto::hash::sha512::hash(&key[..]).0)
}

// relocated_name = Hash(original_name + 1st closest node id + 2nd closest node id)
// In case of only one close node provided (in initial network setup scenario),
// relocated_name = Hash(original_name + 1st closest node id)
pub fn calculate_relocated_name(mut close_nodes: Vec<NameType>,
                                original_name: &NameType)
                                -> Result<NameType, RoutingError> {
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

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
use rand::random;
use std::fmt::{Debug, Formatter, Error};

use NameType;

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

pub type Bytes = Vec<u8>;

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

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CacheOptions {
    cache_plain_data: bool,
    cache_structured_data: bool,
    cache_immutable_data: bool,
}

impl CacheOptions {

    /// Construct with caching off.
    pub fn no_caching() -> CacheOptions {
        CacheOptions {
            cache_plain_data: false,
            cache_structured_data: false,
            cache_immutable_data: false,
        }
    }

    /// Construct with caching optionally set.
    pub fn with_caching(cache_plain_data: bool, cache_structured_data: bool, cache_immutable_data: bool)
            -> CacheOptions {
        CacheOptions {
            cache_plain_data: cache_plain_data,
            cache_structured_data: cache_structured_data,
            cache_immutable_data: cache_immutable_data,
        }
    }

    /// Enable or disable Data caching.
    pub fn set_cache_options(&mut self, cache_options: CacheOptions) {
        self.cache_plain_data = cache_options.cache_plain_data;
        self.cache_structured_data = cache_options.cache_structured_data;
        self.cache_immutable_data = cache_options.cache_immutable_data;
    }

    /// Return true if any caching option is set otherwise false.
    pub fn caching_enabled(& self) -> bool {
        if self.cache_plain_data || self.cache_structured_data || self.cache_immutable_data {
            return true;
        }
        false
    }

    /// Return PlainData caching option.
    pub fn plain_data_caching_enabled(& self) -> bool {
        self.cache_plain_data
    }

    /// Return StructuredData caching option.
    pub fn structured_data_caching_enabled(& self) -> bool {
        self.cache_structured_data
    }

    /// Return ImmutableData caching option.
    pub fn immutable_data_caching_enabled(& self) -> bool {
        self.cache_immutable_data
    }
}

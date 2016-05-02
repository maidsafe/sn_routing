// Copyright 2016 MaidSafe.net limited.
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

#![cfg(feature = "use-mock-crust")]

use xor_name::XorName;
use routing::{FullId, StructuredData};
use rand::{self, random, Rng};

/// utility to create random vec u8 of a given size
pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    rand::thread_rng().gen_iter().take(size).collect()
}

/// creates random structured data - tests only
pub fn random_structured_data(type_tag: u64, full_id: &FullId) -> StructuredData {
    StructuredData::new(type_tag,
                        random::<XorName>(),
                        0,
                        generate_random_vec_u8(10),
                        vec![full_id.public_id().signing_public_key().clone()],
                        vec![],
                        Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test")
}

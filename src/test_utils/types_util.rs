// Copyright 2015 MaidSafe.net limited
//
// This Safe Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the Safe Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations relating to
// use of the Safe Network Software.

use types::*;
use name_type::NameType;
use rand::random;
use super::random_trait::Random;

impl Random for NameAndTypeId {
    fn generate_random() -> NameAndTypeId {
        NameAndTypeId {
            name: Random::generate_random(),
            type_id: random::<u64>(),
        }
    }
}

impl Random for Signature {
    fn generate_random() -> Signature {
        Signature { signature: generate_random_vec_u8(32) }
    }
}

impl Random for PublicSignKey {
    fn generate_random() -> PublicSignKey {
        PublicSignKey { public_sign_key: generate_random_vec_u8(32) }
    }
}

impl Random for PublicKey {
    fn generate_random() -> PublicKey {
        PublicKey { public_key: generate_random_vec_u8(32) }
    }
}

impl Random for PublicPmid {
    fn generate_random() -> PublicPmid {
        PublicPmid::new(&Pmid::new())
    }
}

impl Random for SourceAddress {
    fn generate_random() -> SourceAddress {
        SourceAddress {
            from_node: Random::generate_random(),
            from_group: None,
            reply_to: None,
        }
    }
}

impl Random for NameType {
    fn generate_random() -> NameType {
        NameType(vector_as_u8_64_array(generate_random_vec_u8(64)))
    }
}

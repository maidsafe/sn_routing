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



#[cfg(test)]
mod test {
    use types::*;
    use public_id::PublicId;
    use id::Id;
    use name_type::NameType;
    use rand::random;

    impl Random for NameAndTypeId {
        fn generate_random() -> NameAndTypeId {
            NameAndTypeId {
                name: Random::generate_random(),
                type_id: random::<u64>(),
            }
        }
    }

    impl Random for PublicId {
        fn generate_random() -> PublicId {
            PublicId::new(&Id::new())
        }
    }

    impl Random for SourceAddress {
        fn generate_random() -> SourceAddress {
            SourceAddress {
                from_node: Random::generate_random(), from_group: None, reply_to: None, relayed_for: None }
        }
    }

    impl Random for NameType {
        fn generate_random() -> NameType {
            NameType(vector_as_u8_64_array(generate_random_vec_u8(64)))
        }
    }
}

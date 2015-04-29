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

use name_type;
use sendable::Sendable;

#[derive(Clone)]
pub struct GenericSendableType {
    name: name_type::NameType,
    type_tag: u64,
    serialised_contents: Vec<u8>,
}

impl GenericSendableType {
    pub fn new(name: name_type::NameType, type_tag: u64, serialised_contents: Vec<u8>) -> GenericSendableType {
        GenericSendableType {
            name: name,
            type_tag: type_tag,
            serialised_contents: serialised_contents,
        }
    }
}

impl Sendable for GenericSendableType {
    fn name(&self) -> name_type::NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        self.type_tag
    }

    fn serialised_contents(&self) -> Vec<u8> {
        self.serialised_contents.clone()
    }
}

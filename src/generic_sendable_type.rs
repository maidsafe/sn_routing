// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License, version
// 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which licence you
// accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at
// http://maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to use
// of the MaidSafe Software.

use routing;
use routing::sendable::Sendable;

#[derive(Clone)]
pub struct GenericSendableType {
    name: routing::NameType,
    type_tag: u64,
    serialised_contents: Vec<u8>,
}

impl GenericSendableType {
    pub fn new(name: routing::NameType, type_tag: u64, serialised_contents: Vec<u8>) -> GenericSendableType {
        GenericSendableType {
            name: name,
            type_tag: type_tag,
            serialised_contents: serialised_contents,
        }
    }
}

impl Sendable for GenericSendableType {
    fn name(&self) -> routing::NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        self.type_tag
    }

    fn serialised_contents(&self) -> Vec<u8> {
        self.serialised_contents.clone()
    }
}

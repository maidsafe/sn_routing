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

mod random_trait;
mod types_util;
mod messages_util;

pub use self::random_trait::*;
pub use self::types_util::*;
pub use self::messages_util::*;

use NameType;

pub fn xor(lhs: &NameType, rhs: &NameType) -> NameType {
    let mut result = NameType::new([0u8; 64]);
    for i in 0..lhs.0.len() {
        result.0[i] = lhs.0[i] ^ rhs.0[i];
    }
    result
}

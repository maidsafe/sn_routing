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

use maidsafe_utilities::serialisation::serialise;
use routing::StructuredData;
use xor_name::XorName;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MergedValue<T> {
    pub name: XorName,
    pub value: T,
}

/// This trait is required for any type (normally an account) which is refreshed on a churn event.
pub trait Refreshable : ::rustc_serialize::Encodable + ::rustc_serialize::Decodable {
    /// The serialised contents
    fn serialised_contents(&self) -> Vec<u8> {
        serialise(&self).unwrap_or(vec![])
    }

    /// Merge multiple refreshable objects into one
    fn merge(name: XorName, values: Vec<Self>, quorum_size: usize) -> Option<MergedValue<Self>>;
}

impl Refreshable for StructuredData {
    fn merge(name: XorName, values: Vec<StructuredData>, quorum_size: usize) -> Option<MergedValue<StructuredData>> {
        let mut sds = Vec::<(StructuredData, u64)>::new();
        for value in values {
            let push_in_vec = match sds.iter_mut().find(|a| a.0 == value) {
                Some(find_res) => {
                    find_res.1 += 1;
                    false
                }
                None => true,
            };
            if push_in_vec {
                sds.push((value.clone(), 1));
            }
        }
        sds.sort_by(|a, b| b.1.cmp(&a.1));
        let (sd, count) = sds[0].clone();
        if count >= quorum_size as u64 {
            return Some(MergedValue {
                name: name,
                value: sd,
            });
        }
        None
    }
}

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

use personas::{immutable_data_manager, maid_manager, pmid_manager, mpid_manager};
use routing::{PlainData, StructuredData};
use xor_name::XorName;

#[derive(Debug, Clone, RustcEncodable, RustcDecodable)]
pub struct Refresh {
    pub name: XorName,
    pub value: RefreshValue,
}

impl Refresh {
    pub fn new(name: &XorName, value: RefreshValue) -> Refresh {
        Refresh {
            name: name.clone(),
            value: value,
        }
    }
}

#[derive(Debug, Clone, RustcEncodable, RustcDecodable)]
pub enum RefreshValue {
    MaidManagerAccount(maid_manager::Account),
    ImmutableDataManagerAccount(immutable_data_manager::Account),
    StructuredDataManager(StructuredData),
    PmidManagerAccount(pmid_manager::Account),
    // mpid_manager: account, outbox messages, inbox headers
    MpidManagerAccount(mpid_manager::Account, Vec<PlainData>, Vec<PlainData>),
}

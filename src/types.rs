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

/// MethodCall denotes a specific request to be carried out by routing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MethodCall {
    /// request to have `location` to handle put for the `content`
    Put { location: ::routing::authority::Authority, content: ::routing::data::Data },
    /// request to retreive data with specified type and location from network
    Get { location: ::routing::authority::Authority, data_request: ::routing::data::DataRequest },
    // /// request to post
    // Post { destination: ::routing::NameType, content: Data },
    // /// Request delete
    // Delete { name: ::routing::NameType, data : Data },
    /// request to refresh
    Refresh { type_tag: u64, from_group: ::routing::NameType, payload: Vec<u8> },
    /// reply
    Reply { data: ::routing::data::Data },
    /// response error indicating failed in putting data
    FailedPut { location: ::routing::authority::Authority, data: ::routing::data::Data },
    /// response error indicating clearing sarificial data
    ClearSacrificial { location: ::routing::authority::Authority,
                       name: ::routing::NameType, size: u32 },
    /// response error indicating not enough allowance
    LowBalance{ location: ::routing::authority::Authority,
                data: ::routing::data::Data, balance: u32},
    /// response error indicating invalid request
    InvalidRequest { data: ::routing::data::Data },
}

/// This trait is required for any type (normally an account) which is refreshed on a churn event.
pub trait Refreshable : ::rustc_serialize::Encodable + ::rustc_serialize::Decodable {
    /// The serialised contents
    fn serialised_contents(&self) -> Vec<u8> {
        ::routing::utils::encode(&self).unwrap_or(vec![])
    }

    /// Merge multiple refreshable objects into one
    fn merge(from_group: ::routing::NameType, responses: Vec<Self>) -> Option<Self>;
}

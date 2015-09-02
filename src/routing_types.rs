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


pub use routing::{closer_to_target, NameType, SignedToken, ExternalRequest, ExternalResponse};
pub use routing::authority::Authority;
pub use routing::data::{Data, DataRequest};
pub use routing::error::{RoutingError, InterfaceError, ResponseError};
pub use routing::event::Event;
pub use routing::immutable_data::{ImmutableData, ImmutableDataType};
pub use routing::structured_data::StructuredData;
pub use routing::types::*;

/// MethodCall denotes a specific request to be carried out by routing.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum MethodCall {
    /// request to have `location` to handle put for the `content`
    Put { location: Authority, content: Data },
    /// request to retreive data with specified type and location from network
    Get { location: Authority, data_request: DataRequest },
    // /// request to post
    // Post { destination: NameType, content: Data },
    // /// Request delete
    // Delete { name: NameType, data : Data },
    /// request to refresh
    Refresh { type_tag: u64, from_group: NameType, payload: Vec<u8> },
    /// reply
    Reply { data: Data },
    /// response error indicating failed in putting data
    FailedPut { location: Authority, data: Data },
    /// response error indicating clearing sarificial data
    ClearSacrificial { location: Authority, name: NameType, size: u32 },
    /// response error indicating not enough allowance
    NotEnoughAllowance,
    /// response error indicating invalid request
    InvalidRequest { data: Data },
}

/// This trait is required for any type of message to be
/// passed to routing, refresh / account transfer is optional
/// The name will let routing know its a NaeManager and the owner will allow routing to hash
/// the requesters ID with this name (by hashing the requesters ID) for put and post messages
pub trait Sendable {
	/// return the name
    fn name(&self)->NameType;
    /// return the type_tag
    fn type_tag(&self)->u64;
    /// return serialised content
    fn serialised_contents(&self)->Vec<u8>;
    /// return the owner
    fn owner(&self)->Option<NameType> { None }
    /// is this an account transfer type
    fn refresh(&self)->bool;
    /// Merge two sendable object
    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>>;
}

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

#[cfg(not(feature = "use-actual-routing"))]
pub use non_networking_test_framework::mock_routing_types::*;

/// MethodCall denotes a specific request to be carried out by routing.
#[derive(PartialEq, Eq, Clone)]
pub enum MethodCall {
    /// request to have `destination` to handle put for the `content`
    Put { destination: NameType, content: Data },
    /// request to retreive data with specified type and name from network
    Get { name: NameType, data_request: DataRequest },
    // /// request to post
    // Post { destination: NameType, content: Data },
    // /// Request delete
    // Delete { name: NameType, data : Data },
    /// request to refresh
    Refresh { type_tag: u64, from_group: NameType, payload: Vec<u8> },
    /// request to forward on the request to destination for further handling
    Forward { destination: NameType },
    /// reply
    Reply { data: Data },
    /// terminate
    Terminate,
    // /// shutdown
    // ShutDown
}

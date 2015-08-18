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


// pub use routing::{closer_to_target, NameType};
// pub use routing::data::{Data, DataRequest};
// pub use routing::error::{InterfaceError, ResponseError};
pub use routing::immutable_data::ImmutableData;
// pub use routing::node_interface::MethodCall;
// pub use routing::sendable::Sendable;
pub use routing::structured_data::StructuredData;
pub use routing::types::{GROUP_SIZE, vector_as_u8_64_array};

pub const NAME_TYPE_LEN : usize = 64;
pub const POLL_DURATION_IN_MILLISEC: u32 = 1;

pub use non_networking_test_framework::mock_routing_types::*;
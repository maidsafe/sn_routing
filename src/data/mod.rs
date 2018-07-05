// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod immutable_data;
mod mutable_data;

pub use self::immutable_data::{ImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES};
pub use self::mutable_data::{
    Action, EntryAction, EntryActions, MutableData, PermissionSet, User, Value,
    MAX_MUTABLE_DATA_ENTRIES, MAX_MUTABLE_DATA_SIZE_IN_BYTES,
};

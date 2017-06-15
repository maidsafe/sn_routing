// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod immutable_data;
mod mutable_data;

pub use self::immutable_data::{ImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES};
pub use self::mutable_data::{Action, EntryAction, EntryActions, MAX_MUTABLE_DATA_ENTRIES,
                             MAX_MUTABLE_DATA_SIZE_IN_BYTES, MutableData, PermissionSet, User,
                             Value};
use rust_sodium::crypto::sign::{self, PublicKey};

/// A signing key with no matching private key. Passing ownership to it will make a chunk
/// effectively immutable.
pub const NO_OWNER_PUB_KEY: PublicKey = PublicKey([0; sign::PUBLICKEYBYTES]);

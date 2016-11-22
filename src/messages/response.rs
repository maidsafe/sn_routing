// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use client_error::ClientError;
use data::{ImmutableData, PermissionSet, User, Value};
use rust_sodium::crypto::sign;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use types::MessageId as MsgId;

/// Response message types
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Response {
    /// Returns a success or failure status of account information retrieval.
    GetAccountInfo {
        /// Result of fetching account info from the network.
        res: Result<AccountInfo, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- ImmutableData ---
    // ==========================
    /// Returns a success or failure status of putting ImmutableData to the network.
    PutIData {
        /// Result of putting ImmutableData to the network.
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a result of fetching ImmutableData from the network.
    GetIData {
        /// Result of fetching ImmutableData from the network.
        res: Result<ImmutableData, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- MutableData ---
    // ==========================
    /// Returns a success or failure status of putting MutableData to the network.
    PutMData {
        /// Result of putting MutableData to the network.
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    /// Returns a current version of MutableData stored in the network.
    GetMDataVersion {
        /// Result of getting a version of MutableData
        res: Result<u64, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Data Actions
    /// Returns a complete list of entries in MutableData or an error in case of failure.
    ListMDataEntries {
        /// Result of getting a list of entries in MutableData
        res: Result<BTreeMap<Vec<u8>, Value>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of keys in MutableData or an error in case of failure.
    ListMDataKeys {
        /// Result of getting a list of keys in MutableData
        res: Result<BTreeSet<Vec<u8>>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of values in MutableData or an error in case of failure.
    ListMDataValues {
        /// Result of getting a list of values in MutableData
        res: Result<Vec<Value>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a single entry from MutableData or an error in case of failure.
    GetMDataValue {
        /// Result of getting a value from MutableData
        res: Result<Value, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of mutating MutableData in the network.
    MutateMDataEntries {
        /// Result of mutating an entry in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Permission Actions
    /// Returns a complete list of MutableData permissions stored on the network
    /// or an error in case of failure.
    ListMDataPermissions {
        /// Result of getting a list of permissions in MutableData
        res: Result<BTreeMap<User, PermissionSet>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of permissions for a particular User in MutableData or an
    /// error in case of failure.
    ListMDataUserPermissions {
        /// Result of getting a list of user permissions in MutableData
        res: Result<PermissionSet, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of setting permissions for a particular
    /// User in MutableData.
    SetMDataUserPermissions {
        /// Result of setting a list of user permissions in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting permissions for a particular
    /// User in MutableData.
    DelMDataUserPermissions {
        /// Result of deleting a list of user permissions in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Ownership Actions
    /// Returns a success or failure status of chaning an owner of MutableData.
    ChangeMDataOwner {
        /// Result of chaning an owner of MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- Client (Owner) to MM ---
    // ==========================
    /// Returns a list of authorised keys from MaidManager.
    ListAuthKeysAndVersion {
        /// Result of getting a list of authorised keys
        res: Result<BTreeSet<sign::PublicKey>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of inserting an authorised key into MaidManager.
    InsAuthKey {
        /// Result of inserting an authorised key
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting an authorised key from MaidManager.
    DelAuthKey {
        /// Result of deleting an authorised key
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
}

impl Response {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        /*
        match *self {
            Response::GetSuccess(ref data, _) => {
                match *data {
                    Data::Structured(..) => 4,
                    _ => 5,
                }
            }
            Response::PutSuccess(..) |
            Response::PostSuccess(..) |
            Response::DeleteSuccess(..) |
            Response::AppendSuccess(..) |
            Response::GetAccountInfoSuccess { .. } |
            Response::GetFailure { .. } |
            Response::PutFailure { .. } |
            Response::PostFailure { .. } |
            Response::DeleteFailure { .. } |
            Response::AppendFailure { .. } |
            Response::GetAccountInfoFailure { .. } => 3,
        }
        */

        unimplemented!()
    }

    /// Is this response cacheable?
    pub fn is_cacheable(&self) -> bool {
        if let Response::GetIData { .. } = *self {
            true
        } else {
            false
        }
    }
}

impl Decodable for Response {
    fn decode<D: Decoder>(_d: &mut D) -> Result<Self, D::Error> {
        unimplemented!()
    }
}

impl Encodable for Response {
    fn encode<E: Encoder>(&self, _e: &mut E) -> Result<(), E::Error> {
        unimplemented!()
    }
}

impl Debug for Response {
    fn fmt(&self, _formatter: &mut Formatter) -> fmt::Result {
        /*
        match *self {
            Response::GetSuccess(ref data, ref message_id) => {
                write!(formatter, "GetSuccess({:?}, {:?})", data, message_id)
            }
            Response::PutSuccess(ref name, ref message_id) => {
                write!(formatter, "PutSuccess({:?}, {:?})", name, message_id)
            }
            Response::PostSuccess(ref name, ref message_id) => {
                write!(formatter, "PostSuccess({:?}, {:?})", name, message_id)
            }
            Response::DeleteSuccess(ref name, ref message_id) => {
                write!(formatter, "DeleteSuccess({:?}, {:?})", name, message_id)
            }
            Response::AppendSuccess(ref name, ref message_id) => {
                write!(formatter, "AppendSuccess({:?}, {:?})", name, message_id)
            }
            Response::GetAccountInfoSuccess { ref id, .. } => {
                write!(formatter, "GetAccountInfoSuccess {{ {:?}, .. }}", id)
            }
            Response::GetFailure { ref id, ref data_id, .. } => {
                write!(formatter, "GetFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::PutFailure { ref id, ref data_id, .. } => {
                write!(formatter, "PutFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::PostFailure { ref id, ref data_id, .. } => {
                write!(formatter, "PostFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::DeleteFailure { ref id, ref data_id, .. } => {
                write!(formatter, "DeleteFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::AppendFailure { ref id, ref data_id, .. } => {
                write!(formatter, "AppendFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::GetAccountInfoFailure { ref id, .. } => {
                write!(formatter, "GetAccountInfoFailure {{ {:?}, .. }}", id)
            }
        }
        */

        unimplemented!()
    }
}

/// Account information
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, RustcDecodable, RustcEncodable)]
pub struct AccountInfo {
    /// Number of data pieces stored by the account.
    pub data_stored: u64,
    /// Remaining storage space (in terms of data pieces) for the account.
    pub space_available: u64,
}

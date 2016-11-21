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

use data::{EntryAction, ImmutableData, MutableData, PermissionSet, User, Value};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, BTreeSet};
use types::MessageId as MsgId;
use xor_name::XorName;

/// Request message types
pub enum Request {
    /// Represents a refresh message sent between vaults. Vec<u8> is the message content.
    Refresh(Vec<u8>, MsgId),
    /// Gets MAID account information.
    GetAccountInfo(MsgId),

    // --- ImmutableData ---
    // ==========================
    /// Puts ImmutableData to the network.
    PutIData {
        /// ImmutableData to be stored
        data: ImmutableData,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches ImmutableData from the network by the given name.
    GetIData {
        /// Network identifier of ImmutableData
        name: XorName,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- MutableData ---
    // ==========================
    /// Creates a new MutableData in the network.
    PutMData {
        /// MutableData to be stored
        data: MutableData,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: sign::PublicKey,
    },
    /// Fetches a latest version number.
    GetMDataVersion {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Data Actions
    /// Fetches a list of entries (keys + values).
    ListMDataEntries {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a list of keys in MutableData.
    ListMDataKeys {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a list of values in MutableData.
    ListMDataValues {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a single value from MutableData
    GetMDataValue {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Key of an entry to be fetched
        key: Vec<u8>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Updates MutableData entries in bulk.
    MutateMDataEntries {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A list of mutations (inserts, updates, or deletes) to be performed
        /// on MutableData in bulk.
        actions: BTreeMap<Vec<u8>, EntryAction>,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: sign::PublicKey,
    },

    // Permission Actions
    /// Fetches a complete list of permissions.
    ListMDataPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a list of permissions for a particular User.
    ListMDataUserPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A user identifier used to fetch permissions
        user: User,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Updates or inserts a list of permissions for a particular User in the given MutableData.
    SetMDataUserPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A user identifier used to set permissions
        user: User,
        /// Permissions to be set for a user
        permissions: PermissionSet,
        /// Incremented version of MutableData
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: sign::PublicKey,
    },
    /// Deletes a list of permissions for a particular User in the given MutableData.
    DelMDataUserPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A user identifier used to delete permissions
        user: User,
        /// Incremented version of MutableData
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: sign::PublicKey,
    },

    // Ownership Actions
    /// Changes an owner of the given MutableData. Only the current owner can perform this action.
    ChangeMDataOwner {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A list of new owners
        new_owners: BTreeSet<sign::PublicKey>,
        /// Incremented version of MutableData
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- Client (Owner) to MM ---
    // ==========================
    /// Lists authorised keys and version stored in MaidManager.
    ListAuthKeysAndVersion(MsgId),
    /// Inserts an autorised key (for an app, user, etc.) to MaidManager.
    InsAuthKey {
        /// Authorised key to be inserted
        key: sign::PublicKey,
        /// Incremented version
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Deletes an authorised key from MaidManager.
    DelAuthKey {
        /// Authorised key to be deleted
        key: sign::PublicKey,
        /// Incremented version
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
}

/// Response message types
pub enum Response {
    /// Returns an error occurred during account information retrieval.
    GetAccountInfoFailure {
        /// Description of an occurred error
        reason: Vec<u8>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns an account information.
    GetAccountInfoSuccess {
        /// Amount of data stored on the network by this Client
        data_stored: u64,
        /// Amount of network space available to this Client
        space_available: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- ImmutableData ---
    // ==========================
    /// Returns a success or failure status of putting ImmutableData to the network.
    PutIData {
        /// Result of putting ImmutableData to the network.
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a result of fetching ImmutableData from the network.
    GetIData {
        /// Result of fetching ImmutableData from the network.
        res: Result<ImmutableData, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- MutableData ---
    // ==========================
    /// Returns a success or failure status of putting MutableData to the network.
    PutMData {
        /// Result of putting MutableData to the network.
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    /// Returns a current version of MutableData stored in the network.
    GetMDataVersion {
        /// Result of getting a version of MutableData
        res: Result<u64, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Data Actions
    /// Returns a complete list of entries in MutableData or an error in case of failure.
    ListMDataEntries {
        /// Result of getting a list of entries in MutableData
        res: Result<BTreeMap<Vec<u8>, Value>, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of keys in MutableData or an error in case of failure.
    ListMDataKeys {
        /// Result of getting a list of keys in MutableData
        res: Result<BTreeSet<Vec<u8>>, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of values in MutableData or an error in case of failure.
    ListMDataValues {
        /// Result of getting a list of values in MutableData
        res: Result<Vec<Value>, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a single entry from MutableData or an error in case of failure.
    GetMDataValue {
        /// Result of getting a value from MutableData
        res: Result<Value, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of mutating MutableData in the network.
    MutateMDataEntries {
        /// Result of mutating an entry in MutableData
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Permission Actions
    /// Returns a complete list of MutableData permissions stored on the network
    /// or an error in case of failure.
    ListMDataPermissions {
        /// Result of getting a list of permissions in MutableData
        res: Result<BTreeMap<User, PermissionSet>, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of permissions for a particular User in MutableData or an
    /// error in case of failure.
    ListMDataUserPermissions {
        /// Result of getting a list of user permissions in MutableData
        res: Result<PermissionSet, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of setting permissions for a particular
    /// User in MutableData.
    SetMDataUserPermissions {
        /// Result of setting a list of user permissions in MutableData
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting permissions for a particular
    /// User in MutableData.
    DelMDataUserPermissions {
        /// Result of deleting a list of user permissions in MutableData
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Ownership Actions
    /// Returns a success or failure status of chaning an owner of MutableData.
    ChangeMDataOwner {
        /// Result of chaning an owner of MutableData
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- Client (Owner) to MM ---
    // ==========================
    /// Returns a list of authorised keys from MaidManager.
    ListAuthKeysAndVersion {
        /// Result of getting a list of authorised keys
        res: Result<BTreeSet<sign::PublicKey>, Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of inserting an authorised key into MaidManager.
    InsAuthKey {
        /// Result of inserting an authorised key
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting an authorised key from MaidManager.
    DelAuthKey {
        /// Result of deleting an authorised key
        res: Result<(), Vec<u8>>,
        /// Unique message identifier
        msg_id: MsgId,
    },
}

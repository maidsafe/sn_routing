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

use data::{ImmutableData, MutableData, PermissionSet, User, Value};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, BTreeSet};
use types::MessageId as MsgId;
use xor_name::XorName;

pub enum EntryAction {
    Update(Value),
    Ins(Value),
    Del(u64),
}

#[allow(missing_docs)]
pub enum Request {
    Refresh(Vec<u8>, MsgId),
    GetAccountInfo(MsgId),

    // --- ImmutableData ---
    // ==========================
    PutIData { data: ImmutableData, msg_id: MsgId },
    GetIData { name: XorName, msg_id: MsgId },

    // --- MutableData ---
    // ==========================
    /// Creates a new MutableData in the network
    PutMData {
        data: MutableData,
        msg_id: MsgId,
        requester: sign::PublicKey,
    },
    /// Fetches a latest version number of the provided MutableData
    GetMDataVersion {
        name: XorName,
        tag: u64,
        msg_id: MsgId,
    },

    // Data Actions
    /// Fetches a list of entries (keys + values) of the provided MutableData
    ListMDataEntries {
        name: XorName,
        tag: u64,
        msg_id: MsgId,
    },
    /// Fetches a list of keys of the provided MutableData
    ListMDataKeys {
        name: XorName,
        tag: u64,
        msg_id: MsgId,
    },
    /// Fetches a list of values of the provided MutableData
    ListMDataValues {
        name: XorName,
        tag: u64,
        msg_id: MsgId,
    },
    /// Fetches a single value from the provided MutableData by the given key
    GetMDataValue {
        name: XorName,
        tag: u64,
        key: Vec<u8>,
        msg_id: MsgId,
    },
    /// Updates MutableData entries in bulk
    MutateMDataEntries {
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        msg_id: MsgId,
        requester: sign::PublicKey,
    },

    // Permission Actions
    ListMDataPermissions {
        name: XorName,
        tag: u64,
        msg_id: MsgId,
    },
    ListMDataUserPermissions {
        name: XorName,
        tag: u64,
        user: User,
        msg_id: MsgId,
    },
    SetMDataUserPermissions {
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
        msg_id: MsgId,
        requester: sign::PublicKey,
    },
    DelMDataUserPermissions {
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
        msg_id: MsgId,
        requester: sign::PublicKey,
    },

    // Ownership Actions
    ChangeMDataOwner {
        name: XorName,
        tag: u64,
        new_owners: BTreeSet<sign::PublicKey>,
        version: u64,
        msg_id: MsgId,
    },

    // --- Client (Owner) to MM ---
    // ==========================
    ListAuthKeysAndVersion(MsgId),
    InsAuthKey {
        key: sign::PublicKey,
        version: u64,
        msg_id: MsgId,
    },
    DelAuthKey {
        key: sign::PublicKey,
        version: u64,
        msg_id: MsgId,
    },
}

#[allow(missing_docs)]
pub enum Response {
    GetAccountInfoFailure { reason: Vec<u8>, msg_id: MsgId },
    GetAccountInfoSuccess {
        data_stored: u64,
        space_available: u64,
        msg_id: MsgId,
    },

    // --- ImmutableData ---
    // ==========================
    PutIData {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },
    GetIData {
        res: Result<ImmutableData, Vec<u8>>,
        msg_id: MsgId,
    },

    // --- MutableData ---
    // ==========================
    PutMData {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },

    GetMDataVersion {
        res: Result<u64, Vec<u8>>,
        msg_id: MsgId,
    },

    // Data Actions
    ListMDataEntries {
        res: Result<BTreeMap<Vec<u8>, Value>, Vec<u8>>,
        msg_id: MsgId,
    },
    ListMDataKeys {
        res: Result<BTreeSet<Vec<u8>>, Vec<u8>>,
        msg_id: MsgId,
    },
    ListMDataValues {
        res: Result<Vec<Value>, Vec<u8>>,
        msg_id: MsgId,
    },
    GetMDataValue {
        res: Result<Value, Vec<u8>>,
        msg_id: MsgId,
    },
    MutateMDataEntries {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },

    // Permission Actions
    ListMDataPermissions {
        res: Result<BTreeMap<User, PermissionSet>, Vec<u8>>,
        msg_id: MsgId,
    },
    ListMDataUserPermissions {
        res: Result<PermissionSet, Vec<u8>>,
        msg_id: MsgId,
    },
    SetMDataUserPermissions {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },
    DelMDataUserPermissions {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },

    // Ownership Actions
    ChangeMDataOwner {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },

    // --- Client (Owner) to MM ---
    // ==========================
    ListAuthKeysAndVersion {
        res: Result<BTreeSet<sign::PublicKey>, Vec<u8>>,
        msg_id: MsgId,
    },
    InsAuthKey {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },
    DelAuthKey {
        res: Result<(), Vec<u8>>,
        msg_id: MsgId,
    },
}

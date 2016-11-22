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

use error::RoutingError;
use rust_sodium::crypto::sign::{self, Signature};
use std::collections::BTreeMap;
use super::DataIdentifier;
use xor_name::XorName;

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

/// Mutable map (key-value store) data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct MapData {
    name: XorName,
    data: BTreeMap<Key, Entry>,
    permissions: BTreeMap<Access, Vec<PermissionType>>,
    version: u64,
    owner_keys: Vec<sign::PublicKey>,
}

impl MapData {
    pub fn new(name: XorName) -> Self {
        MapData {
            name: name,
            data: BTreeMap::new(),
            permissions: BTreeMap::new(),
            version: 0,
            owner_keys: Vec::new(),
        }
    }

    pub fn name(&self) -> &XorName {
        &self.name
    }

    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::Map(self.name)
    }

    pub fn validate_permission(&self,
                               _sign_key: &sign::PublicKey,
                               _permission: Permission)
                               -> bool {
        unimplemented!()
    }

    pub fn validate_size(&self) -> bool {
        unimplemented!()
    }

    pub fn get(&self, _key: &Key) -> Result<&Value, RoutingError> {
        unimplemented!()
    }

    // TODO: other operations
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
struct Entry {
    value: Value,
    version: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub enum Access {
    Anyone,
    Someone(sign::PublicKey),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub enum PermissionType {
    Allow(Permission),
    Deny(Permission),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub enum Permission {
    ListKeys,
    ListValues,
    List,
    Get,
    Set,
    Insert,
    Delete,
}

#[allow(unused)]
pub struct DataAction {
    sign_key: sign::PublicKey,
    signature: Signature,
    operation: DataOperation,
}

#[allow(unused)]
pub enum DataOperation {
    /// List keys
    ListKeys,
    /// List values
    ListValues,
    /// List both keys and values
    List,
    /// Get value by key
    Get {
        key: Key,
    },
    /// Set value at key
    Set {
        key: Key,
        value: Value,
        version: u64,
    },
    /// Insert new key-value pair
    Insert {
        key: Key,
        value: Value,
        version: u64,
    },
    /// Delete key
    Delete {
        key: Key,
        version: u64,
    },
}

#[allow(unused)]
pub struct PermissionAction {
    signature: Signature,
    operation: PermissionOperation,
    version: u64,
}

#[allow(unused)]
pub enum PermissionOperation {
    List,
    Get {
        access: Access,
    },
    Set {
        access: Access,
        permissions: Vec<PermissionType>,
    },
    Delete {
        access: Access,
    }
}

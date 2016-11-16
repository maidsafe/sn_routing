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
use maidsafe_utilities::serialisation::serialised_size;
use rust_sodium::crypto::sign::PublicKey;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use super::DataIdentifier;
use xor_name::XorName;

/// Maximum allowed size for MutableData (1 MiB)
pub const MAX_MUTABLE_DATA_SIZE_IN_BYTES: u64 = 1_048_576;

/// Maximum allowed entries in MutableData
pub const MAX_MUTABLE_DATA_ENTRIES: u64 = 100;

/// Mutable data.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub struct MutableData {
    /// Network address
    name: XorName,
    /// Type tag
    tag: u64,
    // ---- owner and vault access only ----
    /// Maps an arbitrary key to a (version, data) tuple value
    data: BTreeMap<Vec<u8>, Value>,
    /// Maps an application key to a list of allowed or forbidden actions
    permissions: BTreeMap<User, PermissionSet>,
    /// Version should be increased for every change in MutableData fields
    /// except for data
    version: u64,
    /// Contains a set of owners which are allowed to mutate permissions.
    /// Currently limited to one owner to disallow multisig.
    owners: BTreeSet<PublicKey>,
}

/// A value in MutableData
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub struct Value {
    content: Vec<u8>,
    entry_version: u64,
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable)]
pub enum User {
    Anyone,
    Key(PublicKey),
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Copy, Clone, RustcEncodable, RustcDecodable)]
pub enum Action {
    Insert,
    Update,
    Delete,
    ManagePermission,
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub struct PermissionSet(BTreeMap<Action, bool>);

impl PermissionSet {
    pub fn new() -> PermissionSet {
        PermissionSet(BTreeMap::new())
    }

    pub fn allow(&mut self, action: Action) -> &mut PermissionSet {
        let _ = self.0.insert(action, true);
        self
    }

    pub fn deny(&mut self, action: Action) -> &mut PermissionSet {
        let _ = self.0.insert(action, false);
        self
    }

    pub fn clear(&mut self, action: Action) -> &mut PermissionSet {
        let _ = self.0.remove(&action);
        self
    }

    pub fn is_allowed(&self, action: Action) -> Option<bool> {
        self.0.get(&action).cloned()
    }
}

impl MutableData {
    /// Creates a new MutableData
    pub fn new(name: XorName,
               tag: u64,
               permissions: BTreeMap<User, PermissionSet>,
               data: BTreeMap<Vec<u8>, Value>,
               owners: BTreeSet<PublicKey>)
               -> Result<MutableData, RoutingError> {
        if owners.len() > 1 {
            return Err(RoutingError::InvalidOwners);
        }

        let md = MutableData {
            name: name,
            tag: tag,
            data: data,
            permissions: permissions,
            version: 0,
            owners: owners,
        };

        if serialised_size(&md) > MAX_MUTABLE_DATA_SIZE_IN_BYTES {
            return Err(RoutingError::ExceededLimits);
        }

        Ok(md)
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::Mutable(self.name)
    }

    /// Returns the type tag of this MutableData
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// Returns the current version of this MutableData
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns a value by the given key
    pub fn get(&self, key: &Vec<u8>) -> Option<&Value> {
        self.data.get(key)
    }

    /// Returns keys of all entries
    pub fn keys(&self) -> BTreeSet<&Vec<u8>> {
        self.data.keys().collect()
    }

    /// Returns values of all entries
    pub fn values(&self) -> Vec<&Value> {
        self.data.values().collect()
    }

    /// Returns all entries
    pub fn entries(&self) -> &BTreeMap<Vec<u8>, Value> {
        &self.data
    }

    /// Inserts a new entry (key + value pair)
    pub fn ins_entry(&mut self,
                     key: Vec<u8>,
                     value: Value,
                     requester: PublicKey)
                     -> Result<(), RoutingError> {
        if !self.is_action_allowed(requester, Action::Insert) {
            return Err(RoutingError::AccessDenied);
        }
        if self.data.contains_key(&key) {
            return Err(RoutingError::EntryAlreadyExist);
        }
        if self.data.len() >= (MAX_MUTABLE_DATA_ENTRIES + 1) as usize {
            return Err(RoutingError::ExceededLimits);
        }
        let _ = self.data.insert(key.clone(), value);
        if !self.validate_size() {
            let _ = self.data.remove(&key);
            return Err(RoutingError::ExceededLimits);
        }
        Ok(())
    }

    /// Updates an existing entry (key + value pair)
    pub fn update_entry(&mut self,
                        key: Vec<u8>,
                        value: Value,
                        requester: PublicKey)
                        -> Result<(), RoutingError> {
        if !self.is_action_allowed(requester, Action::Update) {
            return Err(RoutingError::AccessDenied);
        }
        if !self.data.contains_key(&key) {
            return Err(RoutingError::EntryNotFound);
        }
        let prev = self.data.insert(key.clone(), value);
        if !self.validate_size() {
            // unwrap! would always succeed as we check that the key exists
            let _ = self.data.insert(key, unwrap!(prev));
            return Err(RoutingError::ExceededLimits);
        }
        Ok(())
    }

    /// Deletes an existing entry (key + value pair)
    pub fn del_entry(&mut self, key: &Vec<u8>, requester: PublicKey) -> Result<(), RoutingError> {
        if !self.is_action_allowed(requester, Action::Delete) {
            return Err(RoutingError::AccessDenied);
        }
        if !self.data.contains_key(key) {
            return Err(RoutingError::EntryNotFound);
        }
        let _ = self.data.remove(key);
        Ok(())
    }

    /// Insert or update permissions for the provided user.
    pub fn set_user_permissions(&mut self,
                                user: User,
                                permissions: PermissionSet,
                                requester: PublicKey)
                                -> Result<(), RoutingError> {
        if !self.is_action_allowed(requester, Action::ManagePermission) {
            return Err(RoutingError::AccessDenied);
        }
        let prev = self.permissions.insert(user.clone(), permissions);
        if !self.validate_size() {
            // Serialised data size limit is exceeded
            let _ = match prev {
                None => self.permissions.remove(&user),
                Some(perms) => self.permissions.insert(user, perms),
            };
            return Err(RoutingError::ExceededLimits);
        }
        Ok(())
    }

    /// Delete permissions for the provided user.
    pub fn del_user_permissions(&mut self,
                                user: &User,
                                requester: PublicKey)
                                -> Result<(), RoutingError> {
        if !self.is_action_allowed(requester, Action::ManagePermission) {
            return Err(RoutingError::AccessDenied);
        }
        if !self.permissions.contains_key(user) {
            return Err(RoutingError::EntryNotFound);
        }
        let _ = self.permissions.remove(user);
        Ok(())
    }

    /// Change owner of the mutable data.
    pub fn change_owner(&mut self,
                        new_owner: PublicKey,
                        requester: PublicKey)
                        -> Result<(), RoutingError> {
        if !self.owners.contains(&requester) {
            return Err(RoutingError::AccessDenied);
        }
        self.owners.clear();
        self.owners.insert(new_owner);
        Ok(())
    }

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        serialised_size(self) <= MAX_MUTABLE_DATA_SIZE_IN_BYTES
    }

    fn check_anyone_permissions(&self, action: Action) -> bool {
        match self.permissions.get(&User::Anyone) {
            None => false,
            Some(perms) => perms.is_allowed(action).unwrap_or(false),
        }
    }

    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool {
        if self.owners.contains(&requester) {
            return true;
        }
        match self.permissions.get(&User::Key(requester)) {
            Some(perms) => {
                perms.is_allowed(action)
                    .unwrap_or_else(|| self.check_anyone_permissions(action))
            }
            None => self.check_anyone_permissions(action),
        }
    }
}

impl Debug for MutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // TODO(nbaksalyar): write all other fields
        write!(formatter,
               "MutableData {{ name: {}, tag: {}, version: {}, owners: {:?} }}",
               self.name(),
               self.tag,
               self.version,
               self.owners)
    }
}

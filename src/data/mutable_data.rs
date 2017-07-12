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
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::sign::PublicKey;
use std::collections::BTreeSet;
use std::collections::btree_map::{self, BTreeMap, Entry};
use std::fmt::{self, Debug, Formatter};
use std::mem;
use xor_name::XorName;

/// Maximum allowed size for `MutableData` (1 MiB)
pub const MAX_MUTABLE_DATA_SIZE_IN_BYTES: u64 = 1024 * 1024;

/// Maximum allowed entries in `MutableData`
pub const MAX_MUTABLE_DATA_ENTRIES: u64 = 100;

/// Mutable data.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
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

/// A value in `MutableData`
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct Value {
    /// Content of the entry.
    pub content: Vec<u8>,
    /// Version of the entry.
    pub entry_version: u64,
}

/// Subject of permissions
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum User {
    /// Permissions apply to anyone.
    Anyone,
    /// Permissions apply to a single public key.
    Key(PublicKey),
}

/// Action a permission applies to
#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize)]
pub enum Action {
    /// Permission to insert new entries.
    Insert,
    /// Permission to update existing entries.
    Update,
    /// Permission to delete existing entries.
    Delete,
    /// Permission to modify permissions for other users.
    ManagePermissions,
}

/// Set of user permissions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize,
         Default)]
pub struct PermissionSet {
    insert: Option<bool>,
    update: Option<bool>,
    delete: Option<bool>,
    manage_permissions: Option<bool>,
}

impl PermissionSet {
    /// Construct new permission set.
    pub fn new() -> PermissionSet {
        PermissionSet {
            insert: None,
            update: None,
            delete: None,
            manage_permissions: None,
        }
    }

    /// Allow the given action.
    pub fn allow(mut self, action: Action) -> Self {
        match action {
            Action::Insert => self.insert = Some(true),
            Action::Update => self.update = Some(true),
            Action::Delete => self.delete = Some(true),
            Action::ManagePermissions => self.manage_permissions = Some(true),
        }
        self
    }

    /// Deny the given action.
    pub fn deny(mut self, action: Action) -> Self {
        match action {
            Action::Insert => self.insert = Some(false),
            Action::Update => self.update = Some(false),
            Action::Delete => self.delete = Some(false),
            Action::ManagePermissions => self.manage_permissions = Some(false),
        }
        self
    }

    /// Clear the permission for the given action.
    pub fn clear(mut self, action: Action) -> Self {
        match action {
            Action::Insert => self.insert = None,
            Action::Update => self.update = None,
            Action::Delete => self.delete = None,
            Action::ManagePermissions => self.manage_permissions = None,
        }
        self
    }

    /// Is the given action allowed according to this permission set?
    pub fn is_allowed(&self, action: Action) -> Option<bool> {
        match action {
            Action::Insert => self.insert,
            Action::Update => self.update,
            Action::Delete => self.delete,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

/// Operation on a single entry: insert or update.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub enum EntryAction {
    /// Insert new entry.
    Insert(Value),
    /// Update existing entry.
    Update(Value),
}

/// Helper struct to build entry actions on `MutableData`
#[derive(Debug, Default, Clone)]
pub struct EntryActions(BTreeMap<Vec<u8>, EntryAction>);

impl EntryActions {
    /// Create a helper to simplify construction of entry actions.
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new key-value pair
    pub fn insert(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.0
            .insert(key,
                    EntryAction::Insert(Value {
                                            entry_version: version,
                                            content: content,
                                        }));
        self
    }

    /// Update existing key-value pair
    pub fn update(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.0
            .insert(key,
                    EntryAction::Update(Value {
                                            entry_version: version,
                                            content: content,
                                        }));
        self
    }
}

impl Into<BTreeMap<Vec<u8>, EntryAction>> for EntryActions {
    fn into(self) -> BTreeMap<Vec<u8>, EntryAction> {
        self.0
    }
}

impl IntoIterator for EntryActions {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = btree_map::IntoIter<Vec<u8>, EntryAction>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl MutableData {
    /// Creates a new MutableData
    pub fn new(name: XorName,
               tag: u64,
               permissions: BTreeMap<User, PermissionSet>,
               data: BTreeMap<Vec<u8>, Value>,
               owners: BTreeSet<PublicKey>)
               -> Result<MutableData, ClientError> {
        let md = MutableData {
            name: name,
            tag: tag,
            data: data,
            permissions: permissions,
            version: 0,
            owners: owners,
        };

        md.validate()?;
        Ok(md)
    }

    /// Validate this data.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.owners.len() > 1 {
            return Err(ClientError::InvalidOwners);
        }
        if self.data.len() >= (MAX_MUTABLE_DATA_ENTRIES + 1) as usize {
            return Err(ClientError::TooManyEntries);
        }

        if self.serialised_size() > MAX_MUTABLE_DATA_SIZE_IN_BYTES {
            return Err(ClientError::DataTooLarge);
        }

        Ok(())
    }

    /// Returns the shell of this data. Shell contains the same fields as the data itself,
    /// except the entries.
    pub fn shell(&self) -> MutableData {
        MutableData {
            name: self.name,
            tag: self.tag,
            data: BTreeMap::new(),
            permissions: self.permissions.clone(),
            version: self.version,
            owners: self.owners.clone(),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the type tag of this MutableData
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// Returns the current version of this MutableData
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns the owner keys
    pub fn owners(&self) -> &BTreeSet<PublicKey> {
        &self.owners
    }

    /// Returns a value by the given key
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
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

    /// Removes and returns all entries
    pub fn take_entries(&mut self) -> BTreeMap<Vec<u8>, Value> {
        mem::replace(&mut self.data, BTreeMap::new())
    }

    /// Mutates entries (key + value pairs) in bulk
    pub fn mutate_entries<T>(&mut self,
                             actions: T,
                             version: u64,
                             requester: PublicKey)
                             -> Result<(), ClientError>
        where T: IntoIterator<Item = (Vec<u8>, EntryAction)>
    {
        if version != self.version {
            return Err(ClientError::VersionMismatch);
        }

        // Deconstruct actions into inserts and updates.
        let (insert, update) = actions
            .into_iter()
            .fold((Vec::new(), Vec::new()),
                  |(mut insert, mut update), (key, item)| {
                match item {
                    EntryAction::Insert(value) => {
                        insert.push((key, value));
                    }
                    EntryAction::Update(value) => {
                        update.push((key, value));
                    }
                };
                (insert, update)
            });

        if (!insert.is_empty() && !self.is_action_allowed(requester, Action::Insert)) ||
           (!update.is_empty() && !self.is_action_allowed(requester, Action::Update)) {
            return Err(ClientError::AccessDenied);
        }

        let mut new_data = self.data.clone();

        for (key, val) in insert {
            match new_data.entry(key) {
                Entry::Vacant(entry) => {
                    let _ = entry.insert(val);
                }
                Entry::Occupied(_) => return Err(ClientError::EntryExists),
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Vacant(_) => return Err(ClientError::NoSuchEntry),
                Entry::Occupied(mut entry) => {
                    if val.entry_version == entry.get().entry_version + 1 {
                        let _ = entry.insert(val);
                    } else {
                        return Err(ClientError::InvalidSuccessor);
                    }
                }
            }
        }

        if new_data.len() > MAX_MUTABLE_DATA_ENTRIES as usize {
            return Err(ClientError::TooManyEntries);
        }

        let old_data = mem::replace(&mut self.data, new_data);

        if !self.validate_size() {
            self.data = old_data;
            return Err(ClientError::DataTooLarge);
        }

        Ok(())
    }

    /// Mutates entries without performing any validation.
    ///
    /// An entry is updated only if the entry version of the mutation is higher than
    /// the current version of the entry.
    pub fn mutate_entries_without_validation<T>(&mut self, mutations: T)
        where T: IntoIterator<Item = (Vec<u8>, EntryAction)>
    {
        for (key, mutation) in mutations {
            match mutation {
                EntryAction::Insert(new_value) => {
                    let _ = self.data.insert(key, new_value);
                }
                EntryAction::Update(new_value) => {
                    match self.data.entry(key) {
                        Entry::Occupied(mut entry) => {
                            if new_value.entry_version > entry.get().entry_version {
                                let _ = entry.insert(new_value);
                            }
                        }
                        Entry::Vacant(entry) => {
                            let _ = entry.insert(new_value);
                        }
                    }
                }
            }
        }
    }

    /// Mutates single entry without performing any validations, except the version
    /// check (new version must be higher than the existing one).
    /// If the entry doesn't exist yet, inserts it, otherwise, updates it.
    /// Returns true if the version check passed and the entry was mutated,
    /// false otherwise.
    pub fn mutate_entry_without_validation(&mut self, key: Vec<u8>, value: Value) -> bool {
        match self.data.entry(key) {
            Entry::Occupied(mut entry) => {
                if value.entry_version > entry.get().entry_version {
                    let _ = entry.insert(value);
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(entry) => {
                let _ = entry.insert(value);
                true
            }
        }
    }

    /// Delete entries with the given keys.
    pub fn delete_entries<T>(&mut self,
                             keys: T,
                             version: u64,
                             requester: PublicKey)
                             -> Result<(), ClientError>
        where T: IntoIterator<Item = Vec<u8>>
    {
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor);
        }

        if !self.is_action_allowed(requester, Action::Delete) {
            return Err(ClientError::AccessDenied);
        }

        let keys: Vec<_> = keys.into_iter().collect();

        if keys.is_empty() {
            return Err(ClientError::InvalidOperation);
        }

        if keys.iter().any(|key| !self.data.contains_key(key)) {
            return Err(ClientError::NoSuchEntry);
        }

        for key in keys {
            let _ = self.data.remove(&key);
        }

        self.version = version;
        Ok(())
    }

    /// Delete entries without performing any validation, except the shell
    /// version given must be higher than the current shell version.
    pub fn delete_entries_without_validation<T>(&mut self, keys: T, version: u64) -> bool
        where T: IntoIterator<Item = Vec<u8>>
    {
        if version <= self.version {
            return false;
        }

        for key in keys {
            let _ = self.data.remove(&key);
        }

        self.version = version;
        true
    }

    /// Gets a complete list of permissions
    pub fn permissions(&self) -> &BTreeMap<User, PermissionSet> {
        &self.permissions
    }

    /// Gets a list of permissions for the provided user.
    pub fn user_permissions(&self, user: &User) -> Result<&PermissionSet, ClientError> {
        self.permissions.get(user).ok_or(ClientError::NoSuchKey)
    }

    /// Insert or update permissions for the provided user.
    pub fn set_user_permissions(&mut self,
                                user: User,
                                permissions: PermissionSet,
                                version: u64,
                                requester: PublicKey)
                                -> Result<(), ClientError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(ClientError::AccessDenied);
        }

        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor);
        }

        let prev = self.permissions.insert(user, permissions);

        if self.validate_size() {
            self.version = version;
            Ok(())
        } else {
            // Serialised data size limit is exceeded
            let _ = match prev {
                None => self.permissions.remove(&user),
                Some(perms) => self.permissions.insert(user, perms),
            };

            Err(ClientError::DataTooLarge)
        }
    }

    /// Set user permission without performing any validation.
    pub fn set_user_permissions_without_validation(&mut self,
                                                   user: User,
                                                   permissions: PermissionSet,
                                                   version: u64)
                                                   -> bool {
        if version <= self.version {
            return false;
        }

        let _ = self.permissions.insert(user, permissions);
        self.version = version;
        true
    }

    /// Delete permissions for the provided user.
    pub fn del_user_permissions(&mut self,
                                user: &User,
                                version: u64,
                                requester: PublicKey)
                                -> Result<(), ClientError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(ClientError::AccessDenied);
        }

        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor);
        }

        if self.permissions.remove(user).is_some() {
            self.version = version;
            Ok(())
        } else {
            Err(ClientError::NoSuchKey)
        }
    }

    /// Delete user permissions without performing any validation.
    pub fn del_user_permissions_without_validation(&mut self, user: &User, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        let _ = self.permissions.remove(user);
        self.version = version;
        true
    }

    /// Change owner of the mutable data.
    pub fn change_owner(&mut self, new_owner: PublicKey, version: u64) -> Result<(), ClientError> {
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor);
        }
        self.owners.clear();
        self.owners.insert(new_owner);
        self.version = version;
        Ok(())
    }

    /// Change the owner without performing any validation.
    pub fn change_owner_without_validation(&mut self, new_owner: PublicKey, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        self.owners.clear();
        self.owners.insert(new_owner);
        self.version = version;
        true
    }

    /// Return the size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialisation::serialised_size(self)
    }

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        self.serialised_size() <= MAX_MUTABLE_DATA_SIZE_IN_BYTES
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
                perms
                    .is_allowed(action)
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

#[cfg(test)]
mod tests {
    use super::*;
    use client_error::ClientError;
    use rand;
    use rust_sodium::crypto::sign;
    use std::collections::{BTreeMap, BTreeSet};
    use std::iter;

    macro_rules! assert_err {
        ($left: expr, $err: path) => {{
            let result = $left; // required to prevent multiple repeating expansions
            assert!(if let Err($err) = result {
                true
            } else {
                false
            }, "Expected Err({:?}), found {:?}", $err, result);
        }}
    }

    #[test]
    fn mutable_data_permissions() {
        let (owner, _) = sign::gen_keypair();
        let (pk1, _) = sign::gen_keypair();
        let (pk2, _) = sign::gen_keypair();

        let mut perms = BTreeMap::new();

        let ps1 = PermissionSet::new().allow(Action::Update);
        let _ = perms.insert(User::Anyone, ps1);

        let ps2 = PermissionSet::new()
            .deny(Action::Update)
            .allow(Action::Insert);
        let _ = perms.insert(User::Key(pk1), ps2);

        let k1 = b"123".to_vec();
        let k2 = b"234".to_vec();

        let mut owners = BTreeSet::new();
        owners.insert(owner);
        let mut md = unwrap!(MutableData::new(rand::random(), 0, perms, BTreeMap::new(), owners));

        // Check insert permissions
        unwrap!(md.mutate_entries(EntryActions::new().insert(k1.clone(), b"abc".to_vec(), 0),
                                  0,
                                  pk1));

        assert_err!(md.mutate_entries(EntryActions::new().insert(k2.clone(), b"def".to_vec(), 0),
                                      0,
                                      pk2),
                    ClientError::AccessDenied);
        assert!(md.get(&k1).is_some());

        // Check update permissions
        let muts = EntryActions::new().update(k1.clone(), b"def".to_vec(), 1);
        assert_err!(md.mutate_entries(muts.clone(), 0, pk1),
                    ClientError::AccessDenied);
        unwrap!(md.mutate_entries(muts, 0, pk2));

        // Check delete permissions (which should be implicitly forbidden)
        let keys = iter::once(k1.clone());
        assert_err!(md.delete_entries(keys.clone(), 1, pk1),
                    ClientError::AccessDenied);
        assert!(md.get(&k1).is_some());

        // Actions requested by owner should always be allowed
        unwrap!(md.delete_entries(keys, 1, owner));
        assert!(md.get(&k1).is_none());
    }

    #[test]
    fn permissions() {
        let anyone = PermissionSet::new()
            .allow(Action::Insert)
            .deny(Action::Delete);
        assert!(unwrap!(anyone.is_allowed(Action::Insert)));
        assert!(anyone.is_allowed(Action::Update).is_none());
        assert!(!unwrap!(anyone.is_allowed(Action::Delete)));
        assert!(anyone.is_allowed(Action::ManagePermissions).is_none());

        let user1 = anyone
            .clear(Action::Delete)
            .deny(Action::ManagePermissions);
        assert!(unwrap!(user1.is_allowed(Action::Insert)));
        assert!(user1.is_allowed(Action::Update).is_none());
        assert!(user1.is_allowed(Action::Delete).is_none());
        assert!(!unwrap!(user1.is_allowed(Action::ManagePermissions)));

        let user2 = user1.allow(Action::Update);
        assert!(unwrap!(user2.is_allowed(Action::Insert)));
        assert!(unwrap!(user2.is_allowed(Action::Update)));
        assert!(user2.is_allowed(Action::Delete).is_none());
        assert!(!unwrap!(user2.is_allowed(Action::ManagePermissions)));
    }

    #[test]
    fn max_entries_limit() {
        let val = Value {
            content: b"123".to_vec(),
            entry_version: 0,
        };

        // It must not be possible to create MutableData whose number of entries exceeds the limit.
        let mut data = BTreeMap::new();
        for i in 0..MAX_MUTABLE_DATA_ENTRIES + 1 {
            let _ = data.insert(vec![i as u8], val.clone());
        }
        assert_err!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, BTreeSet::new()),
                    ClientError::TooManyEntries);

        let mut data = BTreeMap::new();
        for i in 0..MAX_MUTABLE_DATA_ENTRIES - 1 {
            let _ = data.insert(vec![i as u8], val.clone());
        }

        let (owner, _) = sign::gen_keypair();
        let owners = iter::once(owner).collect();
        let mut md = unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, owners));

        // Reach the limit.
        let muts = iter::once((vec![99u8], EntryAction::Insert(val.clone())));
        unwrap!(md.mutate_entries(muts, 0, owner));

        assert_eq!(md.keys().len(), MAX_MUTABLE_DATA_ENTRIES as usize);
        assert_eq!(md.values().len(), MAX_MUTABLE_DATA_ENTRIES as usize);
        assert_eq!(md.entries().len(), MAX_MUTABLE_DATA_ENTRIES as usize);

        // Try to get over the limit.
        let muts = iter::once((vec![100u8], EntryAction::Insert(val.clone())));
        assert_err!(md.mutate_entries(muts.clone(), 0, owner),
                    ClientError::TooManyEntries);


        // Insertion is allowed again after deleting some entries first.
        let keys = iter::once(vec![0u8]);
        unwrap!(md.delete_entries(keys, 1, owner));
        unwrap!(md.mutate_entries(muts, 1, owner));
    }

    #[test]
    fn size_limit() {
        let big_val = Value {
            content: vec![0; (MAX_MUTABLE_DATA_SIZE_IN_BYTES - 1024) as usize],
            entry_version: 0,
        };

        let small_val = Value {
            content: vec![0; 2048],
            entry_version: 0,
        };

        // It must not be possible to create MutableData that exceeds the size limit.
        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0], big_val.clone());
        let _ = data.insert(vec![1], small_val.clone());

        assert_err!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, BTreeSet::new()),
                    ClientError::DataTooLarge);

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0], big_val.clone());

        let (owner, _) = sign::gen_keypair();
        let owners = iter::once(owner).collect();
        let mut md = unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, owners));

        // Try to get over the size limit
        let muts = iter::once((vec![1], EntryAction::Insert(small_val.clone())));
        assert_err!(md.mutate_entries(muts.clone(), 0, owner),
                    ClientError::DataTooLarge);

        // Insertion is allowed again after deleting some entries first.
        let keys = iter::once(vec![0]);
        unwrap!(md.delete_entries(keys, 1, owner));
        unwrap!(md.mutate_entries(muts, 1, owner));
    }

    #[test]
    fn transfer_ownership() {
        let (owner, _) = sign::gen_keypair();
        let (pk1, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        owners.insert(owner);

        let mut md =
            unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), BTreeMap::new(), owners));

        assert!(md.change_owner(pk1, 1).is_ok());
        assert!(md.owners().contains(&pk1));
        assert!(!md.owners().contains(&owner));
    }

    #[test]
    fn entry_versions_succession() {
        let (owner, _) = sign::gen_keypair();
        let owners = iter::once(owner).collect();
        let mut md =
            unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), BTreeMap::new(), owners));

        let v1 = iter::once((vec![1],
                             EntryAction::Insert(Value {
                                                     content: vec![100],
                                                     entry_version: 0,
                                                 })));
        unwrap!(md.mutate_entries(v1, 0, owner));

        // Check update with invalid entry versions
        let v2 = iter::once((vec![1],
                             EntryAction::Update(Value {
                                                     content: vec![105],
                                                     entry_version: 0,
                                                 })));
        assert_err!(md.mutate_entries(v2, 0, owner),
                    ClientError::InvalidSuccessor);

        let v2 = iter::once((vec![1],
                             EntryAction::Update(Value {
                                                     content: vec![105],
                                                     entry_version: 2,
                                                 })));
        assert_err!(md.mutate_entries(v2, 0, owner),
                    ClientError::InvalidSuccessor);

        // Check update with invalid shell version
        let v2 = iter::once((vec![1],
                             EntryAction::Update(Value {
                                                     content: vec![105],
                                                     entry_version: 1,
                                                 })));
        assert_err!(md.mutate_entries(v2, 1, owner),
                    ClientError::VersionMismatch);

        // Check update with valid entry and shell versions
        let v2 = iter::once((vec![1],
                             EntryAction::Update(Value {
                                                     content: vec![105],
                                                     entry_version: 1,
                                                 })));
        unwrap!(md.mutate_entries(v2, 0, owner));
    }

    #[test]
    fn changing_permissions() {
        let (owner, _) = sign::gen_keypair();
        let (pk1, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        owners.insert(owner);

        let mut md =
            unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), BTreeMap::new(), owners));

        // Trying to do inserts without having a permission must fail
        let v1 = iter::once((vec![0],
                             EntryAction::Insert(Value {
                                                     content: vec![1],
                                                     entry_version: 0,
                                                 })));
        assert_err!(md.mutate_entries(v1.clone(), 0, pk1),
                    ClientError::AccessDenied);

        // Now allow inserts for pk1
        let ps1 = PermissionSet::new()
            .allow(Action::Insert)
            .allow(Action::ManagePermissions);
        unwrap!(md.set_user_permissions(User::Key(pk1), ps1, 1, owner));

        unwrap!(md.mutate_entries(v1, 1, pk1));

        // pk1 now can change permissions
        let ps2 = PermissionSet::new()
            .allow(Action::Insert)
            .deny(Action::ManagePermissions);
        assert_err!(md.set_user_permissions(User::Key(pk1), ps2, 1, pk1),
                    ClientError::InvalidSuccessor);
        unwrap!(md.set_user_permissions(User::Key(pk1), ps2, 2, pk1));

        // Revoke permissions for pk1
        assert_err!(md.del_user_permissions(&User::Key(pk1), 3, pk1),
                    ClientError::AccessDenied);

        unwrap!(md.del_user_permissions(&User::Key(pk1), 3, owner));

        let v2 = iter::once((vec![1],
                             EntryAction::Insert(Value {
                                                     content: vec![1],
                                                     entry_version: 0,
                                                 })));
        assert_err!(md.mutate_entries(v2, 3, pk1), ClientError::AccessDenied);

        // Revoking permissions for a non-existing user should return an error
        assert_err!(md.del_user_permissions(&User::Key(pk1), 4, owner),
                    ClientError::NoSuchKey);

        // Get must always be allowed
        assert!(md.get(&[0]).is_some());
        assert!(md.get(&[1]).is_none());
    }

    #[test]
    fn deleting_entries() {
        let (owner, _) = sign::gen_keypair();
        let owners = iter::once(owner).collect();

        let k0 = vec![0];
        let k1 = vec![1];
        let k2 = vec![2];

        let mut entries = BTreeMap::new();
        let _ = entries.insert(k0.clone(),
                               Value {
                                   content: vec![0],
                                   entry_version: 0,
                               });
        let _ = entries.insert(k1.clone(),
                               Value {
                                   content: vec![1],
                                   entry_version: 0,
                               });
        let _ = entries.insert(k2.clone(),
                               Value {
                                   content: vec![2],
                                   entry_version: 0,
                               });

        let mut md = unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), entries, owners));

        // Delete requires version bump.
        let keys = vec![k0.clone(), k1.clone()];
        assert_err!(md.delete_entries(keys.clone(), 0, owner),
                    ClientError::InvalidSuccessor);

        unwrap!(md.delete_entries(keys, 1, owner));
        assert!(md.get(&k0).is_none());
        assert!(md.get(&k1).is_none());
        assert!(md.get(&k2).is_some());
        assert_eq!(md.version(), 1);

        // Delete without validation requires version higher than the current version.
        assert!(!md.delete_entries_without_validation(iter::once(k2.clone()), 1));
        assert!(md.delete_entries_without_validation(iter::once(k2.clone()), 2));
        assert!(md.get(&k2).is_none());
        assert_eq!(md.version(), 2);
    }
}

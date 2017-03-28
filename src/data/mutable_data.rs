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
use maidsafe_utilities::serialisation::serialised_size;
use rust_sodium::crypto::sign::PublicKey;
use std::collections::BTreeSet;
use std::collections::btree_map::{BTreeMap, Entry};
use std::fmt::{self, Debug, Formatter};
use xor_name::XorName;

/// Maximum allowed size for `MutableData` (1 MiB)
pub const MAX_MUTABLE_DATA_SIZE_IN_BYTES: u64 = 1024 * 1024;

/// Maximum allowed entries in `MutableData`
pub const MAX_MUTABLE_DATA_ENTRIES: u64 = 100;

/// Manimum number of entries that can be mutated simulaneously.
pub const MAX_MUTABLE_DATA_ENTRY_ACTIONS: u64 = 10;

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

/// A value in `MutableData`
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable, Debug)]
pub struct Value {
    /// Content of the entry.
    pub content: Vec<u8>,
    /// Version of the entry.
    pub entry_version: u64,
}

/// Subject of permissions
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, RustcDecodable, RustcEncodable, Debug)]
pub enum User {
    /// Permissions apply to anyone.
    Anyone,
    /// Permissions apply to a single public key.
    Key(PublicKey),
}

/// Action a permission applies to
#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Copy, Clone, RustcEncodable, RustcDecodable)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, RustcEncodable, RustcDecodable,
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

/// Action performed on a single entry: insert, update or delete.
#[derive(Hash, Debug, Eq, PartialEq, Clone, PartialOrd, Ord, RustcDecodable, RustcEncodable)]
pub enum EntryAction {
    /// Inserts a new entry
    Ins(Value),
    /// Updates an entry with a new value and version
    Update(Value),
    /// Deletes an entry by emptying its contents. Contains the version number
    Del(u64),
}

/// Helper struct to build entry actions on `MutableData`
#[derive(Debug, Default, Clone)]
pub struct EntryActions {
    actions: BTreeMap<Vec<u8>, EntryAction>,
}

impl EntryActions {
    /// Create a helper to simplify construction of `MutableData` actions
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new key-value pair
    pub fn ins(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(key,
                                    EntryAction::Ins(Value {
                                        entry_version: version,
                                        content: content,
                                    }));
        self
    }

    /// Update existing key-value pair
    pub fn update(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(key,
                                    EntryAction::Update(Value {
                                        entry_version: version,
                                        content: content,
                                    }));
        self
    }

    /// Delete existing key
    pub fn del(mut self, key: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(key, EntryAction::Del(version));
        self
    }
}

impl Into<BTreeMap<Vec<u8>, EntryAction>> for EntryActions {
    fn into(self) -> BTreeMap<Vec<u8>, EntryAction> {
        self.actions
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

        if serialised_size(self) > MAX_MUTABLE_DATA_SIZE_IN_BYTES {
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

    /// Mutates entries (key + value pairs) in bulk
    pub fn mutate_entries(&mut self,
                          actions: BTreeMap<Vec<u8>, EntryAction>,
                          requester: PublicKey)
                          -> Result<(), ClientError> {
        if actions.len() > MAX_MUTABLE_DATA_ENTRY_ACTIONS as usize {
            return Err(ClientError::TooManyMutations);
        }

        // Deconstruct actions into inserts, updates, and deletes
        let (insert, update, delete) = actions.into_iter()
            .fold((BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
                  |(mut insert, mut update, mut delete), (key, item)| {
                match item {
                    EntryAction::Ins(value) => {
                        let _ = insert.insert(key, value);
                    }
                    EntryAction::Update(value) => {
                        let _ = update.insert(key, value);
                    }
                    EntryAction::Del(version) => {
                        let _ = delete.insert(key, version);
                    }
                };
                (insert, update, delete)
            });

        if (!insert.is_empty() && !self.is_action_allowed(requester, Action::Insert)) ||
           (!update.is_empty() && !self.is_action_allowed(requester, Action::Update)) ||
           (!delete.is_empty() && !self.is_action_allowed(requester, Action::Delete)) {
            return Err(ClientError::AccessDenied);
        }
        if (!insert.is_empty() || !update.is_empty()) &&
           self.data.len() > MAX_MUTABLE_DATA_ENTRIES as usize {
            return Err(ClientError::TooManyEntries);
        }
        if (!insert.is_empty() || !update.is_empty()) && !self.validate_size() {
            return Err(ClientError::DataTooLarge);
        }

        for (key, val) in insert {
            if self.data.contains_key(&key) {
                return Err(ClientError::EntryExists);
            }
            let _ = self.data.insert(key.clone(), val);
        }

        for (key, val) in update {
            if !self.data.contains_key(&key) {
                return Err(ClientError::NoSuchEntry);
            }
            let version_valid = if let Entry::Occupied(mut oe) = self.data.entry(key.clone()) {
                if val.entry_version != oe.get().entry_version + 1 {
                    false
                } else {
                    let _prev = oe.insert(val);
                    true
                }
            } else {
                false
            };
            if !version_valid {
                return Err(ClientError::InvalidSuccessor);
            }
        }

        for (key, version) in delete {
            if !self.data.contains_key(&key) {
                return Err(ClientError::NoSuchEntry);
            }
            let version_valid = if let Entry::Occupied(mut oe) = self.data.entry(key.clone()) {
                if version != oe.get().entry_version + 1 {
                    false
                } else {
                    /// TODO(nbaksalyar): find a way to decrease a number of entries after deletion.
                    /// In the current implementation if a number of entries exceeds the limit
                    /// there's no way for an owner to delete unneeded entries.
                    let _prev = oe.insert(Value {
                        content: vec![],
                        entry_version: version,
                    });
                    true
                }
            } else {
                false
            };
            if !version_valid {
                return Err(ClientError::InvalidSuccessor);
            }
        }

        if !self.validate_mut_size() {
            return Err(ClientError::DataTooLarge);
        }

        Ok(())
    }

    /// Mutates single entry withou performing any validations, except the version
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
        let prev = self.permissions.insert(user.clone(), permissions);
        if !self.validate_mut_size() {
            // Serialised data size limit is exceeded
            let _ = match prev {
                None => self.permissions.remove(&user),
                Some(perms) => self.permissions.insert(user, perms),
            };
            return Err(ClientError::DataTooLarge);
        }
        self.version = version;
        Ok(())
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
        if !self.permissions.contains_key(user) {
            return Err(ClientError::NoSuchKey);
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        Ok(())
    }

    /// Change owner of the mutable data.
    pub fn change_owner(&mut self,
                        new_owner: PublicKey,
                        version: u64,
                        requester: PublicKey)
                        -> Result<(), ClientError> {
        if !self.owners.contains(&requester) {
            return Err(ClientError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor);
        }
        self.owners.clear();
        self.owners.insert(new_owner);
        self.version = version;
        Ok(())
    }

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        serialised_size(self) <= MAX_MUTABLE_DATA_SIZE_IN_BYTES
    }

    /// Return true if the size is valid after a mutation. We need to have this
    /// because of eventual consistency requirements - in certain cases entries
    /// can go over the default cap of 1 MiB.
    fn validate_mut_size(&self) -> bool {
        serialised_size(self) <= MAX_MUTABLE_DATA_SIZE_IN_BYTES * 2
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

        let ps2 = PermissionSet::new().deny(Action::Update).allow(Action::Insert);
        let _ = perms.insert(User::Key(pk1), ps2);

        let k1 = b"123".to_vec();
        let k2 = b"234".to_vec();

        let mut owners = BTreeSet::new();
        owners.insert(owner);
        let mut md = unwrap!(MutableData::new(rand::random(), 0, perms, BTreeMap::new(), owners));

        // Check insert permissions
        assert!(md.mutate_entries(EntryActions::new()
                                .ins(k1.clone(), b"abc".to_vec(), 0)
                                .into(),
                            pk1)
            .is_ok());

        assert_err!(md.mutate_entries(EntryActions::new()
                                          .ins(k2.clone(), b"def".to_vec(), 0)
                                          .into(),
                                      pk2),
                    ClientError::AccessDenied);

        assert!(md.get(&k1).is_some());

        // Check update permissions
        let upd = EntryActions::new().update(k1.clone(), b"def".to_vec(), 1);

        assert_err!(md.mutate_entries(upd.clone().into(), pk1),
                    ClientError::AccessDenied);

        assert!(md.mutate_entries(upd.into(), pk2).is_ok());

        // Check delete permissions (which should be implicitly forbidden)
        let del = EntryActions::new().del(k1.clone(), 2);
        assert_err!(md.mutate_entries(del.clone().into(), pk1),
                    ClientError::AccessDenied);
        assert!(md.get(&k1).is_some());

        // Actions requested by owner should always be allowed
        assert!(md.mutate_entries(del.into(), owner).is_ok());
        assert_eq!(md.get(&k1).unwrap().content, Vec::<u8>::new());
    }

    #[test]
    fn permissions() {
        let anyone = PermissionSet::new().allow(Action::Insert).deny(Action::Delete);
        assert!(unwrap!(anyone.is_allowed(Action::Insert)));
        assert!(anyone.is_allowed(Action::Update).is_none());
        assert!(!unwrap!(anyone.is_allowed(Action::Delete)));
        assert!(anyone.is_allowed(Action::ManagePermissions).is_none());

        let user1 = anyone.clear(Action::Delete).deny(Action::ManagePermissions);
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

        // It must not be possible to create MutableData with more than 101 entries
        let mut data = BTreeMap::new();
        for i in 0..105 {
            let _ = data.insert(vec![i], val.clone());
        }
        assert_err!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, BTreeSet::new()),
                    ClientError::TooManyEntries);

        let mut data = BTreeMap::new();
        for i in 0..100 {
            let _ = data.insert(vec![i], val.clone());
        }

        let (owner, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        assert!(owners.insert(owner), true);

        let mut md = unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, owners));

        assert_eq!(md.keys().len(), 100);
        assert_eq!(md.values().len(), 100);
        assert_eq!(md.entries().len(), 100);

        // Try to get over the limit
        let mut v1 = BTreeMap::new();
        let _ = v1.insert(vec![101u8], EntryAction::Ins(val.clone()));
        assert!(md.mutate_entries(v1, owner).is_ok());

        let mut v2 = BTreeMap::new();
        let _ = v2.insert(vec![102u8], EntryAction::Ins(val.clone()));
        assert_err!(md.mutate_entries(v2.clone(), owner),
                    ClientError::TooManyEntries);

        let mut del = BTreeMap::new();
        let _ = del.insert(vec![101u8], EntryAction::Del(1));
        assert!(md.mutate_entries(del, owner).is_ok());
    }

    #[test]
    fn size_limit() {
        let big_val = Value {
            content: iter::repeat(0)
                .take((MAX_MUTABLE_DATA_SIZE_IN_BYTES - 1024) as usize)
                .collect(),
            entry_version: 0,
        };

        let small_val = Value {
            content: iter::repeat(0).take(2048).collect(),
            entry_version: 0,
        };

        // It must not be possible to create MutableData with size of more than 1 MiB
        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0], big_val.clone());
        let _ = data.insert(vec![1], small_val.clone());

        assert_err!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, BTreeSet::new()),
                    ClientError::DataTooLarge);

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0], big_val.clone());

        let (owner, _) = sign::gen_keypair();
        let mut owners = BTreeSet::new();
        assert!(owners.insert(owner), true);

        let mut md = unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), data, owners));

        // Try to get over the mutation limit of 2 MiB
        let mut v1 = BTreeMap::new();
        let _ = v1.insert(vec![1], EntryAction::Ins(big_val.clone()));
        assert!(md.mutate_entries(v1, owner).is_ok());

        let mut v2 = BTreeMap::new();
        let _ = v2.insert(vec![2], EntryAction::Ins(small_val.clone()));
        assert_err!(md.mutate_entries(v2.clone(), owner),
                    ClientError::DataTooLarge);

        let mut del = BTreeMap::new();
        let _ = del.insert(vec![0], EntryAction::Del(1));
        assert!(md.mutate_entries(del, owner).is_ok());

        assert!(md.mutate_entries(v2, owner).is_ok());
    }

    #[test]
    fn transfer_ownership() {
        let (owner, _) = sign::gen_keypair();
        let (pk1, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        owners.insert(owner);

        let mut md =
            unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), BTreeMap::new(), owners));

        // Try to do ownership transfer from a non-owner requester
        assert_err!(md.change_owner(pk1, 1, pk1), ClientError::AccessDenied);

        // Transfer ownership from an owner
        assert!(md.change_owner(pk1, 1, owner).is_ok());
        assert_err!(md.change_owner(owner, 1, owner), ClientError::AccessDenied);
    }

    #[test]
    fn versions_succession() {
        let (owner, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        owners.insert(owner);
        let mut md =
            unwrap!(MutableData::new(rand::random(), 0, BTreeMap::new(), BTreeMap::new(), owners));

        let mut v1 = BTreeMap::new();
        let _ = v1.insert(vec![1],
                          EntryAction::Ins(Value {
                              content: vec![100],
                              entry_version: 0,
                          }));
        assert!(md.mutate_entries(v1, owner).is_ok());

        // Check update with invalid versions
        let mut v2 = BTreeMap::new();
        let _ = v2.insert(vec![1],
                          EntryAction::Update(Value {
                              content: vec![105],
                              entry_version: 0,
                          }));
        assert_err!(md.mutate_entries(v2.clone(), owner),
                    ClientError::InvalidSuccessor);

        let _ = v2.insert(vec![1],
                          EntryAction::Update(Value {
                              content: vec![105],
                              entry_version: 2,
                          }));
        assert_err!(md.mutate_entries(v2.clone(), owner),
                    ClientError::InvalidSuccessor);

        // Check update with a valid version
        let _ = v2.insert(vec![1],
                          EntryAction::Update(Value {
                              content: vec![105],
                              entry_version: 1,
                          }));
        assert!(md.mutate_entries(v2, owner).is_ok());

        // Check delete version
        let mut del = BTreeMap::new();
        let _ = del.insert(vec![1], EntryAction::Del(1));
        assert_err!(md.mutate_entries(del.clone(), owner),
                    ClientError::InvalidSuccessor);

        let _ = del.insert(vec![1], EntryAction::Del(2));
        assert!(md.mutate_entries(del, owner).is_ok());
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
        let mut v1 = BTreeMap::new();
        let _ = v1.insert(vec![0],
                          EntryAction::Ins(Value {
                              content: vec![1],
                              entry_version: 0,
                          }));
        assert_err!(md.mutate_entries(v1.clone(), pk1),
                    ClientError::AccessDenied);

        // Now allow inserts for pk1
        let ps1 = PermissionSet::new().allow(Action::Insert).allow(Action::ManagePermissions);
        assert!(md.set_user_permissions(User::Key(pk1), ps1, 1, owner).is_ok());

        assert!(md.mutate_entries(v1, pk1).is_ok());

        // pk1 now can change permissions
        let ps2 = PermissionSet::new().allow(Action::Insert).deny(Action::ManagePermissions);
        assert_err!(md.set_user_permissions(User::Key(pk1), ps2.clone(), 1, pk1),
                    ClientError::InvalidSuccessor);
        assert!(md.set_user_permissions(User::Key(pk1), ps2, 2, pk1).is_ok());

        // Revoke permissions for pk1
        assert_err!(md.del_user_permissions(&User::Key(pk1), 3, pk1),
                    ClientError::AccessDenied);

        assert!(md.del_user_permissions(&User::Key(pk1), 3, owner).is_ok());

        let mut v2 = BTreeMap::new();
        let _ = v2.insert(vec![1],
                          EntryAction::Ins(Value {
                              content: vec![1],
                              entry_version: 0,
                          }));
        assert_err!(md.mutate_entries(v2, pk1), ClientError::AccessDenied);

        // Revoking permissions for a non-existing user should return an error
        assert_err!(md.del_user_permissions(&User::Key(pk1), 4, owner),
                    ClientError::NoSuchKey);

        // Get must always be allowed
        assert!(md.get(&[0]).is_some());
        assert!(md.get(&[1]).is_none());
    }
}

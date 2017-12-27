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

use client_error::{ClientError, EntryError};
use maidsafe_utilities::serialisation;
use rand::{Rand, Rng};
use rust_sodium::crypto::sign::PublicKey;
use std::collections::BTreeSet;
use std::collections::btree_map::{BTreeMap, Entry};
use std::fmt::{self, Debug, Formatter};
use std::mem;
use xor_name::XorName;

/// Maximum allowed size for `MutableData` (1 MiB)
pub const MAX_MUTABLE_DATA_SIZE_IN_BYTES: u64 = 1024 * 1024;

/// Maximum allowed entries in `MutableData`
pub const MAX_MUTABLE_DATA_ENTRIES: u64 = 1000;

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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Default)]
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

impl Rand for PermissionSet {
    fn rand<R: Rng>(rng: &mut R) -> PermissionSet {
        PermissionSet {
            insert: Rand::rand(rng),
            update: Rand::rand(rng),
            delete: Rand::rand(rng),
            manage_permissions: Rand::rand(rng),
        }
    }
}

/// Action performed on a single entry: insert, update or delete.
#[derive(Hash, Debug, Eq, PartialEq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
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
        let _ = self.actions.insert(
            key,
            EntryAction::Ins(Value {
                entry_version: version,
                content: content,
            }),
        );
        self
    }

    /// Update existing key-value pair
    pub fn update(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            EntryAction::Update(Value {
                entry_version: version,
                content: content,
            }),
        );
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
    pub fn new(
        name: XorName,
        tag: u64,
        permissions: BTreeMap<User, PermissionSet>,
        data: BTreeMap<Vec<u8>, Value>,
        owners: BTreeSet<PublicKey>,
    ) -> Result<MutableData, ClientError> {
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
    pub fn mutate_entries(
        &mut self,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        requester: PublicKey,
    ) -> Result<(), ClientError> {
        // Deconstruct actions into inserts, updates, and deletes
        let (insert, update, delete) =
            actions.into_iter().fold(
                (BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
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
                },
            );

        if (!insert.is_empty() && !self.is_action_allowed(requester, Action::Insert)) ||
            (!update.is_empty() && !self.is_action_allowed(requester, Action::Update)) ||
            (!delete.is_empty() && !self.is_action_allowed(requester, Action::Delete))
        {
            return Err(ClientError::AccessDenied);
        }

        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                Entry::Occupied(entry) => {
                    let _ = errors.insert(
                        entry.key().clone(),
                        EntryError::EntryExists(entry.get().entry_version),
                    );
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(val);
                }
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let current_version = entry.get().entry_version;
                    if val.entry_version == current_version + 1 {
                        let _ = entry.insert(val);
                    } else {
                        let _ = errors.insert(
                            entry.key().clone(),
                            EntryError::InvalidSuccessor(current_version),
                        );
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for (key, version) in delete {
            // TODO(nbaksalyar): find a way to decrease a number of entries after deletion.
            // In the current implementation if a number of entries exceeds the limit
            // there's no way for an owner to delete unneeded entries.
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let current_version = entry.get().entry_version;
                    if version == current_version + 1 {
                        let _ = entry.insert(Value {
                            content: Vec::new(),
                            entry_version: version,
                        });
                    } else {
                        let _ = errors.insert(
                            entry.key().clone(),
                            EntryError::InvalidSuccessor(current_version),
                        );
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        if !errors.is_empty() {
            return Err(ClientError::InvalidEntryActions(errors));
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
    /// For updates and deletes, the mutation is performed only if he entry version
    /// of the action is higher than the current version of the entry.
    pub fn mutate_entries_without_validation(&mut self, actions: BTreeMap<Vec<u8>, EntryAction>) {
        for (key, action) in actions {
            match action {
                EntryAction::Ins(new_value) => {
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
                EntryAction::Del(new_version) => {
                    if let Entry::Occupied(mut entry) = self.data.entry(key) {
                        if new_version > entry.get().entry_version {
                            let _ = entry.insert(Value {
                                content: Vec::new(),
                                entry_version: new_version,
                            });
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

    /// Gets a complete list of permissions
    pub fn permissions(&self) -> &BTreeMap<User, PermissionSet> {
        &self.permissions
    }

    /// Gets a list of permissions for the provided user.
    pub fn user_permissions(&self, user: &User) -> Result<&PermissionSet, ClientError> {
        self.permissions.get(user).ok_or(ClientError::NoSuchKey)
    }

    /// Insert or update permissions for the provided user.
    pub fn set_user_permissions(
        &mut self,
        user: User,
        permissions: PermissionSet,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), ClientError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(ClientError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor(self.version));
        }
        let prev = self.permissions.insert(user, permissions);
        if !self.validate_size() {
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

    /// Set user permission without performing any validation.
    pub fn set_user_permissions_without_validation(
        &mut self,
        user: User,
        permissions: PermissionSet,
        version: u64,
    ) -> bool {
        if version <= self.version {
            return false;
        }

        let _ = self.permissions.insert(user, permissions);
        self.version = version;
        true
    }

    /// Delete permissions for the provided user.
    pub fn del_user_permissions(
        &mut self,
        user: &User,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), ClientError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(ClientError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor(self.version));
        }
        if !self.permissions.contains_key(user) {
            return Err(ClientError::NoSuchKey);
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        Ok(())
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
            return Err(ClientError::InvalidSuccessor(self.version));
        }
        self.owners.clear();
        let _ = self.owners.insert(new_owner);
        self.version = version;
        Ok(())
    }

    /// Change the owner without performing any validation.
    pub fn change_owner_without_validation(&mut self, new_owner: PublicKey, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        self.owners.clear();
        let _ = self.owners.insert(new_owner);
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
                perms.is_allowed(action).unwrap_or_else(|| {
                    self.check_anyone_permissions(action)
                })
            }
            None => self.check_anyone_permissions(action),
        }
    }
}

impl Debug for MutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // TODO(nbaksalyar): write all other fields
        write!(
            formatter,
            "MutableData {{ name: {}, tag: {}, version: {}, owners: {:?} }}",
            self.name(),
            self.tag,
            self.version,
            self.owners
        )
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
        ($left: expr, $err: pat) => {{
            let result = $left; // required to prevent multiple repeating expansions
            match result {
                Err($err) => (),
                _ => panic!("Expected Err({:?}), found {:?}", stringify!($err), result),
            }
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

        let ps2 = PermissionSet::new().deny(Action::Update).allow(
            Action::Insert,
        );
        let _ = perms.insert(User::Key(pk1), ps2);

        let k1 = b"123".to_vec();
        let k2 = b"234".to_vec();

        let mut owners = BTreeSet::new();
        let _ = owners.insert(owner);
        let mut md = unwrap!(MutableData::new(
            rand::random(),
            0,
            perms,
            BTreeMap::new(),
            owners,
        ));

        // Check insert permissions
        assert!(
            md.mutate_entries(
                EntryActions::new()
                    .ins(k1.clone(), b"abc".to_vec(), 0)
                    .into(),
                pk1,
            ).is_ok()
        );

        assert_err!(
            md.mutate_entries(
                EntryActions::new()
                    .ins(k2.clone(), b"def".to_vec(), 0)
                    .into(),
                pk2,
            ),
            ClientError::AccessDenied
        );

        assert!(md.get(&k1).is_some());

        // Check update permissions
        let upd = EntryActions::new().update(k1.clone(), b"def".to_vec(), 1);

        assert_err!(
            md.mutate_entries(upd.clone().into(), pk1),
            ClientError::AccessDenied
        );

        assert!(md.mutate_entries(upd.into(), pk2).is_ok());

        // Check delete permissions (which should be implicitly forbidden)
        let del = EntryActions::new().del(k1.clone(), 2);
        assert_err!(
            md.mutate_entries(del.clone().into(), pk1),
            ClientError::AccessDenied
        );
        assert!(md.get(&k1).is_some());

        // Actions requested by owner should always be allowed
        assert!(md.mutate_entries(del.into(), owner).is_ok());
        assert_eq!(md.get(&k1).unwrap().content, Vec::<u8>::new());
    }

    #[test]
    fn permissions() {
        let anyone = PermissionSet::new().allow(Action::Insert).deny(
            Action::Delete,
        );
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
        let to_vec_of_u8 = |i: u64| vec![(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8];
        let val = Value {
            content: b"123".to_vec(),
            entry_version: 0,
        };

        // It must not be possible to create MutableData whose number of entries exceeds the limit.
        let mut data = BTreeMap::new();
        for i in 0..MAX_MUTABLE_DATA_ENTRIES + 1 {
            assert!(data.insert(to_vec_of_u8(i), val.clone()).is_none());
        }
        assert_err!(
            MutableData::new(rand::random(), 0, BTreeMap::new(), data, BTreeSet::new()),
            ClientError::TooManyEntries
        );

        let mut data = BTreeMap::new();
        for i in 0..MAX_MUTABLE_DATA_ENTRIES - 1 {
            assert!(data.insert(to_vec_of_u8(i), val.clone()).is_none());
        }

        let (owner, _) = sign::gen_keypair();
        let owners = iter::once(owner).collect();
        let mut md = unwrap!(MutableData::new(
            rand::random(),
            0,
            BTreeMap::new(),
            data,
            owners,
        ));

        // Reach the limit.
        let actions = iter::once((
            to_vec_of_u8(MAX_MUTABLE_DATA_ENTRIES - 1),
            EntryAction::Ins(val.clone()),
        )).collect();
        unwrap!(md.mutate_entries(actions, owner));

        assert_eq!(md.keys().len(), MAX_MUTABLE_DATA_ENTRIES as usize);
        assert_eq!(md.values().len(), MAX_MUTABLE_DATA_ENTRIES as usize);
        assert_eq!(md.entries().len(), MAX_MUTABLE_DATA_ENTRIES as usize);

        // Try to get over the limit.
        let actions = iter::once((
            to_vec_of_u8(MAX_MUTABLE_DATA_ENTRIES),
            EntryAction::Ins(val.clone()),
        )).collect();
        assert_err!(
            md.mutate_entries(actions, owner),
            ClientError::TooManyEntries
        );

        let actions = iter::once((to_vec_of_u8(0), EntryAction::Del(1))).collect();
        unwrap!(md.mutate_entries(actions, owner));
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

        assert_err!(
            MutableData::new(rand::random(), 0, BTreeMap::new(), data, BTreeSet::new()),
            ClientError::DataTooLarge
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0], big_val.clone());

        let (owner, _) = sign::gen_keypair();
        let owners = iter::once(owner).collect();
        let mut md = unwrap!(MutableData::new(
            rand::random(),
            0,
            BTreeMap::new(),
            data,
            owners,
        ));

        // Try to get over the size limit
        let actions0: BTreeMap<_, _> = iter::once((vec![1], EntryAction::Ins(small_val.clone())))
            .collect();
        assert_err!(
            md.mutate_entries(actions0.clone(), owner),
            ClientError::DataTooLarge
        );

        let actions1 = iter::once((vec![0], EntryAction::Del(1))).collect();
        unwrap!(md.mutate_entries(actions1, owner));
        unwrap!(md.mutate_entries(actions0, owner));
    }

    #[test]
    fn transfer_ownership() {
        let (owner, _) = sign::gen_keypair();
        let (pk1, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        let _ = owners.insert(owner);

        let mut md = unwrap!(MutableData::new(
            rand::random(),
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            owners,
        ));

        assert!(md.change_owner(pk1, 1).is_ok());
        assert!(md.owners().contains(&pk1));
        assert!(!md.owners().contains(&owner));
    }

    #[test]
    fn versions_succession() {
        let (owner, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        let _ = owners.insert(owner);
        let mut md = unwrap!(MutableData::new(
            rand::random(),
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            owners,
        ));

        let mut v1 = BTreeMap::new();
        let _ = v1.insert(
            vec![1],
            EntryAction::Ins(Value {
                content: vec![100],
                entry_version: 0,
            }),
        );
        assert!(md.mutate_entries(v1, owner).is_ok());

        // Check update with invalid versions
        let mut v2 = BTreeMap::new();
        let _ = v2.insert(
            vec![1],
            EntryAction::Update(Value {
                content: vec![105],
                entry_version: 0,
            }),
        );
        match md.mutate_entries(v2.clone(), owner) {
            Err(ClientError::InvalidEntryActions(errors)) => {
                assert_eq!(
                    errors.get([1].as_ref()),
                    Some(&EntryError::InvalidSuccessor(0))
                );
            }
            x => panic!("Unexpected {:?}", x),
        }

        let _ = v2.insert(
            vec![1],
            EntryAction::Update(Value {
                content: vec![105],
                entry_version: 2,
            }),
        );
        match md.mutate_entries(v2.clone(), owner) {
            Err(ClientError::InvalidEntryActions(errors)) => {
                assert_eq!(
                    errors.get([1].as_ref()),
                    Some(&EntryError::InvalidSuccessor(0))
                );
            }
            x => panic!("Unexpected {:?}", x),
        }

        // Check update with a valid version
        let _ = v2.insert(
            vec![1],
            EntryAction::Update(Value {
                content: vec![105],
                entry_version: 1,
            }),
        );
        assert!(md.mutate_entries(v2, owner).is_ok());

        // Check delete version
        let mut del = BTreeMap::new();
        let _ = del.insert(vec![1], EntryAction::Del(1));
        match md.mutate_entries(del.clone(), owner) {
            Err(ClientError::InvalidEntryActions(errors)) => {
                assert_eq!(
                    errors.get([1].as_ref()),
                    Some(&EntryError::InvalidSuccessor(1))
                );
            }
            x => panic!("Unexpected {:?}", x),
        }

        let _ = del.insert(vec![1], EntryAction::Del(2));
        assert!(md.mutate_entries(del, owner).is_ok());
    }

    #[test]
    fn changing_permissions() {
        let (owner, _) = sign::gen_keypair();
        let (pk1, _) = sign::gen_keypair();

        let mut owners = BTreeSet::new();
        let _ = owners.insert(owner);

        let mut md = unwrap!(MutableData::new(
            rand::random(),
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            owners,
        ));

        // Trying to do inserts without having a permission must fail
        let mut v1 = BTreeMap::new();
        let _ = v1.insert(
            vec![0],
            EntryAction::Ins(Value {
                content: vec![1],
                entry_version: 0,
            }),
        );
        assert_err!(
            md.mutate_entries(v1.clone(), pk1),
            ClientError::AccessDenied
        );

        // Now allow inserts for pk1
        let ps1 = PermissionSet::new().allow(Action::Insert).allow(
            Action::ManagePermissions,
        );
        assert!(
            md.set_user_permissions(User::Key(pk1), ps1, 1, owner)
                .is_ok()
        );

        assert!(md.mutate_entries(v1, pk1).is_ok());

        // pk1 now can change permissions
        let ps2 = PermissionSet::new().allow(Action::Insert).deny(
            Action::ManagePermissions,
        );
        assert_err!(
            md.set_user_permissions(User::Key(pk1), ps2, 1, pk1),
            ClientError::InvalidSuccessor(1)
        );
        assert!(md.set_user_permissions(User::Key(pk1), ps2, 2, pk1).is_ok());

        // Revoke permissions for pk1
        assert_err!(
            md.del_user_permissions(&User::Key(pk1), 3, pk1),
            ClientError::AccessDenied
        );

        assert!(md.del_user_permissions(&User::Key(pk1), 3, owner).is_ok());

        let mut v2 = BTreeMap::new();
        let _ = v2.insert(
            vec![1],
            EntryAction::Ins(Value {
                content: vec![1],
                entry_version: 0,
            }),
        );
        assert_err!(md.mutate_entries(v2, pk1), ClientError::AccessDenied);

        // Revoking permissions for a non-existing user should return an error
        assert_err!(
            md.del_user_permissions(&User::Key(pk1), 4, owner),
            ClientError::NoSuchKey
        );

        // Get must always be allowed
        assert!(md.get(&[0]).is_some());
        assert!(md.get(&[1]).is_none());
    }
}

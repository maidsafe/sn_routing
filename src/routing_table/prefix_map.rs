// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::prefix::{Prefix, UnversionedPrefix};
use std::collections::{BTreeMap, btree_map};
use std::fmt::{Debug, Formatter};
use std::fmt::Result as FmtResult;
use std::iter::FromIterator;
use std::u64;

/// Map keyed by `Prefix`es, with additional invariant that two keys must differ in more than just
/// their version.
pub struct PrefixMap<T>(BTreeMap<Prefix, T>);

impl<T> PrefixMap<T> {
    pub fn new() -> Self {
        PrefixMap(BTreeMap::new())
    }

    /// Insert a new entry into the map. If there already was an entry whose
    /// key differs only in version, that entry is replaced.
    pub fn insert(&mut self, key: Prefix, value: T) -> Option<T> {
        let result = if let Some(existing) = self.0
            .range(key.with_version(0)..key.with_version(u64::MAX))
            .next()
            .map(|(key, _)| *key)
        {
            self.0.remove(&existing)
        } else {
            None
        };

        let _ = self.0.insert(key, value);
        result
    }

    /// Remove the entry matching the given key exactly (including version).
    pub fn remove(&mut self, key: &Prefix) -> Option<T> {
        self.0.remove(key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains_key(&self, key: &Prefix) -> bool {
        self.0.contains_key(key)
    }

    pub fn get(&self, key: &Prefix) -> Option<&T> {
        self.0.get(key)
    }

    pub fn get_mut(&mut self, key: &Prefix) -> Option<&mut T> {
        self.0.get_mut(key)
    }

    pub fn iter(&self) -> btree_map::Iter<Prefix, T> {
        self.0.iter()
    }

    pub fn keys(&self) -> btree_map::Keys<Prefix, T> {
        self.0.keys()
    }

    pub fn values(&self) -> btree_map::Values<Prefix, T> {
        self.0.values()
    }

    /// Check whether the map contains a key equal to the given prefix but ignoring versions.
    pub fn contains_key_unversioned<'a>(&'a self, key: &UnversionedPrefix) -> bool {
        self.0
            .range(key.with_version(0)..key.with_version(u64::MAX))
            .next()
            .is_some()
    }

    /// Get the value at the given prefix, ignoring versions.
    pub fn get_unversioned<'a>(&'a self, key: &UnversionedPrefix) -> Option<&'a T> {
        self.0
            .range(key.with_version(0)..key.with_version(u64::MAX))
            .next()
            .map(|(_, value)| value)
    }

    /// Find the entry at the given prefix, ignoring versions.
    pub fn find_unversioned<'a>(&'a self, key: &UnversionedPrefix) -> Option<(Prefix, &'a T)> {
        self.0
            .range(key.with_version(0)..key.with_version(u64::MAX))
            .next()
            .map(|(prefix, value)| (*prefix, value))
    }
}

impl<T> Default for PrefixMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for PrefixMap<T> {
    fn clone(&self) -> Self {
        PrefixMap(self.0.clone())
    }
}

impl<T: PartialEq> PartialEq for PrefixMap<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<T: Eq> Eq for PrefixMap<T> {}

impl<T> FromIterator<(Prefix, T)> for PrefixMap<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (Prefix, T)>,
    {
        let mut result = Self::new();
        result.extend(iter);
        result
    }
}

impl<T> IntoIterator for PrefixMap<T> {
    type Item = (Prefix, T);
    type IntoIter = btree_map::IntoIter<Prefix, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a PrefixMap<T> {
    type Item = (&'a Prefix, &'a T);
    type IntoIter = btree_map::Iter<'a, Prefix, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> Extend<(Prefix, T)> for PrefixMap<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Prefix, T)>,
    {
        for (key, value) in iter {
            let _ = self.insert(key, value);
        }
    }
}

impl<T: Debug> Debug for PrefixMap<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "{:?}", self.0)
    }
}

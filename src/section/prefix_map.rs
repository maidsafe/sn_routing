// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::xor_space::{Prefix, XorName};
use std::{
    collections::{btree_map, BTreeMap},
    fmt::{self, Debug, Formatter},
    iter::FromIterator,
};

/// Map whose keys are `Prefix`es with the additional invariant that no two prefixes that are
/// compatible (one is extension of the other) can be in the map at the same time.
#[derive(Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct PrefixMap<T>(BTreeMap<Prefix<XorName>, T>);

impl<T: Clone> PrefixMap<T> {
    /// Create empty `PrefixMap`.
    pub fn new() -> Self {
        Self(Default::default())
    }

    /// Inserts new entry into the map. Replaces previous entry at `prefix` or any of its ancestors
    /// if it exists. Returns the previous prefix and value.
    /// To maintain the invariant, if the map already contains a prefix that is descendant of
    /// `prefix`, nothing is inserted and the passed `prefix` and `value` are returned.
    pub fn insert(&mut self, prefix: Prefix<XorName>, value: T) -> Option<(Prefix<XorName>, T)> {
        if self.descendants(&prefix).next().is_some() {
            return Some((prefix, value));
        }

        let mut ancestor_entry: Option<(_, T)> = None;

        for ancestor_prefix in prefix.ancestors() {
            if let Some((_, ancestor_value)) = ancestor_entry.as_ref() {
                let _ = self
                    .0
                    .insert(ancestor_prefix.sibling(), ancestor_value.clone());
            } else {
                ancestor_entry = self
                    .0
                    .remove(&ancestor_prefix)
                    .map(|value| (ancestor_prefix, value));
            }
        }

        let old_value = self.0.insert(prefix, value);

        if let Some((_, ancestor_value)) = ancestor_entry.as_ref() {
            let _ = self.0.insert(prefix.sibling(), ancestor_value.clone());
        }

        ancestor_entry.or_else(|| old_value.map(|old_value| (prefix, old_value)))
    }

    /// Get the value at `prefix`, if any.
    pub fn get(&self, prefix: &Prefix<XorName>) -> Option<&T> {
        self.0.get(prefix)
    }

    /// Get the prefix and value at `prefix` or any of its ancestors.
    pub fn get_equal_or_ancestor(
        &self,
        prefix: &Prefix<XorName>,
    ) -> Option<(&Prefix<XorName>, &T)> {
        let mut prefix = *prefix;
        loop {
            if let Some(pair) = self.0.get_key_value(&prefix) {
                return Some(pair);
            }

            if prefix.is_empty() {
                return None;
            }

            prefix = prefix.popped();
        }
    }

    /// Returns an iterator over the entries, in order by prefixes.
    pub fn iter(&self) -> btree_map::Iter<Prefix<XorName>, T> {
        self.0.iter()
    }

    /// Returns an iterator over the prefixes in the map, in sorted order.
    pub fn keys(&self) -> btree_map::Keys<Prefix<XorName>, T> {
        self.0.keys()
    }

    /// Returns an iterator over the values, in order by prefixes.
    pub fn values(&self) -> btree_map::Values<Prefix<XorName>, T> {
        self.0.values()
    }

    /// Returns an iterator over all entries whose prefixes are descendants (extensions) of
    /// `prefix`.
    pub fn descendants<'a>(
        &'a self,
        prefix: &'a Prefix<XorName>,
    ) -> impl Iterator<Item = (&'a Prefix<XorName>, &'a T)> + 'a {
        // TODO: there might be a way to do this in O(logn) using BTreeMap::range
        self.0
            .iter()
            .filter(move |(other_prefix, _)| other_prefix.is_extension_of(prefix))
    }

    /// Retains only the elements specified by the predicate.
    /// Note: unlike `HashMap::retain`, this doesn't allow mutating the values inside the predicate.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&Prefix<XorName>, &T) -> bool,
    {
        let to_remove: Vec<_> = self
            .0
            .iter()
            .filter(|(key, value)| !f(key, value))
            .map(|(key, _)| *key)
            .collect();
        for key in to_remove {
            let _ = self.0.remove(&key);
        }
    }
}

impl<T: Debug> Debug for PrefixMap<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a, T> IntoIterator for &'a PrefixMap<T> {
    type Item = (&'a Prefix<XorName>, &'a T);
    type IntoIter = btree_map::Iter<'a, Prefix<XorName>, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Clone> FromIterator<(Prefix<XorName>, T)> for PrefixMap<T> {
    fn from_iter<I: IntoIterator<Item = (Prefix<XorName>, T)>>(iter: I) -> Self {
        iter.into_iter()
            .fold(Self::new(), |mut map, (prefix, value)| {
                let _ = map.insert(prefix, value);
                map
            })
    }
}

impl<T> From<PrefixMap<T>> for BTreeMap<Prefix<XorName>, T> {
    fn from(map: PrefixMap<T>) -> Self {
        map.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert(prefix("0"), 1), None);
        assert_eq!(map.insert(prefix("0"), 2), Some((prefix("0"), 1)));
        assert_eq!(map.get(&prefix("0")), Some(&2));
    }

    #[test]
    fn insert_direct_descendant_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert(prefix("0"), 1), None);
        assert_eq!(map.insert(prefix("00"), 2), Some((prefix("0"), 1)));

        assert_eq!(map.get(&prefix("0")), None);
        assert_eq!(map.get(&prefix("00")), Some(&2));
        assert_eq!(map.get(&prefix("01")), Some(&1));
    }

    #[test]
    fn insert_indirect_descendant_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert(prefix("0"), 1), None);
        assert_eq!(map.insert(prefix("000"), 2), Some((prefix("0"), 1)));

        assert_eq!(map.get(&prefix("0")), None);
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("000")), Some(&2));
        assert_eq!(map.get(&prefix("001")), Some(&1));
        assert_eq!(map.get(&prefix("01")), Some(&1));
    }

    #[test]
    fn insert_ancestor_of_existing_prefix() {
        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("00"), 1);

        assert_eq!(map.insert(prefix("0"), 2), Some((prefix("0"), 2)));
        assert_eq!(map.get(&prefix("0")), None);
        assert_eq!(map.get(&prefix("00")), Some(&1));
    }

    #[test]
    fn get_equal_or_ancestor() {
        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("0"), 0);
        let _ = map.insert(prefix("10"), 1);

        assert_eq!(
            map.get_equal_or_ancestor(&prefix("0")),
            Some((&prefix("0"), &0))
        );
        assert_eq!(
            map.get_equal_or_ancestor(&prefix("00")),
            Some((&prefix("0"), &0))
        );
        assert_eq!(
            map.get_equal_or_ancestor(&prefix("01")),
            Some((&prefix("0"), &0))
        );

        assert_eq!(map.get_equal_or_ancestor(&prefix("1")), None);
        assert_eq!(
            map.get_equal_or_ancestor(&prefix("10")),
            Some((&prefix("10"), &1))
        );
        assert_eq!(
            map.get_equal_or_ancestor(&prefix("100")),
            Some((&prefix("10"), &1))
        );
    }

    fn prefix(s: &str) -> Prefix<XorName> {
        s.parse().unwrap()
    }
}

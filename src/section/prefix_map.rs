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

/// Map whose keys are `Prefix`es.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct PrefixMap<T>(BTreeMap<Prefix<XorName>, T>);

impl<T: Clone> PrefixMap<T> {
    /// Create empty `PrefixMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts new entry into the map. Replaces previous entry at `prefix`.
    /// Removes those ancestors of `prefix` that are now fully covered by their descendants.
    pub fn insert(&mut self, prefix: Prefix<XorName>, value: T) -> Option<T> {
        // Don't insert if any descendant is already present in the map.
        if self.descendants(&prefix).next().is_some() {
            return Some(value);
        }

        let old = self.0.insert(prefix, value);
        self.prune(prefix.popped());
        old
    }

    /// Get the value at `prefix`, if any.
    #[cfg(test)]
    pub fn get(&self, prefix: &Prefix<XorName>) -> Option<&T> {
        self.0.get(prefix)
    }

    /// Get the entry at `prefix` or any of its ancestors. In case of multiple matches, returns the
    /// one with the longest prefix.
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

    /// Get the entry at the prefix that matches `name`. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub fn get_matching(&self, name: &XorName) -> Option<(&Prefix<XorName>, &T)> {
        self.0
            .iter()
            .filter(|(prefix, _)| prefix.matches(name))
            .max_by_key(|(prefix, _)| prefix.bit_count())
    }

    /// Returns whether the map contain at least one entry whose prefix matches `name`.
    pub fn contains_matching(&self, name: &XorName) -> bool {
        self.0.keys().any(|prefix| prefix.matches(name))
    }

    /// Returns an iterator over the entries, in order by prefixes.
    pub fn iter(&self) -> btree_map::Iter<Prefix<XorName>, T> {
        self.0.iter()
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
    ) -> impl Iterator<Item = (&'a Prefix<XorName>, &'a T)> + Clone + 'a {
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

    // Remove `prefix` and any of its ancestors if they are covered by their descendants.
    // For example, if `(00)` and `(01)` are both in the map, we can remove `(0)` and `()`.
    fn prune(&mut self, mut prefix: Prefix<XorName>) {
        // TODO: can this be optimized?

        loop {
            if prefix.is_covered_by(self.descendants(&prefix).map(|(p, _)| p)) {
                let _ = self.0.remove(&prefix);
            }

            if prefix.is_empty() {
                break;
            } else {
                prefix = prefix.popped();
            }
        }
    }
}

impl<T> Default for PrefixMap<T> {
    fn default() -> Self {
        Self(Default::default())
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
    use crate::rng;
    use rand::Rng;

    #[test]
    fn insert_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert(prefix("0"), 1), None);
        assert_eq!(map.insert(prefix("0"), 2), Some(1));
        assert_eq!(map.get(&prefix("0")), Some(&2));
    }

    #[test]
    fn insert_direct_descendants_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert(prefix("0"), 0), None);

        // Insert the first sibling. Parent remain in the map.
        assert_eq!(map.insert(prefix("00"), 1), None);
        assert_eq!(map.get(&prefix("00")), Some(&1));
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some(&0));

        // Insert the other sibling. Parent is removed because it is now fully covered by its
        // descendants.
        assert_eq!(map.insert(prefix("01"), 2), None);
        assert_eq!(map.get(&prefix("00")), Some(&1));
        assert_eq!(map.get(&prefix("01")), Some(&2));
        assert_eq!(map.get(&prefix("0")), None);
    }

    #[test]
    fn insert_indirect_descendants_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert(prefix("0"), 0), None);

        assert_eq!(map.insert(prefix("000"), 1), None);
        assert_eq!(map.get(&prefix("000")), Some(&1));
        assert_eq!(map.get(&prefix("001")), None);
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some(&0));

        assert_eq!(map.insert(prefix("001"), 2), None);
        assert_eq!(map.get(&prefix("000")), Some(&1));
        assert_eq!(map.get(&prefix("001")), Some(&2));
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some(&0));

        assert_eq!(map.insert(prefix("01"), 3), None);
        assert_eq!(map.get(&prefix("000")), Some(&1));
        assert_eq!(map.get(&prefix("001")), Some(&2));
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), Some(&3));
        // (0) is now fully covered and so was removed
        assert_eq!(map.get(&prefix("0")), None);
    }

    #[test]
    fn insert_ancestor_of_existing_prefix() {
        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("00"), 1);

        assert_eq!(map.insert(prefix("0"), 2), Some(2));
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

    #[test]
    fn get_matching() {
        let mut rng = rng::new();

        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("0"), 0);
        let _ = map.insert(prefix("1"), 1);
        let _ = map.insert(prefix("10"), 10);

        assert_eq!(
            map.get_matching(&prefix("0").substituted_in(rng.gen())),
            Some((&prefix("0"), &0))
        );

        assert_eq!(
            map.get_matching(&prefix("11").substituted_in(rng.gen())),
            Some((&prefix("1"), &1))
        );

        assert_eq!(
            map.get_matching(&prefix("10").substituted_in(rng.gen())),
            Some((&prefix("10"), &10))
        );
    }

    fn prefix(s: &str) -> Prefix<XorName> {
        s.parse().unwrap()
    }
}

// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// A time limited map of key-value pairs.
#[allow(unused)]
pub struct ExpirationMap<K, V> {
    map: ::std::collections::BTreeMap<K, (V, ::time::SteadyTime)>,
    time_to_live: ::time::Duration,
}

#[allow(unused)] // remove when an ExpirationMap has been included elsewhere in the code
impl<K, V> ExpirationMap<K, V> where K: PartialOrd + Ord + Clone, V: Clone {
    /// Constructor
    pub fn with_expiry_duration(time_to_live: ::time::Duration) -> ExpirationMap<K, V> {
        ExpirationMap {
            map: ::std::collections::BTreeMap::new(),
            time_to_live: time_to_live,
        }
    }

    /// Inserts a key-value pair into the map. Returns replaced value if key is already present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.map.insert(key, (value, ::time::SteadyTime::now())) {
            Some((value, _)) => Some(value),
            None => None,
        }
    }

    /// If key exists remove it from the map and return corresponding value, whether expired or not.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        match self.map.remove(key) {
            Some((value, _)) => Some(value),
            None => None,
        }
    }

    /// Retrieves a value for the given key if present in the map.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        match self.map.get(key) {
            Some(&(ref value, time)) => {
                if time + self.time_to_live < ::time::SteadyTime::now() {
                    None
                } else {
                    Some(value)
                }
            },
            None => None
        }
    }

    /// Returns true if a value exists for the specified key.
    pub fn contains_key(&mut self, key: &K) -> bool {
        match self.map.get(key) {
            Some(&(_, time)) => {
                if time + self.time_to_live < ::time::SteadyTime::now() {
                    false
                } else {
                    true
                }
            },
            None => false
        }
    }

    /// Returns an iterator over the entries.
    pub fn iter(&self) -> ::std::collections::btree_map::Iter<K, (V, ::time::SteadyTime)> {
        self.map.iter()
    }

    /// Returns a mutable iterator over the entries.
    pub fn iter_mut(&mut self)
            -> ::std::collections::btree_map::IterMut<K, (V, ::time::SteadyTime)> {
        self.map.iter_mut()
    }

    /// Recover expired key-value pairs removing any such from the map.
    pub fn remove_expired(&mut self) -> Vec<(K,V)> {
        let mut expired = Vec::new();
        let now = ::time::SteadyTime::now();

        for (key, &(ref value, time)) in self.map.iter() {
            if time + self.time_to_live < now {
                expired.push((key.clone(), value.clone()));
            }
        }

        if expired.len() > 0 {
            for key_value in expired.clone() {
                let _ = self.map.remove(&key_value.0);
            }
        }

        return expired;
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn remove_before_expiration_time() {
        let duration = ::time::Duration::milliseconds(10);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);
        let key = 1; let value = 1;
        let old_value = expiration_map.insert(key, value);

        assert!(old_value.is_none());

        let removed_value = expiration_map.remove(&key);

        assert!(!expiration_map.contains_key(&key));
        assert!(removed_value.is_some());
        assert_eq!(removed_value.unwrap(), value);
    }

    #[test]
    fn get_after_expiration_time() {
        let duration = ::time::Duration::milliseconds(10);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);
        let key = 1; let value = 1;
        let old_value = expiration_map.insert(key, value);

        assert!(old_value.is_none());
        assert!(expiration_map.contains_key(&key));
        assert_eq!(expiration_map.get(&key).unwrap(), &value);

        let interval = ::std::time::Duration::from_millis(10);
        ::std::thread::sleep(interval);

        assert!(!expiration_map.contains_key(&key));
        assert!(expiration_map.get(&key).is_none());
    }

    #[test]
    fn remove_expired_values() {
        let duration = ::time::Duration::milliseconds(50);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);

        for i in 0..10 {
            let _ = expiration_map.insert(i, i);
        }

        let interval = ::std::time::Duration::from_millis(50);
        ::std::thread::sleep(interval);

        let old_value = expiration_map.insert(11, 11);

        assert!(old_value.is_none());

        let expired_values = expiration_map.remove_expired();

        assert!(!expired_values.is_empty());

        for i in 0..10 {
            let key_value = expired_values.iter().find(|&&(_, ref value)| *value == i);

            assert!(key_value.is_some());
            assert_eq!(key_value.unwrap().1, i);
        }

        for i in 0..10 {
            assert!(expiration_map.get(&i).is_none());
        }

        assert!(expiration_map.contains_key(&11));
        assert_eq!(expiration_map.get(&11).unwrap(), &11);
    }

    #[test]
    fn insert_same_key_with_different_value() {
        let duration = ::time::Duration::milliseconds(50);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);
        let key = 1; let value1 = 1; let value2 = 2;
        let old_value = expiration_map.insert(key, value1);

        assert!(old_value.is_none());

        let old_value = expiration_map.insert(key, value2);

        assert!(old_value.is_some());
        assert_eq!(old_value.unwrap(), value1);
        assert!(expiration_map.contains_key(&key));
        assert_eq!(expiration_map.get(&key).unwrap(), &value2);

        let interval = ::std::time::Duration::from_millis(50);
        ::std::thread::sleep(interval);

        let expired_values = expiration_map.remove_expired();

        assert!(!expired_values.is_empty());
        assert_eq!(expired_values.len(), 1);
        assert_eq!(expired_values[0].0, key);
        assert_eq!(expired_values[0].1, value2);

        let old_value = expiration_map.insert(key, value1);

        assert!(old_value.is_none());
        assert!(expiration_map.contains_key(&key));
        assert_eq!(expiration_map.get(&key).unwrap(), &value1);
    }
}

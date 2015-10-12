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

extern crate time;

/// A time limited cache of routing connection requests or responses.
#[allow(unused)]
pub struct ExpirationMap<K, V> {
    map: ::std::collections::BTreeMap<K, (V, time::SteadyTime)>,
    time_to_live: time::Duration,
}

#[allow(unused)] // remove when an ExpirationMap has been included elsewhere in the code
impl<K, V> ExpirationMap<K, V> where K: PartialOrd + Ord + Clone, V: Clone {
    /// Constructor
    pub fn with_expiry_duration(time_to_live: time::Duration) -> ExpirationMap<K, V> {
        ExpirationMap {
            map: ::std::collections::BTreeMap::new(),
            time_to_live: time_to_live,
        }
    }

    /// Inserts a key/value pair into the cache and returns expired entries, if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<Vec<V>> {
        if !self.contains_key(&key) {
            let _ = self.map.insert(key, (value, ::time::SteadyTime::now()));
        }

        self.remove_expired()
    }

    /// If key exists, returns Some(value), otherwise returns None.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        match self.map.remove(key) {
            Some((value, _)) => Some(value),
            None => None,
        }
    }

    /// Retrieves a value from the cache if it exists and has not expired, otherwise, if it exists
    /// removes it and returns None.
    pub fn get(&mut self, key: &K) -> Option<V> {
        match self.map.get(key) {
            Some(&(ref value, time)) => {
                if time + self.time_to_live >= ::time::SteadyTime::now() {
                    return Some(value.clone())
                }
            },
            None => return None
        }

        let _ = self.map.remove(key);
        return None
    }

    /// Returns true if a value exists and has not expired for the specified key, otherwise, if it
    /// exists removes it and returns false.
    pub fn contains_key(&mut self, key: &K) -> bool {
        match self.map.get(key) {
            Some(&(_, time)) => {
                if time + self.time_to_live < ::time::SteadyTime::now() {
                    let _ = self.map.remove(key);
                    return false
                } else {
                    return true
                }
            },
            None => false,
        }
    }

    fn remove_expired(&mut self) -> Option<Vec<V>> {
        let mut expired_keys = Vec::new();
        let mut expired_values = Vec::new();

        for (key, &(ref value, time)) in self.map.iter() {
            if time + self.time_to_live < ::time::SteadyTime::now() {
                expired_keys.push(key.clone());
                expired_values.push(value.clone());
            }
        }

        if expired_keys.len() > 0 {
            for expired_key in expired_keys {
                let _ = self.map.remove(&expired_key);
            }
            assert!(expired_values.len() > 0);
            return Some(expired_values);
        }

        return None;
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    #[test]
    fn check_expired_values() {
        let duration = ::time::Duration::milliseconds(500);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);

        for i in 0..10 {
            let _ = expiration_map.insert(i, i);
        }

        ::std::thread::sleep_ms(500);

        let expired_values = expiration_map.insert(11, 11);

        assert!(expired_values.is_some());

        let expired_values = expired_values.unwrap();

        for i in 0..10 {
            let value = expired_values.iter().find(|&value| *value == i);

            assert!(value.is_some());
            assert_eq!(*value.unwrap(), i);
        }

        for i in 0..10 {
            assert!(expiration_map.get(&i).is_none());
        }

        assert!(expiration_map.contains_key(&11));
        assert_eq!(expiration_map.get(&11).unwrap(), 11);
    }

    #[test]
    fn insert_same_key_with_different_value() {
        let duration = ::time::Duration::milliseconds(500);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);

        let expired_values = expiration_map.insert(1, 1);

        assert!(expired_values.is_none());

        let expired_values = expiration_map.insert(1, 2);

        assert!(expired_values.is_none());
        assert!(expiration_map.contains_key(&1));
        assert_eq!(expiration_map.get(&1).unwrap(), 1);

        ::std::thread::sleep_ms(500);

        let expired_values = expiration_map.insert(1, 2);

        assert!(expired_values.is_none());
        assert!(expiration_map.contains_key(&1));
        assert_eq!(expiration_map.get(&1).unwrap(), 2);
    }

    #[test]
    fn remove_before_expiration_time() {
        let duration = ::time::Duration::milliseconds(1000);
        let mut expiration_map =
            super::ExpirationMap::<usize, usize>::with_expiry_duration(duration);
        let key = 1;
        let value = 1;

        let expired_values = expiration_map.insert(key, value);

        assert!(expired_values.is_none());

        let removed_value = expiration_map.remove(&key);

        assert!(!expiration_map.contains_key(&key));
        assert!(removed_value.is_some());
        assert_eq!(removed_value.unwrap(), value);
    }
}

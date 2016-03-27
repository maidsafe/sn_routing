// Copyright 2016 MaidSafe.net limited.
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

use std::hash::Hash;
use std::collections::HashMap;
use time::{Duration, SteadyTime};

/// TimedBuffer
pub struct TimedBuffer<Key, Value> {
    map: HashMap<Key, (Value, SteadyTime)>,
    time_to_live: Duration,
}

impl<Key: Hash + PartialOrd + Ord + Clone, Value: Clone> TimedBuffer<Key, Value>
{
    /// Constructor.
    pub fn new(time_to_live: Duration) -> TimedBuffer<Key, Value> {
        TimedBuffer {
            map: HashMap::new(),
            time_to_live: time_to_live,
        }
    }

    /// Inserts a key-value pair into the buffer with current time.
    pub fn insert(&mut self, key: Key, value: Value) -> Option<Value> {
        self.map.insert(key, (value, SteadyTime::now())).map_or(None, |(value, _)| Some(value))
    }

    /// Removes a value from the buffer.
    pub fn remove(&mut self, key: &Key) -> Option<Value> {
        self.map.remove(key).map_or(None, |(value, _)| Some(value))
    }

    /// Returns the size of the buffer.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Get the keys, if any, that have expired.
    pub fn get_expired(&mut self) -> Vec<Key> {
        let now = SteadyTime::now();
        self.map.iter()
                .filter(|&(_, &(_, timestamp))| timestamp + self.time_to_live < now)
                .map(|(key, &(_, _))| *key)
                .collect()
    }
}


#[cfg(all(test, feature = "use-mock-routing"))]
mod test {
    use super::*;
    use time::Duration;
    use std::thread;

    #[test]
    fn construct_insert() {
        let time_to_live = Duration::milliseconds(100);
        let mut timed_buffer = TimedBuffer::<usize, usize>::with_expiry_duration(time_to_live);

        for i in 0..10 {
            assert_eq!(timed_buffer.len(), i);
            let _ = timed_buffer.insert(i, i);
            assert_eq!(timed_buffer.len(), i + 1);
        }
    }

    #[test]
    fn get_expired() {
        let time_to_live = Duration::milliseconds(100);
        let mut timed_buffer = TimedBuffer::<usize, usize>::with_expiry_duration(time_to_live);
        let insertions = 10;

        for i in 0..insertions {
            assert_eq!(timed_buffer.len(), i);
            let _ = timed_buffer.insert(i, i);
            assert_eq!(timed_buffer.len(), i + 1);
        }

        thread::sleep(::std::time::Duration::from_millis(100));

        let expired = timed_buffer.get_expired();

        assert_eq!(expired.len(), insertions);

        for i in 0..insertions {
            assert_eq!(expired[i], i);
        }
    }
}

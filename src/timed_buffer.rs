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

use std::collections::BTreeMap;
use time::{Duration, SteadyTime};

/// TimedBuffer
#[allow(unused)]
pub struct TimedBuffer<Key, Value> {
    map: BTreeMap<Key, (Value, SteadyTime)>,
    time_to_live: Duration,
}

#[allow(unused)]
impl<Key: PartialOrd + Ord + Clone, Value: Clone> TimedBuffer<Key, Value>
{
    /// Constructor.
    pub fn with_expiry_duration(time_to_live: Duration) -> TimedBuffer<Key, Value> {
        TimedBuffer {
            map: BTreeMap::new(),
            time_to_live: time_to_live,
        }
    }

    /// Inserts a key-value pair into the buffer with current time.
    pub fn insert(&mut self, key: Key, value: Value) -> Option<Value> {
        self.map.insert(key, (value, SteadyTime::now())).map(|pair| pair.0)
    }

    /// Removes a value from the buffer.
    pub fn remove(&mut self, key: &Key) -> Option<Value> {
        self.map.remove(key).map(|(value, _)| value)
    }

    /// Retrieves a value stored under `key`, or `None` if the key doesn't exist.
    pub fn get(&mut self, key: &Key) -> Option<Value> {
        self.map.get(key).map(|&(ref value, _)| value.clone())
    }

    /// Returns the size of the buffer.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    fn expired(&self, key: &Key) -> bool {
        let now = SteadyTime::now();
        self.map.get(key).map_or(false, |&(_, timestamp)| timestamp + self.time_to_live < SteadyTime::now())
    }

    fn get_expired(&mut self) -> Vec<Value> {
        self.map.iter()
                .filter(|&(_, &(_, timestamp))| timestamp + self.time_to_live < SteadyTime::now())
                .map(|(_, &(ref value, _))| value.clone())
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
        let insertions = 0;
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

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

#[cfg(test)]
extern crate rand;

// TODO - Once we're at Stable v1.13.0, avoid disabling the lint check and replace `SipHasher` with
// `std::collections::hash_map::DefaultHasher`.
#[cfg_attr(feature="clippy", allow(useless_attribute))]
#[allow(deprecated)]
use std::hash::{Hash, Hasher, SipHasher};
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

#[allow(deprecated)]
fn hash<T: Hash>(t: &T) -> u64 {
    let mut s = SipHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// A time based message filter that takes any generic type as a key and will drop keys after a
/// time period (LRU Cache pattern).
pub struct MessageFilter<Message> {
    entries: Vec<TimestampedMessage>,
    time_to_live: Duration,
    phantom: PhantomData<Message>,
}

impl<Message: Hash> MessageFilter<Message> {
    /// Constructor for time based `MessageFilter`.
    pub fn with_expiry_duration(time_to_live: Duration) -> MessageFilter<Message> {
        MessageFilter {
            entries: vec![],
            time_to_live: time_to_live,
            phantom: PhantomData,
        }
    }

    /// Adds a message to the filter.
    ///
    /// Removes any expired messages, then adds `message`, then removes enough older messages until
    /// the message count is at or below `capacity`.  If `message` already exists in the filter and
    /// is not already expired, its expiry time is updated and it is moved to the back of the FIFO
    /// queue again.
    ///
    /// The return value is the number of times this specific message has been added, including
    /// this time.
    pub fn insert(&mut self, message: &Message) -> usize {
        self.remove_expired();
        let hash_code = hash(message);
        if let Some(index) = self.entries.iter().position(|t| t.hash_code == hash_code) {
            let mut timestamped_message = self.entries.remove(index);
            timestamped_message.update_expiry_point(self.time_to_live);
            let count = timestamped_message.increment_count();
            self.entries.push(timestamped_message);
            count
        } else {
            self.entries.push(TimestampedMessage::new(hash_code, self.time_to_live));
            1
        }
    }

    /// Returns the number of times this message has already been inserted.
    pub fn count(&self, message: &Message) -> usize {
        let hash_code = hash(message);
        self.entries.iter().find(|t| t.hash_code == hash_code).map_or(0, |t| t.count)
    }

    /// Removes any expired messages, then returns whether `message` exists in the filter or not.
    pub fn contains(&mut self, message: &Message) -> bool {
        self.remove_expired();
        let hash_code = hash(message);
        self.entries.iter().any(|entry| entry.hash_code == hash_code)
    }

    /// Clears the filter, removing all the entries.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn remove_expired(&mut self) {
        let now = SystemTime::now();
        // The entries are sorted from oldest to newest, so just split off the vector at the
        // first unexpired entry and the returned vector is the remaining unexpired values.  If
        // we don't find any unexpired value, just clear the vector.
        if let Some(at) = self.entries.iter().position(|entry| entry.expiry_point > now) {
            self.entries = self.entries.split_off(at)
        } else {
            self.entries.clear();
        }
    }
}

struct TimestampedMessage {
    pub hash_code: u64,
    pub expiry_point: SystemTime,
    /// How many copies of this message have been seen before this one.
    pub count: usize,
}

impl TimestampedMessage {
    pub fn new(hash_code: u64, time_to_live: Duration) -> TimestampedMessage {
        TimestampedMessage {
            hash_code: hash_code,
            expiry_point: SystemTime::now() + time_to_live,
            count: 1,
        }
    }

    /// Updates the expiry point to set the given time to live from now.
    pub fn update_expiry_point(&mut self, time_to_live: Duration) {
        self.expiry_point = SystemTime::now() + time_to_live;
    }

    /// Increments the counter and returns its old value.
    pub fn increment_count(&mut self) -> usize {
        self.count += 1;
        self.count
    }
}



#[cfg(test)]
mod tests {
    use rand;
    use rand::Rng;
    use std::thread;
    use std::time::Duration;
    use super::*;

    #[test]
    fn timeout() {
        let time_to_live = Duration::from_millis(rand::thread_rng().gen_range(50, 150));
        let mut msg_filter = MessageFilter::<usize>::with_expiry_duration(time_to_live);
        assert_eq!(time_to_live, msg_filter.time_to_live);

        // Add 10 messages - all should be added.
        for i in 0..10 {
            assert_eq!(1, msg_filter.insert(&i));
        }
        for i in 0..10 {
            assert!(msg_filter.contains(&i));
        }

        // Allow the added messages time to expire.
        let sleep_duration = time_to_live + Duration::from_millis(10);
        thread::sleep(sleep_duration);

        // Add a new message which should cause the expired values to be removed.
        assert_eq!(1, msg_filter.insert(&11));
        assert!(msg_filter.contains(&11));

        // Check we can add the initial messages again.
        for i in 0..10 {
            assert_eq!(1, msg_filter.insert(&i));
            assert!(msg_filter.contains(&i));
        }
    }

    #[test]
    fn struct_value() {
        #[derive(PartialEq, PartialOrd, Ord, Clone, Eq, Hash)]
        struct Temp {
            id: Vec<u8>,
        }

        impl Default for Temp {
            fn default() -> Temp {
                let mut rng = rand::thread_rng();
                Temp { id: rand::sample(&mut rng, 0u8..255, 64) }
            }
        }

        let time_to_live = Duration::from_millis(rand::thread_rng().gen_range(50, 150));
        let mut msg_filter = MessageFilter::<Temp>::with_expiry_duration(time_to_live);

        let values: Vec<Temp> = (0..10).map(|_| Temp::default()).collect();
        for temp in &values {
            // Add a new message and check that it has been added successfully.
            assert_eq!(1, msg_filter.insert(temp));
            assert!(msg_filter.contains(temp));
        }

        // Allow the added messages time to expire.
        let sleep_duration = time_to_live + Duration::from_millis(10);
        thread::sleep(sleep_duration);

        // Add a new message which should cause the expired values to be removed.
        let temp: Temp = Default::default();
        assert_eq!(1, msg_filter.insert(&temp));
        assert!(msg_filter.contains(&temp));
        for temp in &values {
            assert!(!msg_filter.contains(temp));
        }
    }

    #[test]
    fn add_duplicate() {
        let size = 10;
        let time_to_live = Duration::from_secs(99);
        let mut msg_filter = MessageFilter::<usize>::with_expiry_duration(time_to_live);

        for i in 0..size {
            assert_eq!(1, msg_filter.insert(&i));
        }
        assert!((0..size).all(|index| msg_filter.contains(&index)));

        // Add "0" again.
        assert_eq!(1, msg_filter.count(&0));
        assert_eq!(2, msg_filter.insert(&0));
        assert_eq!(2, msg_filter.count(&0));
    }

    #[test]
    fn insert_resets_timeout() {
        // Check re-adding a message to a filter alters its expiry time.
        let time_to_live = Duration::from_millis(300);
        let sleep_duration = Duration::from_millis(180); // more than half of `time_to_live`
        let mut msg_filter = MessageFilter::<usize>::with_expiry_duration(time_to_live);

        // Add "0".
        assert_eq!(1, msg_filter.insert(&0));

        // Wait for a bit more than half the expiry time and re-add "0".
        thread::sleep(sleep_duration);
        assert_eq!(2, msg_filter.insert(&0));

        // Wait for another half of the expiry time and check it's not been removed.
        thread::sleep(sleep_duration);
        assert!(msg_filter.contains(&0));

        // Wait for another half of the expiry time and check it's been removed.
        thread::sleep(sleep_duration);
        assert!(!msg_filter.contains(&0));
    }
}

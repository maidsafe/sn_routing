// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::time::{Duration, Instant};
use std::{
    collections::{
        hash_map::{DefaultHasher, Entry},
        HashMap, VecDeque,
    },
    hash::{Hash, Hasher},
    marker::PhantomData,
};

fn hash<T: Hash>(t: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    t.hash(&mut hasher);
    hasher.finish()
}

/// A time based message filter that takes any generic type as a key and will drop keys after a
/// time period (LRU Cache pattern).
pub struct MessageFilter<Message> {
    /// The number of times each message has been received so far, and the expiry timestamp.
    count: HashMap<u64, (usize, Instant)>,
    /// A record of message hashes and the expiry timestamps of all insertions, ordered
    /// chronologically. The timestamps are out of date if the same hash has been inserted again.
    timeout_queue: VecDeque<(u64, Instant)>,
    time_to_live: Duration,
    phantom: PhantomData<Message>,
}

impl<Message: Hash> MessageFilter<Message> {
    /// Constructor for time based `MessageFilter`.
    pub fn with_expiry_duration(time_to_live: Duration) -> MessageFilter<Message> {
        Self {
            count: HashMap::new(),
            timeout_queue: VecDeque::new(),
            time_to_live,
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
        let expiry = Instant::now() + self.time_to_live;
        self.timeout_queue.push_back((hash_code, expiry));
        match self.count.entry(hash_code) {
            Entry::Occupied(entry) => {
                let &mut (ref mut c, ref mut t) = entry.into_mut();
                *t = expiry;
                *c += 1;
                *c
            }
            Entry::Vacant(entry) => entry.insert((1, expiry)).0,
        }
    }

    /// Returns the number of times this message has already been inserted.
    #[cfg(test)]
    pub fn count(&self, message: &Message) -> usize {
        let hash_code = hash(message);
        self.count.get(&hash_code).map_or(0, |&(count, _)| count)
    }

    /// Removes any expired messages, then returns whether `message` exists in the filter or not.
    #[cfg(test)]
    pub fn contains(&mut self, message: &Message) -> bool {
        self.remove_expired();
        self.count.contains_key(&hash(message))
    }

    fn remove_expired(&mut self) {
        let now = Instant::now();
        while self
            .timeout_queue
            .front()
            .map_or(false, |&(_, ref t)| *t <= now)
        {
            let (hash_code, _) = self
                .timeout_queue
                .pop_front()
                .expect("Bug in VecDeque for remove_expired");
            if let Entry::Occupied(entry) = self.count.entry(hash_code) {
                if entry.get().1 <= now {
                    let _removed_pair = entry.remove_entry();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, seq::IteratorRandom, Rng};
    use std::time::Duration;

    #[cfg(feature = "mock_base")]
    fn sleep(time: u64) {
        use fake_clock::FakeClock;
        FakeClock::advance_time(time);
    }

    #[cfg(not(feature = "mock_base"))]
    fn sleep(time: u64) {
        use std::thread;
        thread::sleep(Duration::from_millis(time));
    }

    #[test]
    fn timeout() {
        let time_to_live_ms = rand::thread_rng().gen_range(50, 150);
        let time_to_live = Duration::from_millis(time_to_live_ms);
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
        let sleep_duration = time_to_live_ms + 10;
        sleep(sleep_duration);

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
            fn default() -> Self {
                let mut rng = rand::thread_rng();
                Self {
                    id: (0u8..255).choose_multiple(&mut rng, 64),
                }
            }
        }

        let time_to_live_ms = rand::thread_rng().gen_range(50, 150);
        let time_to_live = Duration::from_millis(time_to_live_ms);
        let mut msg_filter = MessageFilter::<Temp>::with_expiry_duration(time_to_live);

        let values: Vec<Temp> = (0..10).map(|_| Temp::default()).collect();
        for temp in &values {
            // Add a new message and check that it has been added successfully.
            assert_eq!(1, msg_filter.insert(temp));
            assert!(msg_filter.contains(temp));
        }

        // Allow the added messages time to expire.
        let sleep_duration = time_to_live_ms + 10;
        sleep(sleep_duration);

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
        let time_to_live = Duration::from_millis(3000);
        let sleep_duration = 1800; // more than half of `time_to_live`
        let mut msg_filter = MessageFilter::<usize>::with_expiry_duration(time_to_live);

        // Add "0".
        assert_eq!(1, msg_filter.insert(&0));

        // Wait for a bit more than half the expiry time and re-add "0".
        sleep(sleep_duration);
        assert_eq!(2, msg_filter.insert(&0));

        // Wait for another half of the expiry time and check it's not been removed.
        sleep(sleep_duration);
        assert!(msg_filter.contains(&0));

        // Wait for another half of the expiry time and check it's been removed.
        sleep(sleep_duration);
        assert!(!msg_filter.contains(&0));
    }
}

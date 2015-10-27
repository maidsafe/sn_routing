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

use lru_time_cache::LruCache;
use std::collections::BTreeSet;
use messages::RoutingMessage;
use NameType;

type Set<K> = BTreeSet<K>;
pub type Bytes = Vec<u8>;

pub struct MessageAccumulator {
    //                                       +-> Who sent it
    //                                       |
    requests: LruCache<RoutingMessage, Set<NameType>>,
}

impl MessageAccumulator {

    pub fn with_expiry_duration(duration: ::time::Duration) -> MessageAccumulator {
        MessageAccumulator { requests: LruCache::with_expiry_duration(duration) }
    }

    pub fn add_message(&mut self,
                       threshold: usize,
                       claimant: NameType,
                       message: RoutingMessage)
                       -> Option<RoutingMessage> {
        {
            if threshold <= 1 {
                return Some(message);
            }

            let claimants = self.requests.entry(message.clone())
                                         .or_insert_with(||Set::new());

            claimants.insert(claimant);

            if claimants.len() < threshold {
                return None;
            }

            debug!("Returning message, {:?}, from accumulator", message);
            Some(message)

        }.map(|message| {
            let _ = self.requests.remove(&message);
            message
        })
    }
}

#[cfg(test)]
mod test {
    use rand;

    #[test]
    fn add_with_fixed_threshold() {
        let threshold = 3usize;
        let id = ::id::Id::new();
        let routing_message = ::test_utils::messages_util::arbitrary_routing_message(
            &id.signing_public_key(), &id.signing_private_key());
        let mut accumulator = ::message_accumulator::MessageAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10));
        for _ in 0..threshold - 1 {
            assert!(accumulator.add_message(threshold.clone(), rand::random(),
                routing_message.clone()).is_none());
        }
        assert_eq!(accumulator.add_message(threshold.clone(), rand::random(),
            routing_message.clone()), Some(routing_message.clone()));

        // assert that the accumulator has been cleared; repeat with the same message
        for _ in 0..threshold - 1 {
            assert!(accumulator.add_message(threshold.clone(), rand::random(),
                routing_message.clone()).is_none());
        }
        assert_eq!(accumulator.add_message(threshold.clone(), rand::random(),
            routing_message.clone()), Some(routing_message));
    }

    #[test]
    fn add_repeat_claimants() {
        let threshold = 3usize;
        let id = ::id::Id::new();
        let routing_message = ::test_utils::messages_util::arbitrary_routing_message(
            &id.signing_public_key(), &id.signing_private_key());
        let mut accumulator = ::message_accumulator::MessageAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10));
        for _ in 0..threshold - 1 {
            let claimant: ::NameType = rand::random();
            assert!(accumulator.add_message(threshold.clone(), claimant.clone(),
                routing_message.clone()).is_none());
            assert!(accumulator.add_message(threshold.clone(), claimant.clone(),
                routing_message.clone()).is_none());
        }
        let claimant: ::NameType = rand::random();
        assert_eq!(accumulator.add_message(threshold.clone(), claimant.clone(),
            routing_message.clone()), Some(routing_message.clone()));
        assert!(accumulator.add_message(threshold.clone(), claimant.clone(),
            routing_message.clone()).is_none());
    }

    #[test]
    fn add_multiple_messages() {
        let threshold = 3usize;
        let id = ::id::Id::new();
        let routing_message1 = ::test_utils::messages_util::arbitrary_routing_message(
            &id.signing_public_key(), &id.signing_private_key());
        let routing_message2 = ::test_utils::messages_util::arbitrary_routing_message(
            &id.signing_public_key(), &id.signing_private_key());
        let mut accumulator = ::message_accumulator::MessageAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10));
        for _ in 0..threshold - 1 {
            let claimant: ::NameType = rand::random();
            assert!(accumulator.add_message(threshold.clone(), claimant.clone(),
                routing_message1.clone()).is_none());
            assert!(accumulator.add_message(threshold.clone(), claimant.clone(),
                routing_message2.clone()).is_none());
        }
        let claimant: ::NameType = rand::random();
        assert_eq!(accumulator.add_message(threshold.clone(), claimant.clone(),
            routing_message1.clone()), Some(routing_message1.clone()));
        assert!(accumulator.add_message(threshold.clone() + 1, claimant.clone(),
            routing_message2.clone()).is_none());
        // lower threshold again
        assert_eq!(accumulator.add_message(threshold.clone(), rand::random(),
            routing_message2.clone()), Some(routing_message2.clone()));
    }
}

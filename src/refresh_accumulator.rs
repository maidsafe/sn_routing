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
use std::collections::BTreeMap;

type Map<K,V> = BTreeMap<K,V>;
pub type Bytes = Vec<u8>;
//                     +-> Source and target group
//                     |
pub type Request = (::authority::Authority, u64, ::NameType);
pub struct RefreshAccumulator {
    //                                 +-> Who sent it
    //                                 |
    requests: LruCache<Request, Map<::NameType, Bytes>>,
    /// causes keeps a recent blocking history on whether the user has already been
    /// asked to do a full refresh for a given cause.  When core initiates a generate_churn
    /// in routing_node, the cause will be registered in the RefreshAccumulator here.
    /// Consequently, if the RefreshAccumulator sees a RefreshMessage for a cause it has not
    /// yet seen, then it can ask the user to perform an Event::DoRefresh for that account.
    causes: ::message_filter::MessageFilter<::NameType>,
    event_sender: ::std::sync::mpsc::Sender<::event::Event>,
}

impl RefreshAccumulator {

    pub fn with_expiry_duration(duration: ::time::Duration,
        event_sender: ::std::sync::mpsc::Sender<::event::Event>) -> RefreshAccumulator {
        RefreshAccumulator {
            requests: LruCache::with_expiry_duration(duration.clone()),
            causes: ::message_filter::MessageFilter::with_expiry_duration(duration),
            event_sender: event_sender,
        }
    }

    pub fn add_message(&mut self,
                       threshold: usize,
                       type_tag: u64,
                       sender_node: ::NameType,
                       sender_group: ::authority::Authority,
                       payload: Bytes,
                       cause: ::NameType)
                       -> Option<Vec<Bytes>> {
        debug!("RefreshAccumulator for {:?} caused by {:?}", sender_group, cause);
        // if the cause was outside our close group
        let unknown_cause = !self.causes.check(&cause);
        let request = (sender_group, type_tag, cause);
        // if this is the first instance of a new refresh request
        let first_request = !self.requests.contains_key(&request);
        if unknown_cause && first_request {
            let _ = self.event_sender.send(::event::Event::DoRefresh(request.1.clone(),
            request.0.clone(), request.2.clone()));
        }
        {
            if threshold <= 1 {
                return Some(vec![payload]);
            }

            let map = self.requests.entry(request.clone()).or_insert_with(||Map::new());
            let _ = map.insert(sender_node, payload);

            if map.len() < threshold {
                return None;
            }

            Some(map.iter().map(|(_, msg)| msg.clone()).collect())

        }.map(|messages| {
            let _ = self.requests.remove(&request);
            messages
        })
    }

    pub fn register_cause(&mut self, cause: &::NameType) {
        self.causes.add(cause.clone());
    }
}

#[cfg(test)]
mod test {
    use rand;

    #[test]
    fn add_with_fixed_threshold_and_unknown_cause() {
        let threshold = 5usize;
        let bytes = ::types::generate_random_vec_u8(120usize);
        let group = ::authority::Authority::NaeManager(rand::random());
        let cause: ::NameType = rand::random();
        let (event_sender, event_receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let mut accumulator = ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10), event_sender);
        assert!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone())
            .is_none());
        assert_eq!(event_receiver.try_recv(), Ok(::event::Event::DoRefresh(1u64, group.clone(),
            cause.clone())));
        for _ in 1..threshold - 1 {
            assert!(accumulator.add_message(threshold.clone(), 1u64,
                rand::random(), group.clone(), bytes.clone(), cause.clone())
                .is_none());
        }
        assert!(event_receiver.try_recv().is_err());
        assert_eq!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone())
            .unwrap().len(), threshold);
        assert!(event_receiver.try_recv().is_err());

        // assert that the accumulator has been cleared; repeat with the same message
        assert!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone())
            .is_none());
        assert_eq!(event_receiver.try_recv(), Ok(::event::Event::DoRefresh(1u64, group.clone(),
            cause.clone())));
        for _ in 1..threshold - 1 {
            assert!(accumulator.add_message(threshold.clone(), 1u64,
                rand::random(), group.clone(), bytes.clone(), cause.clone())
                .is_none());
        }
        assert!(event_receiver.try_recv().is_err());
        assert_eq!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group, bytes, cause)
            .unwrap().len(), threshold);
        assert!(event_receiver.try_recv().is_err());
    }

    #[test]
    fn add_with_fixed_threshold_and_known_cause() {
        let threshold = 5usize;
        let bytes = ::types::generate_random_vec_u8(120usize);
        let group = ::authority::Authority::NaeManager(rand::random());
        let cause = rand::random();
        let (event_sender, event_receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let mut accumulator = ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10), event_sender);
        // register the cause
        accumulator.register_cause(&cause);
        assert!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone())
            .is_none());
        assert!(event_receiver.try_recv().is_err());
        for _ in 1..threshold - 1 {
            assert!(accumulator.add_message(threshold.clone(), 1u64,
                rand::random(), group.clone(), bytes.clone(), cause.clone())
                .is_none());
        }
        assert!(event_receiver.try_recv().is_err());
        assert_eq!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone())
            .unwrap().len(), threshold);
        assert!(event_receiver.try_recv().is_err());

        // assert that the accumulator has been cleared; repeat with the same message
        assert!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone())
            .is_none());
        assert!(event_receiver.try_recv().is_err());
        for _ in 1..threshold - 1 {
            assert!(accumulator.add_message(threshold.clone(), 1u64,
                rand::random(), group.clone(), bytes.clone(), cause.clone())
                .is_none());
        }
        assert!(event_receiver.try_recv().is_err());
        assert_eq!(accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group, bytes, cause)
            .unwrap().len(), threshold);
        assert!(event_receiver.try_recv().is_err());
    }

    #[test]
    fn add_with_updated_bytes() {
        let threshold = 5usize;
        let bytes = ::types::generate_random_vec_u8(120usize);
        let new_bytes = ::types::generate_random_vec_u8(150usize);
        let group = ::authority::Authority::NaeManager(rand::random());
        let cause: ::NameType = rand::random();
        let (event_sender, event_receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let mut accumulator = ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10), event_sender);
        let sender: ::NameType = rand::random();
        assert!(accumulator.add_message(threshold.clone(), 1u64,
            sender.clone(), group.clone(), bytes.clone(), cause.clone())
            .is_none());
        assert_eq!(event_receiver.try_recv(), Ok(::event::Event::DoRefresh(1u64, group.clone(),
            cause.clone())));
        assert!(accumulator.add_message(threshold.clone(), 1u64,
            sender, group.clone(), new_bytes.clone(), cause.clone())
            .is_none());
        for _ in 1..threshold - 1 {
            let sender: ::NameType = rand::random();
            assert!(accumulator.add_message(threshold.clone(), 1u64,
                sender.clone(), group.clone(), bytes.clone(), cause.clone())
                .is_none());
            assert!(accumulator.add_message(threshold.clone(), 1u64,
                sender, group.clone(), new_bytes.clone(), cause.clone())
                .is_none());
        }
        assert!(event_receiver.try_recv().is_err());
        match accumulator.add_message(threshold.clone(), 1u64,
            rand::random(), group.clone(), bytes.clone(), cause.clone()) {
            Some(vector_of_bytes) => {
                assert_eq!(vector_of_bytes.len(), threshold);
                let mut number_of_bytes = 0usize;
                let mut number_of_new_bytes = 0usize;
                for returned_bytes in vector_of_bytes {
                    if returned_bytes == new_bytes {
                        number_of_new_bytes += 1;
                    } else if returned_bytes == bytes {
                        number_of_bytes += 1;
                    } else {
                        panic!("Unexpected bytes");
                    };
                }
                assert_eq!(number_of_new_bytes, threshold - 1);
                assert_eq!(number_of_bytes, 1usize);
            },
            None => panic!("Refresh accumulator should have resolved to a vector of bytes"),
        };
        assert!(event_receiver.try_recv().is_err());
    }
}

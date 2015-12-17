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

use std::sync::mpsc;
use lru_time_cache::LruCache;
use message_filter::MessageFilter;
use std::collections::BTreeMap;
use time::Duration;
use authority::Authority;
use event::Event;
use xor_name::XorName;

//                     +-> Source and target group
//                     |
pub type Request = (Authority, u64, XorName);

pub struct RefreshAccumulator {
    //                                 +-> Who sent it
    //                                 |
    requests: LruCache<Request, BTreeMap<XorName, Vec<u8>>>,
    /// Causes keeps a recent blocking history on whether the user has already been
    /// asked to do a full refresh for a given cause.  When core initiates a generate_churn
    /// in routing_node, the cause will be registered in the RefreshAccumulator here.
    /// Consequently, if the RefreshAccumulator sees a RefreshMessage for a cause it has not
    /// yet seen, then it can ask the user to perform an Event::DoRefresh for that account.
    causes: MessageFilter<XorName>,
    event_sender: mpsc::Sender<Event>,
}

impl RefreshAccumulator {

    pub fn with_expiry_duration(duration: Duration, event_sender: mpsc::Sender<Event>) -> RefreshAccumulator {
        RefreshAccumulator {
            requests: LruCache::with_expiry_duration(duration.clone()),
            causes: MessageFilter::with_expiry_duration(duration),
            event_sender: event_sender,
        }
    }

    pub fn add_message(&mut self,
                       quorum: usize,
                       type_tag: u64,
                       messsage: Vec<u8>,
                       cause: XorName,
                       sender_name: XorName,
                       sender_group: Authority)
                       -> Option<Vec<Vec<u8>>> {
        debug!("RefreshAccumulator for {:?} caused by {:?}", sender_group, cause);
        // If the cause was outside our close group.
        let unknown_cause = !self.causes.contains(&cause);
        let request = (sender_group, type_tag, cause);
        let first_request = !self.requests.contains_key(&request);
        if unknown_cause && first_request {
            let _ = self.event_sender.send(Event::DoRefresh(request.1.clone(), request.0.clone(), request.2.clone()));
        }
        {
            if quorum <= 1 {
                return Some(vec![messsage]);
            }

            let map = self.requests.entry(request.clone()).or_insert_with(||BTreeMap::new());
            let _ = map.insert(sender_name, messsage);

            if map.len() < quorum {
                return None;
            }

            Some(map.iter().map(|(_, msg)| msg.clone()).collect())

        }.map(|messages| {
            let _ = self.requests.remove(&request);
            messages
        })
    }

    pub fn register_cause(&mut self, cause: &XorName) {
        let _ = self.causes.insert(cause.clone());
    }
}

// #[cfg(test)]
// mod test {
//     #[test]
//     fn add_with_fixed_threshold() {
//         let threshold = 5usize;
//         let bytes = ::types::generate_random_vec_u8(120usize);
//         let group = ::authority::Authority::NaeManager(::rand::random());
//         let cause: ::XorName = ::rand::random();
//         let mut accumulator = ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
//             ::time::Duration::minutes(10));

//         for _ in 0..2 {
//             assert_eq!(accumulator.add_message(threshold.clone(),
//                                                1u64,
//                                                ::rand::random(),
//                                                group.clone(),
//                                                bytes.clone(),
//                                                cause.clone()),
//                        (true, None));
//             for _ in 1..threshold - 1 {
//                 assert_eq!(accumulator.add_message(threshold.clone(),
//                                                    1u64,
//                                                    ::rand::random(),
//                                                    group.clone(),
//                                                    bytes.clone(),
//                                                    cause.clone()),
//                            (false, None));
//             }
//             let result = accumulator.add_message(threshold.clone(),
//                                                  1u64,
//                                                  ::rand::random(),
//                                                  group.clone(),
//                                                  bytes.clone(),
//                                                  cause.clone());
//             assert!(!result.0);
//             assert_eq!(unwrap_option!(result.1, "").len(), threshold);
//             // since the message is now accumulated, it should be removed and we're good to do
//             // another full iteration from scratch.
//         }
//     }
// }

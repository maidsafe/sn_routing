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
        info!("RefreshAccumulator for {:?} caused by {:?}", sender_group, cause);
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
            map.insert(sender_node, payload);

            if map.len() < threshold {
                return None;
            }

            Some(map.iter().map(|(_, msg)| msg.clone()).collect())

        }.map(|messages| {
            self.requests.remove(&request);
            messages
        })
    }

    pub fn register_cause(&mut self, cause: &::NameType) {
        self.causes.add(cause.clone());
    }
}

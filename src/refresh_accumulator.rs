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
use std::collections::{BTreeMap};
use rustc_serialize::{Decodable, Encodable};
use sendable::Sendable;
use NameType;

type Map<K,V> = BTreeMap<K,V>;

const MAX_REQUEST_COUNT: usize = 1000;

pub type Request = (NameType, u64);

pub struct RefreshAccumulator<T>
    where T: Clone + Sendable + Encodable + Decodable {

    //                                 +-> Who sent it
    //                                 |
    requests: LruCache<Request, Map<NameType, T>>,
}

impl<T> RefreshAccumulator<T>
    where T: Clone + Sendable + Encodable + Decodable {

    pub fn new() -> RefreshAccumulator<T> {
        RefreshAccumulator {
            requests: LruCache::with_capacity(MAX_REQUEST_COUNT),
        }
    }

    pub fn add_message(&mut self, threshold: usize, sender: NameType, payload: T)
        -> Option<Vec<T>> {
        let request = (payload.name(), payload.type_tag());

        {
            if threshold <= 1 {
                return Some(vec![payload]);
            }

            let map = self.requests.entry(request.clone()).or_insert_with(||Map::new());
            map.insert(sender, payload);

            if map.len() < threshold {
                return None;
            }

            Some(map.iter().map(|(name, msg)| msg.clone()).collect())

        }.map(|messages| {
            self.requests.remove(&request);
            messages
        })
    }
}

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
use NameType;

type Map<K,V> = BTreeMap<K,V>;
pub type Bytes = Vec<u8>;

const MAX_REQUEST_COUNT: usize = 1000;

//                     +-> Source and target group
//                     |
pub type Request = (NameType, u64);

pub struct RefreshAccumulator {
    //                                 +-> Who sent it
    //                                 |
    requests: LruCache<Request, Map<NameType, Bytes>>,
}

impl RefreshAccumulator {

    pub fn new() -> RefreshAccumulator {
        RefreshAccumulator {
            requests: LruCache::with_capacity(MAX_REQUEST_COUNT),
        }
    }

    pub fn add_message(&mut self,
                       threshold:    usize,
                       type_tag:     u64,
                       sender_node:  NameType,
                       sender_group: NameType,
                       payload:      Bytes) -> Option<Vec<Bytes>> {
        let request = (sender_group, type_tag);

        {
            if threshold <= 1 {
                return Some(vec![payload]);
            }

            let map = self.requests.entry(request.clone()).or_insert_with(||Map::new());
            map.insert(sender_node, payload);

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

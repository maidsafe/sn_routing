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

// Tuple of source/target group, type tag, and name of node causing churn
pub type Request = (::authority::Authority, u64, ::XorName);

pub struct RefreshAccumulator {
    // Map of refresh request and <map of sender and payload>
    requests: ::lru_time_cache::LruCache<Request,
                                           ::std::collections::HashMap<::XorName, Vec<u8>>>,
}

impl RefreshAccumulator {
    pub fn with_expiry_duration(duration: ::time::Duration) -> RefreshAccumulator {
        RefreshAccumulator {
            requests: ::lru_time_cache::LruCache::with_expiry_duration(duration.clone()),
        }
    }

    // The first return value is true if this represents the first instance of a new refresh
    // request.  The second return value is `None` if we have accumulated < `threshold` instances of
    // the request, otherwise it is the accumulated collection of payloads for the request.
    pub fn add_message(&mut self,
                       threshold: usize,
                       type_tag: u64,
                       sender_node: ::XorName,
                       sender_group: ::authority::Authority,
                       payload: Vec<u8>,
                       cause: ::XorName)
                       -> (bool, Option<Vec<Vec<u8>>>) {
        debug!("RefreshAccumulator for {:?} caused by {:?}",
               sender_group,
               cause);
        let request = (sender_group, type_tag, cause);
        // if this is the first instance of a new refresh request
        let first_request = !self.requests.contains_key(&request);
        if threshold <= 1 {
            return (first_request, Some(vec![payload]));
        }

        let mut payloads = None;
        {
            let map = self.requests
                          .entry(request.clone())
                          .or_insert_with(::std::collections::HashMap::new);
            let _ = map.insert(sender_node, payload);
            if map.len() >= threshold {
                payloads = Some(map.iter().map(|(_, msg)| msg.clone()).collect());
            }
        }
        if payloads.is_some() {
            let _ = self.requests.remove(&request);
        }
        (first_request, payloads)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn add_with_fixed_threshold() {
        let threshold = 5usize;
        let bytes = ::types::generate_random_vec_u8(120usize);
        let group = ::authority::Authority::NaeManager(::rand::random());
        let cause: ::XorName = ::rand::random();
        let mut accumulator = ::refresh_accumulator::RefreshAccumulator::with_expiry_duration(
            ::time::Duration::minutes(10));

        for _ in 0..2 {
            assert_eq!(accumulator.add_message(threshold.clone(),
                                               1u64,
                                               ::rand::random(),
                                               group.clone(),
                                               bytes.clone(),
                                               cause.clone()),
                       (true, None));
            for _ in 1..threshold - 1 {
                assert_eq!(accumulator.add_message(threshold.clone(),
                                                   1u64,
                                                   ::rand::random(),
                                                   group.clone(),
                                                   bytes.clone(),
                                                   cause.clone()),
                           (false, None));
            }
            let result = accumulator.add_message(threshold.clone(),
                                                 1u64,
                                                 ::rand::random(),
                                                 group.clone(),
                                                 bytes.clone(),
                                                 cause.clone());
            assert!(!result.0);
            assert_eq!(unwrap_option!(result.1, "").len(), threshold);
            // since the message is now accumulated, it should be removed and we're good to do
            // another full iteration from scratch.
        }
    }
}

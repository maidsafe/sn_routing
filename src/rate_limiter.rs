// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#[cfg(feature="fake_clock")]
use fake_clock::FakeClock as Instant;
use messages::{Request, UserMessage, UserMessageCache};
use sha3::Digest256;
use std::cmp;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
#[cfg(not(feature="fake_clock"))]
use std::time::Instant;

/// Maximum total units the `RateLimiter` can hold at any given moment.
const CAPACITY: u64 = 20 * 1024 * 1024;
/// The number of units per second the `RateLimiter` will "leak".
const RATE: f64 = 20.0 * 1024.0 * 1024.0;
/// Default charge for a client get request.
const DEFAULT_CLIENT_GET_CHARGE: u64 = 2 * 1024 * 1024;

pub struct RateLimiter {
    used: HashMap<IpAddr, u64>,
    last_checked: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            used: HashMap::new(),
            last_checked: Instant::now(),
        }
    }

    pub fn add_message(&mut self,
                       online_clients: u64,
                       ip_addr: IpAddr,
                       hash: &Digest256,
                       part_count: &u32,
                       part_index: &u32,
                       payload: &[u8])
                       -> Result<(), ()> {
        self.purge();
        let total_used: u64 = self.used.values().sum();
        let used = self.used.entry(ip_addr).or_insert(0);
        let allowance = cmp::min(CAPACITY - total_used, CAPACITY / online_clients - *used);

        let mut user_msg_cache = UserMessageCache::with_expiry_duration(Duration::from_secs(10));
        let delta = if let Some(user_message) =
            user_msg_cache.add(*hash, *part_count, *part_index, payload.to_vec().clone()) {
            match user_message {
                UserMessage::Request(request) => {
                    match request {
                        Request::GetIData { .. } |
                        Request::GetMData { .. } |
                        Request::GetMDataVersion { .. } |
                        Request::GetMDataShell { .. } |
                        Request::ListMDataKeys { .. } |
                        Request::ListMDataValues { .. } |
                        Request::ListMDataEntries { .. } |
                        Request::GetMDataValue { .. } |
                        Request::ListMDataPermissions { .. } |
                        Request::ListMDataUserPermissions { .. } |
                        Request::ListAuthKeysAndVersion { .. } |
                        Request::GetAccountInfo { .. } |
                        Request::Refresh(..) => DEFAULT_CLIENT_GET_CHARGE,
                        _ => payload.len() as u64,
                    }
                }
                _ => payload.len() as u64,
            }
        } else {
            payload.len() as u64
        };

        if delta > allowance {
            Err(())
        } else {
            *used += delta;
            Ok(())
        }
    }

    fn purge(&mut self) {
        // If there's nothing to purge, update the timestamp and return.
        if self.used.is_empty() {
            self.last_checked = Instant::now();
            return;
        }

        // If the current used total has had time to fully leak away, just clear `used` and return.
        let now = Instant::now();
        let leak_time = (now - self.last_checked).as_secs() as f64 +
                        ((now - self.last_checked).subsec_nanos() as f64 / 1_000_000_000.0);
        self.last_checked = now;
        let mut leaked_units = (RATE * leak_time) as u64;
        if self.used.values().sum::<u64>() <= leaked_units {
            self.used.clear();
            return;
        }

        // Sort entries by least-used to most-used and leak each client's quota.  For any client
        // which doesn't need its full quota, the unused portion is equally distributed amongst the
        // others.
        let leaking_client_count = self.used.len();
        let mut quota = leaked_units / leaking_client_count as u64;
        let mut entries: Vec<(u64, IpAddr)> = self.used
            .drain()
            .map(|(ip_addr, used)| (used, ip_addr))
            .collect();
        entries.sort();
        for (index, (used, client)) in entries.into_iter().enumerate() {
            if used < quota {
                leaked_units -= used;
                quota = leaked_units / (leaking_client_count - index + 1) as u64;
            } else {
                let _ = self.used.insert(client, used - quota);
            }
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

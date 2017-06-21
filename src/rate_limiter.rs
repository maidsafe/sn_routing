// Copyright 2017 MaidSafe.net limited.
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

use error::RoutingError;
#[cfg(feature="fake_clock")]
use fake_clock::FakeClock as Instant;
use maidsafe_utilities::serialisation;
use messages::UserMessage;
use std::cmp;
use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(not(feature="fake_clock"))]
use std::time::Instant;

/// Maximum total bytes the `RateLimiter` allows at any given moment.
const CAPACITY: u64 = 20 * 1024 * 1024;
/// The number of bytes per second the `RateLimiter` will "leak".
const RATE: f64 = 20.0 * 1024.0 * 1024.0;
/// Charge (in bytes) for a client get request.
const CLIENT_GET_CHARGE: u64 = 2 * 1024 * 1024;

/// Used to throttle the rate at which clients can send messages via this node. It works on a "leaky
/// bucket" principle: there is a set rate at which bytes will leak out of the bucket, there is a
/// maximum capacity for the bucket, and connected clients each get an equal share of this capacity.
pub struct RateLimiter {
    /// Map of client IP address to their total bytes remaining in the `RateLimiter`.
    used: HashMap<IpAddr, u64>,
    /// Timestamp of when the `RateLimiter` was last updated.
    last_updated: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            used: HashMap::new(),
            last_updated: Instant::now(),
        }
    }

    /// Try to add a message. If the message is a form of get request, `CLIENT_GET_CHARGE` bytes
    /// will be used, otherwise the actual length of the `payload` will be used. If adding that
    /// amount will cause the client to exceed its share of the `CAPACITY` or cause the total
    /// `CAPACITY` to be exceeded, `Err(ExceedsRateLimit)` is returned. If the message is invalid,
    /// `Err(InvalidMessage)` is returned (this probably indicates malicious behaviour).
    pub fn add_message(&mut self,
                       online_clients: u64,
                       client_ip: IpAddr,
                       part_count: u32,
                       part_index: u32,
                       payload: &[u8])
                       -> Result<(), RoutingError> {
        self.update();
        let total_used: u64 = self.used.values().sum();
        let used = self.used.entry(client_ip).or_insert(0);
        let allowance = cmp::min(CAPACITY - total_used, CAPACITY / online_clients - *used);

        let bytes_to_add = if part_index == 0 {
            use self::UserMessage::*;
            use Request::*;
            match serialisation::deserialise::<UserMessage>(payload) {
                Ok(Request(GetIData { .. })) |
                Ok(Request(GetMData { .. })) |
                Ok(Request(GetMDataVersion { .. })) |
                Ok(Request(GetMDataShell { .. })) |
                Ok(Request(ListMDataKeys { .. })) |
                Ok(Request(ListMDataValues { .. })) |
                Ok(Request(ListMDataEntries { .. })) |
                Ok(Request(GetMDataValue { .. })) |
                Ok(Request(ListMDataPermissions { .. })) |
                Ok(Request(ListMDataUserPermissions { .. })) |
                Ok(Request(ListAuthKeysAndVersion { .. })) |
                Ok(Request(GetAccountInfo { .. })) => {
                    if part_count > 1 {
                        return Err(RoutingError::InvalidMessage);
                    }
                    CLIENT_GET_CHARGE
                }
                Ok(Request(PutIData { .. })) |
                Ok(Request(PutMData { .. })) |
                Ok(Request(MutateMDataEntries { .. })) |
                Ok(Request(SetMDataUserPermissions { .. })) |
                Ok(Request(DelMDataUserPermissions { .. })) |
                Ok(Request(ChangeMDataOwner { .. })) |
                Ok(Request(InsAuthKey { .. })) |
                Ok(Request(DelAuthKey { .. })) => {
                    if part_count > 1 {
                        return Err(RoutingError::InvalidMessage);
                    }
                    payload.len() as u64
                }
                Ok(Request(Refresh(..))) |
                Ok(Response(_)) => return Err(RoutingError::InvalidMessage),
                Err(_) => {
                    if part_count == 1 {
                        return Err(RoutingError::InvalidMessage);
                    }
                    payload.len() as u64
                }
            }
        } else {
            payload.len() as u64
        };

        if bytes_to_add > allowance {
            return Err(RoutingError::ExceedsRateLimit);
        }

        *used += bytes_to_add;
        Ok(())
    }

    fn update(&mut self) {
        // If there's nothing else to update, set the timestamp and return.
        if self.used.is_empty() {
            self.last_updated = Instant::now();
            return;
        }

        // If the current used total has had time to fully leak away, just clear `used` and return.
        let now = Instant::now();
        let leak_time = (now - self.last_updated).as_secs() as f64 +
                        ((now - self.last_updated).subsec_nanos() as f64 / 1_000_000_000.0);
        self.last_updated = now;
        let mut leaked_units = (RATE * leak_time) as u64;
        if self.used.values().sum::<u64>() <= leaked_units {
            self.used.clear();
            return;
        }

        // Sort entries by least-used to most-used and leak each client's quota. For any client
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

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
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use itertools::Itertools;
use maidsafe_utilities::serialisation::{self, SerialisationError};
use messages::{DEFAULT_PRIORITY, MAX_PARTS, MAX_PART_LEN, MessageContent, RoutingMessage,
               UserMessage};
use routing_table::Authority;
use std::cmp;
use std::collections::BTreeMap;
use std::mem;
use std::net::IpAddr;
#[cfg(not(feature = "use-mock-crust"))]
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
#[derive(Debug)]
pub struct RateLimiter {
    /// Map of client IP address to their total bytes remaining in the `RateLimiter`.
    used: BTreeMap<IpAddr, u64>,
    /// Timestamp of when the `RateLimiter` was last updated.
    last_updated: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            used: BTreeMap::new(),
            last_updated: Instant::now(),
        }
    }

    /// Try to add a message. If the message is a form of get request, `CLIENT_GET_CHARGE` bytes
    /// will be used, otherwise the actual length of the `payload` will be used. If adding that
    /// amount will cause the client to exceed its share of the `CAPACITY` or cause the total
    /// `CAPACITY` to be exceeded, `Err(ExceedsRateLimit)` is returned. If the message is invalid,
    /// `Err(InvalidMessage)` is returned (this probably indicates malicious behaviour).
    pub fn check_valid_client_message(&mut self,
                                      online_clients: u64,
                                      client_ip: &IpAddr,
                                      msg: &RoutingMessage)
                                      -> Result<(), RoutingError> {
        match (&msg.src, &msg.content) {
            (&Authority::Client { .. }, &MessageContent::Ack(_ack, priority))
                if priority >= DEFAULT_PRIORITY => Ok(()),
            (&Authority::Client { .. },
             &MessageContent::UserMessagePart {
                  ref part_count,
                  ref part_index,
                  ref priority,
                  ref payload,
                  ..
              }) if *part_count <= MAX_PARTS && part_index < part_count &&
                  *priority >= DEFAULT_PRIORITY &&
                  payload.len() <= MAX_PART_LEN => {
                self.add_message(online_clients, client_ip, *part_count, *part_index, payload)
            }
            _ => {
                debug!("Illegitimate client message {:?}. Refusing to relay.", msg);
                Err(RoutingError::RejectedClientMessage)
            }
        }
    }

    fn add_message(&mut self,
                   online_clients: u64,
                   client_ip: &IpAddr,
                   part_count: u32,
                   part_index: u32,
                   payload: &[u8])
                   -> Result<(), RoutingError> {
        self.update();
        let total_used: u64 = self.used.values().sum();
        let used = self.used.get(client_ip).map_or(0, |used| *used);
        let allowance = cmp::min(CAPACITY - total_used,
                                 (CAPACITY / online_clients).saturating_sub(used));

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
                Err(SerialisationError::DeserialiseExtraBytes) => {
                    return Err(RoutingError::InvalidMessage);
                }
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

        let _ = self.used.insert(*client_ip, used + bytes_to_add);
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
        let mut entries = mem::replace(&mut self.used, Default::default())
            .into_iter()
            .map(|(ip_addr, used)| (used, ip_addr))
            .collect_vec();
        entries.sort();
        for (index, (used, client)) in entries.into_iter().enumerate() {
            if used < quota {
                leaked_units -= used;
                // The divisor will never be `0` as such a case would need all entries to be below
                // their quota (i.e. all usage has fully leaked) and would have results in an early
                // return in the above sum check already.
                quota = leaked_units / (leaking_client_count - index - 1) as u64;
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

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use fake_clock::FakeClock;
    use id::FullId;
    use messages::Request;
    use rand;
    use tiny_keccak::sha3_256;
    use types::MessageId;
    use xor_name::XorName;

    fn gen_routing_message(part_count: u32, part_index: u32, payload: Vec<u8>) -> RoutingMessage {
        let data_name: XorName = rand::random();
        let proxy_name: XorName = rand::random();
        RoutingMessage {
            src: Authority::Client {
                client_id: *FullId::new().public_id(),
                proxy_node_name: proxy_name,
            },
            dst: Authority::NaeManager(data_name),
            content: MessageContent::UserMessagePart {
                hash: sha3_256(&payload),
                part_count: part_count,
                part_index: part_index,
                payload: payload,
                priority: DEFAULT_PRIORITY,
                cacheable: false,
            },
        }
    }

    #[test]
    fn check_valid_client_message() {
        // First client fills the `RateLimiter` with get requests.
        let mut rate_limiter = RateLimiter::new();
        let client_1 = IpAddr::from([0, 0, 0, 0]);
        let get_req_payload = unwrap!(serialisation::serialise(
            &UserMessage::Request(Request::GetIData {
                name: rand::random(),
                msg_id: MessageId::new(),
        })));
        let get_req = gen_routing_message(1, 0, get_req_payload);

        let fill_full_iterations = CAPACITY / CLIENT_GET_CHARGE;
        for _ in 0..fill_full_iterations {
            unwrap!(rate_limiter.check_valid_client_message(1, &client_1, &get_req));
        }

        // Check a second client can't add a message just now.
        let client_2 = IpAddr::from([1, 1, 1, 1]);
        match rate_limiter.check_valid_client_message(1, &client_2, &get_req) {
            Err(RoutingError::ExceedsRateLimit) => {}
            _ => panic!("unexpected result"),
        }

        // Wait until enough has drained to allow the second client's request to succeed.
        let wait_millis = CLIENT_GET_CHARGE * 1000 / RATE as u64;
        FakeClock::advance_time(wait_millis);
        unwrap!(rate_limiter.check_valid_client_message(10, &client_2, &get_req));

        // Wait for the same period, but now try adding invalid messages.
        FakeClock::advance_time(wait_millis);
        let all_zero_req = gen_routing_message(2, 0, vec![0u8; MAX_PART_LEN]);
        match rate_limiter.check_valid_client_message(10, &client_2, &all_zero_req) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        match rate_limiter.check_valid_client_message(10, &client_2, &get_req) {
            Err(RoutingError::ExceedsRateLimit) => {}
            _ => panic!("unexpected result"),
        }
        unwrap!(rate_limiter.check_valid_client_message(2, &client_2, &get_req));

        // Wait for the same period, and push up the second client's usage.
        FakeClock::advance_time(wait_millis);
        unwrap!(rate_limiter.check_valid_client_message(2, &client_2, &get_req));
        // Wait for the same period to drain the second client's usage to half of per-client cap.
        FakeClock::advance_time(wait_millis);
        match rate_limiter.check_valid_client_message(10, &client_2, &get_req) {
            Err(RoutingError::ExceedsRateLimit) => {}
            _ => panic!("unexpected result"),
        }
    }
}

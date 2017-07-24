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

use data::{MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, MAX_MUTABLE_DATA_SIZE_IN_BYTES};
use error::RoutingError;
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use itertools::Itertools;
use maidsafe_utilities::serialisation::{self, SerialisationError};
use messages::UserMessage;
use sha3::Digest256;
use std::cmp;
use std::collections::BTreeMap;
use std::mem;
use std::net::IpAddr;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;

/// The number of bytes per second the `RateLimiter` will "leak".
const RATE: f64 = 5.0 * 1024.0 * 1024.0;

#[cfg(feature = "use-mock-crust")]
#[doc(hidden)]
pub mod rate_limiter_consts {
    pub const RATE: f64 = super::RATE;
}

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

    /// Try to add a message. If the message is a form of get request,
    /// `MAX_IMMUTABLE_DATA_SIZE_IN_BYTES` or `MAX_MUTABLE_DATA_SIZE_IN_BYTES` bytes will be used,
    /// otherwise the actual length of the `payload` will be used. If adding that amount will cause
    /// the client to exceed its capacity (i.e. `MAX_IMMUTABLE_DATA_SIZE_IN_BYTES`), then
    /// `Err(ExceedsRateLimit)` is returned. If the message is invalid, `Err(InvalidMessage)` is
    /// returned (this probably indicates malicious behaviour).
    pub fn add_message(&mut self,
                       client_ip: &IpAddr,
                       hash: &Digest256,
                       part_count: u32,
                       part_index: u32,
                       payload: &[u8])
                       -> Result<u64, RoutingError> {
        self.update();

        let used = self.used.get(client_ip).map_or(0, |used| *used);
        let allowance = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES - used;

        let bytes_to_add = if part_index == 0 {
            use self::UserMessage::*;
            use Request::*;
            match serialisation::deserialise::<UserMessage>(payload) {
                Ok(Request(request)) => {
                    if part_count > 1 {
                        return Err(RoutingError::InvalidMessage);
                    }
                    match request {
                        GetIData { .. } => MAX_IMMUTABLE_DATA_SIZE_IN_BYTES,
                        GetAccountInfo { .. } |
                        GetMData { .. } |
                        GetMDataVersion { .. } |
                        GetMDataShell { .. } |
                        ListMDataEntries { .. } |
                        ListMDataKeys { .. } |
                        ListMDataValues { .. } |
                        GetMDataValue { .. } |
                        ListMDataPermissions { .. } |
                        ListMDataUserPermissions { .. } |
                        ListAuthKeysAndVersion { .. } => MAX_MUTABLE_DATA_SIZE_IN_BYTES,
                        PutIData { .. } |
                        PutMData { .. } |
                        MutateMDataEntries { .. } |
                        SetMDataUserPermissions { .. } |
                        DelMDataUserPermissions { .. } |
                        ChangeMDataOwner { .. } |
                        InsAuthKey { .. } |
                        DelAuthKey { .. } => payload.len() as u64,
                        Refresh(..) => return Err(RoutingError::InvalidMessage),
                    }
                }
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
            return Err(RoutingError::ExceedsRateLimit(*hash));
        }

        let _ = self.used.insert(*client_ip, used + bytes_to_add);
        Ok(bytes_to_add)
    }

    fn update(&mut self) {
        // If there's nothing else to update, set the timestamp and return.
        if self.used.is_empty() {
            self.last_updated = Instant::now();
            return;
        }

        let now = Instant::now();
        let leak_time = (now - self.last_updated).as_secs() as f64 +
                        ((now - self.last_updated).subsec_nanos() as f64 / 1_000_000_000.0);
        self.last_updated = now;
        let mut leaked_units = (RATE * leak_time) as u64;

        // Sort entries by least-used to most-used and leak each client's quota. For any client
        // which doesn't need its full quota, the unused portion is equally distributed amongst the
        // others.
        let leaking_client_count = self.used.len();
        let mut entries = mem::replace(&mut self.used, Default::default())
            .into_iter()
            .map(|(ip_addr, used)| (used, ip_addr))
            .collect_vec();
        entries.sort();
        for (index, (used, client)) in entries.into_iter().enumerate() {
            let quota = cmp::min(used, leaked_units / (leaking_client_count - index) as u64);
            leaked_units -= quota;
            if used > quota {
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
    use maidsafe_utilities::SeededRng;
    use messages::{Request, Response};
    use rand::{self, Rng};
    use std::collections::BTreeMap;
    use tiny_keccak::sha3_256;
    use types::MessageId;

    // Creates a random `GetIData` request and returns it serialised along with its hash digest.
    fn create_get_idata_request() -> (Vec<u8>, Digest256) {
        let payload = unwrap!(serialisation::serialise(
            &UserMessage::Request(Request::GetIData {
                name: rand::random(),
                msg_id: MessageId::new(),
        })));
        let hash = sha3_256(&payload);
        (payload, hash)
    }

    fn assert_get_idata_req_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        let (payload, hash) = create_get_idata_request();
        let _ = unwrap!(rate_limiter.add_message(client, &hash, 1, 0, &payload));
    }

    fn assert_get_idata_req_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        let (payload, hash) = create_get_idata_request();
        match rate_limiter.add_message(client, &hash, 1, 0, &payload) {
            Err(RoutingError::ExceedsRateLimit(returned_hash)) => {
                assert_eq!(hash, returned_hash);
            }
            _ => panic!("unexpected result"),
        }
    }

    fn assert_small_message_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        let payload = vec![0];
        let hash = sha3_256(&payload);
        let _ = unwrap!(rate_limiter.add_message(client, &hash, 2, 1, &payload));
    }

    fn assert_small_message_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        let payload = vec![0];
        let hash = sha3_256(&payload);
        match rate_limiter.add_message(client, &hash, 2, 1, &payload) {
            Err(RoutingError::ExceedsRateLimit(returned_hash)) => {
                assert_eq!(hash, returned_hash);
            }
            _ => panic!("unexpected result"),
        }
    }

    // Checks that a single client cannot exceed its individual limit and that its throughput is the
    // full rate of the rate-limiter.
    #[test]
    fn single_client() {
        let mut rate_limiter = RateLimiter::new();
        let client = IpAddr::from([0, 0, 0, 0]);

        // Consume full allowance.
        assert_get_idata_req_can_be_added(&mut rate_limiter, &client);

        // Check client can't add any more requests just now.
        assert_small_message_cannot_be_added(&mut rate_limiter, &client);

        // Advance the clock 1ms and check the small request can now be added, but the large request
        // is still disallowed.
        FakeClock::advance_time(1);
        assert_small_message_can_be_added(&mut rate_limiter, &client);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client);

        // Advance the clock enough to allow the client's entry to fully drain away. (No need to
        // round up the calculation here as we've already advanced by 1ms which is equivalent to
        // rounding up the millisecond calculation).
        let wait_millis = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES * 1000 / RATE as u64;
        FakeClock::advance_time(wait_millis);
        assert_get_idata_req_can_be_added(&mut rate_limiter, &client);
    }

    // Checks that a second client can add messages even when an initial one has hit its limit. Also
    // checks that the each client's throughput is half the full rate of the rate-limiter.
    #[test]
    fn two_clients() {
        let mut rate_limiter = RateLimiter::new();
        let client1 = IpAddr::from([0, 0, 0, 0]);
        let client2 = IpAddr::from([1, 1, 1, 1]);

        // Each client consumes their full allowance.
        assert_get_idata_req_can_be_added(&mut rate_limiter, &client1);
        assert_get_idata_req_can_be_added(&mut rate_limiter, &client2);

        // Check neither client can add any more requests just now.
        assert_small_message_cannot_be_added(&mut rate_limiter, &client1);
        assert_small_message_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock 1ms and check the small request can now be added by each client, but
        // the large request is still disallowed.
        FakeClock::advance_time(1);
        assert_small_message_can_be_added(&mut rate_limiter, &client1);
        assert_small_message_can_be_added(&mut rate_limiter, &client2);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client1);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock enough to allow a single GetIData request to drain away and check that
        // neither client still cannot add a large request.
        let wait_millis = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES * 1000 / RATE as u64;
        FakeClock::advance_time(wait_millis);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client1);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock by just less than the same amount again and check that neither client
        // still cannot add a large request.
        FakeClock::advance_time(wait_millis - 1);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client1);
        assert_get_idata_req_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock a final small amount and check that both clients can now add large
        // requests.
        FakeClock::advance_time(2);
        assert_get_idata_req_can_be_added(&mut rate_limiter, &client1);
        assert_get_idata_req_can_be_added(&mut rate_limiter, &client2);
    }

    // Checks that many clients can all add messages at the same rate.
    #[test]
    fn many_clients() {
        let mut rate_limiter = RateLimiter::new();
        let num_clients = 100;
        let mut clients_and_counts = (0..num_clients)
            .map(|i| (IpAddr::from([i, i, i, i]), 0))
            .collect::<BTreeMap<_, _>>();
        let (get_req_payload, hash_of_get_req) = create_get_idata_request();
        let mut rng = SeededRng::thread_rng();

        let start = FakeClock::now();
        for _ in 0..500 {
            // Each client tries to add a large request and increments its count on success.
            for (client, count) in &mut clients_and_counts {
                if rate_limiter
                       .add_message(client, &hash_of_get_req, 1, 0, &get_req_payload)
                       .is_ok() {
                    *count += 1;
                }
            }
            FakeClock::advance_time(rng.gen_range(500, 1500));
        }

        // Check that all clients have managed to add the same number of messages.
        let advanced_secs = (FakeClock::now() - start).as_secs() + 1;
        let success_count = (advanced_secs * RATE as u64) /
                            (MAX_IMMUTABLE_DATA_SIZE_IN_BYTES * num_clients as u64);
        for count in clients_and_counts.values() {
            // Allow difference of 1 to accommodate for rounding errors.
            assert!((*count as i64 - success_count as i64).abs() <= 1);
        }
    }

    // Check that invalid messages are handled correctly.
    #[test]
    fn invalid_messages() {
        let mut rate_limiter = RateLimiter::new();
        let client = IpAddr::from([0, 0, 0, 0]);

        // Parses with `SerialisationError::DeserialiseExtraBytes` error.
        let mut payload = vec![0; MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as usize];
        match rate_limiter.add_message(&client, &sha3_256(&payload), 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses with other serialisation error and part count is 1.
        payload = vec![0];
        match rate_limiter.add_message(&client, &sha3_256(&payload), 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses successfully but claims to be part 1 of 2.
        let mut msg = UserMessage::Request(Request::GetIData {
                                               name: rand::random(),
                                               msg_id: MessageId::new(),
                                           });
        payload = unwrap!(serialisation::serialise(&msg));
        match rate_limiter.add_message(&client, &sha3_256(&payload), 2, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses as a refresh request.
        msg = UserMessage::Request(Request::Refresh(vec![0], MessageId::new()));
        payload = unwrap!(serialisation::serialise(&msg));
        match rate_limiter.add_message(&client, &sha3_256(&payload), 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses as a response.
        msg = UserMessage::Response(Response::PutIData {
                                        res: Ok(()),
                                        msg_id: MessageId::new(),
                                    });
        payload = unwrap!(serialisation::serialise(&msg));
        match rate_limiter.add_message(&client, &sha3_256(&payload), 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }
    }
}

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
/// The maximum number of bytes a single client is allowed to have in the `RateLimiter`.  This is
/// slightly larger than `MAX_IMMUTABLE_DATA_SIZE_IN_BYTES` to allow for the extra bytes created by
/// wrapping the chunk in a `UserMessage`, splitting it into parts and wrapping those in
/// `RoutingMessage`s.
const CLIENT_CAPACITY: u64 = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + 10240;

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
    /// Whether rate restriction is disabled.
    disabled: bool,
}

impl RateLimiter {
    pub fn new(disabled: bool) -> Self {
        RateLimiter {
            used: BTreeMap::new(),
            last_updated: Instant::now(),
            disabled: disabled,
        }
    }

    /// Try to add a message. If the message is a form of get request,
    /// `MAX_IMMUTABLE_DATA_SIZE_IN_BYTES` or `MAX_MUTABLE_DATA_SIZE_IN_BYTES` bytes will be used,
    /// otherwise the actual length of the `payload` will be used. If adding that amount will cause
    /// the client to exceed its capacity (`CLIENT_CAPACITY`), then `Err(ExceedsRateLimit)` is
    /// returned. If the message is invalid, `Err(InvalidMessage)` is returned (this probably
    /// indicates malicious behaviour).
    pub fn add_message(
        &mut self,
        client_ip: &IpAddr,
        hash: &Digest256,
        part_count: u32,
        part_index: u32,
        payload: &[u8],
    ) -> Result<u64, RoutingError> {
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

        if self.disabled {
            return Ok(bytes_to_add);
        }

        self.update();

        let used = self.used.get(client_ip).map_or(0, |used| *used);
        let allowance = CLIENT_CAPACITY - used;

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

    static LARGE_MESSAGE: [u8; CLIENT_CAPACITY as usize] = [0; CLIENT_CAPACITY as usize];
    static SMALL_MESSAGE: [u8; 1] = [0];

    fn assert_large_message_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        check_message_addition(rate_limiter, client, true, true)
    }

    fn assert_large_message_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        check_message_addition(rate_limiter, client, true, false)
    }

    fn assert_small_message_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        check_message_addition(rate_limiter, client, false, true)
    }

    fn assert_small_message_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) {
        check_message_addition(rate_limiter, client, false, false)
    }

    fn check_message_addition(
        rate_limiter: &mut RateLimiter,
        client: &IpAddr,
        large_msg: bool,
        should_succeed: bool,
    ) {
        let payload: &[u8] = if large_msg {
            &LARGE_MESSAGE
        } else {
            &SMALL_MESSAGE
        };
        let hash = sha3_256(payload);
        match rate_limiter.add_message(client, &hash, 2, 1, payload) {
            Err(RoutingError::ExceedsRateLimit(returned_hash)) => {
                if should_succeed {
                    panic!("unexpected result");
                } else {
                    assert_eq!(hash, returned_hash);
                }
            }
            Ok(returned_len) => {
                if should_succeed {
                    assert_eq!(payload.len() as u64, returned_len);
                } else {
                    panic!("unexpected result");
                }
            }
            _ => panic!("unexpected result"),
        }
    }

    /// Checks that a single client cannot exceed its individual limit and that its throughput is
    /// the full rate of the rate-limiter.
    #[test]
    fn single_client() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);

        // Consume full allowance.
        assert_large_message_can_be_added(&mut rate_limiter, &client);

        // Check client can't add any more requests just now.
        assert_small_message_cannot_be_added(&mut rate_limiter, &client);

        // Advance the clock 1ms and check the small request can now be added, but the large request
        // is still disallowed.
        FakeClock::advance_time(1);
        assert_small_message_can_be_added(&mut rate_limiter, &client);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client);

        // Advance the clock enough to allow the client's entry to fully drain away. (No need to
        // round up the calculation here as we've already advanced by 1ms which is equivalent to
        // rounding up the millisecond calculation).
        let wait_millis = CLIENT_CAPACITY * 1000 / RATE as u64;
        FakeClock::advance_time(wait_millis);
        assert_large_message_can_be_added(&mut rate_limiter, &client);
    }

    /// Checks that a second client can add messages even when an initial one has hit its limit.
    /// Also checks that the each client's throughput is half the full rate of the rate-limiter.
    #[test]
    fn two_clients() {
        let mut rate_limiter = RateLimiter::new(false);
        let client1 = IpAddr::from([0, 0, 0, 0]);
        let client2 = IpAddr::from([1, 1, 1, 1]);

        // Each client consumes their full allowance.
        assert_large_message_can_be_added(&mut rate_limiter, &client1);
        assert_large_message_can_be_added(&mut rate_limiter, &client2);

        // Check neither client can add any more requests just now.
        assert_small_message_cannot_be_added(&mut rate_limiter, &client1);
        assert_small_message_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock 1ms and check the small request can now be added by each client, but
        // the large request is still disallowed.
        FakeClock::advance_time(1);
        assert_small_message_can_be_added(&mut rate_limiter, &client1);
        assert_small_message_can_be_added(&mut rate_limiter, &client2);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client1);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock enough to allow a single large request to drain away and check that
        // both clients still cannot add a large request.
        let wait_millis = CLIENT_CAPACITY * 1000 / RATE as u64;
        FakeClock::advance_time(wait_millis);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client1);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock by just less than the same amount again and check that neither client
        // still cannot add a large request.
        FakeClock::advance_time(wait_millis - 1);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client1);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client2);

        // Advance the clock a final small amount and check that both clients can now add large
        // requests.
        FakeClock::advance_time(2);
        assert_large_message_can_be_added(&mut rate_limiter, &client1);
        assert_large_message_can_be_added(&mut rate_limiter, &client2);
    }

    /// Checks that if two clients add messages with a delay between them, the rate-limiter's
    /// throughput remains constant, but the per-client throughput drops when both clients have
    /// messages and increases when just one has messages.
    #[test]
    fn staggered_start() {
        let mut rate_limiter = RateLimiter::new(false);
        let client1 = IpAddr::from([0, 0, 0, 0]);
        let client2 = IpAddr::from([1, 1, 1, 1]);

        // This is the time during which half of a large request will leak away. Assert this
        // is the case by adding a large request, then waiting for two times `wait_millis` then
        // trying to add a large request again.
        let wait_millis = (CLIENT_CAPACITY * 500 / RATE as u64) + 1; // round up
        assert_large_message_can_be_added(&mut rate_limiter, &client1);
        FakeClock::advance_time(wait_millis);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client1);
        FakeClock::advance_time(wait_millis);
        assert_large_message_can_be_added(&mut rate_limiter, &client1);

        // Allow the rate-limiter to empty.
        FakeClock::advance_time(2 * wait_millis);

        // Client 1 adds a large message then after `wait_millis`, Client 2 does likewise.
        assert_large_message_can_be_added(&mut rate_limiter, &client1);
        FakeClock::advance_time(wait_millis);
        assert_large_message_can_be_added(&mut rate_limiter, &client2);

        // We wait for a further `wait_millis` then confirm that neither client can add a further
        // large message at this stage (3/4 of the first message and 1/4 of the second message
        // should have drained).
        FakeClock::advance_time(wait_millis);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client1);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client2);

        // After a further `wait_millis`, Client 1 should be able to add a new large message, but
        // not Client 2 (the first message and 1/2 of the second message should have drained).
        FakeClock::advance_time(wait_millis);
        assert_large_message_can_be_added(&mut rate_limiter, &client1);
        assert_large_message_cannot_be_added(&mut rate_limiter, &client2);

        // After a further `3 * wait_millis`, the second and third messages should both have drained
        // allowing both clients to add new large messages.
        FakeClock::advance_time(3 * wait_millis);
        assert_large_message_can_be_added(&mut rate_limiter, &client1);
        assert_large_message_can_be_added(&mut rate_limiter, &client2);
    }

    /// Checks that many clients can all add messages at the same rate.
    #[test]
    fn many_clients() {
        let mut rate_limiter = RateLimiter::new(false);
        let num_clients = 100;
        let mut clients_and_counts = (0..num_clients)
            .map(|i| (IpAddr::from([i, i, i, i]), 0))
            .collect::<BTreeMap<_, _>>();
        let payload = unwrap!(serialisation::serialise(
            &UserMessage::Request(Request::GetIData {
                name: rand::random(),
                msg_id: MessageId::new(),
            }),
        ));
        let hash = sha3_256(&payload);
        let mut rng = SeededRng::thread_rng();

        let start = FakeClock::now();
        for _ in 0..500 {
            // Each client tries to add a large request and increments its count on success.
            for (client, count) in &mut clients_and_counts {
                if rate_limiter
                    .add_message(client, &hash, 1, 0, &payload)
                    .is_ok()
                {
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

    /// Checks that invalid messages are handled correctly.
    #[test]
    fn invalid_messages() {
        let mut rate_limiter = RateLimiter::new(false);
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

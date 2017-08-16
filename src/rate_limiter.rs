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
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::{self, SerialisationError};
use messages::{MAX_PART_LEN, UserMessage};
use sha3::Digest256;
use std::cmp;
use std::collections::BTreeMap;
use std::mem;
use std::net::IpAddr;
use std::time::Duration;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;
use types::MessageId;

/// The number of bytes per second the `RateLimiter` will "leak".
const RATE: f64 = 8.0 * 1024.0 * 1024.0;
/// The minimum allowance (in bytes) for a single client at any given moment in the `RateLimiter`.
/// This is slightly larger than `MAX_IMMUTABLE_DATA_SIZE_IN_BYTES` to allow for the extra bytes
/// created by wrapping the chunk in a `UserMessage`, splitting it into parts and wrapping those in
/// `RoutingMessage`s.
const MIN_CLIENT_CAPACITY: u64 = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + 10240;
/// The maximum number of bytes the `RateLimiter` will "hold" at any given moment. This allowance
/// is split equally between clients with entries in the `RateLimiter`. It is a soft limit in that
/// it can be exceeded if there are enough client entries: each client will be allowed a
/// hard-minimum of `MIN_CLIENT_CAPACITY` even if this means the `RateLimiter`'s total capacity
/// exceeds the `SOFT_CAPACITY`.
#[cfg(not(feature = "use-mock-crust"))]
const SOFT_CAPACITY: u64 = 8 * 1024 * 1024;
/// For the mock-crust tests, we want a small `SOFT_CAPACITY` in order to trigger more rate-limited
/// rejections. This must be at least `2 * MIN_CLIENT_CAPACITY` for the multi-client tests to work.
#[cfg(feature = "use-mock-crust")]
const SOFT_CAPACITY: u64 = 2 * MIN_CLIENT_CAPACITY;
/// Duration for which entries are kept in the `overcharged` cache, in seconds.
const OVERCHARGED_TIMEOUT_SECS: u64 = 300;

#[cfg(feature = "use-mock-crust")]
#[doc(hidden)]
pub mod rate_limiter_consts {
    pub const SOFT_CAPACITY: u64 = super::SOFT_CAPACITY;
    pub const MAX_PARTS: u32 = ::messages::MAX_PARTS;
    pub const MAX_PART_LEN: usize = ::messages::MAX_PART_LEN;
    pub const MIN_CLIENT_CAPACITY: u64 = super::MIN_CLIENT_CAPACITY;
    pub const RATE: f64 = super::RATE;
}

/// Used to throttle the rate at which clients can send messages via this node. It works on a "leaky
/// bucket" principle: there is a set rate at which bytes will leak out of the bucket, there is a
/// maximum capacity for the bucket, and connected clients each get an equal share of this capacity.
pub struct RateLimiter {
    /// Map of client IP address to their total bytes remaining in the `RateLimiter`.
    used: BTreeMap<IpAddr, u64>,
    /// Initial charge amount by GET request message ID.
    /// The IP address of the requesting peer is also tracked so that stale entries can be removed.
    overcharged: LruCache<MessageId, u64>,
    /// Timestamp of when the `RateLimiter` was last updated.
    last_updated: Instant,
    /// Whether rate restriction is disabled.
    disabled: bool,
}

impl RateLimiter {
    pub fn new(disabled: bool) -> Self {
        RateLimiter {
            used: BTreeMap::new(),
            overcharged: LruCache::with_expiry_duration(
                Duration::from_secs(OVERCHARGED_TIMEOUT_SECS),
            ),
            last_updated: Instant::now(),
            disabled: disabled,
        }
    }

    /// Try to add a message. If the message is a form of get request,
    /// `MAX_IMMUTABLE_DATA_SIZE_IN_BYTES` or `MAX_MUTABLE_DATA_SIZE_IN_BYTES` bytes will be used,
    /// otherwise the actual length of the `payload` will be used. If adding that amount will cause
    /// the client to exceed its capacity, then `Err(ExceedsRateLimit)` is returned. If the
    /// message is invalid, `Err(InvalidMessage)` is returned (this probably indicates malicious
    /// behaviour).
    pub fn add_message(
        &mut self,
        client_ip: &IpAddr,
        hash: &Digest256,
        msg_id: &MessageId,
        part_count: u32,
        part_index: u32,
        payload: &[u8],
    ) -> Result<u64, RoutingError> {
        let (bytes_to_add, overcharged) = if part_index == 0 {
            use self::UserMessage::*;
            use Request::*;
            match serialisation::deserialise::<UserMessage>(payload) {
                Ok(Request(request)) => {
                    if part_count > 1 {
                        return Err(RoutingError::InvalidMessage);
                    }
                    match request {
                        GetIData { .. } => (MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, true),
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
                        ListAuthKeysAndVersion { .. } => (MAX_MUTABLE_DATA_SIZE_IN_BYTES, true),
                        PutIData { .. } |
                        PutMData { .. } |
                        MutateMDataEntries { .. } |
                        SetMDataUserPermissions { .. } |
                        DelMDataUserPermissions { .. } |
                        ChangeMDataOwner { .. } |
                        InsAuthKey { .. } |
                        DelAuthKey { .. } => (payload.len() as u64, false),
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
                    (payload.len() as u64, false)
                }
            }
        } else {
            (payload.len() as u64, false)
        };

        if self.disabled {
            return Ok(bytes_to_add);
        }

        self.update();

        let used = self.used.get(client_ip).map_or(0, |used| *used);
        let new_balance = used + bytes_to_add;

        if new_balance > self.client_allowance(client_ip) {
            return Err(RoutingError::ExceedsRateLimit(*hash));
        }

        if overcharged {
            // Record the overcharge amount in the `overcharged` container. If an entry already
            // exists, we leave it as is. This means that *at most 1* refund is applied if multiple
            // messages are sent with the same `msg_id`.
            let _ = self.overcharged.entry(*msg_id).or_insert(bytes_to_add);
        }

        let _ = self.used.insert(*client_ip, new_balance);
        Ok(bytes_to_add)
    }

    /// Compute the usage limit for any single client at the current point in time.
    fn client_allowance(&self, client_ip: &IpAddr) -> u64 {
        let num_clients = if self.used.contains_key(client_ip) {
            self.used.len()
        } else {
            self.used.len() + 1
        };
        cmp::max(MIN_CLIENT_CAPACITY, SOFT_CAPACITY / num_clients as u64)
    }

    /// Update a client's balance to compensate for initial over-counting.
    ///
    /// When a request is made, clients are charged at the maximum size of the data being requested.
    /// This method compensates the client for the over-counting by crediting them the difference
    /// between the maximum and the actual size of the response.
    pub fn apply_refund_for_response(
        &mut self,
        client_ip: &IpAddr,
        msg_id: &MessageId,
        part_count: u32,
        part_index: u32,
        payload: &[u8],
    ) -> Option<u64> {
        use Response::*;

        // Check that this is a message ID we overcharged for.
        if !self.overcharged.contains_key(msg_id) {
            return None;
        }

        // Check that the response isn't a single-part response that we never overcharged for. This
        // prevents a malicious client from gaming the system: for example, by preceding a GET with
        // a PUT with the same `msg_id`.
        if part_count == 1 && part_index == 0 {
            match serialisation::deserialise::<UserMessage>(payload) {
                Ok(UserMessage::Response(response)) => {
                    match response {
                        // We overcharged for these, so we let them through.
                        GetIData { .. } |
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
                        ListAuthKeysAndVersion { .. } => (),
                        // These are responses to requests we didn't overcharge for. All these
                        // responses *should* fit in a single part.
                        PutIData { .. } |
                        PutMData { .. } |
                        MutateMDataEntries { .. } |
                        SetMDataUserPermissions { .. } |
                        DelMDataUserPermissions { .. } |
                        ChangeMDataOwner { .. } |
                        InsAuthKey { .. } |
                        DelAuthKey { .. } => return None,
                    }
                }
                _ => return None,
            }
        }

        let amount_charged = match self.overcharged.remove(msg_id) {
            Some(amount) => amount,
            None => return None,
        };

        let deduction = amount_charged.saturating_sub(part_count as u64 * MAX_PART_LEN as u64);

        self.used.get_mut(client_ip).map(|used| {
            *used = used.saturating_sub(deduction);
            deduction
        })
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

    #[cfg(feature = "use-mock-crust")]
    pub fn usage_map(&self) -> &BTreeMap<IpAddr, u64> {
        &self.used
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use data::ImmutableData;
    use fake_clock::FakeClock;
    use maidsafe_utilities::SeededRng;
    use messages::{MessageContent, Request, Response};
    use rand::Rng;
    use std::collections::BTreeMap;
    use tiny_keccak::sha3_256;
    use types::MessageId;
    use xor_name::{XOR_NAME_LEN, XorName};

    fn huge_message_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) -> bool {
        sized_message_can_be_added(SOFT_CAPACITY, rate_limiter, client)
    }

    fn huge_message_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) -> bool {
        sized_message_cannot_be_added(SOFT_CAPACITY, rate_limiter, client)
    }

    fn large_message_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) -> bool {
        sized_message_can_be_added(MIN_CLIENT_CAPACITY, rate_limiter, client)
    }

    fn large_message_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) -> bool {
        sized_message_cannot_be_added(MIN_CLIENT_CAPACITY, rate_limiter, client)
    }

    fn small_message_can_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) -> bool {
        sized_message_can_be_added(1, rate_limiter, client)
    }

    fn small_message_cannot_be_added(rate_limiter: &mut RateLimiter, client: &IpAddr) -> bool {
        sized_message_cannot_be_added(1, rate_limiter, client)
    }

    fn sized_message_can_be_added(
        size: u64,
        rate_limiter: &mut RateLimiter,
        client: &IpAddr,
    ) -> bool {
        let content = vec![0; size as usize];
        check_message_addition(rate_limiter, client, &content, true)
    }

    fn sized_message_cannot_be_added(
        size: u64,
        rate_limiter: &mut RateLimiter,
        client: &IpAddr,
    ) -> bool {
        let content = vec![0; size as usize];
        check_message_addition(rate_limiter, client, &content, false)
    }

    // Return `true` if the outcome is as expected.
    fn check_message_addition(
        rate_limiter: &mut RateLimiter,
        client: &IpAddr,
        payload: &[u8],
        should_succeed: bool,
    ) -> bool {
        let hash = sha3_256(payload);
        let msg_id = MessageId::new();
        match rate_limiter.add_message(client, &hash, &msg_id, 2, 1, payload) {
            Err(RoutingError::ExceedsRateLimit(returned_hash)) => {
                if should_succeed {
                    false
                } else {
                    assert_eq!(hash, returned_hash);
                    true
                }
            }
            Ok(returned_len) => {
                if should_succeed {
                    assert_eq!(payload.len() as u64, returned_len);
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    // Add a single `UserMessagePart` to the rate limiter.
    fn add_user_msg_part(
        rate_limiter: &mut RateLimiter,
        client: &IpAddr,
        msg: &MessageContent,
    ) -> Result<u64, RoutingError> {
        if let MessageContent::UserMessagePart {
            ref hash,
            ref msg_id,
            part_count,
            part_index,
            ref payload,
            ..
        } = *msg
        {
            rate_limiter.add_message(client, hash, msg_id, part_count, part_index, payload)
        } else {
            panic!("message is not a UserMessagePart: {:?}", msg);
        }
    }

    // Send a single `UserMessagePart` for a response to the rate limiter for refunding.
    fn refund_user_msg_part(
        rate_limiter: &mut RateLimiter,
        client: &IpAddr,
        msg: &MessageContent,
    ) -> Option<u64> {
        if let MessageContent::UserMessagePart {
            ref msg_id,
            part_count,
            part_index,
            ref payload,
            ..
        } = *msg
        {
            rate_limiter.apply_refund_for_response(client, msg_id, part_count, part_index, payload)
        } else {
            panic!("message is not a UserMessagePart: {:?}", msg);
        }
    }

    // Generate a single `UserMessagePart` for a random `GetIData` request.
    fn random_payload<R: Rng>(rng: &mut R) -> MessageContent {
        let user_message = UserMessage::Request(Request::GetIData {
            name: rng.gen(),
            msg_id: MessageId::new(),
        });
        let message_parts = unwrap!(user_message.to_parts(0));
        assert_eq!(message_parts.len(), 1);
        message_parts[0].clone()
    }

    /// Checks that a single client cannot exceed the proxy's soft limit and that its throughput is
    /// the full rate of the rate-limiter.
    #[test]
    fn single_client() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);

        // Consume full allowance.
        assert!(huge_message_can_be_added(&mut rate_limiter, &client));

        // Check client can't add any more requests just now.
        assert!(small_message_cannot_be_added(&mut rate_limiter, &client));

        // Advance the clock 1ms and check the small request can now be added, but the large request
        // is still disallowed.
        FakeClock::advance_time(1);
        assert!(small_message_can_be_added(&mut rate_limiter, &client));
        assert!(huge_message_cannot_be_added(&mut rate_limiter, &client));

        // Advance the clock enough to allow the client's entry to fully drain away. (No need to
        // round up the calculation here as we've already advanced by 1ms which is equivalent to
        // rounding up the millisecond calculation).
        let wait_millis = SOFT_CAPACITY * 1000 / RATE as u64;
        FakeClock::advance_time(wait_millis);
        assert!(huge_message_can_be_added(&mut rate_limiter, &client));
    }

    #[test]
    fn overcharge_correction() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);

        let data_size = SeededRng::new().gen_range(1, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + 1);
        let data = ImmutableData::new(vec![0; data_size as usize]);
        let msg_id = MessageId::new();

        let request = UserMessage::Request(Request::GetIData {
            name: *data.name(),
            msg_id,
        });
        let request_parts = unwrap!(request.to_parts(0));

        let charge = add_user_msg_part(&mut rate_limiter, &client, &request_parts[0]);
        assert_eq!(unwrap!(charge), MAX_IMMUTABLE_DATA_SIZE_IN_BYTES);

        let response = UserMessage::Response(Response::GetIData {
            res: Ok(data),
            msg_id,
        });
        let response_parts = unwrap!(response.to_parts(0));

        let mut single_deduction = None;

        for part in &response_parts {
            if let Some(deduction) = refund_user_msg_part(&mut rate_limiter, &client, part) {
                if single_deduction.is_none() {
                    single_deduction = Some(deduction);
                } else {
                    panic!("deduction was applied more than once!");
                }
            }
        }
        let approx_data_size = (response_parts.len() * MAX_PART_LEN) as u64;
        let expected_refund = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES.saturating_sub(approx_data_size);
        assert_eq!(single_deduction, Some(expected_refund));
    }

    #[test]
    fn prevent_msg_id_reuse_attack() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);

        // Message ID used by both the put and the get.
        let msg_id = MessageId::new();
        let put_data = ImmutableData::new(vec![0; 4]);
        let get_data = ImmutableData::new(vec![1; 10 * MAX_PART_LEN]);

        let put_request = UserMessage::Request(Request::PutIData {
            data: put_data,
            msg_id,
        });
        let put_request_parts = unwrap!(put_request.to_parts(0));
        let put_response = UserMessage::Response(Response::PutIData {
            res: Ok(()),
            msg_id,
        });
        let put_response_parts = unwrap!(put_response.to_parts(0));
        let get_request = UserMessage::Request(Request::GetIData {
            name: *get_data.name(),
            msg_id,
        });
        let get_request_parts = unwrap!(get_request.to_parts(0));
        let get_response = UserMessage::Response(Response::GetIData {
            res: Ok(get_data),
            msg_id,
        });
        let get_response_parts = unwrap!(get_response.to_parts(0));

        // Put request hits the rate limiter first.
        assert!(
            add_user_msg_part(
                &mut rate_limiter,
                &client,
                unwrap!(put_request_parts.first()),
            ).is_ok()
        );
        // Then the get request.
        assert!(
            add_user_msg_part(
                &mut rate_limiter,
                &client,
                unwrap!(get_request_parts.first()),
            ).is_ok()
        );
        // Now if the put response comes back, the proxy *should not* apply a refund for it,
        // even though it has the same message ID as the get that we just overcharged for.
        assert!(
            refund_user_msg_part(
                &mut rate_limiter,
                &client,
                unwrap!(put_response_parts.first()),
            ).is_none()
        );
        // The refund should still correctly be applied for the get response.
        assert!(
            refund_user_msg_part(
                &mut rate_limiter,
                &client,
                unwrap!(get_response_parts.first()),
            ).is_some()
        );
    }

    // Check that a duplicate get request is allowed but only receives a single refund.
    #[test]
    fn duplicate_get() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);
        let mut rng = SeededRng::new();

        let msg_id = MessageId::new();
        let data_size = rng.gen_range(1, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + 1);
        let data = ImmutableData::new(vec![0; data_size as usize]);
        let name = *data.name();

        let request = UserMessage::Request(Request::GetIData { name, msg_id });
        let request_parts = unwrap!(request.to_parts(0));
        let response = UserMessage::Response(Response::GetIData {
            res: Ok(data),
            msg_id,
        });
        let response_parts = unwrap!(response.to_parts(0));

        assert_eq!(
            unwrap!(add_user_msg_part(
                &mut rate_limiter,
                &client,
                &request_parts[0],
            )),
            MAX_IMMUTABLE_DATA_SIZE_IN_BYTES
        );
        assert_eq!(
            unwrap!(add_user_msg_part(
                &mut rate_limiter,
                &client,
                &request_parts[0],
            )),
            MAX_IMMUTABLE_DATA_SIZE_IN_BYTES
        );

        let approx_data_size = (response_parts.len() * MAX_PART_LEN) as u64;
        let expected_refund = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES.saturating_sub(approx_data_size);
        assert_eq!(
            refund_user_msg_part(&mut rate_limiter, &client, &response_parts[0]),
            Some(expected_refund)
        );
        assert!(refund_user_msg_part(&mut rate_limiter, &client, &response_parts[0]).is_none());
    }

    /// Checks that a second client can add messages even when an initial one has hit its limit.
    /// Also checks that the each client's throughput is half the full rate of the rate-limiter.
    #[test]
    fn two_clients() {
        let mut rate_limiter = RateLimiter::new(false);
        let client1 = IpAddr::from([0, 0, 0, 0]);
        let client2 = IpAddr::from([1, 1, 1, 1]);

        // First client can use up to SOFT_CAPACITY in one go.
        assert!(sized_message_can_be_added(
            SOFT_CAPACITY,
            &mut rate_limiter,
            &client1,
        ));
        // Second client can only put up to SOFT_CAPACITY / 2 in its first hit.
        assert!(sized_message_can_be_added(
            SOFT_CAPACITY / 2,
            &mut rate_limiter,
            &client2,
        ));

        // Neither can put a single byte after that.
        assert!(small_message_cannot_be_added(&mut rate_limiter, &client1));
        assert!(small_message_cannot_be_added(&mut rate_limiter, &client2));

        // Advance the clock 1ms and check the small request can now be added by Client 2.
        // Client 1 is still over its capacity.
        FakeClock::advance_time(1);
        assert!(small_message_cannot_be_added(&mut rate_limiter, &client1));
        assert!(small_message_can_be_added(&mut rate_limiter, &client2));
        assert!(large_message_cannot_be_added(&mut rate_limiter, &client1));
        assert!(large_message_cannot_be_added(&mut rate_limiter, &client2));

        // Advance the clock enough to allow SOFT_CAPACITY bytes to drain away.
        // Now client 2 should be able to add another SOFT_CAPACITY / 2.
        let wait_millis = (SOFT_CAPACITY * 1000) / RATE as u64;
        FakeClock::advance_time(wait_millis);
        assert!(sized_message_can_be_added(
            SOFT_CAPACITY / 2,
            &mut rate_limiter,
            &client2,
        ));
        assert!(sized_message_cannot_be_added(
            SOFT_CAPACITY / 2,
            &mut rate_limiter,
            &client1,
        ));
        assert!(small_message_can_be_added(&mut rate_limiter, &client1));
    }

    /// Checks that if two clients add messages with a delay between them, the rate-limiter's
    /// throughput remains constant, but the per-client throughput drops when both clients have
    /// messages and increases when just one has messages.
    #[test]
    fn staggered_start() {
        let mut rate_limiter = RateLimiter::new(false);

        // Saturate the rate limiter so that every client's cap is reduced to MIN_CLIENT_CAPACITY.
        let num_clients = (SOFT_CAPACITY as f64 / MIN_CLIENT_CAPACITY as f64).ceil() as u64;

        let clients: Vec<_> = (0..num_clients as u8)
            .map(|i| IpAddr::from([i, i, i, i]))
            .collect();

        // All clients put a message with `MIN_CLIENT_CAPACITY` bytes.
        for client in &clients {
            assert!(large_message_can_be_added(&mut rate_limiter, client));
        }

        // We wait for most of each message to drain.
        let wait_millis = (num_clients * MIN_CLIENT_CAPACITY * 900) / RATE as u64;
        FakeClock::advance_time(wait_millis);

        // A client that arrives late should only be able to put one large message.
        let late_client = IpAddr::from([255, 255, 255, 255]);
        assert!(large_message_can_be_added(&mut rate_limiter, &late_client));
        // And not a byte more.
        assert!(small_message_cannot_be_added(
            &mut rate_limiter,
            &late_client,
        ));

        // None of the saturated clients should be able to put any more large messages.
        for client in &clients {
            assert!(large_message_cannot_be_added(&mut rate_limiter, client));
        }

        // Now we wait for the remaining part of each saturating client's message to drain.
        let wait_millis = (num_clients + 2) * MIN_CLIENT_CAPACITY * 100 / RATE as u64;
        FakeClock::advance_time(wait_millis);

        // Now, the late client should only have had half its message drained but it should
        // still be able to put another message because of the soft capacity.
        assert!(large_message_can_be_added(&mut rate_limiter, &late_client));

        // All of the initial clients should be able to put large messages again too.
        for client in &clients {
            assert!(large_message_can_be_added(&mut rate_limiter, client));
        }
    }

    /// Checks that many clients can all add messages at the same rate.
    #[test]
    fn many_clients() {
        let mut rate_limiter = RateLimiter::new(false);
        let num_clients = 100;
        let num_iterations = 500;
        let mut clients_and_counts = (0..num_clients)
            .map(|i| (IpAddr::from([i, i, i, i]), 0))
            .collect::<BTreeMap<_, _>>();
        let mut rng = SeededRng::new();

        let start = FakeClock::now();
        let mut elapsed_time: f64 = 0.0;
        let mut offset: u64 = 0;
        for i in 0..num_iterations {
            if elapsed_time > 0.0 {
                let per_client_leak = (elapsed_time * RATE / num_clients as f64) as u64;
                let per_client_used = *unwrap!(rate_limiter.used.values().nth(0));
                if per_client_leak > per_client_used {
                    offset += (per_client_leak - per_client_used) * num_clients as u64;
                }
            }
            // Each client tries to add a large request and increments its count on success.
            for (client, count) in &mut clients_and_counts {
                let payload = random_payload(&mut rng);
                if add_user_msg_part(&mut rate_limiter, client, &payload).is_ok() {
                    *count += 1;
                }
            }
            if i != num_iterations - 1 {
                let elapse = rng.gen_range(500, 1500);
                FakeClock::advance_time(elapse);
                elapsed_time = elapse as f64 / 1E3;
            }
        }

        // Check that all clients have managed to add the same number of messages.
        let elapsed = FakeClock::now() - start;
        let advanced_secs = elapsed.as_secs() as f64 + elapsed.subsec_nanos() as f64 / 1E9;
        let numerator = MIN_CLIENT_CAPACITY as f64 * num_clients as f64 + advanced_secs * RATE -
            offset as f64;
        let denominator = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as f64 * num_clients as f64;
        let success_count = (numerator / denominator) as u64;
        for count in clients_and_counts.values() {
            assert_eq!(*count, success_count);
        }
    }

    /// Checks that invalid messages are handled correctly.
    #[test]
    fn invalid_messages() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);
        let mut rng = SeededRng::new();

        // Parses with `SerialisationError::DeserialiseExtraBytes` error.
        let mut msg_id = MessageId::new();
        let mut payload = vec![0; MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as usize];
        match rate_limiter.add_message(&client, &sha3_256(&payload), &msg_id, 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses with other serialisation error and part count is 1.
        payload = vec![0];
        match rate_limiter.add_message(&client, &sha3_256(&payload), &msg_id, 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses successfully but claims to be part 1 of 2.
        let mut msg = UserMessage::Request(Request::GetIData {
            name: rng.gen(),
            msg_id: MessageId::new(),
        });
        payload = unwrap!(serialisation::serialise(&msg));
        match rate_limiter.add_message(&client, &sha3_256(&payload), &msg_id, 2, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses as a refresh request.
        msg = UserMessage::Request(Request::Refresh(vec![0], MessageId::new()));
        msg_id = *msg.message_id();
        payload = unwrap!(serialisation::serialise(&msg));
        match rate_limiter.add_message(&client, &sha3_256(&payload), &msg_id, 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }

        // Parses as a response.
        msg = UserMessage::Response(Response::PutIData {
            res: Ok(()),
            msg_id: MessageId::new(),
        });
        msg_id = *msg.message_id();
        payload = unwrap!(serialisation::serialise(&msg));
        match rate_limiter.add_message(&client, &sha3_256(&payload), &msg_id, 1, 0, &payload) {
            Err(RoutingError::InvalidMessage) => {}
            _ => panic!("unexpected result"),
        }
    }

    /// Checks that the rate-limiter's `overcharged` container can't be over-filled.
    ///
    /// Keeps trying to add GET requests for `ImmutableData` with a short delay between each
    /// attempt. Most will fail, but this should ensure the `RateLimiter` always has an entry for
    /// this client in its `used` container (in case we go back to using the absence of a client as
    /// a trigger to purge their overcharged entries).
    ///
    /// After `OVERCHARGED_TIMEOUT_SECS` plus one minute has elapsed, there should not be an
    /// excessive number of entries in the `overcharged` container.
    #[test]
    fn overcharged_limit() {
        let mut rate_limiter = RateLimiter::new(false);
        let client = IpAddr::from([0, 0, 0, 0]);
        let wait_millis = MAX_IMMUTABLE_DATA_SIZE_IN_BYTES * 100 / RATE as u64;
        // Note: we add 1 here because the last request added doesn't have to fully drain before
        // the test ends.
        let max_overcharged_entries = OVERCHARGED_TIMEOUT_SECS * RATE as u64 /
            MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + 1;
        let finish_time = FakeClock::now() + Duration::from_secs(OVERCHARGED_TIMEOUT_SECS + 60);
        while FakeClock::now() < finish_time {
            let name = XorName([0; XOR_NAME_LEN]);
            let msg_id = MessageId::new();
            let request = UserMessage::Request(Request::GetIData { name, msg_id });
            let request_parts = unwrap!(request.to_parts(0));
            let _ = add_user_msg_part(&mut rate_limiter, &client, &request_parts[0]);
            FakeClock::advance_time(wait_millis);
        }
        let overcharged_entries = rate_limiter.overcharged.len() as u64;
        assert!(
            overcharged_entries == max_overcharged_entries ||
                overcharged_entries == max_overcharged_entries - 1
        );
    }
}

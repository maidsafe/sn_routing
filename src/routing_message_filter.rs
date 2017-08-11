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

use id::PublicId;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::serialise;
use message_filter::MessageFilter;
use messages::RoutingMessage;
use sha3;
use std::time::Duration;
use tiny_keccak::sha3_256;

const INCOMING_EXPIRY_DURATION_SECS: u64 = 60 * 20;
const OUTGOING_EXPIRY_DURATION_SECS: u64 = 60 * 10;

/// An enum representing a result of message filtering
#[derive(Eq, PartialEq)]
pub enum FilteringResult {
    /// We don't have the message in the filter yet
    NewMessage,
    /// We have the message in the filter, but it was sent on a different route
    KnownMessage,
    /// We have already seen this message on this route
    KnownMessageAndRoute,
}

// Structure to filter (throttle) incoming and outgoing `RoutingMessages`.
pub struct RoutingMessageFilter {
    incoming: MessageFilter<RoutingMessage>,
    incoming_route: MessageFilter<(RoutingMessage, u8)>,
    outgoing: LruCache<(sha3::Digest256, PublicId, u8), ()>,
}

impl RoutingMessageFilter {
    pub fn new() -> Self {
        let incoming_duration = Duration::from_secs(INCOMING_EXPIRY_DURATION_SECS);
        let outgoing_duration = Duration::from_secs(OUTGOING_EXPIRY_DURATION_SECS);

        RoutingMessageFilter {
            incoming: MessageFilter::with_expiry_duration(incoming_duration),
            incoming_route: MessageFilter::with_expiry_duration(incoming_duration),
            outgoing: LruCache::with_expiry_duration(outgoing_duration),
        }
    }

    // Filter incoming `RoutingMessage`. Return the number of times this specific message has been
    // seen, including this time.
    // TODO - refactor to avoid cloning `msg` as `MessageFilter` only holds the hash of the tuple.
    pub fn filter_incoming(&mut self, msg: &RoutingMessage, route: u8) -> FilteringResult {
        let known_msg = self.incoming.insert(msg) > 1;
        let known_msg_rt = self.incoming_route.insert(&(msg.clone(), route)) > 1;
        match (known_msg, known_msg_rt) {
            (false, false) => FilteringResult::NewMessage,
            (true, false) => FilteringResult::KnownMessage,
            (_, true) => FilteringResult::KnownMessageAndRoute,
        }
    }

    // Filter outgoing `RoutingMessage`. Return whether this specific message has been seen recently
    // (and thus should not be sent, due to deduplication).
    //
    // Return `false` if serialisation of the message fails - that can be handled elsewhere.
    pub fn filter_outgoing(&mut self, msg: &RoutingMessage, pub_id: &PublicId, route: u8) -> bool {
        if let Ok(msg_bytes) = serialise(msg) {
            let hash = sha3_256(&msg_bytes);
            self.outgoing.insert((hash, *pub_id, route), ()).is_some()
        } else {
            trace!("Tried to filter oversized routing message: {:?}", msg);
            false
        }
    }

    // Removes the given message from the outgoing filter if it exists.
    pub fn remove_from_outgoing_filter(
        &mut self,
        msg: &RoutingMessage,
        pub_id: &PublicId,
        route: u8,
    ) {
        if let Ok(msg_bytes) = serialise(msg) {
            let hash = sha3_256(&msg_bytes);
            let _ = self.outgoing.remove(&(hash, *pub_id, route));
        }
    }
}

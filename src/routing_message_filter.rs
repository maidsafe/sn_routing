// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::PublicId;
use crate::message_filter::MessageFilter;
use crate::messages::RoutingMessage;
use lru_time_cache::LruCache;
use maidsafe_utilities::serialisation::serialise;
use safe_crypto;
use serde::Serialize;
use std::fmt::Debug;
use std::time::Duration;

type Digest = [u8; 32];

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
    incoming: MessageFilter<Digest>,
    incoming_route: MessageFilter<(Digest, u8)>,
    outgoing: LruCache<(Digest, PublicId, u8), ()>,
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
    pub fn filter_incoming(&mut self, msg: &RoutingMessage, route: u8) -> FilteringResult {
        let hash = match hash(msg) {
            Some(hash) => hash,
            None => return FilteringResult::NewMessage,
        };
        let known_msg = self.incoming.insert(&hash) > 1;
        let known_msg_rt = self.incoming_route.insert(&(hash, route)) > 1;
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
        hash(msg).map_or(false, |hash| {
            self.outgoing.insert((hash, *pub_id, route), ()).is_some()
        })
    }

    // Removes the given message from the outgoing filter if it exists.
    pub fn remove_from_outgoing_filter(
        &mut self,
        msg: &RoutingMessage,
        pub_id: &PublicId,
        route: u8,
    ) {
        if let Some(hash) = hash(msg) {
            let _ = self.outgoing.remove(&(hash, *pub_id, route));
        }
    }
}

impl Default for RoutingMessageFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn hash<T: Serialize + Debug>(msg: &T) -> Option<Digest> {
    if let Ok(msg_bytes) = serialise(msg) {
        Some(safe_crypto::hash(&msg_bytes))
    } else {
        trace!("Tried to filter oversized routing message: {:?}", msg);
        None
    }
}

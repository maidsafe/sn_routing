// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{crypto, id::PublicId, message_filter::MessageFilter, messages::Message};
use bytes::Bytes;
use lru_time_cache::LruCache;
use std::time::Duration;

type Digest = [u8; 32];

const INCOMING_EXPIRY_DURATION_SECS: u64 = 60 * 20;
const OUTGOING_EXPIRY_DURATION_SECS: u64 = 60 * 10;

/// An enum representing a result of message filtering
#[derive(Eq, PartialEq)]
pub enum FilteringResult {
    /// We don't have the message in the filter yet
    NewMessage,
    /// We have the message in the filter
    KnownMessage,
}

impl FilteringResult {
    pub fn is_new(&self) -> bool {
        match self {
            Self::NewMessage => true,
            Self::KnownMessage => false,
        }
    }
}

// Structure to filter (throttle) incoming and outgoing `RoutingMessages`.
pub struct RoutingMessageFilter {
    incoming: MessageFilter<Digest>,
    outgoing: LruCache<(Digest, PublicId), ()>,
}

impl RoutingMessageFilter {
    pub fn new() -> Self {
        let incoming_duration = Duration::from_secs(INCOMING_EXPIRY_DURATION_SECS);
        let outgoing_duration = Duration::from_secs(OUTGOING_EXPIRY_DURATION_SECS);

        Self {
            incoming: MessageFilter::with_expiry_duration(incoming_duration),
            outgoing: LruCache::with_expiry_duration(outgoing_duration),
        }
    }

    // Filter incoming `RoutingMessage`. Return whether this specific message has already been seen.
    pub fn filter_incoming(&mut self, msg: &Message) -> FilteringResult {
        let hash = hash(&msg.inner().to_network_bytes().unwrap()); // FIXME

        if self.incoming.insert(&hash) > 1 {
            FilteringResult::KnownMessage
        } else {
            FilteringResult::NewMessage
        }
    }

    // Filter outgoing `RoutingMessage`. Return whether this specific message has been seen recently
    // (and thus should not be sent, due to deduplication).
    //
    // Return `KnownMessage` also if hashing the message fails - that can be handled elsewhere.
    pub fn filter_outgoing(&mut self, msg: &Message, pub_id: &PublicId) -> FilteringResult {
        let hash = hash(&msg.inner().to_network_bytes().unwrap()); // FIXME

        if self.outgoing.insert((hash, *pub_id), ()).is_some() {
            FilteringResult::KnownMessage
        } else {
            FilteringResult::NewMessage
        }
    }
}

impl Default for RoutingMessageFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn hash(msg_bytes: &Bytes) -> Digest {
    crypto::sha3_256(msg_bytes)
}

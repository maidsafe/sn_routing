// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    id::PublicId,
    location::DstLocation,
    messages::{MessageHash, MessageWithBytes},
};
use lru_time_cache::LruCache;
use std::time::Duration;

const INCOMING_EXPIRY_DURATION: Duration = Duration::from_secs(20 * 60);
const OUTGOING_EXPIRY_DURATION: Duration = Duration::from_secs(10 * 60);

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

// Structure to filter (throttle) incoming and outgoing messages.
pub struct MessageFilter {
    incoming: LruCache<MessageHash, ()>,
    outgoing: LruCache<(MessageHash, PublicId), ()>,
}

impl MessageFilter {
    pub fn new() -> Self {
        Self {
            incoming: LruCache::with_expiry_duration(INCOMING_EXPIRY_DURATION),
            outgoing: LruCache::with_expiry_duration(OUTGOING_EXPIRY_DURATION),
        }
    }

    pub fn contains_incoming(&self, msg: &MessageWithBytes) -> bool {
        self.incoming.contains_key(msg.full_crypto_hash())
    }

    pub fn insert_incoming(&mut self, msg: &MessageWithBytes) {
        // Not filtering direct messages.
        if let DstLocation::Direct = msg.message_dst() {
            return;
        }

        let _ = self.incoming.insert(*msg.full_crypto_hash(), ());
    }

    // Filter outgoing `RoutingMessage`. Return whether this specific message has been seen recently
    // (and thus should not be sent, due to deduplication).
    //
    // Return `KnownMessage` also if hashing the message fails - that can be handled elsewhere.
    pub fn filter_outgoing(
        &mut self,
        msg: &MessageWithBytes,
        pub_id: &PublicId,
    ) -> FilteringResult {
        // Not filtering direct messages.
        if let DstLocation::Direct = msg.message_dst() {
            return FilteringResult::NewMessage;
        }

        let hash = msg.full_crypto_hash();

        if self.outgoing.insert((*hash, *pub_id), ()).is_some() {
            FilteringResult::KnownMessage
        } else {
            FilteringResult::NewMessage
        }
    }
}

impl Default for MessageFilter {
    fn default() -> Self {
        Self::new()
    }
}

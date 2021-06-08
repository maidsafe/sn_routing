// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::cache::Cache;
use sn_messaging::{node::RoutingMsg, DstLocation, MessageId};
use std::time::Duration;
use xor_name::XorName;

const INCOMING_EXPIRY_DURATION: Duration = Duration::from_secs(20 * 60);
const OUTGOING_EXPIRY_DURATION: Duration = Duration::from_secs(10 * 60);
const MAX_ENTRIES: usize = 15_000;

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
pub(crate) struct MessageFilter {
    incoming: Cache<MessageId, ()>,
    outgoing: Cache<(MessageId, XorName), ()>,
}

impl MessageFilter {
    pub fn new() -> Self {
        Self {
            incoming: Cache::with_expiry_duration_and_capacity(
                INCOMING_EXPIRY_DURATION,
                MAX_ENTRIES,
            ),
            outgoing: Cache::with_expiry_duration_and_capacity(
                OUTGOING_EXPIRY_DURATION,
                MAX_ENTRIES,
            ),
        }
    }

    // Filter outgoing `SNRoutingMessage`. Return whether this specific message has been seen recently
    // (and thus should not be sent, due to deduplication).
    //
    pub async fn filter_outgoing(&self, msg: &RoutingMsg, pub_id: &XorName) -> FilteringResult {
        // Not filtering direct messages.
        if let DstLocation::DirectAndUnrouted = msg.dst {
            return FilteringResult::NewMessage;
        }

        if self
            .outgoing
            .set((msg.id, *pub_id), (), None)
            .await
            .is_some()
        {
            trace!("Outgoing message filtered: {:?}", msg.id);
            FilteringResult::KnownMessage
        } else {
            FilteringResult::NewMessage
        }
    }

    // Returns `true` if not already having it.
    pub async fn add_to_filter(&self, msg_id: &MessageId) -> bool {
        let cur_value = self.incoming.set(*msg_id, (), None).await;

        if cur_value.is_some() {
            trace!("Incoming message filtered: {:?}", msg_id);
        }

        cur_value.is_none()
    }

    // Resets both incoming and outgoing filters.
    pub async fn reset(&mut self) {
        self.incoming.clear().await;
        self.outgoing.clear().await;
    }
}

impl Default for MessageFilter {
    fn default() -> Self {
        Self::new()
    }
}

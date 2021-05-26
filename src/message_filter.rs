// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use lru_time_cache::LruCache;
use sn_messaging::MessageId;
use std::time::Duration;

const INCOMING_EXPIRY_DURATION: Duration = Duration::from_secs(20 * 60);
const MAX_ENTRIES: usize = 5_000;

// Structure to filter (throttle) incoming and outgoing messages.
pub(crate) struct MessageFilter {
    incoming: LruCache<MessageId, ()>,
}

impl MessageFilter {
    pub fn new() -> Self {
        Self {
            incoming: LruCache::with_expiry_duration_and_capacity(
                INCOMING_EXPIRY_DURATION,
                MAX_ENTRIES,
            ),
        }
    }

    pub fn contains_incoming(&mut self, msg_id: &MessageId) -> bool {
        let cur_value = self.incoming.insert(*msg_id, ());
        cur_value.is_some()
    }

    // Resets both incoming and outgoing filters.
    pub fn reset(&mut self) {
        self.incoming.clear();
    }
}

impl Default for MessageFilter {
    fn default() -> Self {
        Self::new()
    }
}

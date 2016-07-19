// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::collections::HashMap;
use std::time::Duration;

use message_filter::MessageFilter;
use messages::RoutingMessage;

/// Time (in seconds) after which a message is resent due to being unacknowledged by recipient.
pub const ACK_TIMEOUT_SECS: u64 = 20;

const EXPIRY_DURATION_SECS: u64 = 4 * 60;

/// A copy of a message which has been sent and is pending the ack from the recipient.
#[derive(Clone, Debug)]
pub struct UnacknowledgedMessage {
    pub routing_msg: RoutingMessage,
    pub route: u8,
    pub timer_token: u64,
}

pub struct AckManager {
    pending: HashMap<u64, UnacknowledgedMessage>,
    received: MessageFilter<u64>,
}

impl AckManager {
    pub fn new() -> Self {
        let expiry_duration = Duration::from_secs(EXPIRY_DURATION_SECS);

        AckManager {
            pending: HashMap::new(),
            received: MessageFilter::with_expiry_duration(expiry_duration),
        }
    }

    // Handle received ack.
    pub fn receive(&mut self, ack: u64) {
        if self.pending.remove(&ack).is_none() {
            let _ = self.received.insert(&ack);
        }
    }

    pub fn did_receive(&mut self, ack: u64) -> bool {
        self.received.contains(&ack)
    }

    pub fn add_to_pending(&mut self,
                          ack: u64,
                          unacked_msg: UnacknowledgedMessage)
                          -> Option<UnacknowledgedMessage> {
        self.pending.insert(ack, unacked_msg)
    }

    // Find a timed out unacknowledged message corresponding to the given timer token.
    // If such message exists, returns it with the corresponding ack hash. Otherwise
    // returns None.
    pub fn find_timed_out(&mut self, token: u64) -> Option<(UnacknowledgedMessage, u64)> {
        let timed_out_ack = if let Some((sip_hash, _)) = self.pending
            .iter()
            .find(|&(_, ref unacked_msg)| unacked_msg.timer_token == token) {
            *sip_hash
        } else {
            return None;
        };

        // Safe to use `unwrap!()` here as we just got a valid key in the `find` call above.
        let mut unacked_msg = unwrap!(self.pending.remove(&timed_out_ack));
        unacked_msg.route += 1;

        Some((unacked_msg, timed_out_ack))
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn timer_tokens(&self) -> Vec<u64> {
        self.pending
            .iter()
            .map(|(_, unacked_msg)| unacked_msg.timer_token)
            .collect::<Vec<_>>()
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn clear(&mut self) {
        self.received.clear()
    }
}

// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use error::RoutingError;
use maidsafe_utilities::serialisation;
use message_filter::MessageFilter;
use messages::RoutingMessage;
use sha3;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

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
    pending: HashMap<Ack, UnacknowledgedMessage>,
    received: MessageFilter<Ack>,
}

/// An identifier for a waiting-to-be-acknowledged message (a hash of the message).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, RustcDecodable, RustcEncodable)]
pub struct Ack {
    m_hash: [u8; 32],
}

impl AckManager {
    /// Creates a new manager, with empty lists.
    pub fn new() -> Self {
        let expiry_duration = Duration::from_secs(EXPIRY_DURATION_SECS);

        AckManager {
            pending: HashMap::new(),
            received: MessageFilter::with_expiry_duration(expiry_duration),
        }
    }

    /// Handles a received ack (removes the corresponding message from the list of
    /// pending ones, and remembers that we have received this ack).
    pub fn receive(&mut self, ack: Ack) {
        let _ack = self.pending
            .remove(&ack)
            .ok_or_else(|| debug!("received an Ack we were not expecting : {}", ack));
        // TODO - Should this insert an ack we were not expecting ??
        let count = self.received.insert(&ack);
        trace!("Received ack {} : {} times", ack, count);
    }

    /// Did we receive this ack?
    pub fn did_receive(&mut self, ack: Ack) -> bool {
        self.received.contains(&ack)
    }

    /// Adds a pending message; if another with the same `Ack` identifier exists,
    /// this is removed and returned.
    pub fn add_to_pending(&mut self,
                          ack: Ack,
                          unacked_msg: UnacknowledgedMessage)
                          -> Option<UnacknowledgedMessage> {
        self.pending.insert(ack, unacked_msg)
    }

    // Find a timed out unacknowledged message corresponding to the given timer token.
    // If such message exists, returns it with the corresponding ack hash. Otherwise
    // returns None.
    pub fn find_timed_out(&mut self, token: u64) -> Option<(UnacknowledgedMessage, Ack)> {
        let timed_out_ack = if let Some((sip_hash, _)) =
            self.pending
                .iter()
                .find(|&(_, unacked_msg)| unacked_msg.timer_token == token) {
            *sip_hash
        } else {
            return None;
        };

        // Safe to use `unwrap!()` here as we just got a valid key in the `find` call above.
        let mut unacked_msg = unwrap!(self.pending.remove(&timed_out_ack));
        unacked_msg.route += 1;

        Some((unacked_msg, timed_out_ack))
    }
}

#[cfg(feature = "use-mock-crust")]
impl AckManager {
    /// Are we waiting for any acks?
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Collects all time-out tokens.
    pub fn timer_tokens(&self) -> Vec<u64> {
        self.pending
            .iter()
            .map(|(_, unacked_msg)| unacked_msg.timer_token)
            .collect::<Vec<_>>()
    }

    pub fn clear(&mut self) {
        self.received.clear()
    }
}

impl Ack {
    /// Compute an `Ack` from a message.
    pub fn compute(routing_msg: &RoutingMessage) -> Result<Ack, RoutingError> {
        let hash_msg = serialisation::serialise(routing_msg)?;
        Ok(Ack { m_hash: sha3::hash(&hash_msg) })
    }
}

impl fmt::Display for Ack {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter,
               "hash : {:02x}{:02x}..",
               self.m_hash[0],
               self.m_hash[1])
    }
}

impl fmt::Debug for Ack {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter,
               "Ack(hash : {:02X}{:02X}..)",
               self.m_hash[0],
               self.m_hash[1])
    }
}

// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A system for dispatching `Event`s and possibly in the future other message types.
//!
//! The design allows the separate traits to handle dispatching of each type of message to an
//! object handling the appropriate types of message.

use crate::event::Event;
use std::collections::VecDeque;
use std::default::Default;

/// An event dispatcher. Collects things to deliver and "sends".
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
pub trait EventBox {
    /// Send an event
    fn send_event(&mut self, event: Event);
}

/// Implementor of `EventBox`; stores its events in a `VecDeque`.
#[derive(Default)]
pub struct EventBuf {
    events: VecDeque<Event>,
}

impl EventBox for EventBuf {
    fn send_event(&mut self, event: Event) {
        self.events.push_back(event)
    }
}

impl EventBuf {
    /// Create an empty box
    pub fn new() -> Self {
        Default::default()
    }

    /// Take the first Event, if any is stored.
    pub fn take_first(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Extract the list of events (swapping in an empty list)
    #[cfg(all(test, feature = "mock_base"))]
    pub fn take_all(&mut self) -> VecDeque<Event> {
        std::mem::replace(&mut self.events, Default::default())
    }
}

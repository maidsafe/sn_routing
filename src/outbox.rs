// Copyright 2017 MaidSafe.net limited.
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

//! A system for dispatching `Event`s and possibly in the future other message types.
//!
//! The design allows the separate traits to handle dispatching of each type of message to an
//! object handling the appropriate types of message.

use event::Event;
use std::collections::VecDeque;
use std::default::Default;
use std::mem;


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
    pub fn take_all(&mut self) -> VecDeque<Event> {
        mem::replace(&mut self.events, Default::default())
    }
}

impl Drop for EventBuf {
    fn drop(&mut self) {
        if !self.events.is_empty() {
            error!("EventBox dropped events: {:?}", self.events);
        }
    }
}

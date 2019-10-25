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
use crossbeam_channel::Sender;

/// An event dispatcher. Collects things to deliver and "sends".
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
pub trait EventBox {
    /// Send an event
    fn send_event(&mut self, event: Event);
}

/// Implementor of `EventBox`; sends its events through an mpmc channel.
impl EventBox for Sender<Event> {
    fn send_event(&mut self, event: Event) {
        let _ = self.send(event);
    }
}

/// Stream events into a Vec.
impl EventBox for Vec<Event> {
    fn send_event(&mut self, event: Event) {
        self.push(event);
    }
}

/// Empty sink for events.
impl EventBox for () {
    fn send_event(&mut self, _event: Event) {}
}

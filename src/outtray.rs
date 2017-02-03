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

// The original design was like this:
//
// pub trait EventTray {
//     fn send_event(&mut self, event: Event);
//     fn send_events(&mut self, events: Vec<Event>);
// }
// pub trait MessageTray {
//     fn send_msg(&mut self, msg: Message);
//     fn send_msgs(&mut self, msgs: Vec<Message>);
// }
// pub trait OutTray: EventTray + MessageTray {}
//
// pub struct EventBox { ... }
// impl EventBox { ... }
// impl EventTray for OutBox { ... }
//
// pub struct OutBox { ... }
// impl OutBox { ... }
// impl EventTray for OutBox { ... }
// impl MessageTray for OutBox { ... }
// impl OutTray for OutBox { ... }

use event::Event;
use std::default::Default;
use std::mem;


/// An event dispatcher. Collects things to deliver and "sends".
///
/// For now, this is a struct (to enable static dispatch). The design allows switching this to a
/// trait, updating only a few functions which use it at the top level.
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
#[derive(Default)]
pub struct EventTray {
    events: Vec<Event>,
}

impl EventTray {
    /// Send an event
    pub fn send_event(&mut self, event: Event) {
        self.events.push(event)
    }

    /// Send a `Vec` of events
    pub fn send_events(&mut self, events: Vec<Event>) {
        self.events.extend(events)
    }

    /// Create an empty box
    pub fn new() -> Self {
        Default::default()
    }

    /// Extract the list of events (swapping in an empty list)
    pub fn take_events(&mut self) -> Vec<Event> {
        mem::replace(&mut self.events, vec![])
    }
}

impl Drop for EventTray {
    fn drop(&mut self) {
        if !self.events.is_empty() {
            error!("EventTray dropped events: {:?}", self.events);
        }
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::event::Event;
use std::fmt::{self, Debug, Formatter};
use tokio::sync::mpsc;
/// Stream of routing node events
pub struct EventStream {
    events_rx: mpsc::Receiver<Event>,
}

impl EventStream {
    pub(crate) fn new(events_rx: mpsc::Receiver<Event>) -> Self {
        Self { events_rx }
    }

    /// Returns next event
    pub async fn next(&mut self) -> Option<Event> {
        self.events_rx.recv().await
    }
}

impl Debug for EventStream {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "EventStream")
    }
}

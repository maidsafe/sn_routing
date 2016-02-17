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

use std::thread;
use std::time::Duration;

use action::Action;
use types::RoutingActionSender;

/// Simple timer.
pub struct Timer {
    sender: RoutingActionSender,
    next_token: u64,
}

impl Timer {
    /// Create new timer passing a sender used to send Timeout events.
    pub fn new(sender: RoutingActionSender) -> Self {
        Timer {
            sender: sender,
            next_token: 0,
        }
    }

    /// Schedule a timeout event after `duration`. Returns a token that can be
    /// used to identify the timeout event.
    pub fn schedule(&mut self, duration: Duration) -> u64 {
        let sender = self.sender.clone();
        let token  = self.next_token();

        let _ = thread::spawn(move || {
            thread::sleep(duration);
            let _ = sender.send(Action::Timeout(token));
        });

        token
    }

    fn next_token(&mut self) -> u64 {
        let token = self.next_token;
        self.next_token += 1;
        token
    }
}

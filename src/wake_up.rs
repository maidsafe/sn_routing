// Copyright 2015 MaidSafe.net limited.
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

use std::sync::mpsc;
use std::thread::spawn;
use std::thread;

use action::Action;

pub struct WakeUpCaller {
    action_sender: mpsc::Sender<Action>,
}

impl WakeUpCaller {
    pub fn new(action_sender: mpsc::Sender<Action>) -> WakeUpCaller {
        WakeUpCaller { action_sender: action_sender }
    }

    pub fn start(&self, sleep_duration: u32) {
        let action_sender_clone = self.action_sender.clone();
        spawn(move || {
                       loop {
                           thread::sleep_ms(sleep_duration);
                           match action_sender_clone.send(Action::WakeUp) {
                               Ok(_) => {}
                               Err(_) => {
                                   debug!("Failed to send Action::WakeUp. Stopped WakeUpCaller.");
                                   break;
                               }
                           };
                       }
                   });
    }

    // TODO (ben 16/08/2015) implement stop
}

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

// TODO: consider moving this module to the maidsafe_utilities crate, or to a
// completely separate crate.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub enum RecvWithTimeoutError {
    Disconnected,
    Timeout,
}

/// Blocks until something is received on the `Receiver`, or timeout, whichever happens sooner.
// TODO: Deny this lint again once `elapsed += interval` works with Rust stable.
pub fn recv_with_timeout<T>(receiver: &Receiver<T>,
                            timeout: Duration)
                            -> Result<T, RecvWithTimeoutError> {
    let interval = Duration::from_millis(100);
    let mut elapsed = Duration::from_millis(0);

    loop {
        match receiver.try_recv() {
            Ok(value) => return Ok(value),
            Err(TryRecvError::Disconnected) => return Err(RecvWithTimeoutError::Disconnected),
            Err(TryRecvError::Empty) => {
                thread::sleep(interval);
                elapsed += interval;

                if elapsed > timeout {
                    return Err(RecvWithTimeoutError::Timeout);
                }
            }
        }
    }
}

/// Keep receiving on the receiver until it closes or timeout occurs.
#[allow(unused)]
pub fn iter_with_timeout<T>(receiver: &Receiver<T>, timeout: Duration) -> Iter<T> {
    Iter {
        rx: receiver,
        timeout: timeout,
    }
}

#[allow(unused)]
pub struct Iter<'a, T: 'a> {
    rx: &'a Receiver<T>,
    timeout: Duration,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        recv_with_timeout(self.rx, self.timeout).ok()
    }
}

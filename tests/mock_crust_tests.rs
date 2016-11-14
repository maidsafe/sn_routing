// copyright 2016 maidsafe.net limited.
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

#![cfg(feature = "use-mock-crust")]

extern crate itertools;
#[macro_use]
extern crate log;
extern crate rand;
extern crate routing;
#[macro_use]
extern crate unwrap;
extern crate maidsafe_utilities;

// This module is a driver and defines macros. See `mock_crust` modules for
// tests.

/// Expect that the next event raised by the node matches the given pattern.
/// Panics if no event, or an event that does not match the pattern is raised.
/// (ignores ticks).
macro_rules! expect_next_event {
    ($node:expr, $pattern:pat) => {
        loop {
            match $node.event_rx.try_recv() {
                Ok($pattern) => break,
                Ok(Event::Tick) => (),
                other => panic!("Expected Ok({}) at {}, got {:?}",
                    stringify!($pattern),
                    unwrap!($node.inner.name()),
                    other),
            }
        }
    }
}

/// Expects that any event raised by the node matches the given pattern
/// (with optional pattern guard). Ignores events that do not match the pattern.
/// Panics if the event channel is exhausted before matching event is found.
macro_rules! expect_any_event {
    ($node:expr, $pattern:pat) => {
        expect_any_event!($node, $pattern if true => ())
    };
    ($node:expr, $pattern:pat if $guard:expr) => {
        loop {
            match $node.event_rx.try_recv() {
                Ok($pattern) if $guard => break,
                Ok(_) => (),
                other => panic!("Expected Ok({}) at {}, got {:?}",
                    stringify!($pattern),
                    unwrap!($node.inner.name()),
                    other),
            }
        }
    }
}

/// Expects that the node raised no event, panics otherwise (ignores ticks).
macro_rules! expect_no_event {
    ($node:expr) => {
        match $node.event_rx.try_recv() {
            Ok(Event::Tick) => (),
            Err(mpsc::TryRecvError::Empty) => (),
            other => panic!("Expected no event at {}, got {:?}",
                unwrap!($node.inner.name()),
                other),
        }
    }
}

mod mock_crust;

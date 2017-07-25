// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::sync::mpsc::{RecvError, TryRecvError};

/// Trait to fake a channel.
pub trait EventStream {
    /// Item produced by this stream.
    type Item;

    /// Read the next available event from the stream, blocking until one becomes available.
    fn next_ev(&mut self) -> Result<Self::Item, RecvError>;

    /// Try to read the next available event from the stream without blocking.
    ///
    /// Implementations should return an error if there are no items available, OR
    /// a real error occurs.
    fn try_next_ev(&mut self) -> Result<Self::Item, TryRecvError>;

    /// Process events, storing them on the internal buffer.
    ///
    /// After calling poll, any events produced will be accessible via `next_ev` and `try_next_ev`.
    fn poll(&mut self) -> bool;
}

/// Trait for state machines and other event producers who produce multiple events at once.
pub trait EventStepper {
    type Item;

    /// Produce multiple events and store them internally, or return a `RecvError` if
    /// something goes wrong.
    fn produce_events(&mut self) -> Result<(), RecvError>;

    // Produce multiple events in a non-blocking fashion.
    fn try_produce_events(&mut self) -> Result<(), TryRecvError>;

    /// Pop an item from this type's internal buffer.
    fn pop_item(&mut self) -> Option<Self::Item>;
}

/// Blanket implementation of `EventStream` for types implementing `EventStepper`.
impl<S> EventStream for S
where
    S: EventStepper,
{
    type Item = <S as EventStepper>::Item;

    fn next_ev(&mut self) -> Result<Self::Item, RecvError> {
        // We loop blocking on `produce_events` until an event is produced.
        loop {
            if let Some(cached_ev) = self.pop_item() {
                return Ok(cached_ev);
            }

            match self.produce_events() {
                Ok(()) => {}
                Err(RecvError) => return Err(RecvError),
            }
        }
    }

    fn try_next_ev(&mut self) -> Result<Self::Item, TryRecvError> {
        if let Some(cached_ev) = self.pop_item() {
            return Ok(cached_ev);
        }
        match self.try_produce_events() {
            Ok(()) => {
                self.pop_item().ok_or(TryRecvError::Empty)
            }
            Err(err) => Err(err),
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;
        while Ok(()) == self.try_produce_events() {
            result = true;
        }
        result
    }
}

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

    /// Produce multiple events and return them, or a `RecvError` if something goes wrong.
    fn produce_events(&mut self) -> Result<Vec<Self::Item>, RecvError>;

    // Produce multiple events in a non-blocking fashion.
    fn try_produce_events(&mut self) -> Result<Vec<Self::Item>, TryRecvError>;

    /// Pop an item from this type's internal buffer.
    fn pop_item(&mut self) -> Option<Self::Item>;

    /// Push items to this type's internal buffer.
    fn buffer_items(&mut self, items: Vec<Self::Item>);
}

/// Blanket implementation of `EventStream` for types implementing `EventStepper`.
impl<S> EventStream for S
    where S: EventStepper
{
    type Item = <S as EventStepper>::Item;

    fn next_ev(&mut self) -> Result<Self::Item, RecvError> {
        // We loop blocking on `produce_events` until an event is produced.
        loop {
            if let Some(cached_ev) = self.pop_item() {
                return Ok(cached_ev);
            }

            match self.produce_events() {
                Ok(new_events) => self.buffer_items(new_events),
                Err(RecvError) => return Err(RecvError),
            }
        }
    }

    fn try_next_ev(&mut self) -> Result<Self::Item, TryRecvError> {
        if let Some(cached_ev) = self.pop_item() {
            return Ok(cached_ev);
        }
        match self.try_produce_events() {
            Ok(new_events) => {
                self.buffer_items(new_events);
                self.pop_item().ok_or(TryRecvError::Empty)
            }
            Err(err) => Err(err),
        }
    }

    fn poll(&mut self) -> bool {
        let mut result = false;
        while let Ok(new_events) = self.try_produce_events() {
            self.buffer_items(new_events);
            result = true;
        }
        result
    }
}

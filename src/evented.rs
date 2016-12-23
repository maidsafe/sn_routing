use event::Event;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::mem;

/// A version of `try!` that returns an `Evented<Result>` if its `Result` argument is `Err`.
#[macro_export]
macro_rules! try_ev {
    ($val:expr, $events:expr) => {
        match $val {
            Ok(v) => v,
            Err(err) => return $events.with_value(Err(From::from(err)))
        }
    }
}

/// A version of `try_ev!` for `Evented<Result>` that takes care of extracting the events.
#[macro_export]
macro_rules! try_evx {
    ($val:expr, $events:expr) => {
        try_ev!($val.extract(&mut $events), $events)
    }
}

/// An Evented<T> wraps a T and bundles some events alongside it.
///
/// The public methods on Evented<T> are such that it is difficult
/// to drop the events contained.
#[must_use]
pub struct Evented<T, Ev = Event>
    where Ev: Debug
{
    events: Vec<Ev>,
    /// The value will always be Some(t: T) unless this struct is about to be dropped.
    value: Option<T>,
}

/// Trait for trivial conversions to Evented
pub trait ToEvented<Ev>: Sized
    where Ev: Debug
{
    /// Wrap self in an evented type with no events.
    fn to_evented(self) -> Evented<Self, Ev> {
        Evented::new(vec![], self)
    }
}

/// Blanket impl of `ToEvented` for every sized type.
impl<T, Ev: Debug> ToEvented<Ev> for T where T: Sized {}

/// Explode if an attempt is made to drop events.
impl<T, Ev: Debug> Drop for Evented<T, Ev> {
    fn drop(&mut self) {
        if !self.events.is_empty() {
            // Dropping events is always problematic, and should be considered a bug.
            error!("Events were dropped: {:?}", self.events);
        }
    }
}

impl<Ev: Debug> Evented<(), Ev> {
    /// Construct a valueless Evented struct for storing events.
    pub fn empty() -> Self {
        Evented::new(vec![], ())
    }

    /// Add a value to a valueless Evented struct.
    pub fn with_value<T>(self, val: T) -> Evented<T, Ev> {
        Evented::new(self.into_events(), val)
    }
}

impl<T, Ev: Debug> Evented<T, Ev> {
    /// Construct a new Evented<T> from some events and a value.
    pub fn new(events: Vec<Ev>, val: T) -> Self {
        Evented {
            events: events,
            value: Some(val),
        }
    }

    /// Construct a new Evented<T> from a single event and a value.
    pub fn single(event: Ev, val: T) -> Self {
        Evented::new(vec![event], val)
    }

    /// Apply a function to the value contained within an Evented.
    pub fn map<F, U>(mut self, f: F) -> Evented<U, Ev>
        where F: FnOnce(T) -> U
    {
        Evented::new(self.take_events(), f(self.take_value()))
    }

    /// Apply a function producing another Evented, and combine the events from both.
    pub fn and_then<F, U>(mut self, f: F) -> Evented<U, Ev>
        where F: FnOnce(T) -> Evented<U, Ev>
    {
        let mut intermediate = f(self.take_value());
        let mut all_events = self.take_events();
        all_events.extend(intermediate.take_events());
        Evented::new(all_events, intermediate.take_value())
    }

    /// Combine the events of this Evented with the events and value of another.
    pub fn and<U>(mut self, mut other: Evented<U, Ev>) -> Evented<U, Ev> {
        let mut all_events = self.take_events();
        all_events.extend(other.take_events());
        Evented::new(all_events, other.take_value())
    }

    /// Add a single event.
    pub fn add_event(&mut self, ev: Ev) {
        self.events.push(ev);
    }

    /// Add multiple events.
    pub fn add_events(&mut self, evs: Vec<Ev>) {
        self.events.extend(evs);
    }

    /// Extract the value from this Evented<T>, but ONLY
    /// whilst transferring the events to another Evented value.
    pub fn extract<U>(mut self, other: &mut Evented<U, Ev>) -> T {
        other.add_events(self.take_events());
        self.take_value()
    }

    /// Extract the events to an event buffer.
    pub fn extract_to_buf(mut self, buffer: &mut VecDeque<Ev>) -> T {
        buffer.extend(self.take_events());
        self.take_value()
    }

    /// Consume the Evented<T> and yield just its events.
    ///
    /// This is one of two methods that allows us to drop events (the other is extract_to_buf).
    pub fn into_events(mut self) -> Vec<Ev> {
        self.take_events()
    }

    fn take_value(&mut self) -> T {
        unwrap!(mem::replace(&mut self.value, None))
    }

    fn take_events(&mut self) -> Vec<Ev> {
        mem::replace(&mut self.events, vec![])
    }
}

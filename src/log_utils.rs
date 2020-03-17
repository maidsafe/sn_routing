// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Logging with log identifier
//!
//! This module implement logging macros that automatically prefix each output with a custom log
//! identifier. To log identifier is scoped to the current thread.
//!
//! # Example
//!
//! ```ignore
//! // No ident set so this outputs just "foo"
//! trace!("foo");
//!
//! // Set the ident
//! let guard = log_utils::set_ident(|buffer| {
//!     use std::fmt::Write;
//!     write!(buffer, "MY IDENT: ")
//! });
//!
//! // This now outputs "MY IDENT: bar"
//! trace!("bar");
//!
//! // Guard goes out of scope which clears the ident.
//! drop(guard)
//!
//! // This now outputs just "baz"
//! trace!("baz")
//! ```
//!

use std::{cell::RefCell, fmt, marker::PhantomData};

thread_local! {
    static LOG_IDENT: RefCell<String> = RefCell::new(String::new());
}

/// Set the log identifier for the current thread. Returns a RAII-style guard that automatically
/// clears the ident on scope exit.
pub fn set_ident<F>(f: F) -> Guard
where
    F: FnOnce(&mut String) -> Result<(), fmt::Error>,
{
    LOG_IDENT.with(|ident| {
        let mut buffer = ident.borrow_mut();
        buffer.clear();
        f(&mut *buffer).expect("failed to set log ident")
    });

    Guard::new()
}

/// RAII-style guard that clear the log ident on drop.
pub struct Guard {
    // This makes this type not `Send` to make sure it's dropped in the same thread it was created
    // in.
    _not_send_sync: PhantomData<*const ()>,
}

impl Guard {
    fn new() -> Self {
        Self {
            _not_send_sync: PhantomData,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        LOG_IDENT.with(|ident| ident.borrow_mut().clear())
    }
}

// Internal function but it needs to be `pub` so it can be used in the macros.
#[doc(hidden)]
pub fn with_ident<F: FnOnce(&str)>(f: F) {
    LOG_IDENT.with(|ident| f(&*ident.borrow()))
}

// NOTE: an alternative to having custom logging macros would be to override the logger format and
// inject the ident there.
//
// Example with env_logger:
//
// ```
// env_logger::builder()
//     .format(|buf, record| {
//         log_utils::with_ident(|ident| {
//             writeln!(
//                 buf,
//                 "{} {} {}",
//                 record.level(),
//                 ident
//                 record.args(),
//             )
//         })
//     .init()
// ```
//
// There are tradeoffs with either approach. For example, if we want the upper layers to
// automatically see the log ident, we should use macros. On the other hand, if we want to inject
// the log ident also to the log output of the lower layers, we should use custom logger format.
//
// We are currently opting for the macro approach as it seems useful for the upper layers to see
// the log idents without any additional configuration. This approach might be revisited in the
// future if needed.

/// Log a message at the given level prefixed with the current log ident.
#[macro_export]
macro_rules! log {
    // Log with explicit target.
    (target: $target:expr, $level:expr, $($arg:tt)+) => {
        if log::log_enabled!($level) {
            $crate::log_utils::with_ident(|ident| {
                log::log!(target: $target, $level, "{}{}", ident, format_args!($($arg)+));
            })
        }
    };

    // Log using the current module path as the target.
    ($level:expr, $($arg:tt)+) => {
        log!(target: module_path!(), $level, $($arg)+)
    };
}

/// Log a message at the error level prefixed with the current log ident.
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        log!(log::Level::Error, $($arg)+)
    }
}

/// Log a message at the warn level prefixed with the current log ident.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        log!(log::Level::Warn, $($arg)+)
    }
}

/// Log a message at the info level prefixed with the current log ident.
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        log!(log::Level::Info, $($arg)+)
    }
}

/// Log a message at the debug level prefixed with the current log ident.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        log!(log::Level::Debug, $($arg)+)
    }
}

/// Log a message at the trace level prefixed with the current log ident.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => {
        log!(log::Level::Trace, $($arg)+)
    }
}

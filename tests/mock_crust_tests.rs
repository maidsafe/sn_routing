// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![cfg(feature = "mock")]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
// FIXME: Re-enable `redundant_field_names`.
#![cfg_attr(feature = "cargo-clippy", allow(redundant_field_names))]

extern crate fake_clock;
extern crate itertools;
#[macro_use]
extern crate log;
#[cfg_attr(feature = "cargo-clippy", allow(useless_attribute))]
#[allow(unused_extern_crates)]
extern crate maidsafe_utilities;
extern crate rand;
extern crate routing;
#[macro_use]
extern crate unwrap;

// This module is a driver and defines macros. See `mock_crust` modules for
// tests.

/// Expect that the next event raised by the node matches the given pattern.
/// Panics if no event, or an event that does not match the pattern is raised.
/// (ignores ticks).
macro_rules! expect_next_event {
    ($node:expr, $pattern:pat) => {
        loop {
            match $node.inner.try_next_ev() {
                Ok($pattern) => break,
                Ok(Event::Tick) => (),
                other => panic!(
                    "Expected Ok({}) at {}, got {:?}",
                    stringify!($pattern),
                    $node.name(),
                    other
                ),
            }
        }
    };
}

/// Expects that any event raised by the node matches the given pattern
/// (with optional pattern guard). Ignores events that do not match the pattern.
/// Panics if the event channel is exhausted before matching event is found.
macro_rules! expect_any_event {
    ($node:expr, $pattern:pat) => {
        expect_any_event!($node, $pattern if true)
    };
    ($node:expr, $pattern:pat if $guard:expr) => {
        loop {
            match $node.inner.try_next_ev() {
                Ok($pattern) if $guard => break,
                Ok(_) => (),
                other => panic!(
                    "Expected Ok({}) at {}, got {:?}",
                    stringify!($pattern),
                    $node.name(),
                    other
                ),
            }
        }
    };
}

/// Expects that the node raised no event, panics otherwise (ignores ticks).
macro_rules! expect_no_event {
    ($node:expr) => {{
        match $node.inner.try_next_ev() {
            Ok(Event::Tick) => (),
            Err(mpsc::TryRecvError::Empty) => (),
            other => panic!("Expected no event at {}, got {:?}", $node.name(), other),
        }
    }};
}

mod mock_crust;

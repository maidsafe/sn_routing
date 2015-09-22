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

//! The main API for routing nodes (this is where you give the network its rules)
//!
//! The network will report **from authority your authority** and validate cryptographically any
//! message via group consensus. This means any facade you implement will set out what you deem to
//! be a valid operation.  Routing will provide a valid message sender and authority that will allow
//! you to set up many decentralised services.
//!
//! The data types are encoded with Concise Binary Object Representation (CBOR).
//!
//! We use Iana tag representations http://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
//!

#![doc(html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/routing")]
#![forbid(bad_style, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate log;
extern crate cbor;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate time;

extern crate crust;
// extern crate accumulator;
extern crate lru_time_cache;
extern crate message_filter;

mod common_bits;
mod action;
mod filter;
mod messages;
mod direct_messages;
mod name_type;
mod routing_table;
mod routing_node;
mod routing_core;
mod relay;
mod peer;
mod refresh_accumulator;
mod message_accumulator;

/// Routing provides an actionable interface to routing.
pub mod routing;
/// Client interface to routing.
pub mod routing_client;
/// Event provides the events the user can expect to receive from routing.
pub mod event;
/// Utility structs and functions used during testing.
pub mod test_utils;
/// Types and functions used throught the library.
pub mod types;
/// Private network identity component.
pub mod id;
/// Commonly required functions.
pub mod utils;
/// Public network identity component.
pub mod public_id;
/// Errors reported for failed conditions/operations.
pub mod error;
// FIXME (ben 8/09/2015) make the module authority private
/// Persona types recognised by network.
pub mod authority;
/// StructuredData type.
pub mod structured_data;
/// ImmutableData type.
pub mod immutable_data;
/// PlainData type.
pub mod plain_data;
/// Data types used in messages.
pub mod data;

/// NameType is a 512bit name to address elements on the DHT network.
pub use name_type::{NameType, closer_to_target, NAME_TYPE_LEN};
/// Message types defined by the library.
pub use messages::{SignedToken, ExternalRequest, ExternalResponse};
/// Persona types recognised by the network.
pub use authority::Authority;

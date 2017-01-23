// Copyright 2015 MaidSafe.net limited.
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

//! Client and node implementations for a resilient decentralised network.
//!
//! The network is based on the [`kademlia_routing_table`][1] and uses the XOR metric to define the
//! "distance" between two [`XorName`][2]s. `XorName`s are used as addresses of nodes, clients as
//! well as data.
//!
//! [1]: ../kademlia_routing_table/index.html
//! [2]: ../xor_name/struct.XorName.html
//!
//! Messages are exchanged between _authorities_, where an `Authority` can be an individual client
//! or node, or a collection of nodes called a "section", or a subset of a section called a "group".
//! In all cases, messages are cryptographically signed by the sender, and in the case of sections
//! and groups, it is verified that a sufficient number of members agree on the message: only if
//! that quorum is reached, the message is delivered. In addition, each message has a unique ID, and
//! is delivered only once.
//!
//! Section and group authorities are also addressed using a single `XorName`. The members are the
//! nodes that are closest to that name. Sections contain a minimum number of nodes with the minimum
//! value specified as a network-wide constant. Groups are of fixed size, defined as the above
//! minimum section size. Since nodes are assigned their name by the network, this provides
//! redundancy and resilience: a node has no control over which section or group authority it will
//! be a member of, and without a majority in the section or group it cannot forge a message from
//! there.
//!
//! The library also provides different types for the messages' data.
//!
//!
//! # Usage
//!
//! A decentralised service based on the `routing` library uses `Client` to send requests to the
//! network of nodes and receive responses.
//!
//! `Node` is used to handle and send requests within that network, and to implement its
//! functionality, e.g. storing and retrieving data, validating permissions, managing metadata, etc.
//!
//!
//! ## Client creation
//!
//! A client's name is a hash of its public keys. Upon creation, the client will attempt to connect
//! to the network through any node, and exchange public keys with it. That node becomes a
//! bootstrap node for the client, and messages to and from the client will be routed over it.
//!
//! ```ignore
//! use std::sync::mpsc;
//! use routing::{Client, Event, FullId};
//!
//! let min_section_size = 8;
//!
//! let (sender, _receiver) = mpsc::channel::<Event>();
//! let full_id = FullId::new(); // Generate new keys.
//! let _ = Client::new(sender, Some(full_id.clone()), min_section_size).unwrap();
//!
//! let _ = full_id.public_id().name();
//! ```
//!
//! Messages can be sent using the methods of `client`, and received as `Event`s from the
//! `receiver`.
//!
//!
//! ## Node creation
//!
//! Creating a node looks even simpler:
//!
//! ```no_run
//! use routing::Node;
//!
//! let min_section_size = 8;
//!
//! let _ = Node::builder().create(min_section_size).unwrap();
//! ```
//!
//! Upon creation, the node will first connect to the network as a client. Once it has client
//! status, it requests a new name from the network, and then integrates itself in the network with
//! that new name, adding close nodes to its routing table.
//!
//! Messages can be sent using the methods of `node`, and received as `Event`s from the `receiver`.
//! The node can act as an individual node or as part of a section or group authority. Sending a
//! message as a section or group authority only has an effect if sufficiently many other nodes in
//! that authority send the same message.
//!
//!
//! # Sequence diagrams
//!
//! - [Bootstrapping](bootstrap.png)
//! - [Churn (`NewNode`)](new-node.png)
//! - [Tunnel](tunnel.png)

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "https://docs.rs/routing")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", deny(unicode_not_nfc, wrong_pub_self_convention,
                                    option_unwrap_used))]
#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
#[cfg_attr(feature="cargo-clippy", allow(useless_attribute))]
#[allow(unused_extern_crates)]
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate unwrap;
#[cfg(not(feature = "use-mock-crust"))]
extern crate crust;
extern crate itertools;
extern crate lru_time_cache;
extern crate rand;
extern crate resource_proof;
extern crate rust_sodium;
extern crate rustc_serialize;
extern crate tiny_keccak;

#[macro_use]
mod evented;

mod ack_manager;
mod action;
mod client;
mod cache;
mod data;
mod error;
mod event;
mod event_stream;
mod section_list_cache;
mod id;
mod message_filter;
mod messages;
mod node;
mod peer_manager;
mod routing_message_filter;
mod routing_table;
mod signature_accumulator;
mod state_machine;
mod states;
mod stats;
mod timer;
mod tunnels;
mod types;
mod utils;
mod xor_name;
mod sha3;

/// Mock crust
#[cfg(feature = "use-mock-crust")]
pub mod mock_crust;

/// Messaging infrastructure
pub mod messaging;
/// Error communication between vaults and core
pub mod client_errors;

/// Structured Data Tag for Session Packet Type
pub const TYPE_TAG_SESSION_PACKET: u64 = 0;
/// Structured Data Tag for DNS Packet Type
pub const TYPE_TAG_DNS_PACKET: u64 = 5;

/// The quorum, as a percentage of the number of members of the authority.
pub const QUORUM: usize = 60;

pub use cache::{Cache, NullCache};
pub use client::Client;
pub use data::{AppendWrapper, AppendedData, Data, DataIdentifier, Filter, ImmutableData,
               MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, MAX_PRIV_APPENDABLE_DATA_SIZE_IN_BYTES,
               MAX_PUB_APPENDABLE_DATA_SIZE_IN_BYTES, MAX_STRUCTURED_DATA_SIZE_IN_BYTES,
               NO_OWNER_PUB_KEY, PrivAppendableData, PrivAppendedData, PubAppendableData,
               StructuredData};
pub use error::{InterfaceError, RoutingError};
pub use event::Event;
pub use event_stream::EventStream;
pub use evented::Evented;
pub use id::{FullId, PublicId};
pub use messages::{Request, Response};
#[cfg(feature = "use-mock-crust")]
pub use mock_crust::crust;
pub use node::{Node, NodeBuilder};
pub use routing_table::{Authority, Prefix, RoutingTable, Xorable};
pub use routing_table::Error as RoutingTableError;
#[cfg(any(test, feature = "use-mock-crust"))]
pub use routing_table::verify_network_invariant;
pub use types::MessageId;
pub use xor_name::{XOR_NAME_BITS, XOR_NAME_LEN, XorName, XorNameFromHexError};

#[cfg(test)]
mod tests {
    use super::QUORUM;

    #[test]
    #[cfg_attr(feature="cargo-clippy", allow(eq_op))]
    fn quorum_percentage() {
        assert!(QUORUM <= 100 && QUORUM > 50,
                "Quorum percentage isn't between 51 and 100");
    }
}

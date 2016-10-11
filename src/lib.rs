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
//! Messages are exchanged between _authorities_, where an `Authority` can be an
//! individual client or node, or a group of nodes. In both cases, messages are cryptographically
//! signed by the sender, and in the latter case it is verified that a sufficient number of group
//! members agree on the message: Only if that quorum is reached, the message is delivered. In
//! addition, each message has a unique ID, and is delivered only once.
//!
//! Group authorities are also addressed using a single `XorName`. The members of that group are
//! the nodes that are closest to that name. Since nodes are assigned their name by the network,
//! this provides redundancy and resilience: A node has no control over which group authorities it
//! will be a member of, and without a majority in the group it cannot forge a message from that
//! group.
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
//! functionality, e. g. storing and retrieving data, validating permissions, managing metadata etc.
//!
//!
//! ## Client creation
//!
//! A client's name is a hash of its public keys. Upon creation, the client will attempt to connect
//! to the network through any node, and exchange public keys with it. That node becomes a
//! bootstrap node for the client, and messages to and from the client will be routed over it.
//!
//! ```no_run
//! use std::sync::mpsc;
//! use routing::{Client, Event, FullId};
//!
//! let (sender, _receiver) = mpsc::channel::<Event>();
//! let full_id = FullId::new(); // Generate new keys.
//! let _ = Client::new(sender, Some(full_id.clone())).unwrap();
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
//! use std::sync::mpsc;
//! use routing::{Node, Event};
//!
//! let (sender, _receiver) = mpsc::channel::<Event>();
//! let _ = Node::builder().create(sender).unwrap();
//! ```
//!
//! Upon creation, the node will first connect to the network as a client. Once it has client
//! status, it requests a new name from the network, and then integrates itself in the network with
//! that new name, adding close nodes to its routing table.
//!
//! Messages can be sent using the methods of `node`, and received as `Event`s from the `receiver`.
//! The node can act as an individual node or as part of a group authority. Sending a message as a
//! group authority only has an effect if sufficiently many other nodes in that authority send the
//! same message.
//!
//!
//! # Sequence diagrams
//!
//! - [Bootstrapping](bootstrap.png)
//! - [`GetCloseGroup`](get-close-group.png)
//! - [Churn (`NewNode`)](new-node.png)
//! - [Tunnel](tunnel.png)

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/routing")]

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

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                   option_unwrap_used))]
#![cfg_attr(feature="clippy", allow(use_debug))]

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
#[cfg_attr(feature="clippy", allow(useless_attribute))]
#[allow(unused_extern_crates)]
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate unwrap;
extern crate accumulator;
#[cfg(not(feature = "use-mock-crust"))]
extern crate crust;
extern crate itertools;
extern crate lru_time_cache;
extern crate rand;
extern crate rust_sodium;
extern crate rustc_serialize;

mod ack_manager;
mod action;
mod authority;
mod client;
mod cache;
mod data;
mod error;
mod event;
mod id;
mod immutable_data;
mod message_accumulator;
mod message_filter;
mod messages;
mod node;
mod peer_manager;
mod plain_data;
mod routing_table;
mod signed_message_filter;
mod state_machine;
mod states;
mod stats;
mod structured_data;
mod timer;
mod tunnels;
mod types;
mod utils;
mod xor_name;

#[cfg(feature = "use-mock-crust")]
#[allow(unused)]
mod core_tests;

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

pub use authority::Authority;
pub use cache::Cache;
pub use client::Client;
#[cfg(feature = "use-mock-crust")]
pub use core_tests::verify_invariant;
pub use data::{Data, DataIdentifier};
pub use error::{InterfaceError, RoutingError};
pub use event::Event;
pub use id::{FullId, PublicId};
pub use immutable_data::ImmutableData;
pub use messages::{Request, Response};
#[cfg(feature = "use-mock-crust")]
pub use mock_crust::crust;
pub use node::{Node, NodeBuilder};
pub use peer_manager::{MIN_GROUP_SIZE, QUORUM_SIZE};
pub use plain_data::PlainData;
pub use routing_table::Error as RoutingTableError;
pub use routing_table::Xorable;
pub use structured_data::{MAX_STRUCTURED_DATA_SIZE_IN_BYTES, StructuredData};
pub use types::MessageId;
pub use xor_name::{XOR_NAME_BITS, XOR_NAME_LEN, XorName, XorNameFromHexError};

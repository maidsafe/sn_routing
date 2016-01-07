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

//! Client and node implementations for a resilient decentralised network.
//!
//! The network is based on the Kademlia-like routing table and uses the XOR metric to define the
//! "distance" between two `XorName`s. `XorName`s are used as addresses of nodes, clients as well
//! as data.
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
//! The library also provides different types for the messages' data. The data types are encoded
//! with Concise Binary Object Representation (CBOR).
//!
//!
//! ## Usage
//!
//! A decentralised service based on the `routing` library uses `Client` to send requests to the
//! network of nodes and receive responses.
//!
//! `Node` is used to handle and send requests within that network, and to implement its
//! functionality, e. g. storing and retrieving data, validating permissions, managing metadata etc.
//!
//!
//! # Client creation
//!
//! A client's name is a hash of its public keys. Upon creation, the client will attempt to connect
//! to the network through any node, and exchange public keys with it. That node becomes a
//! bootstrap node for the client, and messages to and from the client will be routed over it.
//!
//! ```
//! use std::sync::mpsc;
//! use routing::{Client, Event, FullId};
//!
//! let (sender, receiver) = mpsc::channel::<Event>();
//! let full_id = FullId::new(); // Generate new keys.
//! let client = Client::new(sender, Some(full_id.clone())).unwrap();
//!
//! let client_name = full_id.public_id().name();
//! ```
//!
//! Messages can be sent using the methods of `client`, and received as `Event`s from the
//! `receiver`.
//!
//!
//! # Node creation
//!
//! Creating a node looks even simpler:
//!
//! ```
//! use std::sync::mpsc;
//! use routing::{Node, Event};
//!
//! let (sender, receiver) = mpsc::channel::<Event>();
//! let node = Node::new(sender).unwrap();
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
//! # Example: Put message flow for immutable data
//!
//! An example implementation of a vault for storing and retrieving `ImmutableData` is included
//! with the code of this library. The flow of a `Put` request there moves through the following
//! authorities:
//!
//! * A `Client` that wants to store a piece of data on the network.
//! * The `ClientManager` group authority that is responsible for that particular client. The nodes
//! in this group have access to metadata about this client and can e. g. verify that it has
//! required permissions or quota to store the data. The `ClientManager`'s address is the `XorName`
//! of the client itself, so it consists of the nodes closest to that name.
//! * The `NaeManager` group authority which is responsible for that particular piece of data and
//! knows where in the network it should be stored. Its address is the `XorName` of the data.
//! * The `ManagedNode`s are the individual nodes that actually store the data. This could be just
//! one, but let's assume that data is stored redundantly in more than one place.
//!
//! The message flow from the client to the managed nodes looks like this:
//!
//! * The client sends a `Put` request to the `ClientManager`, i. e. the sender is the individual
//! `Client` and the receiver is a group of nodes with addresses close to the client's name.
//! * Each node in the `ClientManager` group performs validation and updates metadata (which may
//! involve further messages not considered in this example). If valid, it sends a `PutSuccess`
//! response back to the client, and a `Put` request to the `NaeManager` with the data's `XorName`.
//! In both cases, the sender is the `ClientManager`, not the individual node.
//! * Each node in the `NaeManager` chooses a number of individual nodes that are responsible for
//! storing this specific piece of data. This needs to happen in a deterministic way so that the
//! members of the `NaeManager` agree on the responsible nodes. Then they finally send a `Put`
//! request to each of these. Here the sender is the `NaeManager`, but the recipient is the
//! individual `ManagedNode`.
//! * Each `ManagedNode` locally stores the data.
//!
//! These steps need to be implemented by the user of the library. Each node needs to handle all
//! these cases, as it can be simultaneously a `ManagedNode` and a member of several different
//! `ClientManager`s and `NaeManager`s. A client, however, does not act as a node or vice versa.
//!
//! Transparently to the user, the `routing` library deals with message quora, so the user will only
//! receive a message from a `Client` or `Node` if it was either sent
//!
//! * by a client or individual node, or
//! * by a sufficient number of members of a group authority.
//!

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/routing")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate accumulator;
extern crate cbor;
extern crate crust;
extern crate ip;
extern crate itertools;
extern crate lru_time_cache;
extern crate kademlia_routing_table;
extern crate message_filter;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate time;
extern crate xor_name;

mod acceptors;
mod action;
mod authority;
mod client;
mod connection_management;
mod core;
mod data;
mod error;
mod event;
mod id;
mod immutable_data;
mod messages;
mod node;
mod plain_data;
mod structured_data;
mod types;
mod utils;

pub use authority::Authority;
pub use client::Client;
pub use data::{Data, DataRequest};
pub use error::{InterfaceError, RoutingError};
pub use event::Event;
pub use id::{FullId, PublicId};
pub use immutable_data::{ImmutableData, ImmutableDataType};
pub use messages::{RequestContent, RequestMessage, ResponseContent, ResponseMessage,
                   RoutingMessage, SignedMessage};
pub use node::Node;
pub use plain_data::PlainData;
pub use structured_data::{MAX_STRUCTURED_DATA_SIZE_IN_BYTES, StructuredData};
pub use types::MessageId;

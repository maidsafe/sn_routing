// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

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
//! ```no_run
//! # #![allow(unused)]
//! use std::sync::mpsc;
//! use routing::{Client, Event, FullId};
//!
//! let (sender, receiver) = mpsc::channel::<Event>();
//! let full_id = FullId::new(); // Generate new keys.
//! # #[cfg(not(feature = "mock_base"))]
//! let client = Client::new(sender, Some(full_id), None).unwrap();
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
//! # #![allow(unused)]
//! use routing::Node;
//!
//! let node = Node::builder().create().unwrap();
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

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
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
    while_true,
    clippy::unicode_not_nfc,
    clippy::wrong_pub_self_convention,
    clippy::option_unwrap_used
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
// FIXME: move `deprecated` to `deny` section above
#![allow(
    box_pointers,
    deprecated,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    non_camel_case_types,
    // FIXME: allow `needless_pass_by_value` until it's OK to change the public API
    // FIXME: Re-enable `redundant_field_names`.
    clippy::needless_pass_by_value,
    clippy::redundant_field_names
)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

// Needs to be before all other modules to make the macros available to them.
#[macro_use]
mod macros;

mod action;
mod cache;
mod chain;
mod client;
mod client_error;
mod common_types;
mod config_handler;
mod data;
mod error;
mod event;
mod event_stream;
mod id;
mod message_filter;
mod messages;
mod network_service;
mod node;
mod outbox;
mod peer_manager;
mod peer_map;
mod resource_prover;
mod routing_message_filter;
mod routing_table;
mod signature_accumulator;
mod state_machine;
mod states;
mod time;
mod timer;
mod types;
mod utils;
mod xor_name;

/// Mocking utilities.
#[cfg(feature = "mock_base")]
pub mod mock;
pub(crate) mod parsec;

/// SHA-3 type alias.
pub mod sha3;

/// Messaging infrastructure
pub mod messaging;
/// Structured Data Tag for Session Packet Type
pub const TYPE_TAG_SESSION_PACKET: u64 = 0;
/// Structured Data Tag for DNS Packet Type
pub const TYPE_TAG_DNS_PACKET: u64 = 5;

/// Quorum is defined as having strictly greater than `QUORUM_NUMERATOR / QUORUM_DENOMINATOR`
/// agreement; using only integer arithmetic a quorum can be checked with
/// `votes * QUORUM_DENOMINATOR > voters * QUORUM_NUMERATOR`.
pub const QUORUM_NUMERATOR: usize = 2;
/// See `QUORUM_NUMERATOR`.
pub const QUORUM_DENOMINATOR: usize = 3;

/// Default minimal section size.
pub const MIN_SECTION_SIZE: usize = 3;
/// Key of an account data in the account packet
pub const ACC_LOGIN_ENTRY_KEY: &[u8] = b"Login";

#[cfg(feature = "mock_base")]
use crate::mock::quic_p2p;
#[cfg(any(test, feature = "mock_base"))]
pub use crate::routing_table::verify_network_invariant;
pub use crate::{
    cache::{Cache, NullCache},
    chain::Chain,
    client::Client,
    client_error::{ClientError, EntryError},
    common_types::AccountPacket,
    config_handler::{Config, DevConfig},
    data::{
        Action, EntryAction, EntryActions, ImmutableData, MutableData, PermissionSet, User, Value,
        MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, MAX_MUTABLE_DATA_ENTRIES, MAX_MUTABLE_DATA_SIZE_IN_BYTES,
        NO_OWNER_PUB_KEY,
    },
    error::{InterfaceError, RoutingError},
    event::Event,
    event_stream::EventStream,
    id::{FullId, PublicId},
    messages::{AccountInfo, Request, Response},
    node::{Node, NodeBuilder},
    routing_table::Error as RoutingTableError,
    routing_table::{Authority, Prefix, RoutingTable, VersionedPrefix, Xorable},
    types::MessageId,
    utils::XorTargetInterval,
    xor_name::{XorName, XorNameFromHexError, XOR_NAME_BITS, XOR_NAME_LEN},
};
#[cfg(feature = "mock_base")]
pub use crate::{
    chain::{delivery_group_size, verify_chain_invariant},
    peer_manager::test_consts,
};
#[cfg(not(feature = "mock_base"))]
use quic_p2p;

// Format that can be sent between peers
#[cfg(not(feature = "mock_serialise"))]
pub(crate) type NetworkBytes = bytes::Bytes;
#[cfg(feature = "mock_serialise")]
pub(crate) type NetworkBytes = std::rc::Rc<crate::messages::Message>;

pub use self::quic_p2p::Config as NetworkConfig;
pub(crate) use self::{
    chain::bls_emu::{
        PublicKey as BlsPublicKey, PublicKeySet as BlsPublicKeySet,
        PublicKeyShare as BlsPublicKeyShare, Signature as BlsSignature,
        SignatureShare as BlsSignatureShare,
    },
    network_service::NetworkService,
    quic_p2p::{Event as NetworkEvent, Peer as ConnectionInfo, QuicP2p},
};

#[cfg(test)]
mod tests {
    use super::{QUORUM_DENOMINATOR, QUORUM_NUMERATOR};

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn quorum_check() {
        assert!(
            QUORUM_NUMERATOR < QUORUM_DENOMINATOR,
            "Quorum impossible to achieve"
        );
        assert!(
            QUORUM_NUMERATOR * 2 >= QUORUM_DENOMINATOR,
            "Quorum does not guarantee agreement"
        );
    }
}

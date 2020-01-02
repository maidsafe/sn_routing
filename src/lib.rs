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
//! `Node` is used to handle and send requests within that network, and to implement its
//! functionality, e.g. storing and retrieving data, validating permissions, managing metadata, etc.
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
#![deny(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused,
    unused_qualifications
)]
// FIXME - we need to update rand
#![allow(deprecated)]

// Needs to be before all other modules to make the macros available to them.
#[macro_use]
mod macros;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

// ############################################################################
// API
// ############################################################################

#[cfg(not(feature = "mock_base"))]
use quic_p2p;

pub use crate::chain::quorum_count; // FIXME this is only pub for an integration test
pub use event::ClientEvent;
pub use event::Event;
pub use id::FullId; // currently only used in an integration test but will be required in API
pub use node::Node;
pub use quic_p2p::Config as NetworkConfig;
pub use quic_p2p::NodeInfo as ConnectionInfo;
pub use xor_space::XorName;

// ############################################################################
// Private
// ############################################################################

mod action;
mod authority;
mod chain;
#[cfg(not(feature = "mock_crypto"))]
mod crypto;
mod error;
mod event;
mod event_stream;
mod id;
mod message_filter;
mod messages;
mod network_service;
mod node;
mod outbox;
mod pause;
mod peer_map;
mod relocation;
mod routing_message_filter;
mod signature_accumulator;
mod state_machine;
mod states;
mod time;
mod timer;
mod utils;
mod xor_space;

pub(crate) use threshold_crypto::{
    PublicKey as BlsPublicKey, PublicKeySet as BlsPublicKeySet,
    PublicKeyShare as BlsPublicKeyShare, SecretKeySet as BlsSecretKeySet,
    SecretKeyShare as BlsSecretKeyShare, Signature as BlsSignature,
    SignatureShare as BlsSignatureShare,
};

pub(crate) mod parsec;
/// Quorum is defined as having strictly greater than `QUORUM_NUMERATOR / QUORUM_DENOMINATOR`
/// agreement; using only integer arithmetic a quorum can be checked with
/// `votes * QUORUM_DENOMINATOR > voters * QUORUM_NUMERATOR`.
pub(crate) const QUORUM_NUMERATOR: usize = 2;
/// See `QUORUM_NUMERATOR`.
pub(crate) const QUORUM_DENOMINATOR: usize = 3;

/// Minimal safe section size. Routing will keep add nodes until the section reaches this size.
/// More nodes might be added if requested by the upper layers.
/// This number also detemines when split happens - if both post-split sections would have at least
/// this number of nodes.
pub(crate) const SAFE_SECTION_SIZE: usize = 100;

/// Number of elders per section.
pub(crate) const ELDER_SIZE: usize = 7;

pub(crate) use crate::{
    authority::Authority,
    xor_space::{Prefix, Xorable},
};
pub(crate) use crate::{
    error::RoutingError,
    id::{P2pNode, PublicId},
    messages::Message,
};

pub(crate) use self::{
    network_service::NetworkService,
    quic_p2p::{Event as NetworkEvent, QuicP2p},
};

//###############################################################################
//  Mock and test below here
//###############################################################################

/// Random number generation utilities.
#[cfg(feature = "mock_base")]
pub mod rng;

#[cfg(not(feature = "mock_base"))]
mod rng;

/// Mocking utilities.
#[cfg(feature = "mock_base")]
pub mod mock;

#[cfg(not(feature = "mock_serialise"))]
pub(crate) type NetworkBytes = bytes::Bytes;
#[cfg(any(test, feature = "mock_base"))]
pub(crate) use unwrap::unwrap;

#[cfg(feature = "mock_crypto")]
pub(crate) use self::mock::crypto;

#[cfg(feature = "mock_base")]
pub(crate) use crate::mock::quic_p2p;

#[cfg(feature = "mock_parsec")]
#[allow(unused)]
pub(crate) use crate::parsec::generate_bls_threshold_secret_key;

#[cfg(feature = "mock_parsec")]
#[allow(unused)]
pub(crate) use chain::NetworkParams;

// Format that can be sent between peers
#[cfg(feature = "mock_serialise")]
pub(crate) type NetworkBytes = std::rc::Rc<Message>;

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

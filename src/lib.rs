// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! P2PNode implementation for a resilient decentralised network infrastructure.
//!
//! This is the "engine room" of a hybrid p2p network, where the p2p nodes are built on
//! top of this library. The features this library gives us is:
//!
//!  * Sybil resistant p2p nodes
//!  * Sharded network with up to approx 200 p2p nodes per shard
//!  * All data encrypted at network level with TLS 1.3
//!  * Network level `quic` compatibility, satisfying industry standards and further
//!    obfuscating the p2p network data.
//!  * Upgrade capable nodes.
//!  * All network messages signed via ED25519 and/or BLS
//!  * Section consensus via an ABFT algorithm (PARSEC)
//!
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
    // unused,
    unused_qualifications
)]
// FIXME - we need to update rand
#![allow(deprecated, unused)]

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

pub use self::quic_p2p::{Config as NetworkConfig, NodeInfo as ConnectionInfo};
pub use chain::quorum_count; // FIXME this is only pub for an integration test
pub use error::RoutingError;
pub use event::{ClientEvent, Event};
pub use id::{FullId, P2pNode, PublicId}; // currently only used in an integration test but will be required in API
pub use node::Node;
pub use pause::PausedState;
pub use xor_space::{Prefix, XorName};

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

pub(crate) use crate::{messages::Message, xor_space::Xorable};

pub(crate) use self::{
    network_service::NetworkService,
    quic_p2p::{Event as NetworkEvent, QuicP2p},
};

//###############################################################################
//  Mock and test below here
//###############################################################################

#[cfg(feature = "mock_base")]
#[doc(hidden)]
pub mod test_consts {
    pub use crate::chain::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW};
    pub use crate::states::{BOOTSTRAP_TIMEOUT, JOIN_TIMEOUT};
}

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

#[cfg(feature = "mock_base")]
pub use authority::Authority;

#[cfg(feature = "mock_base")]
pub use event_stream::EventStream;

#[cfg(feature = "mock_parsec")]
#[allow(unused)]
pub(crate) use crate::parsec::generate_bls_threshold_secret_key;

#[cfg(feature = "mock_base")]
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

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
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
/*#![forbid(
    arithmetic_overflow,
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
    deprecated
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    clippy::needless_borrow
)]
// Need this to stop clippy complaining about the `use quic_p2p` line which is actually necessary.
#![allow(clippy::single_component_path_imports)]
*/
#[macro_use]
extern crate serde;

// Needs to be before all other modules to make the macros available to them.
#[macro_use]
mod log_utils;
#[macro_use]
mod macros;

// ############################################################################
// Public API
// ############################################################################
pub use self::{
    error::Error,
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    network_params::NetworkParams,
    node::{EventStream, Node, NodeConfig},
    qp2p::Config as TransportConfig,
    section::SectionProofChain,
};

pub use xor_name::{Prefix, XorName, XOR_NAME_LEN}; // TODO remove pub on API update
/// sn_routing events.
pub mod event;

// ############################################################################
// Mock and test API
// ############################################################################

/// Mocking utilities.
#[cfg(feature = "mock")]
pub mod mock;
/// Random number generation
#[cfg(feature = "mock")]
pub mod rng;

/// Mock network
#[cfg(feature = "mock")]
pub use self::section::{quorum_count, MIN_AGE};

#[cfg(feature = "mock")]
#[doc(hidden)]
pub mod test_consts {
    pub use crate::{
        consensus::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW},
        node::{BOOTSTRAP_TIMEOUT, JOIN_TIMEOUT},
        transport::{RESEND_DELAY, RESEND_MAX_ATTEMPTS},
    };
}

// ############################################################################
// Private
// ############################################################################

mod comm;
mod consensus;
mod delivery_group;
mod error;
mod id;
mod location;
mod message_filter;
mod messages;
mod network_params;
mod node;
mod relocation;
#[cfg(not(feature = "mock"))]
mod rng;
mod section;
mod time;

// Cryptography
mod crypto;

/// Quorum is defined as having strictly greater than `QUORUM_NUMERATOR / QUORUM_DENOMINATOR`
/// agreement; using only integer arithmetic a quorum can be checked with
/// `votes * QUORUM_DENOMINATOR > voters * QUORUM_NUMERATOR`.
const QUORUM_NUMERATOR: usize = 2;
/// See `QUORUM_NUMERATOR`.
const QUORUM_DENOMINATOR: usize = 3;

/// Recommended section size. sn_routing will keep adding nodes until the section reaches this size.
/// More nodes might be added if requested by the upper layers.
/// This number also detemines when split happens - if both post-split sections would have at least
/// this number of nodes.
const RECOMMENDED_SECTION_SIZE: usize = 60;

/// Number of elders per section.
const ELDER_SIZE: usize = 7;

// Quic-p2p
#[cfg(feature = "mock")]
use mock_qp2p as q2p;
#[cfg(not(feature = "mock"))]
use qp2p;

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

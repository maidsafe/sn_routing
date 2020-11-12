// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Peer implementation for a resilient decentralised network infrastructure.
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
#![forbid(
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

#[macro_use]
extern crate log;

// ############################################################################
// Public API
// ############################################################################
pub use self::{
    error::{Error, Result},
    event::{Event, SendStream},
    location::{DstLocation, SrcLocation},
    routing::{Config, EventStream, Routing},
    section::{SectionProofChain, MIN_AGE},
};
pub use qp2p::Config as TransportConfig;

pub use xor_name::{Prefix, XorName, XOR_NAME_LEN}; // TODO remove pub on API update

// ############################################################################
// Private
// ############################################################################

mod consensus;
mod crypto;
mod delivery_group;
mod error;
mod event;
mod location;
mod message_filter;
mod messages;
mod network;
mod node;
mod peer;
mod relocation;
mod routing;
mod section;

/// Recommended section size. sn_routing will keep adding nodes until the section reaches this size.
/// More nodes might be added if requested by the upper layers.
/// This number also detemines when split happens - if both post-split sections would have at least
/// this number of nodes.
pub const RECOMMENDED_SECTION_SIZE: usize = 10;

/// Number of elders per section.
pub const ELDER_SIZE: usize = 5;

/// Number of votes required to agree
/// with a strict majority (i.e. > 50%)
#[inline]
pub(crate) const fn majority(num_possible_voters: usize) -> usize {
    1 + (num_possible_voters / 2)
}
#[cfg(test)]
mod tests {
    use super::majority;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest_strict_majority(a in any::<usize>()) {
            let maj = majority(a);
            let maj_double = maj * 2;
            assert!(maj_double == a + 1 || maj_double == a + 2);
        }
    }
}

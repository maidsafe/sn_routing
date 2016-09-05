// Copyright 2016 MaidSafe.net limited.
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

//! Implementation of the "Vault" node for the SAFE Network.
//!
//! # General
//!
//! Vaults form an overlay network on top of a [Kademlia-like routing network][0] to provide
//! decentralised, autonomous, cloud storage.
//!
//! Clients can connect to this network and make requests to store, retrieve, mutate or delete data.
//! Currently the network handles two types of data chunks: [`ImmutableData`][1] and
//! [`StructuredData`][2].
//!
//! The underlying routing network provides the ability to send and receive messages from peers
//! or groups of "close" peers.  These singletons or groups are referred to as authorities.  See the
//! general [routing docs][0] and the [`Authority` docs][3] for further details.
//!
//! Vaults have two main sets of responsibilities, each set being associated with a "persona" of the
//! Vault; managing Client accounts and managing data stored on the network.  Among other things, it
//! involves passing responsibility to new Vaults when there is local churn (i.e. a Vault joins or
//! leaves nearby).
//!
//!
//! # Client Manager Persona
//!
//! The Client Manager persona (a.k.a. `MaidManager`) holds an account for each Client which is
//! close to it in the network address space.  Each such account is managed by a group of
//! [`GROUP_SIZE`][4] Vaults.
//!
//! A Client's account contains details of how many chunks of data have been put to the network by
//! that Client and how many new chunks can still be put.  If a Client's account indicates that no
//! more chunks can be put to the network, the Client Managers for that Client disallow any further
//! `Put` requests, responding with a `LowBalance` error.
//!
//! Clients can retrieve their account balances by sending a specific request to their Managers,
//! namely a `GetAccountInfo` request.
//!
//! ### Churn
//!
//! When a Vault joins the network nearby, the Client Manager will remove all accounts for which it
//! is no longer responsible and will send the remainder to the close group for each account.
//! These are termed "refresh" messages; they allow all members of each group to synchronise their
//! account information.
//!
//! When a close Vault leaves the network, the Client Manager simply sends a set of refreshes.  It
//! will thus be given any accounts which it was not previously managing, but for which it is now
//! responsible.
//!
//!
//! # Data Manager Persona
//!
//! The Data Manager persona holds a chunk store where data chunks are held and is responsible for
//! chunks whose names are close to it in the network address space.  Not every Data Manager in a
//! given group close to a chunk will necessarily hold that chunk, but every one should be aware of
//! which peers *do* hold it.
//!
//! ### Chunk Cache
//!
//! The Data Manager also holds a cache of chunks for which it is not directly responsible.  These
//! are chunks for which the Vault was recently responsible but has churned out of the close group,
//! or chunks which have recently been requested by a Client.
//!
//! The purpose for caching the former is that there is a reasonable chance that the Vault will soon
//! become responsible for that chunk again due to churn.  This saves the chunk from having to be
//! retrieved via new Get requests.
//!
//! The rationale for the latter is that popular chunks will receive many Get requests by many
//! different Clients and the work of satisfying these requests needs to be spread across more
//! Vaults than normal.  By opportunistically caching chunks which have been retrieved by Clients,
//! popular chunks will end up being cached by many more Vaults than the close group, hence the
//! close group will be protected from excessive numbers of Get requests.
//!
//! ### Churn
//!
//! In a similar way to the Client Manager, the Data Manager will clear out records and send refresh
//! messages.  In addition, it will also try to retrieve any chunks for which it is responsible from
//! any close peer which is not currently busy, i.e. a peer which is not currently being asked for a
//! chunk by this Vault.  Chunk replication to this Vault continues repeatedly until it holds all
//! chunks for which it is responsible.
//!
//!
//! # Message Flows
//!
//! As mentioned above, two chunk types are handled by Vaults: `ImmutableData` and `StructuredData`.
//! Both types can be stored to the network by using `Put` messages and retrieved from the network
//! by using `Get` messages.  `StructuredData` can also be mutated by using `Post` messages or
//! removed by using `Delete` messages.
//!
//! The following sections give an overview of the end-to-end process involved in each of these
//! operations.
//!
//!
//! ## `Put ImmutableData`
//!
//! 1. Client sends `Put` to its `MaidManager` group
//! 1. `MaidManager` responds with failure (ending the message flow) if:
//!    * Client doesn't have an account
//!    * Client's account has insufficient balance to be allowed to store a new chunk
//! 1. `MaidManager` sends `Put` to `DataManager` group for the chunk
//! 1. if `DataManager` already has a copy of the chunk, it responds with success to `MaidManager`
//!    group.  Otherwise, it:
//!    * responds with failure (`NetworkFull` error) to `MaidManager` group if its chunkstore is
//!      full
//!    * tries to store the chunk and responds with appropriate success or failure to `MaidManager`
//!      group
//!    * if the store attempt was successful, sends `Refresh` to its fellow `DataManager`s
//! 1. `MaidManager` then:
//!    * refunds the Client's account if the `DataManager` group reports failure
//!    * sends `Refresh` to its fellow `MaidManager`s
//!    * responds with appropriate success or failure to Client
//!
//!
//! ## `Put StructuredData`
//!
//! 1. Client sends `Put` to its `MaidManager` group
//! 1. if the type tag of the chunk is `0`, (representing an account creation request) `MaidManager`
//!    responds with failure (ending the message flow) if this account already exists
//! 1. if the type tag of the chunk is not `0`, `MaidManager` responds with failure (ending the
//!    message flow) if:
//!     * Client doesn't have an account
//!     * Client's account has insufficient balance to be allowed to store a new chunk
//! 1. `MaidManager` sends `Put` to `DataManager` group for the chunk
//! 1. if `DataManager` already has a copy of the chunk, it responds with failure to `MaidManager`
//!    group.  Otherwise, it:
//!    * responds with failure ("network full" error) to `MaidManager` group if its chunkstore is
//!      full
//!    * tries to store the chunk and responds with appropriate success or failure to `MaidManager`
//!      group
//!    * if the store attempt was successful, sends `Refresh` to its fellow `DataManager`s
//! 1. `MaidManager` then:
//!    * refunds the Client's account if the `DataManager` group reports failure
//!    * sends `Refresh` to its fellow `MaidManager`s
//!    * responds with appropriate success or failure to Client
//!
//!
//! ## `Get ImmutableData` or `Get StructuredData`
//!
//! 1. Client sends `Get` to the `DataManager` group for the chunk
//! 1. `DataManager` responds with appropriate success or failure to Client depending on whether or
//!    not it can retrieve the requested chunk from its chunkstore
//!
//!
//! ## `Post StructuredData`
//!
//! 1. Client sends `Post` to the `DataManager` group for the chunk
//! 1. `DataManager` responds with failure (ending the message flow) to the Client if:
//!    * there isn't an existing `StructuredData` chunk with the same name
//!    * the new chunk isn't a valid successor of the existing one
//!    * the chunkstore can't store the new chunk
//! 1. if storing the chunk succeeds, `DataManager`:
//!    * responds with success to the Client
//!    * sends `Refresh` to its fellow `DataManager`s
//!
//!
//! ## `Delete StructuredData`
//!
//! Note that deleting involves sending a new version of the chunk to be deleted in order to allow
//! validation of the request.
//!
//! 1. Client sends `Delete` to the `DataManager` group for the chunk
//! 1. `DataManager` responds with failure (ending the message flow) to the Client if:
//!    * there isn't an existing `StructuredData` chunk with the same name
//!    * the new chunk isn't a valid successor of the existing one
//!    * the chunkstore can't delete the existing chunk
//! 1. if deleting the chunk succeeds, `DataManager` responds with success to the Client
//!
//!
//! [0]: http://docs.maidsafe.net/routing/master/routing/index.html "Documentation for Routing"
//! [1]: http://docs.maidsafe.net/routing/master/routing/struct.ImmutableData.html
//!      "Documentation for `ImmutableData`"
//! [2]: http://docs.maidsafe.net/routing/master/routing/struct.StructuredData.html
//!      "Documentation for `StructuredData`"
//! [3]: http://docs.maidsafe.net/routing/master/routing/enum.Authority.html
//!      "Documentation for `Authority`"
//! [4]: http://docs.maidsafe.net/routing/master/routing/constant.GROUP_SIZE.html
//!      "Documentation for `GROUP_SIZE`"

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_vault")]

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
#![cfg_attr(feature="clippy", deny(clippy))]
#![cfg_attr(feature="clippy", allow(use_debug, similar_names))] // "mpid" and "maid" are similar.

extern crate accumulator;
extern crate fs2;
#[macro_use]
extern crate log;
extern crate lru_time_cache;
extern crate itertools;
extern crate kademlia_routing_table;
#[macro_use]
extern crate maidsafe_utilities;
extern crate config_file_handler;
// Needed because the crate is only used for macros
#[cfg_attr(feature="clippy", allow(useless_attribute))]
#[allow(unused_extern_crates)]
#[macro_use]
extern crate quick_error;
#[cfg(any(test, feature = "use-mock-crust"))]
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate rust_sodium;
#[cfg(test)]
extern crate tempdir;

mod cache;
mod chunk_store;
mod config_handler;
mod error;
/// For integration tests only
#[cfg(feature = "use-mock-crust")]
pub mod test_utils;
mod personas;
mod utils;
mod vault;
/// For integration tests only
#[cfg(feature = "use-mock-crust")]
pub mod mock_crust_detail;
pub use config_handler::Config;
pub use vault::Vault;

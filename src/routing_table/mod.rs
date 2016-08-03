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

#![doc(html_logo_url =
"https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
html_favicon_url = "http://maidsafe.net/img/favicon.ico",
html_root_url = "http://maidsafe.github.io/kademlia_routing_table")]

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

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                   option_unwrap_used))]
#![cfg_attr(feature="clippy", allow(use_debug))]

//! A routing table to manage contacts for a node in a [Kademlia][1] distributed hash table.
//!
//! [1]: https://en.wikipedia.org/wiki/Kademlia
//!
//!
//! This crate uses the Kademlia mechanism for routing messages in a peer-to-peer network, and
//! generalises it to provide redundancy in every step: for senders, messages in transit and
//! receivers. It contains the routing table and the functionality to decide via which of its
//! entries to route a message, but not the networking functionality itself.
//!
//! It also provides methods to decide which other nodes to connect to, depending on a parameter
//! `bucket_size` (see below).
//!
//!
//! # Addresses and distance functions
//!
//! Nodes in the network are addressed with a [`Xorable`][2] type, an unsigned integer with `B`
//! bits. The *[XOR][3] distance* between two nodes with addresses `x` and `y` is `x ^ y`. This
//! [distance function][4] has the property that no two points ever have the same distance from a
//! given point, i. e. if `x ^ y == x ^ z`, then `y == z`. This property allows us to define the
//! `k`-*close group* of an address as the `k` closest nodes to that address, guaranteeing that the
//! close group will always have exactly `k` members (unless, of course, the whole network has less
//! than `k` nodes).
//!
//! [2]: trait.Xorable.html
//! [3]: https://en.wikipedia.org/wiki/Exclusive_or#Bitwise_operation
//! [4]: https://en.wikipedia.org/wiki/Metric_%28mathematics%29
//!
//! The routing table is associated with a node with some name `x`, and manages a number of
//! contacts to other nodes, sorting them into up to `B` *buckets*, depending on their XOR
//! distance from `x`:
//!
//! * If 2<sup>`B`</sup> > `x ^ y` >= 2<sup>`B - 1`</sup>, then y is in bucket 0.
//! * If 2<sup>`B - 1`</sup> > `x ^ y` >= 2<sup>`B - 2`</sup>, then y is in bucket 1.
//! * If 2<sup>`B - 2`</sup> > `x ^ y` >= 2<sup>`B - 3`</sup>, then y is in bucket 2.
//! * ...
//! * If 2 > `x ^ y` >= 1, then y is in bucket `B - 1`.
//!
//! Equivalently, `y` is in bucket `n` if the longest common prefix of `x` and `y` has length `n`,
//! i. e. the first binary digit in which `x` and `y` disagree is the `(n + 1)`-th one. We call the
//! length of the remainder, without the common prefix, the *bucket distance* of `x` and `y`. Hence
//! `x` and `y` have bucket distance `B - n` if and only if `y` belongs in bucket number `n`.
//!
//! The bucket distance is coarser than the XOR distance: Whenever the bucket distance from `y` to
//! `x` is less than the bucket distance from `z` to `x`, then `y ^ x < z ^ x`. But not vice-versa:
//! Often `y ^ x < z ^ x`, even if the bucket distances are equal. The XOR distance ranges from 0
//! to 2<sup>`B`</sup> (exclusive), while the bucket distance ranges from 0 to `B` (inclusive).
//!
//!
//! # Guarantees
//!
//! The routing table provides functions to decide, for a message with a given destination, which
//! nodes in the table to pass the message on to, so that it is guaranteed that:
//!
//! * If the destination is the address of a node, the message will reach that node after at most
//!   `B - 1` hops.
//! * Otherwise, if the destination is a `k`-close group with `k <= bucket_size`, the message will
//!   reach every member of the `k`-close group of the destination address, i. e. all `k` nodes in
//!   the network that are XOR-closest to that address, and each node knows whether it belongs to
//!   that group.
//! * Each node in a given address' close group is connected to each other node in that group. In
//!   particular, every node is connected to its own close group.
//! * The number of total hop messages created for each message is at most `B`.
//! * For each node there are at most `B * bucket_size` other nodes in the network that would
//!   accept a connection, at any point in time. All other nodes do not need to disclose their IP
//!   address.
//! * There are `bucket_size` different paths along which a message can be sent, to provide
//!   redundancy.
//!
//! However, to be able to make these guarantees, the routing table must be filled with
//! sufficiently many contacts. Specifically, the following invariant must be ensured:
//!
//! > Whenever a bucket `n` has fewer than `bucket_size` entries, it contains *all* nodes in the
//! > network with bucket distance `B - n`.
//!
//! The user of this crate therefore needs to make sure that whenever a node joins or leaves, all
//! affected nodes in the network update their routing tables accordingly.
//!
//!
//! # Resilience against malfunctioning nodes
//!
//! The sender may choose to send a message via up to `bucket_size` distinct paths to provide
//! redundancy against malfunctioning hop nodes. These paths are likely, but not guaranteed, to be
//! disjoint.
//!
//! The concept of close groups exists to provide resilience even against failures of the source or
//! destination itself: If every member of a group tries to send the same message, it will arrive
//! even if some members fail. And if a message is sent to a whole group, it will arrive in most,
//! even if some of them malfunction.
//!
//! Close groups can thus be used as inherently redundant authorities in the network that messages
//! can be sent to and received from, using a consensus algorithm: A message from a group authority
//! is considered to be legitimate, if a majority of group members have sent a message with the same
//! content.

// TODO - remove this
#![allow(unused)]

mod contact_info;
// mod network_test;
mod result;
mod xorable;

pub use self::contact_info::ContactInfo;
pub use self::result::{AddedNodeDetails, DroppedNodeDetails};
pub use self::xorable::Xorable;

use itertools::*;
use std::{cmp, fmt, iter, mem, slice};

type SliceFn<T> = fn(&Vec<T>) -> slice::Iter<T>;

// Amount added to `min_bucket_len` when deciding whether a bucket split can happen.  This helps
// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 1;

/// Immutable iterator over the entries of a `RoutingTable`.
pub struct Iter<'a, T: 'a> {
    inner: iter::FlatMap<iter::Rev<slice::Iter<'a, Vec<T>>>, slice::Iter<'a, T>, SliceFn<T>>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}


/// A message destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Destination<N> {
    /// The `k`-group of the given address. The message should reach the `k` closest nodes.
    Group(N, usize),
    /// The individual node at the given address. The message should reach exactly one node.
    Node(N),
}

impl<N> Destination<N> {
    /// Returns the name of the destination, i.e. the node or group address.
    pub fn name(&self) -> &N {
        match *self {
            Destination::Group(ref name, _) |
            Destination::Node(ref name) => name,
        }
    }

    /// Returns `true` if the destination os a group, and `false` if it is an individual node.
    pub fn is_group(&self) -> bool {
        match *self {
            Destination::Group(_, _) => true,
            Destination::Node(_) => false,
        }
    }
}


/// A routing table to manage contacts for a node.
///
/// It maintains a list of `T::Name`s representing connected peer nodes, and provides algorithms for
/// routing messages.
///
/// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: ContactInfo> {
    /// This nodes' own contact info.
    our_info: T,
    /// The minimum bucket size.
    min_bucket_len: usize,
    /// The buckets, by bucket index. Each bucket is sorted by ascending distance from us.
    buckets: Vec<Vec<T>>,
}

impl<T> RoutingTable<T>
    where T: ContactInfo + fmt::Binary,
          T::Name: PartialEq + Xorable
{
    /// Creates a new routing table for the node with the given info.
    ///
    /// `bucket_size` specifies the minimum number of bucket entries: Whenever a new node joins the
    /// network which belongs to a bucket with `< bucket_size` entries, it _must_ be added to that
    /// bucket. This guarantees that all nodes know which `k`-groups they belong to, for each
    /// `k <= bucket_size`.
    ///
    /// In excess of `bucket_size`, `extra_entries` are considered desired in each bucket. After
    /// that, additional entries are considered unneeded: If both sides agree, they should
    /// disconnect.
    pub fn new(our_info: T, min_bucket_len: usize) -> Self {
        RoutingTable {
            buckets: vec![vec![]],
            our_info: our_info,
            min_bucket_len: min_bucket_len,
        }
    }

    /// Adds a contact to the routing table, or updates it.
    ///
    /// Returns `None` if the contact already existed or was denied (see `allow_connection`).
    /// Otherwise it returns `AddedNodeDetails`.
    pub fn add(&mut self, info: T) -> Option<AddedNodeDetails<T>> {
        if info.name() == self.our_name() {
            return None;
        }
        match self.search(info.name()) {
            (bucket_index, Ok(contact_index)) => {
                self.buckets[bucket_index][contact_index] = info;
                None
            }
            (bucket_index, Err(contact_index)) => {
                if !self.prefix_invariant_holds(bucket_index, info.name()) {
                    // println!("{:08b} ({}) differs in > 1 bit for prefix of len {}", info, self.our_name().max_bucket_index(info.name()), self.buckets.len() - 1);
                    return None;
                }

                self.buckets[bucket_index].insert(contact_index, info);
                let mut unneeded = vec![];
                if let Some(positions) = self.split_positions() {
                    unneeded = self.split(positions);
                    // println!("{:b}", *self);
                    // print!("Pruned: [");
                    // for (index, contact) in unneeded.iter().enumerate() {
                    //     let comma = if index == unneeded.len() - 1 { "" } else { ", " };
                    //     print!("{:08b}{}", contact, comma);
                    // }
                    // println!("]\n");
                }

                Some(AddedNodeDetails {
                    unneeded: unneeded,
                })
            }
        }
    }

    /// Returns whether the given contact should be added to the routing table.
    ///
    /// Returns `false` if adding the contact in question would not bring the routing table closer
    /// to satisfy the invariant. It returns `true` if and only if the new contact would be among
    /// the `bucket_size` closest nodes in its bucket.
    pub fn need_to_add(&self, name: &T::Name) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => false,  // They already are in our routing table.
            (bucket_index, Err(_)) => self.prefix_invariant_holds(bucket_index, name),
        }
    }

    /// Removes the contact from the table.
    ///
    /// If no entry with that name is found, `None` is returned. Otherwise, the entry is removed
    /// from the routing table and `DroppedNodeDetails` are returned.
    pub fn remove(&mut self, name: &T::Name) -> Option<DroppedNodeDetails> {
        if let (bucket_index, Ok(contact_index)) = self.search(name) {
            let _ = self.buckets[bucket_index].remove(contact_index);
            let mut result = DroppedNodeDetails { merged_bucket: None };
            if self.buckets[bucket_index].len() < self.min_bucket_len {
                let merge_index = if bucket_index == self.buckets.len() - 1 {
                    bucket_index - 1
                } else {
                    bucket_index
                };
                self.merge_buckets(merge_index);
                result.merged_bucket = Some(merge_index);
            }
            Some(result)
        } else {
            None
        }
    }

    /// Returns the name of the node this routing table is for.
    pub fn our_name(&self) -> &T::Name {
        self.our_info.name()
    }

















    // Checks to see if the last bucket can be split.  This returns `Some` if:
    //  - a new bucket can be created which will contain at least `min_bucket_len + SPLIT_BUFFER`
    //    contacts with CLBs > current last bucket index
    //  - there are at least `min_bucket_len + SPLIT_BUFFER` contacts left in this current one
    //  - all other buckets will continue to have at least `min_bucket_len + SPLIT_BUFFER` contacts
    //    after pruning them in light of this node's new prefix length
    //
    // The value of a `Some` result is a vector of positions at which each bucket should be split
    // off.  For all but the last bucket, the split off contacts can be removed.  For the last
    // bucket, the split off part becomes the new penultimate bucket.
    fn split_positions(&self) -> Option<Vec<usize>> {
        // Find position at which last bucket will split and check that each part will contain
        // enough contacts.
        let last_bucket_index = self.buckets.len() - 1;
        let min_contacts = self.min_bucket_len + SPLIT_BUFFER;
        let position_of_last_bucket_split = match self.buckets[last_bucket_index].iter().position(|ref contact| self.max_bucket_index(contact.name()) == last_bucket_index) {
            Some(position) => {
                if position < min_contacts || self.buckets[last_bucket_index].len() - position < min_contacts {
                    return None;
                }
                position
            },
            None => return None,
        };

        // Iterate all but last bucket, gathering list of positions from where bucket should be
        // pruned.
        let mut positions = vec![];
        for bucket in &self.buckets[..last_bucket_index] {
            match bucket.iter().position(|ref contact| self.our_name().differs_in_bit(contact.name(), last_bucket_index)) {
                Some(position) => {
                    if position < min_contacts {
                        return None;
                    }
                    positions.push(position)
                },
                None => return None,
            }
        }
        positions.push(position_of_last_bucket_split);
        Some(positions)
    }

    fn split(&mut self, positions: Vec<usize>) -> Vec<T>{
        let mut pruned = vec![];
        // Prune all but last bucket
        for (position, bucket) in (&positions[..positions.len() - 1]).iter().zip(self.buckets.iter_mut()) {
            pruned.append(&mut bucket.split_off(*position));
        }

        // Split the last bucket
        let last_bucket_index = self.buckets.len() - 1;
        let remainder = self.buckets[last_bucket_index].split_off(positions[last_bucket_index]);
        self.buckets.insert(last_bucket_index, remainder);
        pruned
    }

    // Returns true if `name` differs from this node's prefix in exactly one bit.  The prefix length
    // is equal to `self.buckets.len() - 1`.
    fn prefix_invariant_holds(&self, bucket_index: usize, name: &T::Name) -> bool {
        // For the last two buckets (assuming there are multiple buckets), the invariant is already
        // true.  Only check for other buckets.
        if bucket_index + 2 < self.buckets.len() {
            for bit_index in bucket_index + 1..self.buckets.len() - 1 {
                if self.our_name().differs_in_bit(name, bit_index) {
                    return false;
                }
            }
        }
        true
    }

    // Merges all buckets in position >= `index` into a single bucket.
    fn merge_buckets(&mut self, index: usize) {
        let mut temp = vec![];
        let count = self.buckets.len() - index;
        for bucket in self.buckets.iter_mut().rev().take(count) {
            temp.append(bucket);
        }
        mem::swap(&mut temp, &mut self.buckets[index]);
        self.buckets.truncate(index + 1);
    }

    /// This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    /// bits" means the most significant bits.
    fn max_bucket_index(&self, name: &T::Name) -> usize {
        self.our_name().max_bucket_index(name)
    }

    fn bucket_index(&self, name: &T::Name) -> usize {
        cmp::min(self.max_bucket_index(name), self.buckets.len() - 1)
    }

    /// Searches the routing table for the given name.
    ///
    /// Returns a tuple with the bucket index of `name` as the first entry. The second entry is
    /// `Ok(i)` if the node has index `i` in that bucket, or `Err(i)` if it isn't there yet and `i`
    /// is the index inside the bucket where it would be inserted.
    fn search(&self, name: &T::Name) -> (usize, Result<usize, usize>) {
        let bucket_index = self.bucket_index(name);
        (bucket_index,
         match self.buckets.get(bucket_index) {
            None => Err(0),
            Some(bucket) => {
                bucket.binary_search_by(|other| self.our_name().cmp_distance(other.name(), name))
            }
        })
    }
}

impl<T> fmt::Binary for RoutingTable<T>
where T: ContactInfo + fmt::Binary,
      T::Name: PartialEq + Xorable {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(formatter,
               "RoutingTable {{\n\tour_info: {:08b},\n\tmin_bucket_len: {},", self.our_info, self.min_bucket_len));
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            try!(write!(formatter, "\tbucket {}: [", bucket_index));
            for (contact_index, contact) in bucket.iter().enumerate() {
                let comma = if contact_index == bucket.len() - 1 { "" } else { ", " };
                try!(write!(formatter, "{:08b} ({}){}", contact, self.our_name().max_bucket_index(contact.name()), comma));
            }
            let comma = if bucket_index == self.buckets.len() - 1 { "" } else { "," };
            try!(writeln!(formatter, "]{}", comma));
        }
        write!(formatter, "}}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn printout() {
        let mut table = RoutingTable::new(170u8, 3);
        for i in 0u16..256 {
            let _ = table.add((256u16 - i) as u8);
            // print!("{:08b}  {}   ", i, 0u8.bucket_index(&(i as u8)));
            // for b in 0..8 {
            //     print!("{:7}", 0u8.differs_in_bit(&(i as u8), b));
            // }
            // println!("");
        }
        println!("\n{:b}\n", table);

        // let _ = table.remove(&0b10100010);
        // let _ = table.remove(&0b10100011);
        // let _ = table.remove(&0b10100000);
        // let _ = table.remove(&0b10100001);
        // let _ = table.remove(&0b10100110);
        // let _ = table.remove(&0b10100111);

        assert!(unwrap!(table.remove(&0b10101011)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10101000)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10101001)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10101110)).merged_bucket.is_none());
        match table.remove(&0b10101111) {
            Some(result) => println!("Merged bucket {}\n{:b}\n", unwrap!(result.merged_bucket), table),
            None => panic!(),
        }

        assert!(unwrap!(table.remove(&0b10001010)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001011)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001000)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001001)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001110)).merged_bucket.is_none());
        match table.remove(&0b10001111) {
            Some(result) => println!("Merged bucket {}\n{:b}\n", unwrap!(result.merged_bucket), table),
            None => panic!(),
        }
    }
}

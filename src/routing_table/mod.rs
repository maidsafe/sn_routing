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


// A routing table to manage contacts for a node in a [Kademlia][1] distributed hash table.
//
// [1]: https://en.wikipedia.org/wiki/Kademlia
//
//
// This uses the Kademlia mechanism for routing messages in a peer-to-peer network, and generalises
// it to provide redundancy in every step: for senders, messages in transit and receivers.
// It contains the routing table and the functionality to decide via which of its entries to route
// a message, but not the networking functionality itself.
//
// It also provides methods to decide which other nodes to connect to, depending on a parameter
// `bucket_size` (see below).
//
//
// # Addresses and distance functions
//
// Nodes in the network are addressed with a [`Xorable`][2] type, an unsigned integer with `B` bits.
// The *[XOR][3] distance* between two nodes with addresses `x` and `y` is `x ^ y`. This
// [distance function][4] has the property that no two points ever have the same distance from a
// given point, i. e. if `x ^ y == x ^ z`, then `y == z`. This property allows us to define the
// `k`-*close group* of an address as the `k` closest nodes to that address, guaranteeing that the
// close group will always have exactly `k` members (unless, of course, the whole network has less
// than `k` nodes).
//
// [2]: trait.Xorable.html
// [3]: https://en.wikipedia.org/wiki/Exclusive_or#Bitwise_operation
// [4]: https://en.wikipedia.org/wiki/Metric_%28mathematics%29
//
// The routing table is associated with a node with some name `x`, and manages a number of contacts
// to other nodes, sorting them into up to `B` *buckets*, depending on their XOR distance from `x`:
//
// * If 2<sup>`B`</sup> > `x ^ y` >= 2<sup>`B - 1`</sup>, then y is in bucket 0.
// * If 2<sup>`B - 1`</sup> > `x ^ y` >= 2<sup>`B - 2`</sup>, then y is in bucket 1.
// * If 2<sup>`B - 2`</sup> > `x ^ y` >= 2<sup>`B - 3`</sup>, then y is in bucket 2.
// * ...
// * If 2 > `x ^ y` >= 1, then y is in bucket `B - 1`.
//
// Equivalently, `y` is in bucket `n` if the longest common prefix of `x` and `y` has length `n`,
// i. e. the first binary digit in which `x` and `y` disagree is the `(n + 1)`-th one. We call the
// length of the remainder, without the common prefix, the *bucket distance* of `x` and `y`. Hence
// `x` and `y` have bucket distance `B - n` if and only if `y` belongs in bucket number `n`.
//
// The bucket distance is coarser than the XOR distance: Whenever the bucket distance from `y` to
// `x` is less than the bucket distance from `z` to `x`, then `y ^ x < z ^ x`. But not vice-versa:
// Often `y ^ x < z ^ x`, even if the bucket distances are equal. The XOR distance ranges from 0
// to 2<sup>`B`</sup> (exclusive), while the bucket distance ranges from 0 to `B` (inclusive).
//
//
// # Guarantees
//
// The routing table provides functions to decide, for a message with a given destination, which
// nodes in the table to pass the message on to, so that it is guaranteed that:
//
// * If the destination is the address of a node, the message will reach that node after at most
//   `B - 1` hops.
// * Otherwise, if the destination is a `k`-close group with `k <= bucket_size`, the message will
//   reach every member of the `k`-close group of the destination address, i. e. all `k` nodes in
//   the network that are XOR-closest to that address, and each node knows whether it belongs to
//   that group.
// * Each node in a given address' close group is connected to each other node in that group. In
//   particular, every node is connected to its own close group.
// * The number of total hop messages created for each message is at most `B`.
// * For each node there are at most `B * bucket_size` other nodes in the network that would
//   accept a connection, at any point in time. All other nodes do not need to disclose their IP
//   address.
// * There are `bucket_size` different paths along which a message can be sent, to provide
//   redundancy.
//
// However, to be able to make these guarantees, the routing table must be filled with sufficiently
// many contacts. Specifically, the following invariant must be ensured:
//
// > Whenever a bucket `n` has fewer than `bucket_size` entries, it contains *all* nodes in the
// > network with bucket distance `B - n`.
//
// The user of this crate therefore needs to make sure that whenever a node joins or leaves, all
// affected nodes in the network update their routing tables accordingly.
//
//
// # Resilience against malfunctioning nodes
//
// The sender may choose to send a message via up to `bucket_size` distinct paths to provide
// redundancy against malfunctioning hop nodes. These paths are likely, but not guaranteed, to be
// disjoint.
//
// The concept of close groups exists to provide resilience even against failures of the source or
// destination itself: If every member of a group tries to send the same message, it will arrive
// even if some members fail. And if a message is sent to a whole group, it will arrive in most,
// even if some of them malfunction.
//
// Close groups can thus be used as inherently redundant authorities in the network that messages
// can be sent to and received from, using a consensus algorithm: A message from a group authority
// is considered to be legitimate, if a majority of group members have sent a message with the same
// content.

// TODO - remove this
#![allow(unused)]

mod error;
mod network_tests;
mod prefix;
mod xorable;


use itertools::Itertools;
pub use self::error::Error;
pub use self::prefix::Prefix;
pub use self::xorable::Xorable;
use std::{iter, mem};
use std::collections::{HashMap, HashSet, hash_map, hash_set};
use std::fmt::{Binary, Debug, Formatter};
use std::fmt::Result as FmtResult;
use std::hash::Hash;



pub type Groups<T> = HashMap<Prefix<T>, HashSet<T>>;

type MemberIter<'a, T> = hash_set::Iter<'a, T>;
type GroupIter<'a, T> = hash_map::Iter<'a, Prefix<T>, HashSet<T>>;
type FlatMapFn<'a, T> = fn((&Prefix<T>, &'a HashSet<T>)) -> MemberIter<'a, T>;

// Amount added to `min_group_size` when deciding whether a bucket split can happen.  This helps
// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 1;

// Immutable iterator over the entries of a `RoutingTable`.
pub struct Iter<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> {
    inner: iter::FlatMap<GroupIter<'a, T>, MemberIter<'a, T>, FlatMapFn<'a, T>>,
}

impl<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> Iter<'a, T> {
    fn iterate(item: (&Prefix<T>, &'a HashSet<T>)) -> hash_set::Iter<'a, T> {
        item.1.iter()
    }
}

impl<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}



// A message destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Destination<N> {
    // The group closest to the given name.
    Group(N),
    // The individual node at the given name.
    Node(N),
}

impl<N> Destination<N> {
    // Returns the name of the destination, i.e. the node or group name.
    pub fn name(&self) -> &N {
        match *self {
            Destination::Group(ref name) |
            Destination::Node(ref name) => name,
        }
    }

    // Returns `true` if the destination is a group, and `false` if it is an individual node.
    pub fn is_group(&self) -> bool {
        match *self {
            Destination::Group(_) => true,
            Destination::Node(_) => false,
        }
    }

    // Returns `true` if the destination is an individual node, and `false` if it is a group.
    pub fn is_node(&self) -> bool {
        !self.is_group()
    }
}



// Used when removal of a contact triggers the need to merge two or more groups
pub struct OwnMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    prefix: Prefix<T>,
    groups: Groups<T>,
}



// Used when merging our own group to send to peers outwith the new group
#[derive(Debug)]
pub struct OtherMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    prefix: Prefix<T>,
    group: HashSet<T>,
}



// A routing table to manage contacts for a node.
//
// It maintains a list of `T`s representing connected peer nodes, and provides algorithms for
// routing messages.
//
// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: Binary + Clone + Copy + Default + Hash + Xorable + Debug> {
    our_name: T,
    min_group_size: usize,
    our_group_prefix: Prefix<T>,
    groups: Groups<T>,
    needed: HashSet<T>,
}

impl<T: Binary + Clone + Copy + Default + Hash + Xorable + Debug> RoutingTable<T> {
    pub fn new(our_name: T, min_group_size: usize) -> Self {
        let mut groups = HashMap::new();
        let our_group_prefix = Prefix::new(0, our_name);
        let _ = groups.insert(our_group_prefix, HashSet::new());
        RoutingTable {
            our_name: our_name,
            min_group_size: min_group_size,
            our_group_prefix: our_group_prefix,
            groups: groups,
            needed: HashSet::new(),
        }
    }

    pub fn our_name(&self) -> &T {
        &self.our_name
    }

    // Total number of entries in the routing table.
    pub fn len(&self) -> usize {
        self.groups.values().fold(0, |acc, group| acc + group.len())
    }

    pub fn is_empty(&self) -> bool {
        self.groups.values().all(HashSet::is_empty)
    }

    pub fn iter(&self) -> Iter<T> {
        Iter { inner: self.groups.iter().flat_map(Iter::<T>::iterate) }
    }

    // If our group is the closest one to `name`, returns all names in our group *including ours*,
    // otherwise returns `None`.
    pub fn close_names(&self, name: &T) -> Option<HashSet<T>> {
        if self.our_group_prefix.matches(name) {
            let mut our_group = unwrap!(self.groups.get(&self.our_group_prefix)).clone();
            let _ = our_group.insert(self.our_name);
            Some(our_group)
        } else {
            None
        }
    }

    // If our group is the closest one to `name`, returns all names in our group *excluding ours*,
    // otherwise returns `None`.
    pub fn other_close_names(&self, name: &T) -> Option<HashSet<T>> {
        if self.our_group_prefix.matches(name) {
            Some(unwrap!(self.groups.get(&self.our_group_prefix)).clone())
        } else {
            None
        }
    }

    // Returns the list of contacts as a result of a merge to which we aren't currently connected,
    // but should be.
    pub fn needed(&self) -> &HashSet<T> {
        &self.needed
    }

    // Returns whether the given contact should be added to the routing table.
    //
    // Returns `false` if `name` already exists in the routing table, or it doesn't fall within any
    // of our groups, or it's our own name.  Otherwise it returns `true`.
    pub fn need_to_add(&self, name: &T) -> bool {
        if *name == self.our_name {
            return false;
        }
        if let Some(group) = self.get_group(name) {
            !group.contains(name)
        } else {
            false
        }
    }

    // Adds a contact to the routing table.
    //
    // Returns `Err` if `name` already existed in the routing table, or it doesn't fall within any
    // of our groups, or it's our own name.  Otherwise it returns `Ok(Some(prefix))` if the addition
    // succeeded and should cause our group to split (where `prefix` is the one which should split)
    // or `Ok(None)` if the addition succeeded and shouldn't cause a split.
    pub fn add(&mut self, name: T) -> Result<Option<Prefix<T>>, Error> {
        if name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }

        {
            if let Some(group) = self.get_mut_group(&name) {
                if !group.insert(name) {
                    return Err(Error::AlreadyExists);
                }
            } else {
                return Err(Error::PeerNameUnsuitable);
            }
        }

        let _ = self.needed.remove(&name);

        let our_group = unwrap!(self.groups.get(&self.our_group_prefix));
        // Count the number of names which will end up in our group if it is split
        let new_group_size = our_group.iter()
            .filter(|name| self.our_name.common_prefix(name) > self.our_group_prefix.bit_count())
            .count();
        // If either of the two new groups will not contain enough entries, return `None`.
        let min_size = self.min_group_size + SPLIT_BUFFER;
        Ok(if our_group.len() - new_group_size < min_size || new_group_size < min_size {
            None
        } else {
            Some(self.our_group_prefix)
        })
    }

    // Splits a group.
    //
    // If the group exists in the routing table, it is split, otherwise this function is a no-op.
    // If one of the two new groups doesn't satisfy the invariant (i.e. only differs in one bit from
    // our own prefix), it is removed and those contacts are returned.
    pub fn split(&mut self, mut prefix: Prefix<T>) -> Vec<T> {
        let mut result = vec![];
        if prefix == self.our_group_prefix {
            self.split_our_group();
            return result;
        }

        if let Some(to_split) = self.groups.remove(&prefix) {
            let new_prefix = prefix.split();
            let (group1, group2) = to_split.into_iter()
                .partition::<HashSet<_>, _>(|name| prefix.matches(name));

            if self.our_group_prefix.is_neighbour(&prefix) {
                let _ = self.groups.insert(prefix, group1);
            } else {
                result = group1.into_iter().collect_vec();
            }

            if self.our_group_prefix.is_neighbour(&new_prefix) {
                let _ = self.groups.insert(new_prefix, group2);
            } else {
                result = group2.into_iter().collect_vec();
            }
        }
        result
    }

    // Removes a contact from the routing table.
    //
    // If no entry with that name is found, `None` is returned.  Otherwise, the entry is removed
    // from the routing table.  If, after removal, our group needs to merge, the appropriate targets
    // (all members of the merging groups) and the merge details they each need to receive (the new
    // prefix and all groups in the table) is returned, else `None` is returned.
    pub fn remove(&mut self, name: &T) -> Option<(Vec<T>, OwnMergeDetails<T>)> {
        let mut should_merge = false;
        if let Some(prefix) = self.find_group_prefix(name) {
            if let Some(group) = self.groups.get_mut(&prefix) {
                should_merge = group.remove(name) && prefix == self.our_group_prefix &&
                               group.len() < self.min_group_size && prefix.bit_count() != 0;
            }
        }
        if should_merge {
            let mut merged_prefix = self.our_group_prefix;
            merged_prefix.merge();
            let targets = self.groups
                .iter()
                .filter(|&(prefix, _)| merged_prefix.is_compatible(prefix))
                .flat_map(|(_, names)| names.iter())
                .cloned()
                .collect_vec();
            Some((targets,
                  OwnMergeDetails {
                prefix: merged_prefix,
                groups: self.groups.clone(),
            }))
        } else {
            None
        }
    }

    // Merges our own group and all existing compatible groups into the new one defined by
    // `merge_details.prefix`.
    //
    // The appropriate targets (all contacts which are not part of the merging groups) and the merge
    // details they each need to receive (the new prefix and the new group) is returned.
    pub fn merge_own_group(&mut self,
                           merge_details: &OwnMergeDetails<T>)
                           -> (Vec<T>, OtherMergeDetails<T>) {
        self.merge(&merge_details.prefix);

        // For each provided group which is not currently in our routing table and which is not one
        // of the merging groups, add an empty group and cache the corresponding contacts
        let mut needed = HashSet::<T>::new();
        for (prefix, contacts) in merge_details.groups
            .iter()
            .filter(|&(prefix, _)| !merge_details.prefix.is_compatible(prefix)) {
            if self.groups.entry(*prefix).or_insert_with(HashSet::new).is_empty() {
                self.needed.extend(contacts.iter());
                needed.extend(contacts.into_iter());
            }
        }

        // Find all contacts outwith the merging group
        let targets = self.groups
            .iter()
            .filter(|&(prefix, _)| !merge_details.prefix.is_compatible(prefix))
            .flat_map(|(_, names)| names.iter())
            .cloned()
            .collect_vec();

        // Return the targets and the new group
        let mut other_details = OtherMergeDetails {
            prefix: merge_details.prefix,
            group: unwrap!(self.groups.get(&merge_details.prefix)).clone(),
        };
        other_details.group.extend(needed.into_iter());
        (targets, other_details)
    }

    // Merges all existing compatible groups into the new one defined by `merge_details.prefix`.
    // Our own group is not included in the merge.
    //
    // The appropriate targets (all contacts from `merge_details.groups` which are not currently
    // held in the routing table) are returned so the caller can establish connections to these
    // peers and subsequently add them.
    pub fn merge_other_group(&mut self, merge_details: &OtherMergeDetails<T>) -> HashSet<T> {
        self.merge(&merge_details.prefix);

        // Establish list of provided contacts which are currently missing from our table.
        merge_details.group
            .difference(unwrap!(self.groups.get(&merge_details.prefix)))
            .cloned()
            .collect()
    }

    // Returns a collection of nodes to which a message with the given `Destination` should be sent
    // onwards.
    //
    // * If the destination is a group:
    //     - if our group is the closest on the network (i.e. our group's prefix is a prefix of the
    //       destination), returns all other members of our group; otherwise
    //     - if the closest group has fewer than `route` members, returns the `route`-th member of
    //       this group; otherwise
    //     - returns `Err(Error::CannotRoute)`
    //
    // * If the destination is an individual node:
    //     - if our name *is* the destination, returns `Err(Error::OwnName)`; otherwise
    //     - if the destination name is an entry in the routing table, returns it; otherwise
    //     - if our group is the closest on the network (i.e. our group's prefix is a prefix of the
    //       destination), this returns `Err(Error::NoSuchPeer)`; otherwise
    //     - if the closest group has fewer than `route` members, returns the `route`-th member of
    //       this group; otherwise
    //     - returns `Err(Error::CannotRoute)`
    pub fn targets(&self, dst: &Destination<T>, route: usize) -> Result<HashSet<T>, Error> {
        let (closest_group, target_name) = match *dst {
            Destination::Group(ref target_name) => {
                let closest_group_prefix = self.closest_group_prefix(target_name);
                if *closest_group_prefix == self.our_group_prefix {
                    return Ok(unwrap!(self.groups.get(closest_group_prefix)).clone());
                }
                // Safe to unwrap as we just chose `closest_group_prefix` from the list of groups
                (unwrap!(self.groups.get(closest_group_prefix)), target_name)
            }
            Destination::Node(ref target_name) => {
                if *target_name == self.our_name {
                    return Err(Error::OwnName);
                }
                let closest_group_prefix = self.closest_group_prefix(target_name);
                // Safe to unwrap as we just chose `closest_group_prefix` from the list of groups
                let closest_group = unwrap!(self.groups.get(closest_group_prefix));
                if closest_group.contains(target_name) {
                    return Ok([*target_name].iter().cloned().collect());
                } else if *closest_group_prefix == self.our_group_prefix {
                    return Err(Error::NoSuchPeer);
                }
                (closest_group, target_name)
            }
        };
        let mut names = closest_group.iter().collect_vec();
        names.sort_by(|&lhs, &rhs| target_name.cmp_distance(lhs, rhs));
        match names.get(route) {
            Some(&name) => Ok([*name].iter().cloned().collect()),
            None => Err(Error::CannotRoute),
        }
    }

    // Returns whether a `Destination` represents this node.
    //
    // Returns `true` if `dst` is a single node with name equal to `our_name`, or if `dst` is a
    // group and the closest group is our group.
    pub fn is_recipient(&self, dst: &Destination<T>) -> bool {
        match *dst {
            Destination::Node(ref target_name) => *target_name == self.our_name,
            Destination::Group(ref target_name) => self.our_group_prefix.matches(target_name),
        }
    }

    fn split_our_group(&mut self) {
        let our_group = unwrap!(self.groups.remove(&self.our_group_prefix));
        let (our_new_group, other_new_group) = our_group.into_iter()
            .partition::<HashSet<_>, _>(|name| {
                self.our_name.common_prefix(name) > self.our_group_prefix.bit_count()
            });
        let _ = self.groups.insert(self.our_group_prefix.split(), other_new_group);
        let _ = self.groups.insert(self.our_group_prefix, our_new_group);
    }

    fn merge(&mut self, new_prefix: &Prefix<T>) {
        // Partition the groups into those for merging and the rest
        let mut original_groups = Groups::new();
        mem::swap(&mut original_groups, &mut self.groups);
        let (groups_to_merge, mut groups) = original_groups.into_iter()
            .partition::<HashMap<_, _>, _>(|&(prefix, _)| new_prefix.is_compatible(&prefix));

        // Merge selected groups and add the merged group back in.
        let merged_names = groups_to_merge.into_iter()
            .flat_map(|(_, names)| names.into_iter())
            .collect::<HashSet<_>>();
        let _ = groups.insert(*new_prefix, merged_names);
        mem::swap(&mut groups, &mut self.groups);
        let merging_our_group = new_prefix.matches(&self.our_name);
        if merging_our_group {
            self.our_group_prefix = Prefix::new(new_prefix.bit_count(), self.our_name);
        }
    }

    fn get_group(&self, name: &T) -> Option<&HashSet<T>> {
        if let Some(prefix) = self.find_group_prefix(name) {
            return self.groups.get(&prefix);
        }
        None
    }

    fn get_mut_group(&mut self, name: &T) -> Option<&mut HashSet<T>> {
        if let Some(prefix) = self.find_group_prefix(name) {
            return self.groups.get_mut(&prefix);
        }
        None
    }

    // Returns the prefix of the group in which `name` belongs, or `None` if there is no such group
    // in the routing table.
    fn find_group_prefix(&self, name: &T) -> Option<Prefix<T>> {
        self.groups.keys().find(|&prefix| prefix.matches(name)).cloned()
    }

    // Returns the prefix of the group closest to `name`, regardless of whether `name` belongs in
    // that group or not.
    fn closest_group_prefix(&self, name: &T) -> &Prefix<T> {
        let mut keys = self.groups.keys().collect_vec();
        keys.sort_by(|&lhs, &rhs| lhs.cmp_distance(rhs, name));
        keys[0]
    }

    #[test]
    fn num_of_groups(&self) -> usize {
        self.groups.len()
    }
}

impl<T: Binary + Clone + Copy + Default + Hash + Xorable + Debug> Binary for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        try!(writeln!(formatter,
                      "RoutingTable {{\n\tour_name: {:08b},\n\tmin_group_size: \
                       {},\n\tour_group_prefix: {:?},",
                      self.our_name,
                      self.min_group_size,
                      self.our_group_prefix));
        let mut groups = self.groups.iter().collect_vec();
        groups.sort_by(|&(lhs_prefix, _), &(rhs_prefix, _)| {
            lhs_prefix.max_identical_index(&self.our_name)
                .cmp(&rhs_prefix.max_identical_index(&self.our_name))
        });
        for (group_index, &(prefix, group)) in groups.iter().enumerate() {
            try!(write!(formatter, "\tgroup {} with {:?}: {{\n", group_index, prefix));
            for (name_index, name) in group.iter().enumerate() {
                let comma = if name_index == group.len() - 1 {
                    ""
                } else {
                    ","
                };
                try!(writeln!(formatter, "\t\t{:08b}{}", name, comma));
            }
            let comma = if group_index == groups.len() - 1 {
                ""
            } else {
                ","
            };
            try!(writeln!(formatter, "\t}}{}", comma));
        }
        write!(formatter, "}}")
    }
}

impl<T: Binary + Clone + Copy + Default + Hash + Xorable + Debug> Debug for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}

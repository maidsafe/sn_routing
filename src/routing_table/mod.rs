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
#[derive(Debug)]
pub struct OwnMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    pub prefix: Prefix<T>,
    pub groups: Groups<T>,
}



// Used when merging our own group to send to peers outwith the new group
#[derive(Debug)]
pub struct OtherMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    pub prefix: Prefix<T>,
    pub group: HashSet<T>,
}



// Details returned by a successful `RoutingTable::remove()`.
#[derive(Debug)]
pub struct RemovalDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    // Peer name
    pub name: T,
    // True if the removed peer was in our group.
    pub was_in_our_group: bool,
    // If, after removal, our group needs to merge, this is set to `Some`. It contains the
    // appropriate targets (all members of the merging groups) and the merge details they each need
    // to receive (the new prefix and all groups in the table).
    pub targets_and_merge_details: Option<(Vec<T>, OwnMergeDetails<T>)>,
}



// A routing table to manage contacts for a node.
//
// It maintains a list of `T`s representing connected peer nodes, and provides algorithms for
// routing messages.
//
// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> {
    our_name: T,
    min_group_size: usize,
    our_group_prefix: Prefix<T>,
    groups: Groups<T>,
    needed: HashSet<T>,
}

impl<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> RoutingTable<T> {
    /// Create a new RoutingTable.
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

    pub fn our_group_prefix(&self) -> &Prefix<T> {
        &self.our_group_prefix
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

    /// Returns true if `name` is in our group (including if it is our own name).
    pub fn is_in_our_group(&self, name: &T) -> bool {
        if self.our_group_prefix.matches(name) {
            *name == self.our_name ||
            unwrap!(self.groups.get(&self.our_group_prefix)).contains(name)
        } else {
            false
        }
    }

    // Returns the list of contacts as a result of a merge to which we aren't currently connected,
    // but should be.
    pub fn needed(&self) -> &HashSet<T> {
        &self.needed
    }

    // Returns `Ok(())` if the given contact should be added to the routing table.
    //
    // Returns `Err` if `name` already exists in the routing table, or it doesn't fall within any
    // of our groups, or it's our own name.  Otherwise it returns `true`.
    pub fn need_to_add(&self, name: &T) -> Result<(), Error> {
        if *name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }
        if let Some(group) = self.get_group(name) {
            if group.contains(name) {
                Err(Error::AlreadyExists)
            } else {
                Ok(())
            }
        } else {
            Err(Error::PeerNameUnsuitable)
        }
    }

    // Adds a contact to the routing table.
    //
    // Returns `Err` if `name` already existed in the routing table, or it doesn't fall within any
    // of our groups, or it's our own name.  Otherwise it returns `Ok(true)` if the addition
    // succeeded and should cause our group to split or `Ok(false)` if the addition succeeded and
    // shouldn't cause a split.
    pub fn add(&mut self, name: T) -> Result<bool, Error> {
        if name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }

        if let Some(group) = self.get_mut_group(&name) {
            if !group.insert(name) {
                return Err(Error::AlreadyExists);
            }
        } else {
            return Err(Error::PeerNameUnsuitable);
        }

        let _ = self.needed.remove(&name);

        let our_group = unwrap!(self.groups.get(&self.our_group_prefix));
        // Count the number of names which will end up in our group if it is split (this
        // implies common prefix is 1 longer than existing prefix).
        let new_group_size = our_group.iter()
            .filter(|name| self.our_name.common_prefix(name) > self.our_group_prefix.bit_count())
            .count();
        // If either of the two new groups will not contain enough entries, return `None` (add 1
        // when considering our own group to also count ourself as a member of this group).
        let min_size = self.min_split_size();
        Ok(our_group.len() - new_group_size >= min_size && new_group_size + 1 >= min_size)
    }

    // Splits a group.
    //
    // If the group exists in the routing table, it is split, otherwise this function is a no-op.
    // If one of the two new groups doesn't satisfy the invariant (i.e. differs by more than one
    // bit from our own prefix), it is removed and those contacts are returned.
    pub fn split(&mut self, prefix: Prefix<T>) -> Vec<T> {
        let mut result = vec![];
        if prefix == self.our_group_prefix {
            self.split_our_group();
            return result;
        }

        if let Some(to_split) = self.groups.remove(&prefix) {
            let prefix0 = prefix.pushed(false);
            let prefix1 = prefix.pushed(true);
            let (group0, group1) = to_split.into_iter()
                .partition::<HashSet<_>, _>(|name| prefix0.matches(name));

            if self.our_group_prefix.is_neighbour(&prefix0) {
                let _ = self.groups.insert(prefix0, group0);
            } else {
                result.extend(group0);
            }

            if self.our_group_prefix.is_neighbour(&prefix1) {
                let _ = self.groups.insert(prefix1, group1);
            } else {
                result.extend(group1);
            }
        }
        result
    }

    // Removes a contact from the routing table.
    //
    // If no entry with that name is found, `Err(Error::NoSuchPeer)` is returned.  Otherwise, the
    // entry is removed from the routing table and `RemovalDetails` is returned.  See that struct's
    // docs for further info.
    pub fn remove(&mut self, name: &T) -> Result<RemovalDetails<T>, Error> {
        let mut should_merge = false;
        let mut removal_details = RemovalDetails {
            name: *name,
            was_in_our_group: false,
            targets_and_merge_details: None,
        };
        if let Some(prefix) = self.find_group_prefix(name) {
            removal_details.was_in_our_group = prefix == self.our_group_prefix;
            if let Some(group) = self.groups.get_mut(&prefix) {
                if !group.remove(name) {
                    return Err(Error::NoSuchPeer);
                }
                should_merge = removal_details.was_in_our_group &&
                               group.len() < self.min_group_size &&
                               prefix.bit_count() != 0;
            }
        } else {
            return Err(Error::NoSuchPeer);
        }
        if should_merge {
            let merged_prefix = self.our_group_prefix.popped();
            let targets = self.groups
                .iter()
                .filter(|&(prefix, _)| merged_prefix.is_compatible(prefix))
                .flat_map(|(_, names)| names.iter())
                .cloned()
                .collect_vec();
            removal_details.targets_and_merge_details = Some((targets,
                                                              OwnMergeDetails {
                prefix: merged_prefix,
                groups: self.groups.clone(),
            }));
        }
        Ok(removal_details)
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
        other_details.group.insert(self.our_name);
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
    // onwards.  In all non-error cases below, the returned collection will have the members of
    // `exclude` removed, possibly resulting in an empty set being returned.
    //
    // * If the destination is a group:
    //     - if our group is the closest on the network (i.e. our group's prefix is a prefix of the
    //       destination), returns all other members of our group; otherwise
    //     - if the closest group has more than `route` members, returns the `route`-th member of
    //       this group; otherwise
    //     - returns `Err(Error::CannotRoute)`
    //
    // * If the destination is an individual node:
    //     - if our name *is* the destination, returns `Err(Error::OwnName)`; otherwise
    //     - if the destination name is an entry in the routing table, returns it; otherwise
    //     - if our group is the closest on the network (i.e. our group's prefix is a prefix of the
    //       destination), this returns `Err(Error::NoSuchPeer)`; otherwise
    //     - if the closest group has more than `route` members, returns the `route`-th member of
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

    // Returns true if our name is the `route`-th closest to `src_name` in our group.
    //
    // Used when sending a message from a group to decide which one of the group should send the
    // full message (the remainder sending just a hash of the message).
    pub fn should_route_full_message(&self, src_name: &T, route: usize) -> bool {
        let mut our_group = unwrap!(self.groups.get(&self.our_group_prefix)).iter().collect_vec();
        our_group.push(&self.our_name);
        our_group.sort_by(|&lhs, &rhs| src_name.cmp_distance(lhs, rhs));
        match our_group.get(route) {
            Some(&name) => *name == self.our_name,
            None => false,
        }
    }

    fn split_our_group(&mut self) {
        let our_group = unwrap!(self.groups.remove(&self.our_group_prefix));
        let prefix0 = self.our_group_prefix.pushed(false);
        let prefix1 = self.our_group_prefix.pushed(true);
        let (group0, group1) = our_group.into_iter()
            .partition::<HashSet<_>, _>(|name| prefix0.matches(name));
        self.our_group_prefix = if prefix0.matches(&self.our_name) {
            prefix0
        } else {
            prefix1
        };
        let _ = self.groups.insert(prefix0, group0);
        let _ = self.groups.insert(prefix1, group1);
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
            self.our_group_prefix = *new_prefix;
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

    fn min_split_size(&self) -> usize {
        self.min_group_size + SPLIT_BUFFER
    }

    #[cfg(test)]
    fn num_of_groups(&self) -> usize {
        self.groups.len()
    }
}

impl<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> Binary for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        try!(writeln!(formatter,
                      "RoutingTable {{\n\tour_name: {},\n\tmin_group_size: \
                       {},\n\tour_group_prefix: {:?},",
                      self.our_name.debug_binary(),
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
                try!(writeln!(formatter, "\t\t{}{}", name.debug_binary(), comma));
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

impl<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> Debug for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::{Binary, Debug};
    use std::hash::Hash;

    // Must always be true (except while a function is running on the table).
    fn invariant<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable>
        (rt: &RoutingTable<T>)
         -> Result<(), &'static str> {
        if !rt.our_group_prefix.matches(&rt.our_name) {
            return Err("our prefix does not match our name");
        }
        if !rt.groups.contains_key(&rt.our_group_prefix) {
            return Err("our group not found");
        }
        let has_enough_nodes = rt.len() >= rt.min_group_size;
        for (prefix, group) in &rt.groups {
            // Only enforce group size when there are actually enough nodes!
            if has_enough_nodes && group.len() < rt.min_group_size {
                return Err("min group size not met");
            }
            for name in group {
                if !prefix.matches(name) {
                    return Err("name doesn't match group prefix");
                }
            }
        }
        // TODO: any other invariants to check? What about `rt.needed`?
        Ok(())
    }

    #[test]
    fn small() {
        let name = 123u32;
        let table = RoutingTable::new(name, 6);
        assert_eq!(*table.our_name(), name);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.iter().count(), 0);
    }

    // Test explicitly covers close_names(),  other_close_names(),
    // is_in_our_group() and need_to_add() while also implicitly testing
    // add() and split() through set-up of random groups with invariant.
    #[test]
    fn test_routing_groups() {
        // Use replicable random numbers to initialse a table:
        use rand::{Rng, SeedableRng, XorShiftRng};
        let mut rng: XorShiftRng = SeedableRng::from_seed([1315, 30, 61894, 315]);
        let our_name = rng.next_u32();
        let mut table = RoutingTable::new(our_name, 8);
        unwrap!(invariant(&table));
        let mut unknown_distant_name = None;

        for _ in 0..1000 {
            let new_name = rng.next_u32();
            // Try to add new_name. We double-check the output to test this too.
            match table.add(new_name) {
                Err(Error::AlreadyExists) => {
                    unwrap!(invariant(&table));
                    assert!(table.iter().any(|u| *u == new_name));
                    // skip
                }
                Err(Error::PeerNameUnsuitable) => {
                    unwrap!(invariant(&table));
                    assert!(table.groups.keys().all(|p| !p.matches(&new_name)));
                    // We should get a few of these. Save one for tests, but otherwise ignore.
                    unknown_distant_name = Some(new_name);
                }
                Err(_) => {
                    assert!(false); // no other errors should be possible
                }
                Ok(true) => {
                    unwrap!(invariant(&table));
                    let our_prefix = *table.our_group_prefix();
                    assert!(our_prefix.matches(&new_name));
                    let v = table.split(our_prefix);
                    unwrap!(invariant(&table));
                    // We just split our group: one half is new "our group", other is a neighbour
                    // so neither gets lost (hence 0 here).
                    assert!(v.len() == 0);
                }
                Ok(false) => {
                    unwrap!(invariant(&table));
                    assert!(table.iter().any(|u| *u == new_name));
                    if table.is_in_our_group(&new_name) {
                        continue;   // add() already checked for necessary split
                    }

                    // Not a split event for our group, but might be for a different group.
                    let group_prefix = table.find_group_prefix(&new_name)
                        .expect("get group added to");
                    let (group_len, new_group_size) = {
                        let group = table.groups.get(&group_prefix).expect("get group from prefix");
                        // Count size of group after an arbitrary split (note that there is only
                        // one split possible; the arbitrariness is just which half we choose here).
                        (group.len(),
                         group.iter()
                            .filter(|name| new_name.common_prefix(name) > group_prefix.bit_count())
                            .count())
                    };
                    let min_size = table.min_split_size();
                    if new_group_size >= min_size && group_len - new_group_size >= min_size {
                        let _ = table.split(group_prefix);  // do the split
                        unwrap!(invariant(&table));
                    }
                }
            }
        }

        let unknown_neighbour;
        loop {
            let new_name = rng.next_u32();
            if table.our_group_prefix.matches(&new_name) {
                continue;
            }
            if let Some(prefix) = table.groups.keys().find(|p| p.matches(&new_name)) {
                if !unwrap!(table.groups.get(&prefix)).contains(&new_name) {
                    unknown_neighbour = new_name;
                    break;
                }
            }
        }

        let unknown_distant_name = unwrap!(unknown_distant_name);
        // These numbers depend on distribution of names
        let num_known_nodes = 114;
        let num_groups = 9;
        let len_our_group = 13;
        assert_eq!(table.len(), num_known_nodes);
        assert_eq!(table.groups.len(), num_groups);
        assert_eq!(table.groups.get(&table.our_group_prefix).unwrap().len() + 1,
                   len_our_group);
        assert_eq!(our_name, table.our_name);

        // Get some names
        let close_name: u32 =
            *unwrap!(unwrap!(table.groups.get(&table.our_group_prefix)).iter().nth(4));
        let mut known_neighbour: Option<u32> = None;
        for (prefix, group) in &table.groups {
            if *prefix == table.our_group_prefix {
                continue;
            }
            known_neighbour = Some(*unwrap!(group.iter().next()));
            break;
        }
        let known_neighbour = unwrap!(known_neighbour);
        assert!(!table.our_group_prefix.matches(&known_neighbour));

        assert!(table.iter().any(|u| *u == close_name));
        assert!(table.iter().any(|u| *u == known_neighbour));
        assert!(table.iter().all(|u| *u != unknown_neighbour));
        assert!(table.iter().all(|u| *u != unknown_distant_name));
        assert!(table.is_in_our_group(&close_name));
        assert!(!table.is_in_our_group(&known_neighbour));

        // Tests on close_names
        assert_eq!(table.close_names(&close_name).unwrap().len(), len_our_group);
        assert!(table.close_names(&known_neighbour).is_none());
        assert!(table.close_names(&unknown_neighbour).is_none());
        assert!(table.close_names(&unknown_distant_name).is_none());

        // Tests on other_close_names
        assert_eq!(table.other_close_names(&close_name).unwrap().len(),
                   len_our_group - 1);
        assert!(table.other_close_names(&known_neighbour).is_none());
        assert!(table.other_close_names(&unknown_neighbour).is_none());
        assert!(table.other_close_names(&unknown_distant_name).is_none());

        // Tests on is_in_our_group
        assert!(table.is_in_our_group(&our_name));
        assert!(table.is_in_our_group(&close_name));
        assert!(!table.is_in_our_group(&known_neighbour));
        assert!(!table.is_in_our_group(&unknown_neighbour));
        assert!(!table.is_in_our_group(&unknown_distant_name));

        // Tests on need_to_add
        assert_eq!(table.need_to_add(&our_name), Err(Error::OwnNameDisallowed));
        assert_eq!(table.need_to_add(&close_name), Err(Error::AlreadyExists));
        assert_eq!(table.need_to_add(&known_neighbour),
                   Err(Error::AlreadyExists));
        assert_eq!(table.need_to_add(&unknown_neighbour), Ok(()));
        assert_eq!(table.need_to_add(&unknown_distant_name),
                   Err(Error::PeerNameUnsuitable));
    }
}

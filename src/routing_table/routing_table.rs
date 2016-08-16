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

use super::result::{AddedNodeDetails, DroppedNodeDetails};
use super::xorable::Xorable;

use itertools::*;
use std::{cmp, fmt, iter, mem, slice};

type SliceFn<T> = fn(&Vec<T>) -> slice::Iter<T>;

// Amount added to `min_group_size` when deciding whether a bucket split can happen.  This helps
// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 1;

// Immutable iterator over the entries of a `RoutingTable`.
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

// A message destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Destination<N> {
    // The `k`-group of the given address. The message should reach the `k` closest nodes.
    Group(N, usize),
    // The individual node at the given address. The message should reach exactly one node.
    Node(N),
}

impl<N> Destination<N> {
    // Returns the name of the destination, i.e. the node or group address.
    pub fn name(&self) -> &N {
        match *self {
            Destination::Group(ref name, _) |
            Destination::Node(ref name) => name,
        }
    }

    // Returns `true` if the destination is a group, and `false` if it is an individual node.
    pub fn is_group(&self) -> bool {
        match *self {
            Destination::Group(_, _) => true,
            Destination::Node(_) => false,
        }
    }

    // Returns `true` if the destination is an individual node, and `false` if it is a group.
    pub fn is_node(&self) -> bool {
        !self.is_group()
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Prefix<T: Xorable> {
    // The length of the prefix.
    valid_bit_count: usize,
    // A member address bearing the prefix.
    address: T,
}

impl<T> Prefix<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    pub fn new(valid_bit_count: usize, address: T) -> Self {
        Prefix {
            valid_bit_count: valid_bit_count,
            address: address,
        }
    }

    // Returns the copy of the original prefix
    pub fn move_one_bit(&mut self) -> Self {
        let prefix = self.clone();
        self.address = self.address.with_flipped_bit(self.valid_bit_count);
        self.valid_bit_count += 1;
        prefix
    }

    pub fn belongs_to(&self, name: &T) -> bool {
        self.address.max_bucket_index(name) >= self.valid_bit_count
    }

    pub fn increase_valid_bit_count(&mut self) {
        self.valid_bit_count += 1;
    }

    pub fn decrease_valid_bit_count(&mut self) {
        self.valid_bit_count -= 1;
    }

    pub fn max_bucket_index(&self, name: &T) -> usize {
        cmp::min(self.valid_bit_count, self.address.max_bucket_index(name))
    }

    pub fn max_identical_index(&self, name: &T) -> usize {
        self.address.max_bucket_index(name)
    }

    pub fn address(&self) -> &T {
        &self.address
    }
}

impl<T> fmt::Binary for Prefix<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Prefix (valid_bit_count: {}, address: {:08b}", self.valid_bit_count, self.address)
    }
}

impl<T> fmt::Debug for Prefix<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Prefix (valid_bit_count: {}, address: {:08b}", self.valid_bit_count, self.address)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CloseGroup<T: Xorable> {
    min_group_size: usize,
    prefix: Prefix<T>,
    members: Vec<T>,
}

impl<T> CloseGroup<T> where T: Clone + Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    pub fn new(min_group_size: usize, prefix: Prefix<T>, members: Vec<T>) -> Self {
        CloseGroup {
            min_group_size: min_group_size,
            prefix: prefix,
            members: members,
        }
    }

    pub fn prefix(&self) -> &Prefix<T> {
        &self.prefix
    }

    pub fn members(&self) -> &Vec<T> {
        &self.members
    }

    pub fn belongs_to(&self, name: &T) -> bool {
        self.prefix.belongs_to(name)
    }

    pub fn contains(&self, name: &T) -> bool {
        match self.search(&name) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn add(&mut self, member: T) -> bool {
        if !self.belongs_to(&member) {
            return false;
        }
        match self.search(&member) {
            Ok(_) => false,
            Err(index) => {
                self.members.insert(index, member);
                true
            }
        }
    }

    pub fn remove(&mut self, name: &T) -> bool {
        match self.search(name) {
            Ok(index) => {
                let _ = self.members.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    // Returns a new split off group or None if doesn't need to split
    pub fn split(&mut self) -> Option<Self> {
        match self.split_position() {
            Some(split_position) => {
                let mut new_prefix = self.prefix.clone();
                self.prefix.increase_valid_bit_count();
                let _ = new_prefix.move_one_bit();
                let split_off = self.members.split_off(split_position);
                Some(CloseGroup::new(self.min_group_size, new_prefix, split_off))
            }
            None => None,
        }
    }

    // Returns whether the group should be split
    pub fn should_split(&self) -> bool {
        match self.split_position() {
            Some(_) => true,
            None => false,
        }
    }

    // Returns the new group after merge
    fn merge(&mut self, merging_in_group: &CloseGroup<T>) -> Option<CloseGroup<T>> {
        if self.prefix.belongs_to(merging_in_group.prefix.address()) {
            let new_members = self.members.iter()
                .chain(merging_in_group.members().clone().iter())
                .cloned()
                .collect_vec();
            self.members = new_members;
            return Some(self.clone());
        }
        None
    }

    pub fn max_bucket_index(&self, name: &T) -> usize {
        self.prefix.max_bucket_index(name)
    }

    pub fn max_identical_index(&self, name: &T) -> usize {
        self.prefix.max_identical_index(name)
    }

    // Checks to see if the group can be split.  This returns `Some` if:
    //  - a new group can be created which will contain at least `min_bucket_len + SPLIT_BUFFER`
    //    contacts with CLBs > current valid_bit_count
    //  - there are at least `min_bucket_len + SPLIT_BUFFER` contacts left in this current group
    //
    // The value of a `Some` result is the position at which should be split off.
    fn split_position(&self) -> Option<usize> {
        // Find position at which the group will split and check that each part will contain
        // enough contacts.
        let min_contacts = self.min_group_size + SPLIT_BUFFER;
        match self.members.iter().position(|ref contact| self.prefix.address.max_bucket_index(contact) == self.prefix.valid_bit_count) {
            Some(position) => {
                if position < min_contacts || self.members.len() - position < min_contacts {
                    return None;
                }
                Some(position)
            },
            None => None,
        }
    }

    fn search(&self, name: &T) -> Result<usize, usize> {
        self.members.binary_search_by(|member| member.cmp(name))
    }
}

impl<T> fmt::Binary for CloseGroup<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(formatter, "\t\tGroup {{ {:?}", self.prefix));
        for (member_index, member) in self.members.iter().enumerate() {
            let comma = if member_index == self.members.len() - 1 { "]" } else { "," };
            try!(writeln!(formatter, "\t\t\t{:08b} {} ", member, comma));
        }
        write!(formatter, " \t\t}}")
    }
}

impl<T> fmt::Debug for CloseGroup<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(formatter, "\t\tGroup {{ {:?}", self.prefix));
        for (member_index, member) in self.members.iter().enumerate() {
            let comma = if member_index == self.members.len() - 1 { "]" } else { "," };
            try!(writeln!(formatter, "\t\t\t{:08b} {} ", member, comma));
        }
        write!(formatter, " \t\t}}")
    }
}

// A routing table to manage contacts for a node.
//
// It maintains a list of `T::Name`s representing connected peer nodes, and provides algorithms for
// routing messages.
//
// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: Xorable>  {
    // This nodes' own contact info.
    our_info: T,
    // The minimum group size.
    min_group_size: usize,  // 2 * (GROUP_ZISE + SPLIT_BUFFER)  = 20 starts split
    // The buckets, by bucket index. Each bucket contains groups bearing the prefix.
    // The last bucket shall always contain only one group which is us belong to.
    // TODO: change the data struct to HashMap<Prefix, Vec<Group>>?
    buckets: Vec<(Prefix<T>, Vec<CloseGroup<T>>)>,
}

impl<T> RoutingTable<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    // Creates a new routing table for the node with the given info.
    //
    // `bucket_size` specifies the minimum number of bucket entries: Whenever a new node joins the
    // network which belongs to a bucket with `< bucket_size` entries, it _must_ be added to that
    // bucket. This guarantees that all nodes know which `k`-groups they belong to, for each
    // `k <= bucket_size`.
    //
    // In excess of `bucket_size`, `extra_entries` are considered desired in each bucket. After
    // that, additional entries are considered unneeded: If both sides agree, they should
    // disconnect.
    pub fn new(our_info: T, min_group_size: usize) -> Self {
        RoutingTable {
            our_info: our_info,
            min_group_size: min_group_size,
            buckets: vec![],
        }
    }

    // Number of entries in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().fold(0, |acc, bucket| acc + bucket.1.iter().fold(0, |acc, group| acc + group.len()))
    }

    // Adds a contact to the routing table.
    //
    // Returns `None` if the contact already existed or was denied (see `allow_connection`).
    // Otherwise it returns `AddedNodeDetails`.
    pub fn add(&mut self, info: T) -> Option<AddedNodeDetails<T>> {
        if info == *self.our_name() || info == T::all_zero_copy() {
            return None;
        }
        if self.buckets.len() == 0 {
            let bucket_prefix = Prefix::new(0, self.our_name().clone());
            let group_prefix = Prefix::new(0, T::all_zero_copy());
            let group = CloseGroup::new(self.min_group_size, group_prefix, vec![info]);
            self.buckets.push((bucket_prefix, vec![group]));
            return Some(AddedNodeDetails::<T> {
                            unneeded: vec![],
                        });
        }
        match self.search(&info) {
            (Err(_), _) => None,
            (Ok(bucket_index), Ok(group_index)) => None,
            (Ok(bucket_index), Err(group_index)) => {
                let _ = self.buckets[bucket_index].1[group_index].add(info);
                self.split_last_bucket();
                // TODO: a possible split alert for `our_group` ?
                Some(AddedNodeDetails {
                    unneeded: vec![],
                })
            }
        }
    }

    // Resturns the indexing of the group that should be split
    pub fn should_split(&self) -> Option<(usize, usize)> {
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            for (group_index, group) in bucket.1.iter().enumerate() {
                if group.should_split() {
                    return Some((bucket_index, group_index));
                }
            }
        }
        None
    }

    pub fn split(&mut self) {
        self.split_last_bucket();
        if let Some((bucket_index, group_index)) = self.should_split() {
            let split_result = self.buckets[bucket_index].1[group_index].split();
            match split_result {
                Some(split_off_group) => self.buckets[bucket_index].1.push(split_off_group),
                None => {}
            }
        }
    }

    pub fn connected_peers(&self) -> Vec<T> {
        let mut connected_peers = vec![];
        for bucket in self.buckets.iter() {
            for group in bucket.1.iter() {
                connected_peers.append(&mut group.members().clone());
            }
        }
        connected_peers
    }

    // Split only carries out for the last bucket and once it happens, only update the group prefix
    // for each bucket, say bucket 1 changing from 010 to 0100. But the members won't be updated
    // untill received merge_group message, i.e. calling split_group function
    fn split_last_bucket(&mut self) {
        let last_bucket_index = self.buckets.len() - 1;
        let split_result = self.buckets[last_bucket_index].1[0].split();
        match split_result {
            Some(split_off_group) => {
                let mut old_bucket_prefix = self.buckets[last_bucket_index].0.move_one_bit();
                if self.buckets.len() - 1 > 0 {
                    for i in 0..(self.buckets.len() - 1) {
                        self.buckets[i].0.increase_valid_bit_count();
                    }
                }
                old_bucket_prefix.increase_valid_bit_count();

                if T::all_zero_copy().differs_in_bit(&self.our_info, last_bucket_index) {
                    self.buckets.push((old_bucket_prefix, vec![split_off_group]));
                } else {
                    let swap_group = self.buckets[last_bucket_index].1[0].clone();
                    self.buckets[last_bucket_index].1[0] = split_off_group;
                    self.buckets.push((old_bucket_prefix, vec![swap_group]));
                }
            }
            None => {}
        }
    }

    // Removes the contact from the table.
    //
    // If no entry with that name is found, `None` is returned. Otherwise, the entry is removed
    // from the routing table and `DroppedNodeDetails` are returned.
    pub fn remove(&mut self, name: &T) -> Option<DroppedNodeDetails> {
        if let (Ok(bucket_index), Ok(group_index)) = self.search(name) {
            let _ = self.buckets[bucket_index].1[group_index].remove(name);
            // TODO: merge notification
            Some(DroppedNodeDetails { merged_bucket: None })
        } else {
            None
        }
    }

    // Returns the new group after merge
    pub fn merge(&mut self) -> Option<CloseGroup<T>> {
        let last_bucket = self.buckets.len() - 1;
        if self.buckets[last_bucket].1[0].len() < self.min_group_size {
            if self.buckets.len() - 1 > 0 {
                for i in 0..(self.buckets.len() - 1) {
                    self.buckets[i].0.decrease_valid_bit_count();
                }
            }
        }

        if let Some((bucket_index, group_index)) = self.should_merge() {
            let removed_group = self.buckets[bucket_index].1.remove(group_index);
            if self.buckets[bucket_index].1.len() == 0 {
                let _ = self.buckets.remove(bucket_index);
            }
            return self.merge_group(&removed_group);
        }
        None
    }

    // Resturns the indexing of the group that should be merged into other
    pub fn should_merge(&self) -> Option<(usize, usize)> {
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            for (group_index, group) in bucket.1.iter().enumerate() {
                if group.len() < self.min_group_size {
                    return Some((bucket_index, group_index));
                }
            }
        }
        None
    }

    // Returns the new group after merge
    fn merge_group(&mut self, merging_in_group: &CloseGroup<T>) -> Option<CloseGroup<T>> {
        for bucket in self.buckets.iter_mut() {
            for group in bucket.1.iter_mut() {
                match group.merge(merging_in_group) {
                    Some(new_group) => return Some(new_group),
                    None => {}
                }
            }
        }
        None
    }

    // // DroppedNodeDetails shall now contains the nodes that to be disconnected
    // pub fn split_group(old_group: Group, new_groups: (Group, Group) ) -> DroppedNodeDetails {

    // }

    // // ConnectNodeDetails shall now contains the nodes that to connect
    // pub fn merge_group(group: Group) -> ConnectNodeDetails {
    // }


    // Returns whether the given contact should be added to the routing table.
    //
    // Returns `true` if the contact falls in any group we known, otherwise return `false`

    // TODO: probably won't be required as later on a confirmation from GROUP is required any way
    pub fn allow_to_add(&self, name: &T) -> bool {
        if name == self.our_name() {
            return false;
        }
        if self.buckets.len() == 0 {
            return true;
        }
        match self.search(name) {
            (Ok(_), Ok(_)) => false,  // They already are in our routing table.
            (Ok(_), Err(_)) => true,
            (Err(_), _) => true,  // Not falls in any group
        }
    }

    // Returns the name of the node this routing table is for.
    pub fn our_name(&self) -> &T {
        &self.our_info
    }

    // Checks whether the routing table contains the specified name.
    pub fn contains(&self, name: &T) -> bool {
        if let (_, Ok(_)) = self.search(name) {
            true
        } else {
            false
        }
    }

    // Returns `true` whenever the name belongs to our_group, otherwise returns `false`
    pub fn is_close(&self, name: &T) -> bool {
        if self.buckets.len() == 0 {
            true
        } else {
            self.buckets[self.buckets.len() - 1].1[0].belongs_to(name)
        }
    }

    // Returns the Group that name belongs to or the closest Group we know
    // or just return ALL nodes sorted/truncated to GROUP_SIZE, as this function may not needed later on
    fn closest_nodes_to(&self, target: &T, n: usize, ourselves: bool) -> Vec<T> {
        if self.buckets.len() == 0 {
            return vec![];
        }
        let mut closest_group = &self.buckets[0].1[0];
        let mut max_bucket_index = 0;
        for bucket in self.buckets.iter() {
            for group in bucket.1.iter() {
                let common_bits = group.max_identical_index(target);
                if common_bits >= max_bucket_index {
                    max_bucket_index = common_bits;
                    closest_group = group;
                }
            }
        }
        closest_group.members().clone()
    }

    // Returns the members of the group that name belongs to or the closest Group we know
    pub fn close_nodes(&self, target: &T) -> Option<Vec<T>> {
        let mut result = None;
        let mut max_bucket_index = 0;
        for bucket in self.buckets.iter() {
            for group in bucket.1.iter() {
                let common_bits = group.max_bucket_index(target);
                if common_bits >= max_bucket_index {
                    max_bucket_index = common_bits;
                    result = Some(group.members().clone());
                }
            }
        }
        result
    }

    // Returns a collection of nodes to which a message should be sent onwards.
    //
    // If the message is addressed at a group we are a member of, this returns all other members of
    // that group.
    //
    // If the message is addressed at an individual node that is directly connected to us, this
    // returns the destination node.
    //
    // If we are the individual recipient, it also returns an empty collection.
    //
    // Otherwise it returns the `n`-th closest node to the target if route is `n`.
    //
    // # Arguments
    //
    // * `dst` -   The destination of the message.
    // * `hop` -   The name of the node that relayed the message to us, or ourselves if we are the
    //             original sender.
    // * `route` - The route number.
    pub fn target_nodes(&self, dst: Destination<T>, hop: &T, route: usize) -> Vec<T> {
        let target = match dst {
            Destination::Group(ref target, group_size) => {
                if let Some(mut group) = self.other_close_nodes(target, group_size) {
                    group.retain(|t| *t != *hop);
                    return group;
                }
                target
            }
            Destination::Node(ref target) => {
                if target == self.our_name() {
                    return vec![];
                } else if self.contains(target) {
                    return vec![target.clone()];
                } else {
                    if let Some(mut group) = self.other_close_nodes(target, self.min_group_size) {
                        return group;
                    }
                }
                target
            }
        };
        self.closest_nodes_to(target, route + 2, false)
            .into_iter()
            .filter(|node| *node != *hop)
            .skip(route)
            .take(1)
            .collect()
    }

    // Returns whether the message is addressed to this node.
    //
    // If this returns `true`, this node is either the single recipient of the message, or a
    // member of the group authority to which it is addressed. It therefore needs to handle the
    // message.
    pub fn is_recipient(&self, dst: Destination<T>) -> bool {
        match dst {
            Destination::Node(ref target) => target == self.our_name(),
            Destination::Group(ref target, group_size) => self.is_close(target),
        }
    }

    // Returns the other members of `name`'s close group, or `None` if we are not a member of it.
    pub fn other_close_nodes(&self, name: &T, _group_size: usize) -> Option<Vec<T>> {
        if self.is_close(name) {
            Some(self.buckets[self.buckets.len() - 1].1[0].members().clone())
        } else {
            None
        }
    }

    // // Merges all buckets in position >= `index` into a single bucket.
    // fn merge_buckets(&mut self, index: usize) {
    //     let mut temp = vec![];
    //     let count = self.buckets.len() - index;
    //     for bucket in self.buckets.iter_mut().rev().take(count) {
    //         temp.append(bucket);
    //     }
    //     mem::swap(&mut temp, &mut self.buckets[index]);
    //     self.buckets.truncate(index + 1);
    // }

    fn bucket_index(&self, name: &T) -> usize {
        cmp::min(self.our_info.max_bucket_index(name), self.buckets.len() - 1)
    }

    // Searches the routing table for the given name.
    //
    // Returns a tuple with the bucket index of `name` as the first entry, `Ok(index)` if there is
    // bucket containing a group this node belongs to, `Err` if no such group. The second entry is
    // `Ok(i)` if the node exists in `i`th group in that bucket, or `Err(i)` if it isn't there yet
    // and `i` is the group index inside the bucket where it would be inserted.
    fn search(&self, name: &T) -> (Result<usize, usize>, Result<usize, usize>) {
        let bucket_index = self.bucket_index(name);
        match self.buckets.get(bucket_index) {
            None => (Err(0), Err(0)),
            Some(bucket) => {
                for (index, group) in bucket.1.iter().enumerate() {
                    if group.belongs_to(name) {
                        if group.contains(name) {
                            return (Ok(bucket_index), Ok(index));
                        } else {
                            return (Ok(bucket_index), Err(index));
                        }
                    }
                }
                // The node doesn't fall in any group
                (Err(0), Err(0))
            }
        }
    }
}

impl<T> fmt::Binary for RoutingTable<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(formatter,
               "RoutingTable {{\n\tour_info: {:08b},\n\tmin_group_size: {},", self.our_info, self.min_group_size));
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            try!(write!(formatter, "\tbucket {} : {:?} \n", bucket_index, bucket.0));
            for (group_index, group) in bucket.1.iter().enumerate() {
                let comma = if group_index == bucket.1.len() - 1 { "" } else { "\n" };
                try!(write!(formatter, "{:?} {}", group, comma));
            }
            let comma = if bucket_index == self.buckets.len() - 1 { "" } else { "," };
            try!(writeln!(formatter, "]{}", comma));
        }
        write!(formatter, "}}")
    }
}

impl<T> fmt::Debug for RoutingTable<T> where T: Clone +  Ord + PartialEq + Xorable + fmt::Binary + fmt::Debug {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(formatter,
               "RoutingTable {{\n\tour_info: {:08b},\n\tmin_group_size: {},", self.our_info, self.min_group_size));
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            try!(write!(formatter, "\tbucket {} : {:?} \n", bucket_index, bucket.0));
            for (group_index, group) in bucket.1.iter().enumerate() {
                let comma = if group_index == bucket.1.len() - 1 { "" } else { "\n" };
                try!(write!(formatter, "{:?} {}", group, comma));
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
        for i in 1u16..256 {
            let node = (256u16 - i) as u8;
            let _ = table.add(node);
            // print!("{:08b}  {}   ", i, 0u8.bucket_index(&(i as u8)));
            // for b in 0..8 {
            //     print!("{:7}", 0u8.differs_in_bit(&(i as u8), b));
            // }
            // println!("");
        }

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
        // match table.remove(&0b10101111) {
        //     Some(result) => println!("Merged bucket {}\n{:b}\n", unwrap!(result.merged_bucket), table),
        //     None => panic!(),
        // }
        assert!(unwrap!(table.remove(&0b10101111)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001010)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001011)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001000)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001001)).merged_bucket.is_none());
        assert!(unwrap!(table.remove(&0b10001110)).merged_bucket.is_none());
        // match table.remove(&0b10001111) {
        //     Some(result) => println!("Merged bucket {}\n{:b}\n", unwrap!(result.merged_bucket), table),
        //     None => panic!(),
        // }
        assert!(unwrap!(table.remove(&0b10001111)).merged_bucket.is_none());
    }
}

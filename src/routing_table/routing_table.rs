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

use super::contact_info::ContactInfo;
use super::result::{AddedNodeDetails, DroppedNodeDetails};
use super::xorable::Xorable;

use itertools::*;
use std::{cmp, fmt, iter, mem, slice};

type SliceFn<T> = fn(&Vec<T>) -> slice::Iter<T>;

// Amount added to `min_bucket_len` when deciding whether a bucket split can happen.  This helps
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

    // Returns `true` if the destination os a group, and `false` if it is an individual node.
    pub fn is_group(&self) -> bool {
        match *self {
            Destination::Group(_, _) => true,
            Destination::Node(_) => false,
        }
    }
}


// A routing table to manage contacts for a node.
//
// It maintains a list of `T::Name`s representing connected peer nodes, and provides algorithms for
// routing messages.
//
// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: ContactInfo> {
    // This nodes' own contact info.
    our_info: T,
    // The minimum bucket size.
    min_bucket_len: usize,
    // The buckets, by bucket index. Each bucket is sorted by ascending distance from us.
    buckets: Vec<Vec<T>>,
}

impl<T> RoutingTable<T>
    where T: ContactInfo + fmt::Binary + fmt::Debug,
          T::Name: PartialEq + Xorable + fmt::Binary + fmt::Debug
{
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
    pub fn new(our_info: T, min_bucket_len: usize) -> Self {
        RoutingTable {
            buckets: vec![vec![]],
            our_info: our_info,
            min_bucket_len: min_bucket_len,
        }
    }

    // Number of entries in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().fold(0, |acc, bucket| acc + bucket.len())
    }

    // Adds a contact to the routing table, or updates it.
    //
    // Returns `None` if the contact already existed or was denied (see `allow_connection`).
    // Otherwise it returns `AddedNodeDetails`.
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
                }

                Some(AddedNodeDetails {
                    unneeded: unneeded,
                })
            }
        }
    }

    // Returns the contact associated with the given name.
    pub fn get(&self, name: &T::Name) -> Option<&T> {
        if let (bucket_index, Ok(node_index)) = self.search(name) {
            Some(&self.buckets[bucket_index][node_index])
        } else if name == self.our_name() {
            Some(&self.our_info)
        } else {
            None
        }
    }

    // Returns whether the given contact should be added to the routing table.
    //
    // Returns `false` if adding the contact in question would not bring the routing table closer
    // to satisfy the invariant. It returns `true` if and only if the new contact would be among
    // the `bucket_size` closest nodes in its bucket.
    pub fn need_to_add(&self, name: &T::Name) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => false,  // They already are in our routing table.
            (bucket_index, Err(_)) => self.prefix_invariant_holds(bucket_index, name),
        }
    }

    // Removes the contact from the table.
    //
    // If no entry with that name is found, `None` is returned. Otherwise, the entry is removed
    // from the routing table and `DroppedNodeDetails` are returned.
    pub fn remove(&mut self, name: &T::Name) -> Option<DroppedNodeDetails> {
        if let (bucket_index, Ok(contact_index)) = self.search(name) {
            let _ = self.buckets[bucket_index].remove(contact_index);
            let mut result = DroppedNodeDetails { merged_bucket: None };
            // Only merging the last bucket when it contains not enough elements
            if bucket_index == self.buckets.len() - 1 &&
               self.buckets[bucket_index].len() < self.min_bucket_len {
                let merge_index = bucket_index - 1;
                self.merge_buckets(merge_index);
                result.merged_bucket = Some(merge_index);
            }
            Some(result)
        } else {
            None
        }
    }

    // Returns the name of the node this routing table is for.
    pub fn our_name(&self) -> &T::Name {
        self.our_info.name()
    }

    // Check whether contains the specific name
    pub fn contains(&self, name: &T::Name) -> bool {
        if let (_, Ok(_)) = self.search(name) {
            true
        } else {
            false
        }
    }

    // Returns `true` if there are fewer than `GROUP_SIZE` nodes in our routing table that are
    // closer to `name` than we are.
    //
    // In other words, it returns `true` whenever we cannot rule out that we might be among the
    // `group_size` closest nodes to `name`.
    //
    // If the routing table is filled in such a way that each bucket contains `group_size`
    // elements unless there aren't enough such nodes in the network, then this criterion is
    // actually sufficient! In that case, `true` is returned if and only if we are among the
    // `group_size` closest node to `name` in the network.
    pub fn is_close(&self, name: &T::Name, group_size: usize) -> bool {
        let differ_index = self.our_name().max_bucket_index(name);
        let result = if differ_index < self.buckets.len() - 1 {
            // Buckets only got merged when the last one is short of elements
            if self.buckets[differ_index].len() < group_size {
                let mut bucket_copy = self.buckets[differ_index + 1].clone();
                bucket_copy.sort_by(|node0, node1| name.cmp_distance(&node0.name(), &node1.name()));
                name.cmp_distance(&self.our_name(), &bucket_copy[group_size - self.buckets[differ_index].len() - 1].name()) == cmp::Ordering::Less
            } else {
                false
            }
        } else {
            if self.buckets[self.buckets.len() - 1].len() < group_size {
                true
            } else {
                let mut bucket_copy = self.buckets[self.buckets.len() - 1].clone();
                bucket_copy.sort_by(|node0, node1| name.cmp_distance(&node0.name(), &node1.name()));
                name.cmp_distance(&self.our_name(), &bucket_copy[group_size - 1].name()) == cmp::Ordering::Less
            }
        };
        info!("our_name {:64b} target {:64b} differ_index {:?} buckets {:?} result {:?}",
              self.our_name(), name, differ_index, self.buckets, result);
        result
    }

    // Returns the `n` nodes in our routing table that are closest to `target`.
    //
    // Returns fewer than `n` nodes if the routing table doesn't have enough entries. If
    // `ourselves` is `true`, this could potentially include ourselves. Otherwise, our own name is
    // skipped.
    pub fn closest_nodes_to(&self, target: &T::Name, n: usize, ourselves: bool) -> Vec<T> {
        let cmp = |a: &&T, b: &&T| target.cmp_distance(a.name(), b.name());
        // If we disagree with target in a bit, that bit's bucket contains contacts that are closer
        // to the target than we are. The lower the bucket index, the closer it is:
        let closer_buckets_iter = self.buckets
            .iter()
            .enumerate()
            .filter(|&(bit, _)| self.our_name().differs_in_bit(target, bit))
            .flat_map(|(_, b)| b.iter().sorted_by(&cmp).into_iter());
        // Nothing or ourselves, depending on whether we should be include in the result:
        let ourselves_iter = if ourselves {
            Some(&self.our_info).into_iter()
        } else {
            None.into_iter()
        };
        // If we agree with target in a bit, that bit's bucket contains contacts that are further
        // away from the target than we are. The lower the bucket index, the further away it is:
        let further_buckets_iter = self.buckets
            .iter()
            .enumerate()
            .rev()
            .filter(|&(bit, _)| !self.our_name().differs_in_bit(target, bit))
            .flat_map(|(_, b)| b.iter().sorted_by(&cmp).into_iter());
        // Chaining these iterators puts the buckets in the right order, with ascending distance
        // from the target. Finally, we need to sort each bucket's contents and take n:
        closer_buckets_iter.chain(ourselves_iter)
            .chain(further_buckets_iter)
            .take(n)
            .cloned()
            .collect()
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
    pub fn target_nodes(&self, dst: Destination<T::Name>, hop: &T::Name, route: usize) -> Vec<T> {
        let target = match dst {
            Destination::Group(ref target, group_size) => {
                if let Some(mut group) = self.other_close_nodes(target, group_size) {
                    group.retain(|t| t.name() != hop);
                    return group;
                }
                target
            }
            Destination::Node(ref target) => {
                if target == self.our_name() {
                    return vec![];
                } else if let Some(target_contact) = self.get(target) {
                    return vec![target_contact.clone()];
                } else if self.is_close(target, self.min_bucket_len) {
                    return self.closest_nodes_to(target, self.min_bucket_len - 1, false);
                }
                target
            }
        };
        self.closest_nodes_to(target, route + 2, false)
            .into_iter()
            .filter(|node| node.name() != hop)
            .skip(route)
            .take(1)
            .collect()
    }

    // Returns whether the message is addressed to this node.
    //
    // If this returns `true`, this node is either the single recipient of the message, or a
    // member of the group authority to which it is addressed. It therefore needs to handle the
    // message.
    pub fn is_recipient(&self, dst: Destination<T::Name>) -> bool {
        match dst {
            Destination::Node(ref target) => target == self.our_name(),
            Destination::Group(ref target, group_size) => self.is_close(target, group_size),
        }
    }

    // Returns the other members of `name`'s close group, or `None` if we are not a member of it.
    pub fn other_close_nodes(&self, name: &T::Name, group_size: usize) -> Option<Vec<T>> {
        if self.is_close(name, group_size) {
            Some(self.closest_nodes_to(name, group_size - 1, false))
        } else {
            None
        }
    }

    // Returns whether we can allow the given contact to connect to us.
    //
    // The connection is allowed if:
    //
    // * they already are one of our contacts,
    // * we need them in our routing table to satisfy the invariant or
    // * we are in the `bucket_size`-group of one of their bucket addresses.
    pub fn allow_connection(&self, name: &T::Name) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => true,
            (_, Err(i)) => i < self.min_bucket_len || self.is_close_to_bucket_of(name),
        }
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

    // Returns whether we are `bucket_size`-close to one of `name`'s bucket addresses or to `name`
    // itself.
    fn is_close_to_bucket_of(&self, name: &T::Name) -> bool {
        // We are close to `name` if the buckets where `name` disagrees with us have less than
        // `bucket_size` entries in total. Therefore we are close to a bucket address of `name`, if
        // removing the largest such bucket gets us below `bucket_size`.
        let mut closer_contacts: usize = 0;
        let mut largest_bucket: usize = 0;
        for (bit, bucket) in self.buckets.iter().enumerate() {
            if self.our_name().differs_in_bit(name, bit) {
                largest_bucket = cmp::max(largest_bucket, bucket.len());
                closer_contacts += bucket.len();
                if closer_contacts >= largest_bucket + self.min_bucket_len {
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

    // This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    // bits" means the most significant bits.
    fn max_bucket_index(&self, name: &T::Name) -> usize {
        self.our_name().max_bucket_index(name)
    }

    fn bucket_index(&self, name: &T::Name) -> usize {
        cmp::min(self.max_bucket_index(name), self.buckets.len() - 1)
    }

    // Searches the routing table for the given name.
    //
    // Returns a tuple with the bucket index of `name` as the first entry. The second entry is
    // `Ok(i)` if the node has index `i` in that bucket, or `Err(i)` if it isn't there yet and `i`
    // is the index inside the bucket where it would be inserted.
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
where T: ContactInfo + fmt::Binary + fmt::Debug,
      T::Name: PartialEq + Xorable + fmt::Binary + fmt::Debug {
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

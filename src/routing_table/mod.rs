// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
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
// * Otherwise, if the destination is a `k`-close group with `k <= group_size`, the message
//   will reach every member of the `k`-close group of the destination address, i.e. all `k` nodes
//   in the network that are XOR-closest to that address, and each node knows whether it belongs to
//   that group.
// * Each node in a given address' close group is connected to each other node in that section. In
//   particular, every node is connected to its own close group.
// * The number of total hop messages created for each message is at most `B`.
// * There are `group_size` different paths along which a message can be sent, to provide
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
// The concept of sections exists to provide resilience even against failures of the source or
// destination itself: If every member of a section tries to send the same message, it will arrive
// even if some members fail. And if a message is sent to a whole section, it will arrive in most,
// even if some of them malfunction.
//
// Close sections can thus be used as inherently redundant authorities in the network that messages
// can be sent to and received from, using a consensus algorithm: A message from a section authority
// is considered to be legitimate, if a majority of section members have sent a message with the
// same content.

mod authority;
mod error;
mod network_tests;
pub mod prefix;

pub use self::authority::Authority;
pub use self::error::Error;
#[cfg(any(test, feature = "use-mock-crust"))]
pub use self::network_tests::verify_network_invariant;
pub use self::prefix::{Prefix, UnversionedPrefix};
pub use super::{XOR_NAME_BITS, XOR_NAME_LEN, XorName};
use itertools::Itertools;
use log::LogLevel;
use std::{iter, mem};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Binary, Debug, Formatter};
use std::fmt::Result as FmtResult;

pub type Sections = BTreeMap<Prefix, BTreeSet<XorName>>;
type SectionItem<'a> = (Prefix, &'a BTreeSet<XorName>);

// Amount added to `group_size` when deciding whether a bucket split can happen. This helps
// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 3;

// Immutable iterator over the entries of a `RoutingTable`.
pub struct Iter<'a> {
    inner: Box<Iterator<Item = &'a XorName> + 'a>,
    our_name: XorName,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a XorName;

    #[cfg_attr(feature = "cargo-clippy", allow(while_let_on_iterator))]
    fn next(&mut self) -> Option<&'a XorName> {
        while let Some(name) = self.inner.next() {
            if *name != self.our_name {
                return Some(name);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}



// Details returned by a successful `RoutingTable::remove()`.
#[derive(Debug)]
pub struct RemovalDetails {
    // Node name
    pub name: XorName,
    // True if the removed node was in our section.
    pub was_in_our_section: bool,
}



// Details returned by `RoutingTable::merge_own_section()`.
pub enum OwnMergeState {
    // If an ongoing merge is happening, and this call to `merge_own_section()` completes the merge
    // (i.e. all merging sections have sent us their merge details), then `Completed` is returned,
    // containing the appropriate targets (the `Prefix`es of all sections outwith the merging ones)
    // and the merge details they each need to receive (the new prefix and merged section).
    Completed {
        targets: BTreeSet<Prefix>,
        prefix: Prefix,
        section: BTreeSet<XorName>,
    },
    // The merge has already completed, implying that no further action by the caller is required.
    AlreadyMerged,
}



/// A routing table to manage contacts for a node.
///
/// It maintains a list of sections (identified by a `Prefix`), each with a list of node identifiers
/// of type `XorName` representing connected nodes, and provides algorithms for routing messages.
///
/// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable {
    /// Minimum number of nodes we consider acceptable in a section
    group_size: usize,
    /// Name of node holding this table
    our_name: XorName,
    /// Prefix of our section
    our_prefix: Prefix,
    /// Members of our section, including our own name
    our_section: BTreeSet<XorName>,
    /// Other sections (excludes our own) (TODO: rename)
    sections: Sections,
}

impl RoutingTable {
    /// Creates a new `RoutingTable`.
    pub fn new(our_name: XorName, group_size: usize) -> Self {
        RoutingTable {
            our_name,
            group_size,
            our_section: iter::once(our_name).collect(),
            our_prefix: Default::default(),
            sections: BTreeMap::new(),
        }
    }

    /// Adds the list of `Prefix`es as empty sections.
    ///
    /// Called once a node has been approved by its own section and is given its nodes' tables.
    /// Expects the current sections to be empty and have version 0.
    pub fn add_prefixes(&mut self, prefixes: Vec<Prefix>) -> Result<(), Error> {
        if self.our_prefix.version() != 0 || !self.sections.is_empty() {
            return Err(Error::InvariantViolation);
        }
        for prefix in prefixes {
            if prefix.matches(&self.our_name) {
                self.our_prefix = prefix;
            } else if self.sections.insert(prefix, BTreeSet::new()).is_some() {
                return Err(Error::InvariantViolation);
            };
        }
        // In case our section has split while we've been going through the approval process, we
        // need to assign the original members of our section to the new appropriate sections.
        let our_section = mem::replace(&mut self.our_section, BTreeSet::new());
        for name in our_section {
            let sec_insert = |section: &mut BTreeSet<XorName>| !section.insert(name);
            if self.get_section_mut(&name).map_or(true, sec_insert) {
                return Err(Error::InvariantViolation);
            }
        }
        self.check_invariant(true, true)
    }

    /// Checks that the `NodeApproval` message contains a valid `RoutingTable`.
    pub fn check_node_approval_msg(
        &self,
        sections: &BTreeMap<Prefix, BTreeSet<XorName>>,
    ) -> Result<(), Error> {
        let mut temp_rt = RoutingTable::new(self.our_name, self.group_size);
        temp_rt.add_prefixes(
            sections
                .keys()
                .map(|pfx| pfx.with_version(0))
                .collect(),
        )?;
        for node in sections.values().flat_map(BTreeSet::iter) {
            let _ = temp_rt.add(*node);
        }
        temp_rt.check_invariant(false, true)
    }

    /// Returns the `Prefix` of our section.
    pub fn our_prefix(&self) -> &Prefix {
        &self.our_prefix
    }

    /// Returns our own section, including our own name.
    pub fn our_section(&self) -> &BTreeSet<XorName> {
        &self.our_section
    }

    /// Returns the whole routing table, including our section and our name
    pub fn all_sections(&self) -> Sections {
        self.all_sections_iter()
            .map(|(pfx, section)| (pfx, section.clone()))
            .collect()
    }

    /// Create an iterator over all sections including our own.
    pub fn all_sections_iter<'a>(&'a self) -> Box<Iterator<Item = SectionItem> + 'a> {
        let iter = self.sections
            .iter()
            .map(|(&p, section)| (p, section))
            .chain(iter::once((self.our_prefix, &self.our_section)));
        Box::new(iter)
    }

    /// Returns the section with the given prefix (ignoring version), if any (includes
    /// own name if is own section)
    pub fn section_matching_prefix(
        &self,
        prefix: &UnversionedPrefix,
    ) -> Option<(Prefix, &BTreeSet<XorName>)> {
        if *prefix == self.our_prefix.unversioned() {
            Some((self.our_prefix, &self.our_section))
        } else {
            prefix::unversioned_find(&self.sections, prefix)
        }
    }

    /// Returns the total number of entries in the routing table, excluding our own name.
    // TODO: refactor to include our name?
    pub fn len(&self) -> usize {
        self.all_sections_iter()
            .map(|(_, section)| section.len())
            .sum::<usize>() - 1
    }

    /// Is the table empty? (Returns `true` if no nodes besides our own are known;
    /// empty sections are ignored.)
    pub fn is_empty(&self) -> bool {
        self.our_section.len() == 1 && self.sections.values().all(|section| section.is_empty())
    }

    /// Returns the group size.
    pub fn group_size(&self) -> usize {
        self.group_size
    }

    /// Returns the number of nodes which need to exist in each subsection of a given section to
    /// allow it to be split.
    pub fn min_split_size(&self) -> usize {
        self.group_size + SPLIT_BUFFER
    }

    /// Returns whether the table contains the given `name`.
    pub fn has(&self, name: &XorName) -> bool {
        self.get_section(name).map_or(
            false,
            |section| section.contains(name),
        )
    }

    /// Iterates over all nodes known by the routing table, excluding our own name.
    // TODO: do we need to exclude our name?
    pub fn iter(&self) -> Iter {
        let iter = self.all_sections_iter().flat_map(
            |(_, section)| section.iter(),
        );
        Iter {
            inner: Box::new(iter),
            our_name: self.our_name,
        }
    }

    /// Compute an estimate of the size of the network from the size of our routing table.
    ///
    /// Return (estimate, exact), with exact = true iff we have the whole network in our
    /// routing table.
    pub fn network_size_estimate(&self) -> (u64, bool) {
        let known_prefixes = self.prefixes();
        let is_exact = Prefix::default().is_covered_by(known_prefixes.iter());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes
            .iter()
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        // Total size estimate = known_nodes / network_fraction
        let network_size = (self.len() + 1) as f64 / network_fraction;

        (network_size.ceil() as u64, is_exact)
    }

    /// Collects prefixes of all sections known by the routing table other than ours into a
    /// `BTreeSet`.
    pub fn other_prefixes(&self) -> BTreeSet<Prefix> {
        self.sections.keys().cloned().collect()
    }

    /// Collects prefixes of all sections known by the routing table into a `BTreeSet`.
    pub fn prefixes(&self) -> BTreeSet<Prefix> {
        self.all_sections_iter().map(|(prefix, _)| prefix).collect()
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &XorName) -> Option<BTreeSet<XorName>> {
        if self.our_prefix.matches(name) {
            Some(self.our_section().clone())
        } else {
            None
        }
    }

    /// If our section is the closest one to `name`, returns all names in our section *excluding
    /// ours*, otherwise returns `None`.
    pub fn other_close_names(&self, name: &XorName) -> Option<BTreeSet<XorName>> {
        if self.our_prefix.matches(name) {
            let mut section = self.our_section.clone();
            let _fixme = section.remove(&self.our_name);
            Some(section)
        } else {
            None
        }
    }

    /// Are we among the `count` closest nodes to `name`?
    pub fn is_closest(&self, name: &XorName, count: usize) -> bool {
        self.closest_names(name, count).is_some()
    }

    /// Returns the `count` closest entries to `name` in the routing table, including our own name,
    /// sorted by ascending distance to `name`. If we are not close, returns `None`.
    pub fn closest_names(&self, name: &XorName, count: usize) -> Option<Vec<&XorName>> {
        let result = self.closest_known_names(name, count);
        if result.contains(&&self.our_name) {
            Some(result)
        } else {
            None
        }
    }

    /// Returns the `count-1` closest entries to `name` in the routing table, excluding
    /// our own name, sorted by ascending distance to `name` -  or `None`, if our name
    /// isn't among `count` names closest to `name`.
    pub fn other_closest_names(&self, name: &XorName, count: usize) -> Option<Vec<&XorName>> {
        self.closest_names(name, count).map(|mut result| {
            result.retain(|name| *name != &self.our_name);
            result
        })
    }

    /// Returns true if `name` is in our section (including if it is our own name).
    pub fn is_in_our_section(&self, name: &XorName) -> bool {
        self.our_section.contains(name)
    }

    /// Returns `Ok(())` if the given contact should be added to the routing table.
    ///
    /// Returns `Err` if `name` already exists in the routing table, or it doesn't fall within any
    /// of our sections, or it's our own name.
    pub fn need_to_add(&self, name: &XorName) -> Result<(), Error> {
        if *name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }
        if let Some(section) = self.get_section(name) {
            if section.contains(name) {
                Err(Error::AlreadyExists)
            } else {
                Ok(())
            }
        } else {
            Err(Error::NodeNameUnsuitable)
        }
    }

    /// Validates a joining node's name.
    pub fn validate_joining_node(&self, name: &XorName) -> Result<(), Error> {
        if !self.our_prefix.matches(name) {
            return Err(Error::NodeNameUnsuitable);
        }
        if self.our_section.contains(name) {
            return Err(Error::AlreadyExists);
        }
        Ok(())
    }

    /// Adds a contact to the routing table.
    ///
    /// Returns `Err` if `name` already existed in the routing table, or it doesn't fall within any
    /// of our sections, or it's our own name.
    pub fn add(&mut self, name: XorName) -> Result<(), Error> {
        if name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }

        if let Some(section) = self.get_section_mut(&name) {
            if !section.insert(name) {
                return Err(Error::AlreadyExists);
            }
        } else {
            return Err(Error::NodeNameUnsuitable);
        }
        Ok(())
    }

    /// Finds the `count` names closest to `name` in the whole routing table.
    fn closest_known_names(&self, name: &XorName, count: usize) -> Vec<&XorName> {
        self.all_sections_iter()
            .sorted_by(|&(pfx0, _), &(pfx1, _)| pfx0.cmp_distance(&pfx1, name))
            .into_iter()
            .flat_map(|(_, section)| {
                section.iter().sorted_by(
                    |name0, name1| name.cmp_distance(name0, name1),
                )
            })
            .take(count)
            .collect_vec()
    }

    /// Return true if any neighbouring section needs to merge with our section.
    fn neighbour_needs_merge(&self) -> bool {
        self.neighbour_size_is_below(self.group_size)
    }

    /// Return true if any neighbouring section might soon need to merge with our section.
    fn neighbour_might_need_merge(&self) -> bool {
        self.neighbour_size_is_below(self.min_split_size())
    }

    /// Return true if any neighbouring section is below the given size threshold.
    fn neighbour_size_is_below(&self, threshold: usize) -> bool {
        self.sections.iter().any(|(prefix, section)| {
            prefix.popped().is_compatible(&self.our_prefix) && section.len() < threshold
        })
    }

    /// Returns whether we should split into two sections.
    pub fn should_split(&self) -> bool {
        // If we're currently merging or are close to merging, we shouldn't split.
        if self.neighbour_might_need_merge() {
            return false;
        }

        // Count the number of names which will end up in each new section if our section is split.
        let split_size = self.min_split_size();
        let new_size = self.our_section
            .iter()
            .filter(|name| {
                self.our_name.common_prefix(name) > self.our_prefix.bit_count()
            })
            .count();
        // If either of the two new sections will not contain enough entries, return `false`.
        new_size >= split_size && self.our_section().len() >= split_size + new_size
    }

    /// Splits a section.
    ///
    /// If the section exists in the routing table and has the given version, it is split,
    /// otherwise this function is a no-op. If any of the sections don't satisfy the invariant any
    /// more (i.e. only differ in one bit from our own prefix), they are removed and those contacts
    /// are returned. If the split is happening to our own section, our new prefix is returned in
    /// the optional field.
    pub fn split(&mut self, prefix: Prefix) -> (Vec<XorName>, Option<Prefix>) {
        let mut result = vec![];

        if prefix == self.our_prefix {
            result = self.split_our_section(prefix.version());
            return (result, Some(self.our_prefix));
        }

        let to_split = if let Some(section) = self.sections.remove(&prefix) {
            section
        } else {
            return (result, None);
        };

        let prefix0 = prefix.pushed(false).with_version(prefix.version() + 1);
        let prefix1 = prefix.pushed(true).with_version(prefix.version() + 1);
        let (section0, section1) = to_split.into_iter().partition::<BTreeSet<_>, _>(
            |name| prefix0.matches(name),
        );

        for (pfx, section) in vec![(prefix0, section0), (prefix1, section1)] {
            if self.our_prefix.is_neighbour(&pfx) {
                self.insert_new_section(pfx, section);
            } else {
                result.extend(section);
            }
        }

        (result, None)
    }

    /// Adds the given prefix to the routing table, merging or splitting if necessary. Returns the
    /// entries that have been dropped. If the version is lower or equal to the one in the routing
    /// table, the change is not applied.
    pub fn add_prefix(&mut self, prefix: Prefix) -> Vec<XorName> {
        // If the prefix isn't relevant to our RT, reject the change.
        if !prefix.is_compatible(&self.our_prefix) && !prefix.is_neighbour(&self.our_prefix) {
            return vec![];
        }

        // If the prefix doesn't supersede an existing one, reject.
        for (pfx, _) in self.all_sections_iter() {
            if prefix.is_compatible(&pfx) && prefix.version() <= pfx.version() {
                trace!(
                    "{:?} Not adding {:?} to the RT as the existing {:?} \
                     does not predate it.",
                    self.our_name,
                    prefix,
                    pfx,
                );
                return vec![];
            }
        }

        let original_sections = mem::replace(&mut self.sections, Sections::new());
        let (sections_to_replace, sections) =
            original_sections
                .into_iter()
                .partition::<BTreeMap<_, _>, _>(|&(ref pfx, _)| prefix.is_compatible(pfx));
        self.sections = sections;
        if prefix.matches(&self.our_name) {
            self.our_prefix = prefix;
        } else if prefix.is_compatible(&self.our_prefix) {
            self.our_prefix = Prefix::new(
                prefix.common_prefix(&self.our_name) + 1,
                self.our_name,
                self.our_prefix.version(),
            );
            self.insert_new_section(prefix, BTreeSet::new());
        } else {
            self.insert_new_section(prefix, BTreeSet::new());
        }
        self.add_missing_prefixes();
        sections_to_replace
            .into_iter()
            .flat_map(|(_, names)| names)
            .chain(mem::replace(
                &mut self.our_section,
                iter::once(self.our_name).collect(),
            ))
            .filter(|name| {
                *name != self.our_name && self.add(*name) == Err(Error::NodeNameUnsuitable)
            })
            .collect()
    }

    /// Removes a contact from the routing table.
    ///
    /// If no entry with that name is found, `Err(Error::NoSuchNode)` is returned. Otherwise, the
    /// entry is removed from the routing table and `RemovalDetails` is returned. See that struct's
    /// docs for further info.
    pub fn remove(&mut self, name: &XorName) -> Result<RemovalDetails, Error> {
        let removal_details = RemovalDetails {
            name: *name,
            was_in_our_section: self.our_prefix.matches(name),
        };
        if removal_details.was_in_our_section {
            if self.our_name == *name {
                return Err(Error::OwnNameDisallowed);
            }
            if !self.our_section.remove(name) {
                return Err(Error::NoSuchNode);
            }
        } else if let Some(prefix) = self.find_section_prefix(name) {
            if let Some(section) = self.sections.get_mut(&prefix) {
                if !section.remove(name) {
                    return Err(Error::NoSuchNode);
                }
            }
        } else {
            return Err(Error::NoSuchNode);
        }
        Ok(removal_details)
    }

    /// Returns whether we should merge with our sibling section.
    ///
    /// Merging is required if any section has dropped below the minimum size and can only restore
    /// it by ultimately merging with us.
    ///
    /// However, merging happens in simple steps, each of which involves only two sections. If. e.g.
    /// section `1` drops below the minimum size, and the other sections are `01`, `001` and `000`,
    /// then this will return `true` only in the latter two. Once they are merged and have
    /// established all their new connections, it will return `true` in `01` and `00`. Only after
    /// that, the section `0` will merge with section `1`.
    pub fn should_merge(&self) -> bool {
        let bit_count = self.our_prefix.bit_count();

        if bit_count == 0 ||
            !prefix::unversioned_contains_key(&self.sections, &self.our_prefix.sibling())
        {
            return false; // We can't merge, or we already sent our merge message.
        }
        self.our_section.len() < self.group_size || self.neighbour_needs_merge()
    }

    /// When a merge of our own section is triggered (either from our own section or a neighbouring
    /// one) this function handles the incoming merge details from the nodes within the merging
    /// sections.
    ///
    /// The actual merge of the section is only done once all expected merging sections have
    /// provided details. See the docs for `OwnMergeState` for full details of the return value.
    pub fn merge_own_section<I>(&mut self, merge_prefix: Prefix, prefixes: I) -> OwnMergeState
    where
        I: IntoIterator<Item = Prefix>,
    {
        // TODO: Return an error if they are not compatible instead?
        if !self.our_prefix.is_compatible(&merge_prefix) ||
            self.our_prefix.bit_count() != merge_prefix.bit_count() + 1
        {
            debug!(
                "{:?} Attempt to call merge_own_section() for an already merged prefix {:?}",
                self.our_name,
                merge_prefix
            );
            return OwnMergeState::AlreadyMerged;
        }
        self.merge(&merge_prefix);
        let dropped_names = prefixes
            .into_iter()
            .flat_map(|prefix| self.add_prefix(prefix))
            .collect_vec();
        if !dropped_names.is_empty() {
            log_or_panic!(
                LogLevel::Warn,
                "{:?} Removed nodes from RT as part of OwnSectionMerge {:?}",
                self.our_name,
                dropped_names
            );
        }

        self.add_missing_prefixes();
        // The update needs to be sent to all neighbouring sections. However, while those are
        // merging/splitting, our own section might not agree on their prefixes and the message can
        // fail to accumulate. So also include results of flipping one bit in the `merge_prefix`.
        let targets = self.sections
            .keys()
            .cloned()
            .chain((0..merge_prefix.bit_count()).map(|i| {
                merge_prefix.with_flipped_bit(i)
            }))
            .collect();
        OwnMergeState::Completed {
            targets: targets,
            prefix: *self.our_prefix(),
            section: self.our_section().clone(),
        }
    }

    /// Merges all existing compatible sections into the new one defined by `merge_details.prefix`.
    /// Our own section is not included in the merge.
    ///
    /// The appropriate targets (all contacts from `merge_details.sections` which are not currently
    /// held in the routing table) are returned so the caller can establish connections to these
    /// nodes and subsequently add them.
    pub fn merge_other_section<I>(&mut self, prefix: Prefix, members: I) -> BTreeSet<XorName>
    where
        I: IntoIterator<Item = XorName>,
    {
        if self.our_prefix.is_compatible(&prefix) {
            error!(
                "{:?} Attempt to merge other section {:?} when our prefix is {:?}",
                self.our_name,
                prefix,
                self.our_prefix
            );
            return BTreeSet::new();
        }
        self.merge(&prefix);
        // Establish list of provided contacts which are currently missing from our table.
        prefix::unversioned_get(&self.sections, &prefix).map_or_else(BTreeSet::new, |section| {
            members
                .into_iter()
                .filter(|name| !section.contains(name))
                .collect()
        })
    }

    /// Returns a collection of nodes to which a message for the given `Authority` should be sent
    /// onwards. In all non-error cases below, the returned collection will have the members of
    /// `exclude` removed, possibly resulting in an empty set being returned.
    ///
    /// * If the destination is an `Authority::Section`:
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `route`-th closest member of the RT to the target
    ///
    /// * If the destination is an `Authority::PrefixSection`:
    ///     - if the prefix is compatible with our prefix and is fully-covered by prefixes in our
    ///       RT, returns all members in these prefixes except ourself; otherwise
    ///     - if the prefix is compatible with our prefix and is *not* fully-covered by prefixes in
    ///       our RT, returns `Err(Error::CannotRoute)`; otherwise
    ///     - returns the `route`-th closest member of the RT to the lower bound of the target
    ///       prefix
    ///
    /// * If the destination is a group (`ClientManager`, `NaeManager` or `NodeManager`):
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `route`-th closest member of the RT to the target
    ///
    /// * If the destination is an individual node (`ManagedNode` or `Client`):
    ///     - if our name *is* the destination, returns an empty set; otherwise
    ///     - if the destination name is an entry in the routing table, returns it; otherwise
    ///     - returns the `route`-th closest member of the RT to the target
    pub fn targets(
        &self,
        dst: &Authority,
        exclude: XorName,
        route: usize,
    ) -> Result<BTreeSet<XorName>, Error> {
        let candidates = |target_name: &XorName| {
            self.closest_known_names(target_name, self.group_size)
                .into_iter()
                .filter(|name| **name != self.our_name)
                .cloned()
                .collect::<BTreeSet<XorName>>()
        };

        let closest_section = match *dst {
            Authority::ManagedNode(ref target_name) |
            Authority::Client { proxy_node_name: ref target_name, .. } => {
                if *target_name == self.our_name {
                    return Ok(BTreeSet::new());
                }
                if self.has(target_name) {
                    return Ok(iter::once(*target_name).collect());
                }
                candidates(target_name)
            }
            Authority::ClientManager(ref target_name) |
            Authority::NaeManager(ref target_name) |
            Authority::NodeManager(ref target_name) => {
                if let Some(group) = self.other_closest_names(target_name, self.group_size) {
                    return Ok(group.into_iter().cloned().collect());
                }
                candidates(target_name)
            }
            Authority::Section(ref target_name) => {
                let (prefix, section) = self.closest_section(target_name);
                if prefix.unversioned() == self.our_prefix.unversioned() {
                    // Exclude our name since we don't need to send to ourself
                    let mut section = section.clone();
                    let _fixme = section.remove(&self.our_name);
                    return Ok(section);
                }
                candidates(target_name)
            }
            Authority::PrefixSection(ref prefix) => {
                if prefix.is_compatible(&self.our_prefix) {
                    // only route the message when we have all the targets in our routing table -
                    // this is to prevent spamming the network by sending messages with
                    // intentionally short prefixes
                    if prefix.is_covered_by(self.prefixes().iter()) {
                        return Ok(
                            self.sections
                                .iter()
                                .filter_map(|(pfx, section)| if prefix.is_compatible(pfx) {
                                    Some(section)
                                } else {
                                    None
                                })
                                .flat_map(BTreeSet::iter)
                                .chain(self.our_section.iter().filter(
                                    |name| **name != self.our_name,
                                ))
                                .cloned()
                                .collect(),
                        );
                    } else {
                        return Err(Error::CannotRoute);
                    }
                }
                candidates(&prefix.lower_bound())
            }
        };
        Ok(
            iter::once(self.get_routeth_node(
                &closest_section,
                dst.name(),
                Some(exclude),
                route,
            )?).collect(),
        )
    }

    /// Returns whether we are a part of the given authority.
    pub fn in_authority(&self, auth: &Authority) -> bool {
        match *auth {
            // clients have no routing tables
            Authority::Client { .. } => false,
            Authority::ManagedNode(ref name) => self.our_name == *name,
            Authority::ClientManager(ref name) |
            Authority::NaeManager(ref name) |
            Authority::NodeManager(ref name) => self.is_closest(name, self.group_size),
            Authority::Section(ref name) => self.our_prefix.matches(name),
            Authority::PrefixSection(ref prefix) => self.our_prefix.is_compatible(prefix),
        }
    }

    /// Returns the section matching the given `name`, if present.
    /// Includes our own name in the case that our prefix matches `name`.
    pub fn get_section(&self, name: &XorName) -> Option<&BTreeSet<XorName>> {
        if self.our_prefix.matches(name) {
            return Some(&self.our_section);
        }
        if let Some(prefix) = self.find_section_prefix(name) {
            return self.sections.get(&prefix);
        }
        None
    }

    /// Get a mutable reference to whichever section matches the given name. If our own section,
    /// our name is included.
    fn get_section_mut(&mut self, name: &XorName) -> Option<&mut BTreeSet<XorName>> {
        if self.our_prefix.matches(name) {
            return Some(&mut self.our_section);
        }
        if let Some(prefix) = self.find_section_prefix(name) {
            return self.sections.get_mut(&prefix).map(|section| section);
        }
        None
    }

    /// Returns our name.
    pub fn our_name(&self) -> &XorName {
        &self.our_name
    }

    /// Returns the prefix of the section in which `name` belongs, or `None` if there is no such
    /// section in the routing table.
    pub fn find_section_prefix(&self, name: &XorName) -> Option<Prefix> {
        if self.our_prefix.matches(name) {
            return Some(self.our_prefix);
        }
        self.sections
            .keys()
            .find(|&prefix| prefix.matches(name))
            .cloned()
    }

    /// Return a minimum length prefix, favouring our prefix if it is one of the shortest.
    pub fn min_len_prefix(&self) -> Prefix {
        *iter::once(&self.our_prefix)
            .chain(self.sections.keys())
            .min_by_key(|prefix| prefix.bit_count())
            .unwrap_or(&self.our_prefix)
    }

    fn split_our_section(&mut self, version: u64) -> Vec<XorName> {
        let next_bit = self.our_name.bit(self.our_prefix.bit_count());
        let other_prefix = self.our_prefix.pushed(!next_bit).with_version(version + 1);
        self.our_prefix = self.our_prefix.pushed(next_bit).with_version(version + 1);

        let (our_new_section, other_section) =
            self.our_section.iter().partition::<BTreeSet<_>, _>(
                |name| self.our_prefix.matches(name),
            );
        self.our_section = our_new_section;
        // Drop sections that ceased to be our neighbours.
        let sections_to_remove = self.sections
            .keys()
            .filter(|prefix| !prefix.is_neighbour(&self.our_prefix))
            .cloned()
            .collect_vec();
        self.insert_new_section(other_prefix, other_section);
        sections_to_remove
            .into_iter()
            .filter_map(|prefix| self.sections.remove(&prefix))
            .flat_map(BTreeSet::into_iter)
            .collect()
    }

    /// Inserts the given section. Logs an error if it already exists.
    fn insert_new_section(&mut self, prefix: Prefix, section: BTreeSet<XorName>) {
        let section = if let Some(old_prefix) = prefix::unversioned_find(&self.sections, &prefix)
            .map(|(old_prefix, old_section)| {
                error!(
                    "{:?} Inserting section {:?}, but already has members {:?}. This is a bug!",
                    self.our_name,
                    prefix,
                    old_section
                );
                old_prefix
            })
        {
            if old_prefix.version() > prefix.version() {
                return; // Wrong version.
            }

            let mut old_section = self.sections.remove(&old_prefix).unwrap_or_else(
                BTreeSet::new,
            );
            old_section.extend(section);
            old_section
        } else {
            section
        };

        let _ = self.sections.insert(prefix, section);
    }

    fn merge(&mut self, new_pfx: &Prefix) {
        if new_pfx.is_extension_of(&self.our_prefix) ||
            self.sections.keys().any(|pfx| new_pfx.is_extension_of(pfx))
        {
            return; // Not a merge!
        }
        let dropped_names = self.add_prefix(*new_pfx);
        if !dropped_names.is_empty() {
            error!(
                "{:?} Dropped names when merging {:?}: {:?}",
                self.our_name,
                new_pfx,
                dropped_names
            );
        }
    }

    /// Inserts empty sections so that the prefixes cover all neighbouring areas of the namespace.
    fn add_missing_prefixes(&mut self) {
        let mut prefix = self.our_prefix;
        let mut missing_pfxs = vec![];
        while prefix.bit_count() > 0 {
            missing_pfxs.push(prefix.sibling());
            prefix = prefix.popped();
        }
        while let Some(pfx) = missing_pfxs.pop() {
            if !pfx.is_covered_by(self.sections.keys()) && pfx.is_neighbour(&self.our_prefix) {
                if self.sections.keys().any(|p| pfx.is_compatible(p)) {
                    missing_pfxs.push(pfx.pushed(true));
                    missing_pfxs.push(pfx.pushed(false));
                } else {
                    self.insert_new_section(pfx.with_version(0), BTreeSet::new());
                }
            }
        }
    }

    /// Returns the prefix of the closest non-empty section to `name`, regardless of whether `name`
    /// belongs in that section or not, and the section itself.
    fn closest_section(&self, name: &XorName) -> (Prefix, &BTreeSet<XorName>) {
        let mut result = (self.our_prefix, &self.our_section);
        for (prefix, section) in &self.sections {
            if !section.is_empty() && result.0.cmp_distance(prefix, name) == Ordering::Greater {
                result = (*prefix, section)
            }
        }
        result
    }

    /// Gets the `route`-th name from a collection of names
    fn get_routeth_name<'a, U: IntoIterator<Item = &'a XorName>>(
        names: U,
        dst_name: &XorName,
        route: usize,
    ) -> &'a XorName {
        let sorted_names = names.into_iter().sorted_by(|&lhs, &rhs| {
            dst_name.cmp_distance(lhs, rhs)
        });
        sorted_names[route % sorted_names.len()]
    }

    /// Returns the `route`-th node in the given section, sorted by distance to `target`
    fn get_routeth_node(
        &self,
        section: &BTreeSet<XorName>,
        target: XorName,
        exclude: Option<XorName>,
        route: usize,
    ) -> Result<XorName, Error> {
        let names = if let Some(exclude) = exclude {
            section.iter().filter(|&x| *x != exclude).collect_vec()
        } else {
            section.iter().collect_vec()
        };

        if names.is_empty() {
            return Err(Error::CannotRoute);
        }

        Ok(*RoutingTable::get_routeth_name(names, &target, route))
    }

    /// Checks if the invariant is held. Allows printing additional log messages for failures and
    /// excluding small section sizes from triggering invariant failures.
    pub fn check_invariant(
        &self,
        allow_small_sections: bool,
        show_warnings: bool,
    ) -> Result<(), Error> {
        let warn = |log_msg: String| -> Result<(), Error> {
            if show_warnings {
                warn!("{}", log_msg);
            }
            Err(Error::InvariantViolation)
        };
        if !self.our_prefix.matches(&self.our_name) {
            return warn(format!("Our prefix does not match our name: {:?}", self));
        }
        if self.sections.contains_key(&self.our_prefix) {
            return warn(format!(
                "Our own section is in the sections map: {:?}",
                self
            ));
        }
        let has_enough_nodes = self.len() >= self.group_size;
        if has_enough_nodes && self.our_section.len() < self.group_size {
            return warn(format!(
                "Group size not met for section {:?}: {:?}",
                self.our_prefix,
                self
            ));
        }
        for name in &self.our_section {
            if !self.our_prefix.matches(name) {
                return warn(format!(
                    "Name {} doesn't match section prefix {:?}: {:?}",
                    name.debug_binary(),
                    self.our_prefix,
                    self
                ));
            }
        }

        for (prefix, section) in &self.sections {
            if has_enough_nodes && section.len() < self.group_size {
                if section.len() <= 1 && allow_small_sections {
                    continue;
                }
                return warn(format!(
                    "Minimum group size not met for group {:?}: {:?}",
                    prefix,
                    self
                ));
            }
            for name in section {
                if !prefix.matches(name) {
                    return warn(format!(
                        "Name {} doesn't match section prefix {:?}: {:?}",
                        name.debug_binary(),
                        prefix,
                        self
                    ));
                }
            }
        }

        let all_are_neighbours = self.sections.keys().all(
            |&x| self.our_prefix.is_neighbour(&x),
        );
        let all_neighbours_covered = {
            let prefixes = self.prefixes();
            (0..self.our_prefix.bit_count()).all(|i| {
                self.our_prefix.with_flipped_bit(i).is_covered_by(&prefixes)
            })
        };
        if !all_are_neighbours {
            return warn(format!(
                "Some sections in the RT aren't neighbours of our section: {:?}",
                self
            ));
        }
        if !all_neighbours_covered {
            return warn(format!(
                "Some neighbours aren't fully covered by the RT: {:?}",
                self
            ));
        }

        Ok(())
    }

    /// Runs the built-in invariant checker
    #[cfg(any(test, feature = "use-mock-crust"))]
    pub fn verify_invariant(&self) {
        unwrap!(
            self.check_invariant(false, true),
            "Invariant not satisfied for RT: {:?}",
            self
        );
    }

    #[cfg(test)]
    fn num_of_sections(&self) -> usize {
        self.sections.len()
    }
}

impl Binary for RoutingTable {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        writeln!(formatter, "RoutingTable {{")?;
        writeln!(formatter, "\tgroup_size: {},", self.group_size)?;
        writeln!(
            formatter,
            "\tour_name: {:?} ({}),",
            self.our_name,
            self.our_name.debug_binary()
        )?;
        writeln!(formatter, "\tour_prefix: {:?}", self.our_prefix)?;

        let sections = self.all_sections_iter().collect::<BTreeSet<_>>();
        for (section_index, &(prefix, section)) in sections.iter().enumerate() {
            write!(
                formatter,
                "\tsection {} with {:?}: {{\n",
                section_index,
                prefix,
            )?;
            for (name_index, name) in section.iter().enumerate() {
                let comma = if name_index == section.len() - 1 {
                    ""
                } else {
                    ","
                };
                writeln!(
                    formatter,
                    "\t\t{:?} ({}){}",
                    name,
                    name.debug_binary(),
                    comma
                )?;
            }
            let comma = if section_index == sections.len() - 1 {
                ""
            } else {
                ","
            };
            writeln!(formatter, "\t}}{}", comma)?;
        }
        write!(formatter, "}}")
    }
}

impl Debug for RoutingTable {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // use itertools::Itertools;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    // use std::collections::BTreeSet;
    // use std::str::FromStr;

    #[test]
    fn small() {
        let mut rng = SeededRng::thread_rng();
        let name = rng.gen();
        let table = RoutingTable::new(name, 6);
        assert_eq!(*table.our_name(), name);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.iter().count(), 0);
        assert_eq!(table.all_sections_iter().count(), 1);
    }

    /*
    // Adds `min_split_size() - 1` entries to `table`, starting at `name` and incrementing it by 1
    // each time.
    fn add_sequential_entries(table: &mut RoutingTable, name: &mut XorName) {
        for _ in 1..table.min_split_size() {
            assert_eq!(table.add(*name), Ok(()));
            assert!(!table.should_split());
            table.verify_invariant();
            let mut index = XOR_NAME_LEN - 1;
            while name[index] == 255 {
                index -= 1;
            }
            name[index] += 1;
        }
    }

    // Test explicitly covers `close_names()`, `other_close_names()`, `is_in_our_section()` and
    // `need_to_add()` while also implicitly testing `add()` and `split()`.
    #[test]
    fn test_routing_sections() {
        assert!(
            SPLIT_BUFFER < 3818,
            "Given the chosen values for 'our_name' and RT type (u16), this requires the \
                 SPLIT_BUFFER to be less than 3818."
        );
        let our_name = 0b_0001_0001_0001_0001u16;
        let mut table = RoutingTable::new(our_name, 5);
        table.verify_invariant();

        // Set up initial section so the half with our prefix has `min_split_size` entries and the
        // other half has one less (i.e. so it's ready to split).
        let mut expected_rt_len = 0; // doesn't include own name
        let mut section_00_name = our_name + 1;
        let mut section_10_name = our_name.with_flipped_bit(0);
        add_sequential_entries(&mut table, &mut section_00_name);
        add_sequential_entries(&mut table, &mut section_10_name);
        expected_rt_len += 2 * (table.min_split_size() - 1);

        // Add one name to the other half to trigger the split to sections 0 and 1.
        assert_eq!(table.add(section_10_name), Ok(()));
        assert!(table.should_split());
        expected_rt_len += 1;
        let mut expected_own_prefix = Prefix::new(0, our_name);
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        let (nodes_to_drop, our_new_prefix) = table.split(expected_own_prefix.with_version(0));
        expected_own_prefix = Prefix::new(1, our_name);
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        assert_eq!(unwrap!(our_new_prefix), expected_own_prefix);
        assert!(nodes_to_drop.is_empty());
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);
        assert_eq!(table.all_sections().len(), 2);
        assert_eq!(table.our_section().len(), table.min_split_size());

        // Add `min_split_size - 1` with names 01... and names 11... to get both sections ready to
        // split again.
        let mut section_01_name = our_name.with_flipped_bit(1);
        let mut section_11_name = section_10_name.with_flipped_bit(1);
        add_sequential_entries(&mut table, &mut section_01_name);
        add_sequential_entries(&mut table, &mut section_11_name);
        expected_rt_len += 2 * (table.min_split_size() - 1);

        // Trigger split in our own section first to yield sections 00, 01 and 1.
        assert_eq!(table.add(section_01_name), Ok(()));
        assert!(table.should_split());
        expected_rt_len += 1;
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        let (nodes_to_drop, our_new_prefix) = table.split(expected_own_prefix.with_version(1));
        expected_own_prefix = Prefix::new(2, our_name);
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        assert_eq!(unwrap!(our_new_prefix), expected_own_prefix);
        assert!(nodes_to_drop.is_empty());
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);
        assert_eq!(table.all_sections().len(), 3);
        assert_eq!(table.our_section().len(), table.min_split_size());

        // Now trigger split in section 1, which should cause section 11 to get ejected, leaving
        // sections 00, 01 and 10.
        assert_eq!(table.add(section_11_name), Ok(()));
        assert!(!table.should_split());
        expected_rt_len += 1;
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        let (nodes_to_drop, our_new_prefix) =
            table.split(Prefix::new(1, section_11_name).with_version(1));
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        assert!(our_new_prefix.is_none());
        assert_eq!(nodes_to_drop.len(), table.min_split_size());
        let mut drop_prefix = Prefix::new(2, section_11_name);
        assert!(nodes_to_drop.iter().all(|name| drop_prefix.matches(name)));
        expected_rt_len -= nodes_to_drop.len();
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);
        assert_eq!(table.all_sections().len(), 3);
        assert_eq!(table.our_section().len(), table.min_split_size());

        // Add `min_split_size - 1` with names 001... and names 011... to get sections 00 and 01
        // ready to split.
        let mut section_001_name = our_name.with_flipped_bit(2);
        let mut section_011_name = section_001_name.with_flipped_bit(1);
        add_sequential_entries(&mut table, &mut section_001_name);
        add_sequential_entries(&mut table, &mut section_011_name);
        expected_rt_len += 2 * (table.min_split_size() - 1);

        // Trigger split in other section (i.e. section 01) first this time to yield sections 00,
        // 010, 011 and 10.
        assert_eq!(table.add(section_011_name), Ok(()));
        assert!(!table.should_split());
        expected_rt_len += 1;
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        let (nodes_to_drop, our_new_prefix) =
            table.split(Prefix::new(2, section_011_name).with_version(2));
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        assert!(our_new_prefix.is_none());
        assert!(nodes_to_drop.is_empty());
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);
        assert_eq!(table.all_sections().len(), 4);
        assert_eq!(table.our_section().len(), 2 * table.min_split_size() - 1);

        // Now trigger split in own section (i.e. section 00), which should cause section 011 to get
        // ejected, leaving sections 000, 001, 010 and 10.
        assert_eq!(table.add(section_001_name), Ok(()));
        assert!(table.should_split());
        expected_rt_len += 1;
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        let (nodes_to_drop, our_new_prefix) = table.split(expected_own_prefix.with_version(
            expected_own_prefix.bit_count() as
                u64,
        ));
        expected_own_prefix = Prefix::new(3, our_name);
        assert_eq!(*table.our_prefix(), expected_own_prefix);
        assert_eq!(unwrap!(our_new_prefix), expected_own_prefix);
        assert_eq!(nodes_to_drop.len(), table.min_split_size());
        drop_prefix = Prefix::new(3, section_011_name);
        assert!(nodes_to_drop.iter().all(|name| drop_prefix.matches(name)));
        expected_rt_len -= nodes_to_drop.len();
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);
        assert_eq!(table.all_sections().len(), 4);
        assert_eq!(table.our_section().len(), table.min_split_size());

        // Try to add a name which is already in the RT.
        assert_eq!(table.add(section_001_name), Err(Error::AlreadyExists));
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);

        // Try to add our own name.
        assert_eq!(table.add(our_name), Err(Error::OwnNameDisallowed));
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);

        // Try to add a name which doesn't fit any section.
        assert_eq!(table.add(nodes_to_drop[0]), Err(Error::NodeNameUnsuitable));
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);

        // Check `is_in_our_section()`.
        assert!(table.is_in_our_section(&our_name));
        assert!(table.is_in_our_section(&(section_00_name - 1)));
        assert!(!table.is_in_our_section(&section_001_name));
        assert!(!table.is_in_our_section(&section_10_name));

        // Check `close_names()`.
        let our_section = table.our_section().clone();
        assert!(our_section.contains(&our_name));
        assert_eq!(unwrap!(table.close_names(&our_name)), our_section);
        assert_eq!(unwrap!(table.close_names(&section_00_name)), our_section);
        assert!(table.close_names(&section_001_name).is_none());
        assert!(table.close_names(&section_10_name).is_none());

        // Check `other_close_names()`.
        let our_section_without_us = our_section
            .into_iter()
            .filter(|name| *name != our_name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            unwrap!(table.other_close_names(&our_name)),
            our_section_without_us
        );
        assert_eq!(
            unwrap!(table.other_close_names(&section_00_name)),
            our_section_without_us
        );
        assert!(table.other_close_names(&section_001_name).is_none());
        assert!(table.other_close_names(&section_10_name).is_none());

        // Check `need_to_add()`.
        assert_eq!(
            table.need_to_add(&section_001_name),
            Err(Error::AlreadyExists)
        );
        assert_eq!(table.need_to_add(&our_name), Err(Error::OwnNameDisallowed));
        assert_eq!(
            table.need_to_add(&nodes_to_drop[0]),
            Err(Error::NodeNameUnsuitable)
        );
        assert_eq!(table.need_to_add(&(section_001_name + 1)), Ok(()));
    }

    #[test]
    fn test_closest_names() {
        let our_name = 0u16;
        let mut table = RoutingTable::new(our_name, 8);
        // initialize the table
        unwrap!(table.add(0x8000));
        unwrap!(table.add(0x4000));
        unwrap!(table.add(0x2000));
        unwrap!(table.add(0x1000));
        unwrap!(table.add(0x0800));
        unwrap!(table.add(0x0400));
        unwrap!(table.add(0x0200));
        unwrap!(table.add(0x0100));
        unwrap!(table.add(0x0080));
        unwrap!(table.add(0x0040));

        let mut name = 0xFFFF;
        assert!(table.closest_names(&name, 10).is_none());
        assert!(table.other_closest_names(&name, 10).is_none());
        assert!(table.closest_names(&name, 11).is_some());
        let result = unwrap!(table.other_closest_names(&name, 11));
        assert_eq!(result.len(), 10);

        name = 0x01FF;
        assert!(table.closest_names(&name, 3).is_none());
        let result = unwrap!(table.closest_names(&name, 4));
        assert_eq!(result.len(), 4);
        assert_eq!(*result[0], 0x0100);
        assert_eq!(*result[1], 0x0080);
        assert_eq!(*result[2], 0x0040);
        assert_eq!(*result[3], 0x0000);

        let result = unwrap!(table.other_closest_names(&name, 4));
        assert_eq!(result.len(), 3);
        assert_eq!(*result[0], 0x0100);
        assert_eq!(*result[1], 0x0080);
        assert_eq!(*result[2], 0x0040);
    }

    #[test]
    fn test_add_prefix() {
        let our_name = 0u8;
        let mut table = RoutingTable::new(our_name, 1);
        // Add 10, 20, 30, 40, 50, 60, 70, 80, 90, A0, B0, C0, D0, E0 and F0.
        for i in 1..0x10 {
            unwrap!(table.add(i * 0x10));
        }
        assert_eq!(prefixes_from_strs(vec![""]), table.prefixes());
        assert_eq!(
            Vec::<u8>::new(),
            table.add_prefix(unwrap!(Prefix::from_str("01")).with_version(2))
        );
        assert_eq!(prefixes_from_strs(vec!["1", "00", "01"]), table.prefixes());
        assert_eq!(
            Vec::<u8>::new(),
            table
                .add_prefix(unwrap!(Prefix::from_str("111")).with_version(4))
                .into_iter()
                .sorted()
        );
        assert_eq!(prefixes_from_strs(vec!["1", "00", "01"]), table.prefixes());
        assert_eq!(
            vec![0xc0, 0xd0, 0xe0, 0xf0u8],
            table
                .add_prefix(unwrap!(Prefix::from_str("101")).with_version(4))
                .into_iter()
                .sorted()
        );
        assert_eq!(
            prefixes_from_strs(vec!["101", "100", "01", "00"]),
            table.prefixes()
        );
        assert_eq!(
            Vec::<u8>::new(),
            table.add_prefix(unwrap!(Prefix::from_str("0")).with_version(7))
        );
        assert_eq!(
            prefixes_from_strs(vec!["101", "11", "100", "0"]),
            table.prefixes()
        );
        assert_eq!(
            Vec::<u8>::new(),
            table.add_prefix(unwrap!(Prefix::from_str("")).with_version(15))
        );
        assert_eq!(prefixes_from_strs(vec![""]), table.prefixes());
    }

    #[test]
    fn test_add_prefix_outdated_version() {
        let our_name = 0u8;
        let mut table = RoutingTable::<u8>::new(our_name, 1);
        // Add 10, 20, 30, 40, 50, 60, 70, 80, 90, A0, B0, C0, D0, E0 and F0.
        for i in 1..0x10 {
            unwrap!(table.add(i * 0x10));
        }
        let empty = Vec::<u8>::new();

        // Split into {0, 1}
        assert_eq!(empty, table.add_prefix(prefix_str("0").with_version(1)));
        assert_eq!(Some(1), table.section_version(&prefix_str("0")));
        assert_eq!(Some(0), table.section_version(&prefix_str("1")));

        // Split 0 into {00, 01}.
        assert_eq!(empty, table.add_prefix(prefix_str("00").with_version(2)));
        assert_eq!(Some(2), table.section_version(&prefix_str("00")));
        assert_eq!(Some(0), table.section_version(&prefix_str("01")));
        assert_eq!(Some(0), table.section_version(&prefix_str("1")));

        // Split into 1 into {10,11}, dropping the nodes in 11.
        assert_eq!(
            vec![0xc0, 0xd0, 0xe0, 0xf0u8],
            table
                .add_prefix(prefix_str("10").with_version(2))
                .into_iter()
                .sorted()
        );
        assert_eq!(prefixes_from_strs(vec!["10", "01", "00"]), table.prefixes());

        // Simulate a missed update for the split from 10 to 100 and 101 and subsequent merge.
        assert_eq!(empty, table.add_prefix(prefix_str("10").with_version(4)));
        assert_eq!(Some(4), table.section_version(&prefix_str("10")));

        // RT shouldn't change if it now gets an update for prefix 100 v3.
        assert_eq!(empty, table.add_prefix(prefix_str("100").with_version(3)));
        assert_eq!(Some(4), table.section_version(&prefix_str("10")));
        assert_eq!(prefixes_from_strs(vec!["10", "01", "00"]), table.prefixes());

        // Similarly, none of these bogus updates should be accepted.
        assert_eq!(empty, table.add_prefix(prefix_str("").with_version(0)));
        assert_eq!(empty, table.add_prefix(prefix_str("0").with_version(1)));
        assert_eq!(empty, table.add_prefix(prefix_str("101").with_version(3)));
        assert_eq!(prefixes_from_strs(vec!["10", "01", "00"]), table.prefixes());

        // Finally, adding an existing prefix (01) should update its version.
        assert_eq!(empty, table.add_prefix(prefix_str("01").with_version(2)));
        assert_eq!(Some(2), table.section_version(&prefix_str("01")));
    }

    fn prefix_str(s: &str) -> Prefix {
        unwrap!(Prefix::from_str(s))
    }

    fn prefixes_from_strs(strs: Vec<&str>) -> BTreeSet<Prefix> {
        strs.into_iter()
            .map(|s| unwrap!(Prefix::from_str(s)))
            .collect()
    }*/
}

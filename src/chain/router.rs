// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{delivery_group_size, shared_state::SharedState, EldersInfo, MemberInfo};
use crate::{Authority, P2pNode, Prefix, XorName, Xorable};
use err_derive::Error;
use std::{cmp::Ordering, collections::BTreeMap, iter};

/// Utility for routing messages and obtaining information about our network neighbourhood.
pub struct Router<'a> {
    our_name: &'a XorName,
    our_info: &'a EldersInfo,
    our_members: &'a BTreeMap<XorName, MemberInfo>,
    neighbour_infos: &'a BTreeMap<Prefix<XorName>, EldersInfo>,
    post_split_sibling_members: &'a BTreeMap<XorName, MemberInfo>,
}

impl<'a> Router<'a> {
    pub fn new(our_name: &'a XorName, state: &'a SharedState) -> Self {
        Self {
            our_name,
            our_info: state.our_info(),
            our_members: &state.our_members,
            neighbour_infos: &state.neighbour_infos,
            post_split_sibling_members: &state.post_split_sibling_members,
        }
    }

    /// Returns a set of nodes to which a message for the given `Authority` could be sent
    /// onwards, sorted by priority, along with the number of targets the message should be sent to.
    /// If the total number of targets returned is larger than this number, the spare targets can
    /// be used if the message can't be delivered to some of the initial ones.
    ///
    /// * If the destination is an `Authority::Section`:
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    ///
    /// * If the destination is an `Authority::PrefixSection`:
    ///     - if the prefix is compatible with our prefix and is fully-covered by prefixes in our
    ///       RT, returns all members in these prefixes except ourself; otherwise
    ///     - if the prefix is compatible with our prefix and is *not* fully-covered by prefixes in
    ///       our RT, returns `Err(Error::CannotRoute)`; otherwise
    ///     - returns the `N/3` closest members of the RT to the lower bound of the target
    ///       prefix
    ///
    /// * If the destination is an `Authority::Node`:
    ///     - if our name *is* the destination, returns an empty set; otherwise
    ///     - if the destination name is an entry in the routing table, returns it; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    pub fn targets(&self, dst: &Authority<XorName>) -> Result<(Vec<P2pNode>, usize), RouterError> {
        let candidates = |target_name: &XorName| {
            let filtered_sections = self
                .closest_sections_info(target_name)
                .into_iter()
                .map(|(prefix, members)| (prefix, members.len(), members.member_nodes().cloned()));

            let mut dg_size = 0;
            let mut nodes_to_send = Vec::new();
            for (idx, (prefix, len, connected)) in filtered_sections.enumerate() {
                nodes_to_send.extend(connected);
                dg_size = delivery_group_size(len);

                if prefix == self.our_prefix() {
                    // Send to all connected targets so they can forward the message
                    nodes_to_send.retain(|node| node.name() != self.our_name);
                    dg_size = nodes_to_send.len();
                    break;
                }
                if idx == 0 && nodes_to_send.len() >= dg_size {
                    // can deliver to enough of the closest section
                    break;
                }
            }
            nodes_to_send.sort_by(|lhs, rhs| target_name.cmp_distance(lhs.name(), rhs.name()));

            if dg_size > 0 && nodes_to_send.len() >= dg_size {
                Ok((dg_size, nodes_to_send))
            } else {
                Err(RouterError)
            }
        };

        let (dg_size, best_section) = match dst {
            Authority::Node(target_name) => {
                if target_name == self.our_name {
                    return Ok((Vec::new(), 0));
                }
                if let Some(node) = self.get_node(target_name) {
                    return Ok((vec![node.clone()], 1));
                }
                candidates(target_name)?
            }
            Authority::Section(target_name) => {
                let (prefix, section) = self.closest_section_info(target_name);
                if prefix == self.our_prefix() || prefix.is_neighbour(self.our_prefix()) {
                    // Exclude our name since we don't need to send to ourself
                    let our_name = self.our_name;

                    // FIXME: only doing this for now to match RT.
                    // should confirm if needed esp after msg_relay changes.
                    let section: Vec<_> = section
                        .member_nodes()
                        .filter(|node| node.name() != our_name)
                        .cloned()
                        .collect();
                    let dg_size = section.len();
                    return Ok((section, dg_size));
                }
                candidates(target_name)?
            }
            Authority::PrefixSection(prefix) => {
                if prefix.is_compatible(self.our_prefix()) || prefix.is_neighbour(self.our_prefix())
                {
                    // only route the message when we have all the targets in our routing table -
                    // this is to prevent spamming the network by sending messages with
                    // intentionally short prefixes
                    if prefix.is_compatible(self.our_prefix())
                        && !prefix.is_covered_by(self.all_prefixes())
                    {
                        return Err(RouterError);
                    }

                    let is_compatible = |(pfx, section)| {
                        if prefix.is_compatible(pfx) {
                            Some(section)
                        } else {
                            None
                        }
                    };

                    // Exclude our name since we don't need to send to ourself
                    let our_name = self.our_name;

                    let targets = self
                        .all_sections()
                        .filter_map(is_compatible)
                        .flat_map(EldersInfo::member_nodes)
                        .filter(|node| node.name() != our_name)
                        .cloned()
                        .collect::<Vec<_>>();
                    let dg_size = targets.len();
                    return Ok((targets, dg_size));
                }
                candidates(&prefix.lower_bound())?
            }
        };

        Ok((best_section, dg_size))
    }

    /// All prefixes of all sections known to us.
    pub fn all_prefixes(&'a self) -> impl Iterator<Item = &'a Prefix<XorName>> + Clone {
        self.other_prefixes()
            .chain(iter::once(self.our_info.prefix()))
    }

    /// Prefixes of all our neighbours.
    pub fn other_prefixes(&self) -> impl Iterator<Item = &Prefix<XorName>> + Clone {
        self.neighbour_infos.keys()
    }

    /// Returns an iterator over all neighbouring sections and our own, together with their prefix.
    pub fn all_sections(&self) -> impl Iterator<Item = (&'a Prefix<XorName>, &'a EldersInfo)> {
        self.neighbour_infos
            .iter()
            .chain(iter::once((self.our_info.prefix(), self.our_info)))
    }

    /// Returns the `P2pNode` struct for a known node with the given name.
    pub fn get_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.get_member_node(name)
            .or_else(|| self.get_our_elder_node(name))
            .or_else(|| self.get_neighbour_node(name))
            .or_else(|| self.get_post_split_sibling_member_node(name))
    }

    /// Returns our section member `P2pNode`.
    pub fn get_member_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.our_members
            .get(name)
            .map(|member_info| &member_info.p2p_node)
    }

    /// Returns the prefix of the closest non-empty section to `name`, regardless of whether `name`
    /// belongs in that section or not, and the section itself.
    pub fn closest_section_info(&self, name: &XorName) -> (&'a Prefix<XorName>, &'a EldersInfo) {
        let mut best_pfx = self.our_prefix();
        let mut best_info = self.our_info;
        for (pfx, info) in self.neighbour_infos {
            // TODO: Remove the first check after verifying that section infos are never empty.
            if !info.is_empty() && best_pfx.cmp_distance(pfx, name) == Ordering::Greater {
                best_pfx = pfx;
                best_info = info;
            }
        }

        (best_pfx, best_info)
    }

    fn get_our_elder_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.our_info.member_map().get(name)
    }

    fn get_neighbour_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.neighbour_infos
            .iter()
            .find(|(pfx, _)| pfx.matches(name))
            .and_then(|(_, elders_info)| elders_info.member_map().get(name))
    }

    fn get_post_split_sibling_member_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.post_split_sibling_members
            .get(name)
            .map(|member_info| &member_info.p2p_node)
    }

    /// Returns the known sections sorted by the distance from a given XorName.
    fn closest_sections_info(&self, name: &XorName) -> Vec<(&Prefix<XorName>, &EldersInfo)> {
        let mut result: Vec<_> = iter::once((self.our_prefix(), self.our_info))
            .chain(self.neighbour_infos.iter())
            .collect();
        result.sort_by(|lhs, rhs| lhs.0.cmp_distance(rhs.0, name));
        result
    }

    fn our_prefix(&self) -> &'a Prefix<XorName> {
        self.our_info.prefix()
    }
}

/// Router error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
#[error(display = "Cannot route.")]
pub struct RouterError;

#[cfg(test)]
mod tests {
    /*
    TODO: these tests were copied from routing_table. Port them over.

    use super::SPLIT_BUFFER;
    use super::*;
    use itertools::Itertools;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    #[test]
    fn small() {
        let name = 123u32;
        let table = RoutingTable::new(name, 6);
        assert_eq!(*table.our_name(), name);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.iter().count(), 0);
        assert_eq!(table.all_sections_iter().count(), 1);
    }

    // Adds `min_split_size() - 1` entries to `table`, starting at `name` and incrementing it by 1
    // each time.
    fn add_sequential_entries(table: &mut RoutingTable<u16>, name: &mut u16) {
        for _ in 1..table.min_split_size() {
            assert_eq!(table.add(*name), Ok(()));
            assert!(!table.should_split());
            table.verify_invariant();
            *name += 1;
        }
    }

    // Test explicitly covers `close_names()`, `other_close_names()`, `is_in_our_section()` and
    // `need_to_add()` while also implicitly testing `add()` and `split()`.
    #[test]
    #[ignore]
    #[allow(clippy::cognitive_complexity, clippy::assertions_on_constants)]
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
        let (nodes_to_drop, our_new_prefix) =
            table.split(expected_own_prefix.with_version(expected_own_prefix.bit_count() as u64));
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
        assert_eq!(table.add(nodes_to_drop[0]), Err(Error::PeerNameUnsuitable));
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
            Err(Error::PeerNameUnsuitable)
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
    #[ignore]
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

    fn prefix_str(s: &str) -> Prefix<u8> {
        unwrap!(Prefix::from_str(s))
    }

    fn prefixes_from_strs(strs: Vec<&str>) -> BTreeSet<Prefix<u8>> {
        strs.into_iter()
            .map(|s| unwrap!(Prefix::from_str(s)))
            .collect()
    }
    */
}

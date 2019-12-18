// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod authority;
mod error;
mod prefix;
mod xorable;

pub use self::authority::Authority;
pub use self::error::RoutingTableError;
pub use self::prefix::{Prefix, VersionedPrefix};
pub use self::xorable::Xorable;

/*

TODO: port these tests over to chain

#[cfg(test)]
mod tests {
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
        assert_eq!(
            table.add(section_001_name),
            Err(RoutingTableError::AlreadyExists)
        );
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);

        // Try to add our own name.
        assert_eq!(
            table.add(our_name),
            Err(RoutingTableError::OwnNameDisallowed)
        );
        table.verify_invariant();
        assert_eq!(table.len(), expected_rt_len);

        // Try to add a name which doesn't fit any section.
        assert_eq!(
            table.add(nodes_to_drop[0]),
            Err(RoutingTableError::PeerNameUnsuitable)
        );
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
            Err(RoutingTableError::AlreadyExists)
        );
        assert_eq!(
            table.need_to_add(&our_name),
            Err(RoutingTableError::OwnNameDisallowed)
        );
        assert_eq!(
            table.need_to_add(&nodes_to_drop[0]),
            Err(RoutingTableError::PeerNameUnsuitable)
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
}
*/

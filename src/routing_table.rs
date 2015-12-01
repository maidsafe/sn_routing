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

use std::cmp;
use std::usize;

use crust::Connection;
use itertools::*;
use public_id::PublicId;
use name_type::{closer_to_target, closer_to_target_or_equal, NameType};
use types;

static BUCKET_SIZE: usize = 1;
pub static PARALLELISM: usize = 4;
static OPTIMAL_SIZE: usize = 64;

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub public_id: PublicId,
    pub connections: Vec<Connection>,
    #[cfg(test)]
    pub id: NameType,
}

impl NodeInfo {
    #[cfg(not(test))]
    pub fn new(public_id: PublicId, connections: Vec<Connection>) -> NodeInfo {
        NodeInfo {
            public_id: public_id,
            connections: connections,
        }
    }
    #[cfg(not(test))]
    pub fn id(&self) -> &NameType {
        self.public_id.name()
    }

    #[cfg(test)]
    pub fn new(public_id: PublicId, connections: Vec<Connection>) -> NodeInfo {
        let id = public_id.name().clone();
        NodeInfo {
            public_id: public_id,
            connections: connections,
            id: id,
        }
    }
    #[cfg(test)]
    pub fn id(&self) -> &NameType {
        &self.id
    }
}



/// The RoutingTable class is used to maintain a list of contacts to which the node is connected.
pub struct RoutingTable {
    routing_table: Vec<NodeInfo>,
    our_id: NameType,
}

impl RoutingTable {
    pub fn new(our_id: &NameType) -> RoutingTable {
        RoutingTable {
            routing_table: Vec::<NodeInfo>::new(),
            our_id: our_id.clone(),
        }
    }

    pub fn get_bucket_len() -> usize {
        BUCKET_SIZE
    }

    pub fn get_parallelism() -> usize {
        PARALLELISM
    }

    pub fn get_optimal_len() -> usize {
        OPTIMAL_SIZE
    }

    pub fn get_group_len() -> usize {
        types::GROUP_SIZE
    }

    /// Adds a contact to the routing table.  If the contact is added, the first return arg is true,
    /// otherwise false.  If adding the contact caused another contact to be dropped, the dropped
    /// one is returned in the second field, otherwise the optional field is empty.  The following
    /// steps are used to determine whether to add the new contact or not:
    ///
    /// 1 - if the contact is ourself, or doesn't have a valid public key, or is already in the
    ///     table, it will not be added
    /// 2 - if the routing table is not full (len < Optimallen()), the contact will be added
    /// 3 - if the contact is within our close group, it will be added
    /// 4 - if we can find a candidate for removal (a contact in a bucket with more than BUCKET_SIZE
    ///     contacts, which is also not within our close group), and if the new contact will fit in
    ///     a bucket closer to our own bucket, then we add the new contact.
    pub fn add_node(&mut self, their_info: NodeInfo) -> (bool, Option<NodeInfo>) {
        if self.our_id == *their_info.id() {
            return (false, None);
        }

        if self.has_node(&their_info.id()) {
            debug!("Routing table {:?} has node {:?}.", self.routing_table, their_info);
            return (false, None);
        }

        if self.routing_table.len() < RoutingTable::get_optimal_len() {
            self.push_back_then_sort(their_info);
            return (true, None);
        }

        if closer_to_target(&their_info.id(),
                            &self.routing_table[RoutingTable::get_group_len()].id(),
                            &self.our_id) {
            self.push_back_then_sort(their_info);
            let removal_node_index = self.find_candidate_for_removal();
            if removal_node_index == usize::MAX {
                return (true, None);
            } else {
                let removal_node = self.routing_table[removal_node_index].clone();
                let _ = self.routing_table.remove(removal_node_index);
                return (true, Some(removal_node));
            }
        }

        let removal_node_index = self.find_candidate_for_removal();
        if removal_node_index != usize::MAX &&
           self.new_node_is_better_than_existing(&their_info.id(), removal_node_index) {
            let removal_node = self.routing_table[removal_node_index].clone();
            let _ = self.routing_table.remove(removal_node_index);
            self.push_back_then_sort(their_info);
            return (true, Some(removal_node));
        }
        (false, None)
    }

    /// Adds a connection to an existing entry.  Should be called after `has_node`.
    pub fn add_connection(&mut self, their_id: &NameType, connection: Connection) {
        match self.routing_table.iter_mut().find(|node_info| node_info.id() == their_id) {
            Some(mut node_info) => {
                node_info.connections.push(connection);
                node_info.connections = node_info.connections.iter().cloned().unique().collect();
            },
            None => error!("The NodeInfo should already exist here."),
        }
    }

    /// This is used to check whether it is worth while retrieving a contact's public key from the
    /// PKI with a view to adding the contact to our routing table.  The checking procedure is the
    /// same as for 'AddNode' above, except for the lack of a public key to check in step 1.
    pub fn want_to_add(&self, their_id: &NameType) -> bool {
        if self.our_id == *their_id {
            return false;
        }
        if self.has_node(their_id) {
            return false;
        }
        if self.routing_table.len() < RoutingTable::get_optimal_len() {
            return true;
        }
        let group_len = RoutingTable::get_group_len() - 1;
        if closer_to_target(&their_id,
                            &self.routing_table[group_len].id(),
                            &self.our_id) {
            return true;
        }
        self.new_node_is_better_than_existing(&their_id, self.find_candidate_for_removal())
    }

    /// This unconditionally removes the contact from the table.
    pub fn drop_node(&mut self, node_to_drop: &NameType) {
        let mut index_of_removal = usize::MAX;

        for i in 0..self.routing_table.len() {
            if self.routing_table[i].id() == node_to_drop {
                index_of_removal = i;
                break;
            }
        }

        if index_of_removal < self.routing_table.len() {
            let _ = self.routing_table.remove(index_of_removal);
        }
    }

    /// This returns a collection of contacts to which a message should be sent onwards.  It will
    /// return all of our close group (comprising 'Grouplen' contacts) if the closest one to the
    /// target is within our close group.  If not, it will return the 'Parallelism()' closest
    /// contacts to the target.
    pub fn target_nodes(&self, target: &NameType) -> Vec<NodeInfo> {

        let parallelism = RoutingTable::get_parallelism();

        if self.address_in_our_close_group_range(target) {
            return self.our_close_group();    
        }
 
        let mut result = Vec::new();
        
        // if not in close group but connected then send direct        
        for node in &self.routing_table { 
            if node.id() == target {
                result.push(node.clone());
                return result;
            }
        }
        
        // not in close group or routing table so send to closest known nodes up to parallelism 
        // count
        self.routing_table.iter().sorted_by(|a, b| if closer_to_target(&a.id(), &b.id(), &target) {
                                                        cmp::Ordering::Less
                                                    } else {
                                                        cmp::Ordering::Greater
                                                    }
                                            ).into_iter()
                                             .cloned()
                                             .take(parallelism)
                                             .collect::<Vec<_>>()
    }

    /// This returns our close group, i.e. the 'Grouplen' contacts closest to our ID (or the entire
    /// table if we hold less than 'Grouplen' contacts in total).
    pub fn our_close_group(&self) -> Vec<NodeInfo> {
        self.routing_table.iter()
                          .take(RoutingTable::get_group_len())
                          .into_iter()
                          .cloned()
                          .collect::<Vec<_>>()
    }

    pub fn drop_connection(&mut self, lost_connection: &Connection) -> Option<NameType> {
        let remove_connection = |node_info: &mut NodeInfo| {
            if let Some(index) = node_info.connections
                                          .iter()
                                          .position(|connection| connection == lost_connection) {
                let _ = node_info.connections.remove(index);
                true
            } else {
                false
            }
        };
        if let Some(node_index) = self.routing_table.iter_mut().position(remove_connection) {
            if self.routing_table[node_index].connections.is_empty() {
               return Some(self.routing_table.remove(node_index).id().clone())
            }
        }
        None
    }

    /// This returns the length of the routing table.
    pub fn len(&self) -> usize {
        self.routing_table.len()
    }

    pub fn our_name(&self) -> &NameType {
        &self.our_id
    }

    /// This returns true if the provided id is closer than or equal to the furthest node in our
    /// close group. If the routing table contains less than Grouplen nodes, then every address is
    /// considered to be in our close group range.
    pub fn address_in_our_close_group_range(&self, id: &NameType) -> bool {
        if self.routing_table.len() < types::GROUP_SIZE {
            return true;
        }
        let furthest_close_node = self.routing_table[types::GROUP_SIZE - 1].clone();
        closer_to_target_or_equal(&id, &furthest_close_node.id(), &self.our_id)
    }

    fn find_candidate_for_removal(&self) -> usize {
        assert!(self.routing_table.len() >= RoutingTable::get_optimal_len());

        let mut number_in_bucket = 0usize;
        let mut current_bucket = 0usize;

        // Start iterating from the end, i.e. the furthest from our ID.
        let mut counter = self.routing_table.len() - 1;
        let mut furthest_in_this_bucket = counter;

        // Stop iterating at our furthest close group member since we won't remove any peer in our
        // close group
        let finish = RoutingTable::get_group_len();

        while counter >= finish {
            let bucket_index = self.bucket_index(&self.routing_table[counter].id());

            // If we're entering a new bucket, reset details.
            if bucket_index != current_bucket {
                current_bucket = bucket_index;
                number_in_bucket = 0;
                furthest_in_this_bucket = counter;
            }

            // Check for an excess of contacts in this bucket.
            number_in_bucket += 1;
            if number_in_bucket > RoutingTable::get_bucket_len() {
                break;
            }

            counter -= 1;
        }

        if counter < finish {
            usize::MAX
        } else {
            furthest_in_this_bucket
        }
    }

    fn bucket_index(&self, id: &NameType) -> usize {
            let mut outer_count;
        for i in 0..::name_type::NAME_TYPE_LEN {
            if i == 0 { outer_count = 1; } else { outer_count = i * 8; }

            let mut us = ::bit_set::BitSet::from_bytes(&[self.our_id.0][i]);
            let them = ::bit_set::BitSet::from_bytes(&[id.0][i]);
            us.symmetric_difference_with(&them);
            for (test, num) in us.iter().enumerate() {
              if test == 0b1 {
                  return 512 - (num * outer_count);
                  }
            }
        }
        unreachable!();
    }

    pub fn has_node(&self, node_id: &NameType) -> bool {
        self.routing_table.iter().any(|node_info| node_info.id() == node_id)
    }
    
    fn push_back_then_sort(&mut self, node_info: NodeInfo) {
        {  // Try to find and update an existing entry
            if let Some(mut entry) = self.routing_table
                                         .iter_mut()
                                         .find(|element| element.id() == node_info.id()) {
                entry.connections.extend(node_info.connections);
                return
            }
        }
        // We didn't find an existing entry, so insert a new one
        self.routing_table.push(node_info);
        let our_id = &self.our_id;
        self.routing_table.sort_by(|a, b| {
            if closer_to_target(&a.id(), &b.id(), our_id) {
                cmp::Ordering::Less
            } else {
                cmp::Ordering::Greater
            }
        });
    }

    fn new_node_is_better_than_existing(&self,
                                        new_node: &NameType,
                                        removal_node_index: usize)
                                        -> bool {
        if removal_node_index >= self.routing_table.len() {
            return false;
        }
        let removal_node = &self.routing_table[removal_node_index];
        self.bucket_index(new_node) > self.bucket_index(&removal_node.id())
    }

}



#[cfg(test)]
mod test {
    extern crate bit_vec;
    use rand;

    enum ContactType {
        Far,
        Mid,
        Close,
    }

    fn are_nodes_sorted(routing_table: &super::RoutingTable) -> bool {
        for i in 1..routing_table.routing_table.len() {
            if ::name_type::closer_to_target(&routing_table.routing_table[i].id(),
                                             &routing_table.routing_table[i - 1].id(),
                                             &routing_table.our_id) {
                return false
            }
        }
        true
    }

    fn get_contact(farthest_from_tables_own_id: &::NameType,
                   index: usize,
                   contact_type: ContactType)
                   -> ::NameType {
        let mut binary_id = self::bit_vec::BitVec::from_bytes(&farthest_from_tables_own_id.0);
        if index > 0 {
            for i in 0..index {
                let bit = unwrap_option!(binary_id.get(i), "");
                binary_id.set(i, !bit);
            }
        }

        match contact_type {
            ContactType::Mid => {
                let bit_num = binary_id.len() - 1;
                let bit = unwrap_option!(binary_id.get(bit_num), "");
                binary_id.set(bit_num, !bit);
            }
            ContactType::Close => {
                let bit_num = binary_id.len() - 2;
                let bit = unwrap_option!(binary_id.get(bit_num), "");
                binary_id.set(bit_num, !bit);
            }
            ContactType::Far => {}
        };

        ::NameType(::types::slice_as_u8_64_array(&binary_id.to_bytes()[..]))
    }

    struct Bucket {
        far_contact: ::NameType,
        mid_contact: ::NameType,
        close_contact: ::NameType,
    }

    impl Bucket {
        fn new(farthest_from_tables_own_id: ::NameType, index: usize) -> Bucket {
            Bucket {
                far_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Far),
                mid_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Mid),
                close_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Close),
            }
        }
    }

    struct RoutingTableUnitTest {
        our_id: ::NameType,
        table: super::RoutingTable,
        buckets: Vec<Bucket>,
        node_info: super::NodeInfo,
        initial_count: usize,
        added_ids: Vec<::NameType>,
    }

    impl RoutingTableUnitTest {
        fn new() -> RoutingTableUnitTest {
            let node_info = create_random_node_info();
            let table = RoutingTableUnitTest {
                our_id: node_info.id().clone(),
                table: super::RoutingTable {
                    routing_table: Vec::new(),
                    our_id: node_info.id().clone(),
                },
                buckets: initialise_buckets(&node_info.id()),
                node_info: node_info,
                initial_count: (::rand::random::<usize>() %
                                (super::RoutingTable::get_group_len() - 1)) +
                               1,
                added_ids: Vec::new(),
            };

            for i in 0..99 {
                assert!(::name_type::closer_to_target(&table.buckets[i].mid_contact,
                                                      &table.buckets[i].far_contact,
                                                      &table.our_id));
                assert!(::name_type::closer_to_target(&table.buckets[i].close_contact,
                                                      &table.buckets[i].mid_contact,
                                                      &table.our_id));
                assert!(::name_type::closer_to_target(&table.buckets[i + 1].far_contact,
                                                      &table.buckets[i].close_contact,
                                                      &table.our_id));
            }

            assert!(::name_type::closer_to_target(&table.buckets[99].mid_contact,
                                                  &table.buckets[99].far_contact,
                                                  &table.our_id));
            assert!(::name_type::closer_to_target(&table.buckets[99].close_contact,
                                                  &table.buckets[99].mid_contact,
                                                  &table.our_id));

            table
        }

        fn partially_fill_table(&mut self) {
            for i in 0..self.initial_count {
                self.node_info.id = self.buckets[i].mid_contact.clone();
                self.added_ids.push(self.node_info.id().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(self.initial_count, self.table.len());
        }

        fn complete_filling_table(&mut self) {
            for i in self.initial_count..super::RoutingTable::get_optimal_len() {
                self.node_info.id = self.buckets[i].mid_contact.clone();
                self.added_ids.push(self.node_info.id().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(super::RoutingTable::get_optimal_len(), self.table.len());
        }

        fn public_id(&self, their_id: &::NameType) -> Option<::public_id::PublicId> {
            debug_assert!(are_nodes_sorted(&self.table), "RT::public_id: Nodes are not sorted");
            match self.table.routing_table.iter().find(|&node_info| node_info.id() == their_id) {
                Some(node) => Some(node.public_id.clone()),
                None => None,
            }
        }

    }

    fn initialise_buckets(our_id: &::NameType) -> Vec<Bucket> {
        let arr = [255u8; 64];
        let mut arr_res = [0u8; 64];
        for i in 0..64 {
            arr_res[i] = arr[i] ^ our_id.0[i];
        }

        let farthest_from_tables_own_id = ::NameType::new(arr_res);

        let mut buckets = Vec::new();
        for i in 0..100 {
            buckets.push(Bucket::new(farthest_from_tables_own_id.clone(), i));
        }

        buckets
    }

    fn create_random_node_info() -> super::NodeInfo {
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        super::NodeInfo {
            id: public_id.name().clone(),
            public_id: public_id,
            connections: Vec::new(),
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<super::RoutingTable> {
        let mut vector: Vec<super::RoutingTable> = Vec::with_capacity(num_of_tables);
        for _ in 0..num_of_tables {
            vector.push(super::RoutingTable {
                routing_table: Vec::new(),
                our_id: rand::random(),
            });
        }
        vector
    }

    #[test]
    fn want_to_add() {
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);

        for i in 0..num_of_tables {
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();

                if tables[i].want_to_add(&node_info.id()) {
                    let removed_node = tables[i].add_node(node_info);
                    assert!(removed_node.0);
                }
            }
        }
    }

    #[test]
    fn routing_table_test() {

        let mut table = super::RoutingTable {
            routing_table: Vec::new(),
            our_id: rand::random(),
        };

        for _ in 0..super::RoutingTable::get_group_len() {
            let id = rand::random();
            assert!(table.want_to_add(&id));
        }

        assert_eq!(table.len(), 0);

        for _ in 0..super::RoutingTable::get_group_len() {
            let node_info = create_random_node_info();
            assert!(table.add_node(node_info).0);
        }

        assert_eq!(table.len(), super::RoutingTable::get_group_len());
    }

    #[test]
    fn add_check_close_group_test() {
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<::NameType> = Vec::with_capacity(num_of_tables);

        for i in 0..num_of_tables {
            addresses.push(tables[i].our_id.clone());
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                let _ = tables[i].add_node(node_info);
            }
        }
        for it in tables.iter() {
            let id = it.our_id.clone();
            addresses.sort_by(|a, b| {
                if ::name_type::closer_to_target(&a, &b, &id) {
                    ::std::cmp::Ordering::Less
                } else {
                    ::std::cmp::Ordering::Greater
                }
            });
            let mut groups = it.our_close_group();
            assert_eq!(groups.len(), super::RoutingTable::get_group_len());

            // TODO(Spandan) vec.dedup does not compile - manually doing it
            if groups.len() > 1 {
                let mut new_end = 1usize;
                for i in 1..groups.len() {
                    if groups[new_end - 1].id() != groups[i].id() {
                        if new_end != i {
                            groups[new_end] = groups[i].clone();
                        }
                        new_end += 1;
                    }
                }
                assert_eq!(new_end, groups.len());
            }

            assert_eq!(groups.len(), super::RoutingTable::get_group_len());

            for i in 0..super::RoutingTable::get_group_len() {
                assert!(groups[i].id() == &addresses[i + 1]);
            }
        }
    }

    #[test]
    fn add_node_test() {
        let mut test = RoutingTableUnitTest::new();

        assert_eq!(test.table.len(), 0);

        // try with our id - should fail
        test.node_info.id = test.table.our_id.clone();
        let mut result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(test.table.len(), 0);

        // add first contact
        test.node_info.id = test.buckets[0].far_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(test.table.len(), 1);

        // try with the same contact - should fail
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(test.table.len(), 1);

        // Add further 'Optimallen()' - 1 contacts (should all succeed with no removals).  Set this
        // up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have 0 or
        // 1 contacts.

        // Bucket 0
        test.node_info.id = test.buckets[0].mid_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(2, test.table.len());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(2, test.table.len());

        test.node_info.id = test.buckets[0].close_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(3, test.table.len());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(3, test.table.len());

        // Bucket 1
        test.node_info.id = test.buckets[1].far_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(4, test.table.len());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(4, test.table.len());

        test.node_info.id = test.buckets[1].mid_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(5, test.table.len());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(5, test.table.len());

        test.node_info.id = test.buckets[1].close_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(6, test.table.len());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(6, test.table.len());

        // Add remaining contacts
        for i in 2..(super::RoutingTable::get_optimal_len() - 4) {
            test.node_info.id = test.buckets[i].mid_contact.clone();
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {}
            };
            assert_eq!(i + 5, test.table.len());
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(!result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {}
            };
            assert_eq!(i + 5, test.table.len());
        }

        // Check next 4 closer additions return 'buckets_[0].far_contact', 'buckets_[0].mid_contact',
        // 'buckets_[1].far_contact', and 'buckets_[1].mid_contact' as dropped (in that order)
        let mut dropped: Vec<::NameType> = Vec::new();
        let optimal_len = super::RoutingTable::get_optimal_len();
        for i in (optimal_len - 4)..optimal_len {
            test.node_info.id = test.buckets[i].mid_contact.clone();
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(result_of_add.0);
            match result_of_add.1 {
                Some(dropped_info) => {
                    dropped.push(dropped_info.id().clone())
                }
                None => panic!("Unexpected"),
            };
            assert_eq!(super::RoutingTable::get_optimal_len(), test.table.len());
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(!result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {}
            };
            assert_eq!(super::RoutingTable::get_optimal_len(), test.table.len());
        }
        assert!(test.buckets[0].far_contact == dropped[0]);
        assert!(test.buckets[0].mid_contact == dropped[1]);
        assert!(test.buckets[1].far_contact == dropped[2]);
        assert!(test.buckets[1].mid_contact == dropped[3]);

        // Try to add far contacts again (should fail)
        for far_contact in dropped {
            test.node_info.id = far_contact.clone();
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(!result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {}
            };
            assert_eq!(super::RoutingTable::get_optimal_len(), test.table.len());
        }

        // Add final close contact to push len of table_ above Optimallen()
        test.node_info.id = test.buckets[super::RoutingTable::get_optimal_len()]
                                .mid_contact
                                .clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(super::RoutingTable::get_optimal_len() + 1,
                   test.table.len());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {}
        };
        assert_eq!(super::RoutingTable::get_optimal_len() + 1,
                   test.table.len());
    }

    #[test]
    fn drop_node_test() {
        // Check on empty table
        let mut test = RoutingTableUnitTest::new();

        assert_eq!(test.table.len(), 0);

        // Fill the table
        test.partially_fill_table();
        test.complete_filling_table();

        // Try with invalid Address
        test.table.drop_node(&::NameType::new([0u8; 64]));
        assert_eq!(super::RoutingTable::get_optimal_len(), test.table.len());

        // Try with our ID
        let drop_id = test.table.our_id.clone();
        test.table.drop_node(&drop_id);
        assert_eq!(super::RoutingTable::get_optimal_len(), test.table.len());

        // Try with Address of node not in table
        test.table.drop_node(&test.buckets[0].far_contact);
        assert_eq!(super::RoutingTable::get_optimal_len(), test.table.len());

        // Remove all nodes one at a time
        // TODO(Spandan) Shuffle not implemented
        let mut len = test.table.len();
        for id in test.added_ids {
            len -= 1;
            test.table.drop_node(&id);
            assert_eq!(len, test.table.len());
        }
    }

    #[test]
    fn check_node_test() {
        let mut routing_table_utest = RoutingTableUnitTest::new();

        // Try with our ID
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.table.our_id),
                   false);

        // Should return true for empty routing table
        assert!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0].far_contact));

        // Add the first contact, and check it doesn't allow duplicates
        let mut new_node_0 = create_random_node_info();
        new_node_0.id = routing_table_utest.buckets[0].far_contact.clone();
        assert!(routing_table_utest.table.add_node(new_node_0).0);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .far_contact
                                                             .clone()),
                   false);

        // Add further 'Optimallen()' - 1 contact (should all succeed with no removals).  Set this
        // up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have 0 or
        // 1 contacts.

        let mut new_node_1 = create_random_node_info();
        new_node_1.id = routing_table_utest.buckets[0].mid_contact.clone();
        assert!(routing_table_utest.table.want_to_add(&new_node_1.id()));
        assert!(routing_table_utest.table.add_node(new_node_1).0);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .mid_contact
                                                             .clone()),
                   false);

        let mut new_node_2 = create_random_node_info();
        new_node_2.id = routing_table_utest.buckets[0].close_contact.clone();
        assert!(routing_table_utest.table.want_to_add(&new_node_2.id()));
        assert!(routing_table_utest.table.add_node(new_node_2).0);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .close_contact
                                                             .clone()),
                   false);

        let mut new_node_3 = create_random_node_info();
        new_node_3.id = routing_table_utest.buckets[1].far_contact.clone();
        assert!(routing_table_utest.table.want_to_add(&new_node_3.id()));
        assert!(routing_table_utest.table.add_node(new_node_3).0);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .far_contact
                                                             .clone()),
                   false);

        let mut new_node_4 = create_random_node_info();
        new_node_4.id = routing_table_utest.buckets[1].mid_contact.clone();
        assert!(routing_table_utest.table.want_to_add(&new_node_4.id()));
        assert!(routing_table_utest.table.add_node(new_node_4).0);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .mid_contact
                                                             .clone()),
                   false);

        let mut new_node_5 = create_random_node_info();
        new_node_5.id = routing_table_utest.buckets[1].close_contact.clone();
        assert!(routing_table_utest.table.want_to_add(&new_node_5.id()));
        assert!(routing_table_utest.table.add_node(new_node_5).0);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .close_contact
                                                             .clone()),
                   false);

        for i in 2..(super::RoutingTable::get_optimal_len() - 4) {
            let mut new_node = create_random_node_info();
            new_node.id = routing_table_utest.buckets[i].mid_contact.clone();
            assert!(routing_table_utest.table.want_to_add(&new_node.id()));
            assert!(routing_table_utest.table.add_node(new_node).0);
            assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[i]
                                                                 .mid_contact
                                                                 .clone()),
                       false);
        }

        assert_eq!(super::RoutingTable::get_optimal_len(),
                   routing_table_utest.table.routing_table.len());

        let optimal_len = super::RoutingTable::get_optimal_len();
        for i in (optimal_len - 4)..optimal_len {
            let mut new_node = create_random_node_info();
            new_node.id = routing_table_utest.buckets[i].mid_contact.clone();
            assert!(routing_table_utest.table.want_to_add(&new_node.id()));
            assert!(routing_table_utest.table.add_node(new_node).0);
            assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[i]
                                                                 .mid_contact
                                                                 .clone()),
                       false);
            assert_eq!(super::RoutingTable::get_optimal_len(),
                       routing_table_utest.table.routing_table.len());
        }

        // Check for contacts again which are now not in the table
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .far_contact
                                                             .clone()),
                   false);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .mid_contact
                                                             .clone()),
                   false);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .far_contact
                                                             .clone()),
                   false);
        assert_eq!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .mid_contact
                                                             .clone()),
                   false);

        // Check final close contact which would push len of table_ above Optimallen()
        assert!(routing_table_utest.table.want_to_add(
          &routing_table_utest.buckets[super::RoutingTable::get_optimal_len()]
                              .mid_contact.clone()));
    }

    #[test]
    fn churn_test() {
        let network_len = 200usize;
        let nodes_to_remove = 20usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<::NameType> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_id.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                let _ = tables[i].add_node(node_info);
            }
        }

        // now remove nodes
        let mut drop_vec: Vec<::NameType> = Vec::with_capacity(nodes_to_remove);
        for i in 0..nodes_to_remove {
            drop_vec.push(addresses[i].clone());
        }

        tables.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            for j in 0..drop_vec.len() {
                tables[i].drop_node(&drop_vec[j]);
            }
        }
        // remove IDs too
        addresses.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            let len = if super::RoutingTable::get_group_len() < tables[i].len() {
                super::RoutingTable::get_group_len()
            } else {
                tables[i].len()
            };
            let id = tables[i].our_id.clone();
            addresses.sort_by(|a, b| {
                if ::name_type::closer_to_target(&a, &b, &id) {
                    ::std::cmp::Ordering::Less
                } else {
                    ::std::cmp::Ordering::Greater
                }
            });
            let groups = tables[i].our_close_group();
            assert_eq!(groups.len(), len);
        }
    }

    #[test]
    fn target_nodes_group_test() {
        let network_len = 100usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<::NameType> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_id.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                let _ = tables[i].add_node(node_info);
            }
        }

        for i in 0..tables.len() {
            addresses.sort_by(|a, b| {
                if ::name_type::closer_to_target(&a, &b, &tables[i].our_id) {
                    ::std::cmp::Ordering::Less
                } else {
                    ::std::cmp::Ordering::Greater
                }
            });
            // if target is in close group return the whole close group excluding target
            for j in 1..(super::RoutingTable::get_group_len() - ::types::QUORUM_SIZE) {
                let target_close_group = tables[i].target_nodes(&addresses[j]);
                assert_eq!(super::RoutingTable::get_group_len(),
                           target_close_group.len());
                // should contain our close group
                for k in 0..target_close_group.len() {
                    assert!(target_close_group[k].id() == &addresses[k + 1]);
                }
            }
        }
    }

    #[test]
    fn our_close_group_and_in_range() {
        // independent double verification of our_close_group()
        // this test verifies that the close group is returned sorted
        let our_id_name = ::id::Id::new().name();
        let mut routing_table = super::RoutingTable::new(&our_id_name);

        let mut count: usize = 0;
        loop {
            let _ = routing_table.add_node(super::NodeInfo::new(
                ::public_id::PublicId::new(&::id::Id::new()), vec![]));
            count += 1;
            if routing_table.len() >= super::RoutingTable::get_optimal_len() {
                break;
            }
            if count >= 2 * super::RoutingTable::get_optimal_len() {
                panic!("Routing table does not fill up.");
            }
        }
        let our_close_group: Vec<super::NodeInfo> = routing_table.our_close_group();
        assert_eq!(our_close_group.len(), super::RoutingTable::get_group_len());
        let mut closer_name: ::NameType = our_id_name.clone();
        for close_node in &our_close_group {
            assert!(::name_type::closer_to_target(&closer_name, &close_node.id(), &our_id_name));
            assert!(routing_table.address_in_our_close_group_range(&close_node.id()));
            closer_name = close_node.id().clone();
        }
        for node in &routing_table.routing_table {
            if our_close_group.iter()
                              .filter(|close_node| close_node.id() == node.id())
                              .count() > 0 {
                assert!(routing_table.address_in_our_close_group_range(&node.id()));
            } else {
                assert_eq!(false,
                           routing_table.address_in_our_close_group_range(&node.id()));
            }
        }
    }

    #[test]
    fn our_close_group_test() {
        let mut table_unit_test = RoutingTableUnitTest::new();
        assert!(table_unit_test.table.our_close_group().is_empty());

        table_unit_test.partially_fill_table();
        assert_eq!(table_unit_test.initial_count,
                   table_unit_test.table.our_close_group().len());

        for i in 0..table_unit_test.initial_count {
            assert!(table_unit_test.table
                                   .our_close_group()
                                   .iter()
                                   .filter(|&node| {
                                       node.id() == &table_unit_test.buckets[i].mid_contact
                                   })
                                   .count() > 0);
        }

        table_unit_test.complete_filling_table();
        assert_eq!(super::RoutingTable::get_group_len(),
                   table_unit_test.table.our_close_group().len());

        for close_node in table_unit_test.table.our_close_group().iter() {
            assert!(table_unit_test.added_ids
                                   .iter()
                                   .filter(|&node| node == close_node.id())
                                   .count() == 1);
        }
    }

    #[test]
    fn target_nodes_test() {
        let mut routing_table_utest = RoutingTableUnitTest::new();

        // Check on empty table
        let mut target_nodes_ = routing_table_utest.table.target_nodes(&rand::random());
        assert_eq!(target_nodes_.len(), 0);

        // Partially fill the table with < Grouplen contacts
        routing_table_utest.partially_fill_table();

        // Check we get all contacts returnedta
        target_nodes_ = routing_table_utest.table.target_nodes(&rand::random());
        assert_eq!(routing_table_utest.initial_count, target_nodes_.len());

        for i in 0..routing_table_utest.initial_count {
            let mut assert_checker = 0;
            for j in 0..target_nodes_.len() {
                if target_nodes_[j].id() == &routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Complete filling the table up to RoutingTable::get_optimal_len() contacts
        routing_table_utest.complete_filling_table();

        // Try with our ID (should return closest to us, i.e. buckets 63 to 32)
        target_nodes_ = routing_table_utest.table.target_nodes(&routing_table_utest.table.our_id);
        assert_eq!(super::RoutingTable::get_group_len(), target_nodes_.len());

        for i in ((super::RoutingTable::get_optimal_len() -
                   super::RoutingTable::get_group_len())..
                   super::RoutingTable::get_optimal_len() - 1).rev() {
            let mut assert_checker = 0;
            for j in 0..target_nodes_.len() {
                if target_nodes_[j].id() == &routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Try with nodes far from us, first time *not* in table and second time *in* table (should
        // return 'RoutingTable::Parallelism()' contacts closest to target)
        let mut target: ::NameType;
        for count in 0..2 {
            for i in 0..(super::RoutingTable::get_optimal_len() -
                         super::RoutingTable::get_group_len()) {
                target = if count == 0 {
                    routing_table_utest.buckets[i].far_contact.clone()
                } else {
                    routing_table_utest.buckets[i].mid_contact.clone()
                };
                target_nodes_ = routing_table_utest.table.target_nodes(&target);
                assert_eq!(super::RoutingTable::get_parallelism(), target_nodes_.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if ::name_type::closer_to_target(
                            &a.id(), &b.id(), &routing_table_utest.our_id) {
                        ::std::cmp::Ordering::Less
                    } else {
                        ::std::cmp::Ordering::Greater
                    });

                for i in 0..target_nodes_.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_ids.len() {
                        if target_nodes_[i].id() == &routing_table_utest.added_ids[j] {
                            assert_checker = 1;
                            continue;
                        }
                    }
                    assert!(assert_checker == 1);
                }
            }
        }

        // Try with nodes close to us, first time *not* in table and second time *in* table (should
        // return Grouplen closest to target)
        for count in 0..2 {
            for i in (super::RoutingTable::get_optimal_len() -
                      super::RoutingTable::get_group_len())..
                      super::RoutingTable::get_optimal_len() {
                target = if count == 0 {
                    routing_table_utest.buckets[i].far_contact.clone()
                } else {
                    routing_table_utest.buckets[i].mid_contact.clone()
                };
                target_nodes_ = routing_table_utest.table.target_nodes(&target);
                assert_eq!(super::RoutingTable::get_group_len(), target_nodes_.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if ::name_type::closer_to_target(
                            &a.id(), &b.id(), &routing_table_utest.our_id) {
                        ::std::cmp::Ordering::Less
                    } else {
                        ::std::cmp::Ordering::Greater
                    });

                for i in 0..target_nodes_.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_ids.len() {
                        if target_nodes_[i].id() == &routing_table_utest.added_ids[j] {
                            assert_checker = 1;
                            continue;
                        }
                    }
                    assert!(assert_checker == 1);
                }
            }
        }
    }

    #[test]
    fn trivial_functions_test() {
        let mut table_unit_test = RoutingTableUnitTest::new();
        match table_unit_test.public_id(&table_unit_test.buckets[0].mid_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {}
        }
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(0, table_unit_test.table.routing_table.len());

        // Check on partially filled the table
        table_unit_test.partially_fill_table();
        let test_node = create_random_node_info();
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.public_id(&table_unit_test.node_info.id()) {
            Some(_) => {}
            None => panic!("PublicId None"),
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_public_id.public_key(),
        //                                 *table_.GetPublicKey(info_.id())));
        match table_unit_test.public_id(&table_unit_test.buckets[table_unit_test.buckets.len() -
                                                                 1]
                                             .far_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {}
        }
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(table_unit_test.initial_count + 1,
                   table_unit_test.table.routing_table.len());

        // Check on fully filled the table
        table_unit_test.table.drop_node(&test_node.id().clone());
        table_unit_test.complete_filling_table();
        table_unit_test.table.drop_node(&table_unit_test.buckets[0].mid_contact.clone());
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.public_id(&table_unit_test.node_info.id()) {
            Some(_) => {}
            None => panic!("PublicId None"),
        }
        match table_unit_test.public_id(&table_unit_test.buckets[table_unit_test.buckets.len() -
                                                                 1]
                                             .far_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {}
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_public_id.public_key(),
        //                                 *table_.GetPublicKey(info_.id())));
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(super::RoutingTable::get_optimal_len(),
                   table_unit_test.table.routing_table.len());
    }

    #[test]
    fn bucket_index() {
        // Set our name for routing table to max possible value (in binary, all `1`s)
        let our_name = ::NameType::new([255u8; ::NAME_TYPE_LEN]);
        let routing_table = super::RoutingTable::new(&our_name);

        // Iterate through each u8 element of a target name identical to ours and set it to each
        // possible value for u8 other than 255 (since that which would a target name identical to
        // our name)
        for index in 0..::NAME_TYPE_LEN {
            let mut array = [255u8; ::NAME_TYPE_LEN];
            for modified_element in 0..255u8 {
                array[index] = modified_element;
                let target_name = ::NameType::new(array);
                // `index` is equivalent to common leading bytes, so the common leading bits (CLBs)
                // is `index` * 8 plus some value for `modified_element`.  Where
                // 0 <= modified_element < 128, the first bit is different so CLBs is 0, and for
                // 128 <= modified_element < 192, the second bit is different, so CLBs is 1, and so
                // on.
                let expected_bucket_index = (index * 8) + match modified_element {
                    0...127 => 0,
                    128...191 => 1,
                    192...223 => 2,
                    224...239 => 3,
                    240...247 => 4,
                    248...251 => 5,
                    252 | 253 => 6,
                    254 => 7,
                    _ => unreachable!(),
                };
                if expected_bucket_index != routing_table.bucket_index(&target_name) {
                    let as_binary = |name: &::NameType| -> String {
                        let mut name_as_binary = String::new();
                        for i in name.0.iter() {
                            name_as_binary.push_str(&format!("{:08b}", i));
                        }
                        name_as_binary
                    };
                    println!("us:   {}", as_binary(&our_name));
                    println!("them: {}", as_binary(&target_name));
                    println!("index:                 {}", index);
                    println!("modified_element:      {}", modified_element);
                    println!("expected bucket_index: {}", expected_bucket_index);
                    println!("actual bucket_index:   {}", routing_table.bucket_index(&target_name));
                }
                assert_eq!(expected_bucket_index, routing_table.bucket_index(&target_name));
            }
        }

        // Check the bucket index of our own name is 512
        assert_eq!(::NAME_TYPE_LEN * 8, routing_table.bucket_index(&our_name));
    }
}

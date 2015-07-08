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
use std::collections::{HashMap};

use crust::Endpoint;

use common_bits::*;
use types::PublicId;
use name_type::{closer_to_target, closer_to_target_or_equal, NameType};
use types;

static BUCKET_SIZE: usize = 1;
pub static PARALLELISM: usize = 4;
static OPTIMAL_SIZE: usize = 64;

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub fob: PublicId,
    pub endpoints: Vec<Endpoint>,
    pub connected_endpoint: Option<Endpoint>,
    #[cfg(test)]
    pub id: NameType,
}

impl NodeInfo {
    #[cfg(not(test))]
    pub fn new(fob: PublicId, endpoints: Vec<Endpoint>,
               connected_endpoint: Option<Endpoint>) -> NodeInfo {
        NodeInfo {
            fob: fob,
            endpoints: endpoints,
            connected_endpoint: connected_endpoint,
        }
    }
    #[cfg(not(test))]
    pub fn id(&self) -> NameType {
        self.fob.name()
    }

    #[cfg(test)]
    pub fn new(fob: PublicId, endpoints: Vec<Endpoint>,
               connected_endpoint: Option<Endpoint>) -> NodeInfo {
        let id = fob.name();
        NodeInfo {
            fob: fob,
            endpoints: endpoints,
            connected_endpoint: connected_endpoint,
            id: id,
        }
    }
    #[cfg(test)]
    pub fn id(&self) -> NameType {
        self.id.clone()
    }
}

/// The RoutingTable class is used to maintain a list of contacts to which the node is connected.
pub struct RoutingTable {
    routing_table: Vec<NodeInfo>,
    lookup_map: HashMap<Endpoint, NameType>,
    our_id: NameType,
}

impl RoutingTable {
    pub fn new(our_id: &NameType) -> RoutingTable {
        RoutingTable {
            routing_table: Vec::<NodeInfo>::new(),
            lookup_map: HashMap::new(),
            our_id: our_id.clone()
        }
    }

    pub fn get_bucket_size() -> usize { BUCKET_SIZE }

    pub fn get_parallelism() -> usize { PARALLELISM }

    pub fn get_optimal_size() -> usize { OPTIMAL_SIZE }

    pub fn get_group_size() -> usize { types::GROUP_SIZE }

    /// Adds a contact to the routing table.  If the contact is added, the first return arg is true,
    /// otherwise false.  If adding the contact caused another contact to be dropped, the dropped
    /// one is returned in the second field, otherwise the optional field is empty.  The following
    /// steps are used to determine whether to add the new contact or not:
    ///
    /// 1 - if the contact is ourself, or doesn't have a valid public key, or is already in the
    ///     table, it will not be added
    /// 2 - if the routing table is not full (size < OptimalSize()), the contact will be added
    /// 3 - if the contact is within our close group, it will be added
    /// 4 - if we can find a candidate for removal (a contact in a bucket with more than BUCKET_SIZE
    ///     contacts, which is also not within our close group), and if the new contact will fit in
    ///     a bucket closer to our own bucket, then we add the new contact.
    pub fn add_node(&mut self, their_info: NodeInfo)->(bool, Option<NodeInfo>) {
        if self.our_id == their_info.id() {
            return (false, None);
        }

        if self.has_node(&their_info.id()) {
            return (false, None);
        }

        if self.routing_table.len() < RoutingTable::get_optimal_size() {
            self.push_back_then_sort(their_info);
            return (true, None);
        }

        if closer_to_target(&their_info.id(),
                            &self.routing_table[RoutingTable::get_group_size()].id(),
                            &self.our_id) {
            self.push_back_then_sort(their_info);
            let removal_node_index = self.find_candidate_for_removal();
            if removal_node_index == usize::MAX {
                return (true, None);
            } else {
                let removal_node = self.routing_table[removal_node_index].clone();
                self.remove_dangling_endpoints(&removal_node.id());
                self.routing_table.remove(removal_node_index);
                return (true, Some(removal_node));
            }
        }

        let removal_node_index = self.find_candidate_for_removal();
        if removal_node_index != usize::MAX &&
                self.new_node_is_better_than_existing(&their_info.id(), removal_node_index) {
            let removal_node = self.routing_table[removal_node_index].clone();
            self.remove_dangling_endpoints(&removal_node.id());
            self.routing_table.remove(removal_node_index);
            self.push_back_then_sort(their_info);
            return (true, Some(removal_node));
        }
        (false, None)
    }

    /// This changes the connected status of the peer from false to true.  Only one connection is
    /// allowed per node, so this returns None if the endpoint doesn't exist anywhere in the table
    /// or if the peer already has a connected endpoint.  Otherwise it returns the peer's ID.
    pub fn mark_as_connected(&mut self, endpoint: &Endpoint) -> Option<NameType> {
        let has_endpoint = |ref node_info: &NodeInfo| {
            for ref candidate_endpoint in &node_info.endpoints {
                if **candidate_endpoint == *endpoint {
                    return true;
                }
            }
            false
        };
        match self.routing_table.iter().position(has_endpoint) {
            None => None,
            Some(index) => {
                self.routing_table[index].connected_endpoint = Some(endpoint.clone());
                // always force update lookup_map
                self.lookup_map.remove(&endpoint);
                self.lookup_map.entry(endpoint.clone())
                               .or_insert(self.routing_table[index].id());
                Some(self.routing_table[index].id())
            },
        }
    }

    /// This is used to check whether it is worth while retrieving a contact's public key from the
    /// PKI with a view to adding the contact to our routing table.  The checking procedure is the
    /// same as for 'AddNode' above, except for the lack of a public key to check in step 1.
    pub fn check_node(&self, their_id: &NameType)->bool {
        if self.our_id == *their_id {
            return false;
        }
        if self.has_node(their_id) {
            return false;
        }
        //  std::lock_guard<std::mutex> lock(mutex_);
        if self.routing_table.len() < RoutingTable::get_optimal_size() {
            return true;
        }
        let group_size = RoutingTable::get_group_size() - 1;
        if closer_to_target(&their_id, &self.routing_table[group_size].id(), &self.our_id) {
            return true;
        }
        self.new_node_is_better_than_existing(&their_id, self.find_candidate_for_removal())
    }

    /// This unconditionally removes the contact from the table.
    pub fn drop_node(&mut self, node_to_drop: &NameType) {
        let mut index_of_removal = usize::MAX;

        for i in 0..self.routing_table.len() {
            if self.routing_table[i].id() == *node_to_drop {
                index_of_removal = i;
                break;
            }
        }

        if index_of_removal < self.routing_table.len() {
            let removal_name : NameType = self.routing_table[index_of_removal].id();
            self.remove_dangling_endpoints(&removal_name);
            self.routing_table.remove(index_of_removal);
        }
    }

    /// This returns a collection of contacts to which a message should be sent onwards.  It will
    /// return all of our close group (comprising 'GroupSize' contacts) if the closest one to the
    /// target is within our close group.  If not, it will return the 'Parallelism()' closest
    /// contacts to the target.
    pub fn target_nodes(&self, target: &NameType)->Vec<NodeInfo> {
        let mut our_close_group = Vec::new();
        let mut closest_to_target = Vec::new();
        let mut result: Vec<NodeInfo> = Vec::new();
        let mut iterations = 0usize;

        let parallelism = if RoutingTable::get_parallelism() < self.routing_table.len() {
            RoutingTable::get_parallelism()
        } else {
            self.routing_table.len()
        };

        for iter in self.routing_table.iter() {
            if iterations < RoutingTable::get_group_size() {
                our_close_group.push(iter.clone());
            }
            closest_to_target.push(iter.clone());
            iterations += 1;
        }

        if closest_to_target.is_empty() {
            return result;
        }

        closest_to_target.sort_by(
            |a, b| if closer_to_target(&a.id(), &b.id(), &target) {
                cmp::Ordering::Less
            } else {
                cmp::Ordering::Greater
            });

        if RoutingTable::is_any_of(&our_close_group, &closest_to_target) {
            for iter in our_close_group.iter() {
                result.push(iter.clone());
            }
        } else {
            for iter in closest_to_target.iter().take(parallelism) {
                result.push(iter.clone());
            }
        }
        result
    }

    /// This returns our close group, i.e. the 'GroupSize' contacts closest to our ID (or the entire
    /// table if we hold less than 'GroupSize' contacts in total).
    pub fn our_close_group(&self) -> Vec<NodeInfo> {
        let group_size = RoutingTable::get_group_size();
        let size = cmp::min(group_size, self.routing_table.len());
        let mut result = Vec::new();
        for i in 0..size {
            // is cloning advisable?
            result.push(self.routing_table[i].clone());
        }
        result
    }

    // /// This returns the public key for the given node if the node is in our table.
    // pub fn public_id(&self, their_id: &NameType)->Option<PublicId> {
    //     debug_assert!(self.is_nodes_sorted(), "RT::public_id: Nodes are not sorted");
    //     match self.routing_table.iter().find(|&node_info| node_info.id() == *their_id) {
    //         Some(node) => Some(node.fob.clone()),
    //         None => None,
    //     }
    // }

    pub fn lookup_endpoint(&self, their_endpoint: &Endpoint) -> Option<NameType> {
        debug_assert!(self.is_nodes_sorted(), "RT::Lookup: Nodes are not sorted");
        match self.lookup_map.get(their_endpoint) {
            Some(name) => Some(name.clone()),
            None => None
        }
    }

    /// This returns the length of the routing table.
    pub fn size(&self)->usize {
        //std::lock_guard<std::mutex> lock(mutex_);
        self.routing_table.len()
    }

    pub fn our_name(&self) -> NameType {
        self.our_id.clone()
    }

    /// This returns true if the provided id is closer than or equal to the furthest node in our
    /// close group. If the routing table contains less than GroupSize nodes, then every address is
    /// considered to be in our close group range.
    pub fn address_in_our_close_group_range(&self, id: &NameType) -> bool {
        if self.routing_table.len() < types::GROUP_SIZE {
            return true;
        }
        let furthest_close_node = self.routing_table[types::GROUP_SIZE - 1].clone();
        closer_to_target_or_equal(&id, &furthest_close_node.id(), &self.our_id)
    }

    fn find_candidate_for_removal(&self) -> usize {
        assert!(self.routing_table.len() >= RoutingTable::get_optimal_size());

        let mut number_in_bucket = 0usize;
        let mut current_bucket = 0usize;

        // Start iterating from the end, i.e. the furthest from our ID.
        let mut counter = self.routing_table.len() - 1;
        let mut furthest_in_this_bucket = counter;

        // Stop iterating at our furthest close group member since we won't remove any peer in our
        // close group
        let finish = RoutingTable::get_group_size();

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
            if number_in_bucket > RoutingTable::get_bucket_size() {
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
        let mut index_of_mismatch = 0usize;

        while index_of_mismatch < self.our_id.0.len() {
            if id.0[index_of_mismatch] != self.our_id.0[index_of_mismatch] {
                break;
            }
            index_of_mismatch += 1;
        }

        if index_of_mismatch == self.our_id.0.len() {
            return 8 * self.our_id.0.len();
        }

        let common_bits = K_COMMON_BITS[self.our_id.0[index_of_mismatch] as usize]
                                       [id.0[index_of_mismatch] as usize];
        8 * index_of_mismatch + common_bits as usize
    }

    fn has_node(&self, node_id: &NameType) -> bool {
        for node_info in &self.routing_table {
            if node_info.id() == *node_id {
                return true;
            }
        }
        false
    }

    fn push_back_then_sort(&mut self, node_info: NodeInfo) {
        match node_info.connected_endpoint.clone() {
            Some(endpoint) => {
                self.lookup_map.remove(&endpoint);
                self.lookup_map.entry(endpoint.clone())
                               .or_insert(node_info.id());
            },
            None => ()
        };
        self.routing_table.push(node_info);
        let our_id = &self.our_id;
        self.routing_table.sort_by(
            |a, b| if closer_to_target(&a.id(), &b.id(), our_id) {
                cmp::Ordering::Less
            } else {
                cmp::Ordering::Greater
            });
    }

    fn is_nodes_sorted(&self) -> bool {
        for i in 1..self.routing_table.len() {
            if closer_to_target(&self.routing_table[i].id(), &self.routing_table[i - 1].id(), &self.our_id) {
                return false;
            }
        }
        true
    }

    fn new_node_is_better_than_existing (&self, new_node: &NameType,
                                         removal_node_index: usize) -> bool {
        if removal_node_index >= self.routing_table.len() {
            return false;
        }
        let removal_node = &self.routing_table[removal_node_index];
        self.bucket_index(new_node) > self.bucket_index(&removal_node.id())
    }

    fn is_any_of(vec_close_group: &Vec<NodeInfo>, vec_closest_to_target: &Vec<NodeInfo>) -> bool {
        for iter in vec_close_group.iter() {
            if iter.id() == vec_closest_to_target[0].id() {
                return true;
            }
        }
        false
    }

    fn remove_dangling_endpoints(&mut self, name_removed: &NameType) {
        let dangling_endpoints = self.lookup_map.iter()
            .filter_map(|(endpoint, name)| if name == name_removed {
                    Some(endpoint.clone())
                } else { None })
            .collect::<Vec<_>>();
        for endpoint in dangling_endpoints {
            self.lookup_map.remove(&endpoint);
        }
    }
}



#[cfg(test)]
mod test {
    extern crate bit_vec;

    use super::*;
    use std::cmp;
    use self::bit_vec::BitVec;
    use std::collections::{HashMap};
    use types::PublicId;
    use name_type::closer_to_target;
    use types;
    use NameType;
    use rand;
    use test_utils::{Random, random_endpoints};

    enum ContactType {
        Far,
        Mid,
        Close,
    }

    fn get_contact(farthest_from_tables_own_id: &NameType, index: usize,
                   contact_type: ContactType) -> NameType {
        let mut binary_id = BitVec::from_bytes(&farthest_from_tables_own_id.0);
        if index > 0 {
            for i in 0..index {
                let bit = binary_id.get(i).unwrap();
                binary_id.set(i, !bit);
            }
        }

        match contact_type {
            ContactType::Mid => {
                let bit_num = binary_id.len() - 1;
                let bit = binary_id.get(bit_num).unwrap();
                binary_id.set(bit_num, !bit);
            },
            ContactType::Close => {
                let bit_num = binary_id.len() - 2;
                let bit = binary_id.get(bit_num).unwrap();
                binary_id.set(bit_num, !bit);
            },
            ContactType::Far => {},
        };

        NameType(types::vector_as_u8_64_array(binary_id.to_bytes()))
    }

    struct Bucket {
        far_contact: NameType,
        mid_contact: NameType,
        close_contact: NameType,
    }

    impl Bucket {
        fn new(farthest_from_tables_own_id: NameType, index: usize) -> Bucket {
            Bucket {
                far_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Far),
                mid_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Mid),
                close_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Close),
            }
        }
    }

    struct RoutingTableUnitTest {
        our_id: NameType,
        table: RoutingTable,
        buckets: Vec<Bucket>,
        node_info: NodeInfo,
        initial_count: usize,
        added_ids: Vec<NameType>,
    }

    impl RoutingTableUnitTest {
        fn new() -> RoutingTableUnitTest {
            let node_info = create_random_node_info();
            let table = RoutingTableUnitTest {
                our_id: node_info.id().clone(),
                table: RoutingTable {
                    routing_table: Vec::new(),
                    lookup_map: HashMap::new(),
                    our_id: node_info.id().clone(),
                },
                buckets: initialise_buckets(&node_info.id()),
                node_info: node_info,
                initial_count: (rand::random::<usize>() % (RoutingTable::get_group_size() - 1)) + 1,
                added_ids: Vec::new(),
            };

            for i in 0..99 {
                assert!(closer_to_target(&table.buckets[i].mid_contact,
                    &table.buckets[i].far_contact, &table.our_id));
                assert!(closer_to_target(&table.buckets[i].close_contact,
                    &table.buckets[i].mid_contact, &table.our_id));
                assert!(closer_to_target(&table.buckets[i + 1].far_contact,
                    &table.buckets[i].close_contact, &table.our_id));
            }

            assert!(closer_to_target(&table.buckets[99].mid_contact,
                &table.buckets[99].far_contact, &table.our_id));
            assert!(closer_to_target(&table.buckets[99].close_contact,
                &table.buckets[99].mid_contact, &table.our_id));

            table
        }

        fn partially_fill_table(&mut self) {
            for i in 0..self.initial_count {
                self.node_info.id = self.buckets[i].mid_contact.clone();
                self.added_ids.push(self.node_info.id().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(self.initial_count, self.table.size());
        }

        fn complete_filling_table(&mut self) {
            for i in self.initial_count..RoutingTable::get_optimal_size() {
                self.node_info.id = self.buckets[i].mid_contact.clone();
                self.added_ids.push(self.node_info.id().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(RoutingTable::get_optimal_size(), self.table.size());
        }

        fn public_id(&self, their_id: &NameType)->Option<PublicId> {
            debug_assert!(self.table.is_nodes_sorted(), "RT::public_id: Nodes are not sorted");
            match self.table.routing_table.iter().find(|&node_info| node_info.id() == *their_id) {
                Some(node) => Some(node.fob.clone()),
                None => None,
            }
        }

    }

    fn initialise_buckets(our_id: &NameType) -> Vec<Bucket> {
        let arr = [255u8; 64];
        let mut arr_res = [0u8; 64];
        for i in 0..64 {
            arr_res[i] = arr[i] ^ our_id.0[i];
        }

        let farthest_from_tables_own_id = NameType::new(arr_res);

        let mut buckets = Vec::new();
        for i in 0..100 {
            buckets.push(Bucket::new(farthest_from_tables_own_id.clone(), i));
        }

        buckets
    }

    fn create_random_node_info() -> NodeInfo {
        let public_id = types::PublicId::new(&types::Id::new());
        NodeInfo {
            id: public_id.name(),
            fob: public_id,
            endpoints: random_endpoints(),
            connected_endpoint: None,
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<RoutingTable> {
        use test_utils::Random;

        let mut vector: Vec<RoutingTable> = Vec::with_capacity(num_of_tables);
        for _ in 0..num_of_tables {
            vector.push(RoutingTable {
                routing_table: Vec::new(),
                lookup_map: HashMap::new(),
                our_id: Random::generate_random()
            });
        }
        vector
    }

    #[test]
    fn add_check_nodes_test() {
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);

        for i in 0..num_of_tables {
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();

                if tables[i].check_node(&node_info.id()) {
                    let removed_node = tables[i].add_node(node_info);
                    assert!(removed_node.0);
                }
            }
        }
    }

    #[test]
    fn routing_table_test() {

        let mut table = RoutingTable {
            routing_table: Vec::new(),
            lookup_map: HashMap::new(),
            our_id: Random::generate_random()
        };

        for _ in 0..RoutingTable::get_group_size() {
            let id = Random::generate_random();
            assert!(table.check_node(&id));
        }

        assert_eq!(table.size(), 0);

        for _ in 0..RoutingTable::get_group_size() {
            let node_info = create_random_node_info();
            assert!(table.add_node(node_info).0);
        }

        assert_eq!(table.size(), RoutingTable::get_group_size());
    }

    #[test]
    fn add_check_close_group_test() {
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<NameType> = Vec::with_capacity(num_of_tables);

        for i in 0..num_of_tables {
            addresses.push(tables[i].our_id.clone());
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                tables[i].add_node(node_info);
            }
        }
        for it in tables.iter() {
            let id = it.our_id.clone();
            addresses.sort_by(
                |a, b| if closer_to_target(&a, &b, &id) {
                    cmp::Ordering::Less
                } else {
                    cmp::Ordering::Greater
                });
            let mut groups = it.our_close_group();
            assert_eq!(groups.len(), RoutingTable::get_group_size());

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

            assert_eq!(groups.len(), RoutingTable::get_group_size());

            for i in 0..RoutingTable::get_group_size() {
                assert!(groups[i].id() == addresses[i + 1]);
            }
        }
    }

    #[test]
    fn add_node_test() {
        let mut test = RoutingTableUnitTest::new();

        assert_eq!(test.table.size(), 0);

        // try with our id - should fail
        test.node_info.id = test.table.our_id.clone();
        let mut result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(test.table.size(), 0);

        // add first contact
        test.node_info.id = test.buckets[0].far_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(test.table.size(), 1);

        // try with the same contact - should fail
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(test.table.size(), 1);

        // Add further 'OptimalSize()' - 1 contacts (should all succeed with no removals).  Set this
        // up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have 0 or
        // 1 contacts.

        // Bucket 0
        test.node_info.id = test.buckets[0].mid_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(2, test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(2, test.table.size());

        test.node_info.id = test.buckets[0].close_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(3, test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(3, test.table.size());

        // Bucket 1
        test.node_info.id = test.buckets[1].far_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(4, test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(4, test.table.size());

        test.node_info.id = test.buckets[1].mid_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(5, test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(5, test.table.size());

        test.node_info.id = test.buckets[1].close_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(6, test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(6, test.table.size());

        // Add remaining contacts
        for i in 2..(RoutingTable::get_optimal_size() - 4) {
            test.node_info.id = test.buckets[i].mid_contact.clone();
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {},
            };
            assert_eq!(i + 5, test.table.size());
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(!result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {},
            };
            assert_eq!(i + 5, test.table.size());
        }

        // Check next 4 closer additions return 'buckets_[0].far_contact', 'buckets_[0].mid_contact',
        // 'buckets_[1].far_contact', and 'buckets_[1].mid_contact' as dropped (in that order)
        let mut dropped: Vec<NameType> = Vec::new();
        for i in (RoutingTable::get_optimal_size() - 4)..RoutingTable::get_optimal_size() {
            test.node_info.id = test.buckets[i].mid_contact.clone();
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(result_of_add.0);
            match result_of_add.1 {
                Some(dropped_info) => { dropped.push(dropped_info.id()) },
                None => panic!("Unexpected"),
            };
            assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(!result_of_add.0);
            match result_of_add.1 {
                Some(_) => panic!("Unexpected"),
                None => {},
            };
            assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
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
                None => {},
            };
            assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
        }

        // Add final close contact to push size of table_ above OptimalSize()
        test.node_info.id = test.buckets[RoutingTable::get_optimal_size()].mid_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(RoutingTable::get_optimal_size() + 1, test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(RoutingTable::get_optimal_size() + 1, test.table.size());
    }

    #[test]
    fn drop_node_test() {
        // Check on empty table
        let mut test = RoutingTableUnitTest::new();

        assert_eq!(test.table.size(), 0);

        // Fill the table
        test.partially_fill_table();
        test.complete_filling_table();

        // Try with invalid Address
        test.table.drop_node(&NameType::new([0u8;64]));
        assert_eq!(RoutingTable::get_optimal_size(), test.table.size());

        // Try with our ID
        let drop_id = test.table.our_id.clone();
        test.table.drop_node(&drop_id);
        assert_eq!(RoutingTable::get_optimal_size(), test.table.size());

        // Try with Address of node not in table
        test.table.drop_node(&test.buckets[0].far_contact);
        assert_eq!(RoutingTable::get_optimal_size(), test.table.size());

        // Remove all nodes one at a time
        // TODO(Spandan) Shuffle not implemented
        let mut size = test.table.size();
        for id in test.added_ids {
            size -= 1;
            test.table.drop_node(&id);
            assert_eq!(size, test.table.size());
        }
    }

    #[test]
    fn check_node_test() {
      let mut routing_table_utest = RoutingTableUnitTest::new();

      // Try with our ID
      assert_eq!(routing_table_utest.table.check_node(&routing_table_utest.table.our_id), false);

      // Should return true for empty routing table
      assert!(routing_table_utest.table.check_node(&routing_table_utest.buckets[0].far_contact));

      // Add the first contact, and check it doesn't allow duplicates
      let mut new_node_0 = create_random_node_info();
      new_node_0.id = routing_table_utest.buckets[0].far_contact.clone();
      assert!(routing_table_utest.table.add_node(new_node_0).0);
      assert_eq!(
          routing_table_utest.table.check_node(&routing_table_utest.buckets[0].far_contact.clone()),
          false);

      // Add further 'OptimalSize()' - 1 contact (should all succeed with no removals).  Set this
      // up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have 0 or 1
      // contacts.

      let mut new_node_1 = create_random_node_info();
      new_node_1.id =  routing_table_utest.buckets[0].mid_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_1.id()));
      assert!(routing_table_utest.table.add_node(new_node_1).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[0].mid_contact.clone()), false);

      let mut new_node_2 = create_random_node_info();
      new_node_2.id =  routing_table_utest.buckets[0].close_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_2.id()));
      assert!(routing_table_utest.table.add_node(new_node_2).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[0].close_contact.clone()), false);

      let mut new_node_3 = create_random_node_info();
      new_node_3.id = routing_table_utest.buckets[1].far_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_3.id()));
      assert!(routing_table_utest.table.add_node(new_node_3).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].far_contact.clone()), false);

      let mut new_node_4 = create_random_node_info();
      new_node_4.id =  routing_table_utest.buckets[1].mid_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_4.id()));
      assert!(routing_table_utest.table.add_node(new_node_4).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].mid_contact.clone()), false);

      let mut new_node_5 = create_random_node_info();
      new_node_5.id =  routing_table_utest.buckets[1].close_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_5.id()));
      assert!(routing_table_utest.table.add_node(new_node_5).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].close_contact.clone()), false);

      for i in 2..(RoutingTable::get_optimal_size() - 4) {
          let mut new_node = create_random_node_info();
          new_node.id =  routing_table_utest.buckets[i].mid_contact.clone();
          assert!(routing_table_utest.table.check_node(&new_node.id()));
          assert!(routing_table_utest.table.add_node(new_node).0);
          assert_eq!(routing_table_utest.table.check_node(
              &routing_table_utest.buckets[i].mid_contact.clone()), false);
      }

      assert_eq!(RoutingTable::get_optimal_size(), routing_table_utest.table.routing_table.len());

      for i in (RoutingTable::get_optimal_size() - 4)..RoutingTable::get_optimal_size() {
          let mut new_node = create_random_node_info();
          new_node.id =  routing_table_utest.buckets[i].mid_contact.clone();
          assert!(routing_table_utest.table.check_node(&new_node.id()));
          assert!(routing_table_utest.table.add_node(new_node).0);
          assert_eq!(routing_table_utest.table.check_node(
              &routing_table_utest.buckets[i].mid_contact.clone()), false);
          assert_eq!(RoutingTable::get_optimal_size(),
              routing_table_utest.table.routing_table.len());
      }

      // Check for contacts again which are now not in the table
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[0].far_contact.clone()), false);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[0].mid_contact.clone()), false);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].far_contact.clone()), false);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].mid_contact.clone()), false);

      // Check final close contact which would push size of table_ above OptimalSize()
      assert!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[RoutingTable::get_optimal_size()].mid_contact.clone()));
    }

    #[test]
    fn churn_test() {
        let network_size = 200usize;
        let nodes_to_remove = 20usize;

        let mut tables = create_random_routing_tables(network_size);
        let mut addresses: Vec<NameType> = Vec::with_capacity(network_size);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_id.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                tables[i].add_node(node_info);
            }
        }

        // now remove nodes
        let mut drop_vec: Vec<NameType> = Vec::with_capacity(nodes_to_remove);
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
            let size = if RoutingTable::get_group_size() < tables[i].size() {
                RoutingTable::get_group_size()
            } else {
                tables[i].size()
            };
            let id = tables[i].our_id.clone();
            addresses.sort_by(
                |a, b| if closer_to_target(&a, &b, &id) {
                    cmp::Ordering::Less
                } else {
                    cmp::Ordering::Greater
                });
            let groups = tables[i].our_close_group();
            assert_eq!(groups.len(), size);
        }
    }

    #[test]
    fn target_nodes_group_test() {
        let network_size = 100usize;

        let mut tables = create_random_routing_tables(network_size);
        let mut addresses: Vec<NameType> = Vec::with_capacity(network_size);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_id.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                tables[i].add_node(node_info);
            }
        }

        for i in 0..tables.len() {
            addresses.sort_by(
                |a, b| if closer_to_target(&a, &b, &tables[i].our_id) {
                    cmp::Ordering::Less
                } else {
                    cmp::Ordering::Greater
                });
            // if target is in close group return the whole close group excluding target
            for j in 1..(RoutingTable::get_group_size() - types::QUORUM_SIZE) {
                let target_close_group = tables[i].target_nodes(&addresses[j]);
                assert_eq!(RoutingTable::get_group_size(), target_close_group.len());
                // should contain our close group
                for k in 0..target_close_group.len() {
                    assert!(target_close_group[k].id() == addresses[k + 1]);
                }
            }
        }
    }

    #[test]
    fn our_close_group_and_in_range() {
        // independent double verification of our_close_group()
        // this test verifies that the close group is returned sorted
        let our_id_name = types::Id::new().get_name();
        let mut routing_table: RoutingTable = RoutingTable::new(&our_id_name);

        let mut count: usize = 0;
        loop {
            routing_table.add_node(
                NodeInfo::new(types::PublicId::new(&types::Id::new()), random_endpoints(),
                              None));
            count += 1;
            if routing_table.size() >=
                RoutingTable::get_optimal_size() { break; }
            if count >= 2 * RoutingTable::get_optimal_size() {
                panic!("Routing table does not fill up."); }
        }
        let our_close_group: Vec<NodeInfo> = routing_table.our_close_group();
        assert_eq!(our_close_group.len(), RoutingTable::get_group_size() );
        let mut closer_name: NameType = our_id_name.clone();
        for close_node in &our_close_group {
            assert!(closer_to_target(&closer_name, &close_node.id(), &our_id_name));
            assert!(routing_table.address_in_our_close_group_range(&close_node.id()));
            closer_name = close_node.id().clone();
        }
        for node in &routing_table.routing_table {
            if our_close_group.iter().filter(|close_node| close_node.id() == node.id())
                              .count() > 0 {
                assert!(routing_table.address_in_our_close_group_range(&node.id()));
            } else {
                assert_eq!(false, routing_table.address_in_our_close_group_range(&node.id()));
            }
        }
    }

    #[test]
    fn our_close_group_test() {
        let mut table_unit_test = RoutingTableUnitTest::new();
        assert!(table_unit_test.table.our_close_group().is_empty());

        table_unit_test.partially_fill_table();
        assert_eq!(table_unit_test.initial_count, table_unit_test.table.our_close_group().len());

        for i in 0..table_unit_test.initial_count {
            assert!(table_unit_test.table.our_close_group().iter().filter(
                |&node| { node.id() == table_unit_test.buckets[i].mid_contact }).count() > 0);
        }

        table_unit_test.complete_filling_table();
        assert_eq!(RoutingTable::get_group_size(), table_unit_test.table.our_close_group().len());

        for close_node in table_unit_test.table.our_close_group().iter() {
            assert!(table_unit_test.added_ids.iter().filter(
                |&node| { node == &close_node.id() }).count() == 1);
        }
    }

    #[test]
    fn target_nodes_test() {
        let mut routing_table_utest = RoutingTableUnitTest::new();

        // Check on empty table
        let mut target_nodes_ = routing_table_utest.table.target_nodes(&Random::generate_random());
        assert_eq!(target_nodes_.len(), 0);

        // Partially fill the table with < GroupSize contacts
        routing_table_utest.partially_fill_table();

        // Check we get all contacts returnedta
        target_nodes_ = routing_table_utest.table.target_nodes(&Random::generate_random());
        assert_eq!(routing_table_utest.initial_count, target_nodes_.len());

        for i in 0..routing_table_utest.initial_count {
            let mut assert_checker = 0;
            for j in 0..target_nodes_.len() {
                if target_nodes_[j].id() == routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Complete filling the table up to RoutingTable::get_optimal_size() contacts
        routing_table_utest.complete_filling_table();

        // Try with our ID (should return closest to us, i.e. buckets 63 to 32)
        target_nodes_ =
            routing_table_utest.table.target_nodes(&routing_table_utest.table.our_id);
        assert_eq!(RoutingTable::get_group_size(), target_nodes_.len());

        for i in ((RoutingTable::get_optimal_size() - RoutingTable::get_group_size())..
                   RoutingTable::get_optimal_size() - 1).rev() {
            let mut assert_checker = 0;
            for j in 0..target_nodes_.len() {
                if target_nodes_[j].id() == routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Try with nodes far from us, first time *not* in table and second time *in* table (should
        // return 'RoutingTable::Parallelism()' contacts closest to target)
        let mut target: NameType;
        for count in 0..2 {
            for i in 0..(RoutingTable::get_optimal_size() - RoutingTable::get_group_size()) {
                target = if count == 0 {
                    routing_table_utest.buckets[i].far_contact.clone()
                } else {
                    routing_table_utest.buckets[i].mid_contact.clone()
                };
                target_nodes_ = routing_table_utest.table.target_nodes(&target);
                assert_eq!(RoutingTable::get_parallelism(), target_nodes_.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if closer_to_target(&a.id(), &b.id(), &routing_table_utest.our_id) {
                        cmp::Ordering::Less
                    } else {
                        cmp::Ordering::Greater
                    });

                for i in 0..target_nodes_.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_ids.len() {
                        if target_nodes_[i].id() == routing_table_utest.added_ids[j] {
                            assert_checker = 1;
                            continue;
                        }
                    }
                    assert!(assert_checker == 1);
                }
            }
        }

        // Try with nodes close to us, first time *not* in table and second time *in* table (should
        // return GroupSize closest to target)
        for count in 0..2 {
            for i in (RoutingTable::get_optimal_size() - RoutingTable::get_group_size())..
                      RoutingTable::get_optimal_size() {
                target = if count == 0 {
                    routing_table_utest.buckets[i].far_contact.clone()
                } else {
                    routing_table_utest.buckets[i].mid_contact.clone()
                };
                target_nodes_ = routing_table_utest.table.target_nodes(&target);
                assert_eq!(RoutingTable::get_group_size(), target_nodes_.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if closer_to_target(&a.id(), &b.id(), &routing_table_utest.our_id) {
                        cmp::Ordering::Less
                    } else {
                        cmp::Ordering::Greater
                    });

                for i in 0..target_nodes_.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_ids.len() {
                        if target_nodes_[i].id() == routing_table_utest.added_ids[j] {
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
            None => {},
        }
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(0, table_unit_test.table.routing_table.len());

        // Check on partially filled the table
        table_unit_test.partially_fill_table();
        let test_node = create_random_node_info();
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.public_id(&table_unit_test.node_info.id()) {
            Some(_) => {},
            None => panic!("PublicId None"),
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_fob.public_key(),
        //                                 *table_.GetPublicKey(info_.id())));
        match table_unit_test.public_id(
                &table_unit_test.buckets[table_unit_test.buckets.len() - 1].far_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {},
        }
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(table_unit_test.initial_count + 1, table_unit_test.table.routing_table.len());

        // Check on fully filled the table
        table_unit_test.table.drop_node(&test_node.id().clone());
        table_unit_test.complete_filling_table();
        table_unit_test.table.drop_node(&table_unit_test.buckets[0].mid_contact.clone());
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.public_id(&table_unit_test.node_info.id()) {
            Some(_) => {},
            None => panic!("PublicId None"),
        }
        match table_unit_test.public_id(
                &table_unit_test.buckets[table_unit_test.buckets.len() - 1].far_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {},
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_fob.public_key(),
        //                                 *table_.GetPublicKey(info_.id())));
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(RoutingTable::get_optimal_size(), table_unit_test.table.routing_table.len());
    }
}

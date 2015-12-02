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

// Defines the number of contacts which should be returned by the `target_nodes` function for a
// target which is outwith our close group and is not a contact in the table.
pub const PARALLELISM: usize = 4;

// Defines the target max number of contacts per bucket.  This is not a hard limit; buckets can
// exceed this size if required.
const BUCKET_SIZE: usize = 1;

// Defines the target max number of contacts for the whole routing table.  This is not a hard limit;
// the table size can exceed this size if required.
const OPTIMAL_TABLE_SIZE: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub public_id: ::id::PublicId,
    pub connections: Vec<::crust::Connection>,
}

impl NodeInfo {
    pub fn new(public_id: ::id::PublicId, connections: Vec<::crust::Connection>) -> NodeInfo {
        NodeInfo {
            public_id: public_id,
            connections: connections,
        }
    }

    pub fn name(&self) -> &::NameType {
        self.public_id.name()
    }
}



// The RoutingTable class is used to maintain a list of contacts to which the node is connected.
pub struct RoutingTable {
    routing_table: Vec<NodeInfo>,
    our_name: ::NameType,
}

impl RoutingTable {
    pub fn new(our_name: &::NameType) -> RoutingTable {
        RoutingTable {
            routing_table: Vec::<NodeInfo>::new(),
            our_name: our_name.clone(),
        }
    }

    // Adds a contact to the routing table.  If the contact is added, the first return arg is true,
    // otherwise false.  If adding the contact caused another contact to be dropped, the dropped
    // one is returned in the second field, otherwise the optional field is empty.  The following
    // steps are used to determine whether to add the new contact or not:
    //
    // 1 - if the contact is ourself, or doesn't have a valid public key, or is already in the
    //     table, it will not be added (N.B. to append a new connection to an existing contact's
    //     entry, use the `add_connection` function)
    // 2 - if the routing table is not full (len() < OPTIMAL_TABLE_SIZE), the contact will be added
    // 3 - if the contact is within our close group, it will be added
    // 4 - if we can find a candidate for removal (a contact in a bucket with more than BUCKET_SIZE
    //     contacts, which is also not within our close group), and if the new contact will fit in
    //     a bucket closer to our own bucket, then we add the new contact.
    pub fn add_node(&mut self, their_info: NodeInfo) -> (bool, Option<NodeInfo>) {
        if self.our_name == *their_info.name() {
            return (false, None)
        }

        if self.has_node(their_info.name()) {
            debug!("Routing table {:?} has node {:?}. not adding", self.routing_table, their_info);
            return (false, None)
        }

        if self.routing_table.len() < OPTIMAL_TABLE_SIZE {
            self.push_back_then_sort(their_info);
            return (true, None)
        }

        if ::name_type::closer_to_target(their_info.name(),
                                         self.routing_table[::types::GROUP_SIZE].name(),
                                         &self.our_name) {
            self.push_back_then_sort(their_info);
            return match self.find_candidate_for_removal() {
                None => (true, None),
                Some(node_index) => (true, Some(self.routing_table.remove(node_index))),
            }
        }

        let removal_node_index = self.find_candidate_for_removal();
        if self.new_node_is_better_than_existing(their_info.name(), removal_node_index) {
            // safe to unwrap since new_node_is_better_than_existing has returned true
            let removal_node = self.routing_table.remove(unwrap_option!(removal_node_index, ""));
            self.push_back_then_sort(their_info);
            return (true, Some(removal_node))
        }

        (false, None)
    }

    // Adds a connection to an existing entry.  Should be called after `has_node`.
    pub fn add_connection(&mut self, their_name: &::NameType, connection: ::crust::Connection) {
        use itertools::Itertools;
        match self.routing_table.iter_mut().find(|node_info| node_info.name() == their_name) {
            Some(mut node_info) => {
                node_info.connections.push(connection);
                node_info.connections = node_info.connections.iter().cloned().unique().collect();
            },
            None => error!("The NodeInfo should already exist here."),
        }
    }

    // This is used to check whether it is worthwhile trying to connect to the peer with a view to
    // adding the contact to our routing table, i.e. would this contact improve our table.  The
    // checking procedure is the same as for `add_node`, except for the lack of a public key to
    // check in step 1.
    pub fn want_to_add(&self, their_name: &::NameType) -> bool {
        if self.our_name == *their_name {
            return false
        }
        if self.has_node(their_name) {
            return false
        }
        if self.routing_table.len() < OPTIMAL_TABLE_SIZE {
            return true
        }
        let group_len = ::types::GROUP_SIZE - 1;
        if ::name_type::closer_to_target(their_name,
                                         self.routing_table[group_len].name(),
                                         &self.our_name) {
            return true
        }
        self.new_node_is_better_than_existing(&their_name, self.find_candidate_for_removal())
    }

    // This unconditionally removes the contact from the table.
    pub fn drop_node(&mut self, node_to_drop: &::NameType) {
        self.routing_table.retain(|x| x.name() != node_to_drop);
    }

    // This should be called when Crust notifies us that a connection has dropped.  If the
    // affected entry has no connections after removing this one, the entry is removed from the
    // routing table and its name is returned.  If the entry still has at least one connection, or
    // an entry cannot be found for 'lost_connection', the function returns 'None'.
    pub fn drop_connection(&mut self, lost_connection: &::crust::Connection) -> Option<::NameType> {
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
               return Some(self.routing_table.remove(node_index).name().clone())
            }
        }
        None
    }

    // This returns a collection of contacts to which a message should be sent onwards.  It will
    // return all of our close group (comprising 'GROUP_SIZE' contacts) if the closest one to the
    // target is within our close group.  If not, it will return either the 'PARALLELISM' closest
    // contacts to the target or a single contact if 'target' is the name of a contact in the table.
    pub fn target_nodes(&self, target: &::NameType) -> Vec<NodeInfo> {
        use itertools::Itertools;
        //if in range of close_group send to all close_group
        if self.is_close(target) {
            return self.our_close_group()
        }

        // if not in close group but connected then send direct
        for node in &self.routing_table {
            if node.name() == target {
                return vec![node.clone()]
            }
        }

        // not in close group or routing table so send to closest known nodes up to parallelism
        // count
        self.routing_table
            .iter()
            .sorted_by(|a, b| if ::name_type::closer_to_target(a.name(), b.name(), &target) {
                                  ::std::cmp::Ordering::Less
                              } else {
                                  ::std::cmp::Ordering::Greater
                              })
            .into_iter()
            .take(PARALLELISM)
            .cloned()
            .collect()
    }

    // This returns our close group, i.e. the 'GROUP_SIZE' contacts closest to our name (or the
    // entire table if we hold less than 'GROUP_SIZE' contacts in total) sorted by closeness to us.
    pub fn our_close_group(&self) -> Vec<NodeInfo> {
        self.routing_table.iter().take(::types::GROUP_SIZE).cloned().collect()
    }

    // This returns true if the provided name is closer than or equal to the furthest node in our
    // close group. If the routing table contains less than GROUP_SIZE nodes, then every address is
    // considered to be close.
    pub fn is_close(&self, name: &::NameType) -> bool {
        if self.routing_table.len() < ::types::GROUP_SIZE {
            return true
        }
        let furthest_close_node = self.routing_table[::types::GROUP_SIZE - 1].clone();
        ::name_type::closer_to_target_or_equal(name, furthest_close_node.name(), &self.our_name)
    }

    pub fn len(&self) -> usize {
        self.routing_table.len()
    }

    pub fn our_name(&self) -> &::NameType {
        &self.our_name
    }

    pub fn has_node(&self, name: &::NameType) -> bool {
        self.routing_table.iter().any(|node_info| node_info.name() == name)
    }

    // This effectively reverse iterates through all non-empty buckets (i.e. starts at furthest
    // bucket from us) checking for overfilled ones and returning the table index of the furthest
    // contact within that bucket.  No contacts within our close group will be considered.  If the
    // table size is below OPTIMAL_TABLE_SIZE, this will return None.
    fn find_candidate_for_removal(&self) -> Option<usize> {
        assert!(self.routing_table.len() >= OPTIMAL_TABLE_SIZE);

        let mut number_in_bucket = 0usize;
        let mut current_bucket = 0usize;

        // Start iterating from the end, i.e. the furthest from our ID.
        let mut counter = self.routing_table.len() - 1;
        let mut furthest_in_this_bucket = counter;

        // Stop iterating at our furthest close group member since we won't remove any peer in our
        // close group
        let finish = ::types::GROUP_SIZE;

        while counter >= finish {
            let bucket_index = self.bucket_index(self.routing_table[counter].name());

            // If we're entering a new bucket, reset details.
            if bucket_index != current_bucket {
                current_bucket = bucket_index;
                number_in_bucket = 0;
                furthest_in_this_bucket = counter;
            }

            // Check for an excess of contacts in this bucket.
            number_in_bucket += 1;
            if number_in_bucket > BUCKET_SIZE {
                break;
            }

            counter -= 1;
        }

        if counter < finish {
            None
        } else {
            Some(furthest_in_this_bucket)
        }
    }

    // This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    // bits" means the most significant bits.
    fn bucket_index(&self, name: &::NameType) -> usize {
        for byte_index in 0..::NAME_TYPE_LEN {
            if self.our_name.0[byte_index] != name.0[byte_index] {
                return (byte_index * 8) + match self.our_name.0[byte_index] ^ name.0[byte_index] {
                    1 => 7,
                    2 | 3 => 6,
                    4...7 => 5,
                    8...15 => 4,
                    16...31 => 3,
                    32...63 => 2,
                    64...127 => 1,
                    128...255 => 0,
                    _ => unreachable!(),
                }
            }
        }
        ::NAME_TYPE_LEN * 8
    }

    fn push_back_then_sort(&mut self, node_info: NodeInfo) {
        {  // Try to find and update an existing entry
            if let Some(mut entry) = self.routing_table
                                         .iter_mut()
                                         .find(|element| element.name() == node_info.name()) {
                entry.connections.extend(node_info.connections);
                return
            }
        }
        // We didn't find an existing entry, so insert a new one
        self.routing_table.push(node_info);
        let name = &self.our_name;
        self.routing_table.sort_by(|a, b| {
            if ::name_type::closer_to_target(a.name(), b.name(), name) {
                ::std::cmp::Ordering::Less
            } else {
                ::std::cmp::Ordering::Greater
            }
        });
    }

    // Returns true if 'removal_node_index' is Some and the new node is in a closer bucket than the
    // removal candidate.
    fn new_node_is_better_than_existing(&self,
                                        new_node: &::NameType,
                                        removal_node_index: Option<usize>)
                                        -> bool {
        match removal_node_index {
            Some(index) => {
                let removal_node = &self.routing_table[index];
                self.bucket_index(new_node) > self.bucket_index(removal_node.name())
            },
            None => false,
        }
    }
}



#[cfg(test)]
mod test {
    extern crate bit_vec;

    enum ContactType {
        Far,
        Mid,
        Close,
    }

    fn are_nodes_sorted(routing_table: &super::RoutingTable) -> bool {
        for i in 1..routing_table.routing_table.len() {
            if ::name_type::closer_to_target(routing_table.routing_table[i].name(),
                                             routing_table.routing_table[i - 1].name(),
                                             &routing_table.our_name) {
                return false
            }
        }
        true
    }

    fn get_contact(farthest_from_tables_own_name: &::NameType,
                   index: usize,
                   contact_type: ContactType)
                   -> ::NameType {
        let mut binary_name = self::bit_vec::BitVec::from_bytes(&farthest_from_tables_own_name.0);
        if index > 0 {
            for i in 0..index {
                let bit = unwrap_option!(binary_name.get(i), "");
                binary_name.set(i, !bit);
            }
        }

        match contact_type {
            ContactType::Mid => {
                let bit_num = binary_name.len() - 1;
                let bit = unwrap_option!(binary_name.get(bit_num), "");
                binary_name.set(bit_num, !bit);
            }
            ContactType::Close => {
                let bit_num = binary_name.len() - 2;
                let bit = unwrap_option!(binary_name.get(bit_num), "");
                binary_name.set(bit_num, !bit);
            }
            ContactType::Far => {}
        };

        ::NameType(::types::slice_as_u8_64_array(&binary_name.to_bytes()[..]))
    }

    struct Bucket {
        far_contact: ::NameType,
        mid_contact: ::NameType,
        close_contact: ::NameType,
    }

    impl Bucket {
        fn new(farthest_from_tables_own_name: ::NameType, index: usize) -> Bucket {
            Bucket {
                far_contact: get_contact(&farthest_from_tables_own_name, index, ContactType::Far),
                mid_contact: get_contact(&farthest_from_tables_own_name, index, ContactType::Mid),
                close_contact: get_contact(&farthest_from_tables_own_name, index,
                                           ContactType::Close),
            }
        }
    }

    struct RoutingTableUnitTest {
        name: ::NameType,
        table: super::RoutingTable,
        buckets: Vec<Bucket>,
        node_info: super::NodeInfo,
        initial_count: usize,
        added_names: Vec<::NameType>,
    }

    impl RoutingTableUnitTest {
        fn new() -> RoutingTableUnitTest {
            let node_info = create_random_node_info();
            let table = RoutingTableUnitTest {
                name: node_info.name().clone(),
                table: super::RoutingTable {
                    routing_table: Vec::new(),
                    our_name: node_info.name().clone(),
                },
                buckets: initialise_buckets(node_info.name()),
                node_info: node_info,
                initial_count: (::rand::random::<usize>() % (::types::GROUP_SIZE - 1)) + 1,
                added_names: Vec::new(),
            };

            for i in 0..99 {
                assert!(::name_type::closer_to_target(&table.buckets[i].mid_contact,
                                                      &table.buckets[i].far_contact,
                                                      &table.name));
                assert!(::name_type::closer_to_target(&table.buckets[i].close_contact,
                                                      &table.buckets[i].mid_contact,
                                                      &table.name));
                assert!(::name_type::closer_to_target(&table.buckets[i + 1].far_contact,
                                                      &table.buckets[i].close_contact,
                                                      &table.name));
            }

            assert!(::name_type::closer_to_target(&table.buckets[99].mid_contact,
                                                  &table.buckets[99].far_contact,
                                                  &table.name));
            assert!(::name_type::closer_to_target(&table.buckets[99].close_contact,
                                                  &table.buckets[99].mid_contact,
                                                  &table.name));

            table
        }

        fn partially_fill_table(&mut self) {
            for i in 0..self.initial_count {
                self.node_info.public_id.set_name(self.buckets[i].mid_contact.clone());
                self.added_names.push(self.node_info.name().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(self.initial_count, self.table.len());
        }

        fn complete_filling_table(&mut self) {
            for i in self.initial_count..super::OPTIMAL_TABLE_SIZE {
                self.node_info.public_id.set_name(self.buckets[i].mid_contact.clone());
                self.added_names.push(self.node_info.name().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(super::OPTIMAL_TABLE_SIZE, self.table.len());
        }

        fn public_id(&self, name: &::NameType) -> Option<::id::PublicId> {
            debug_assert!(are_nodes_sorted(&self.table), "RT::public_id: Nodes are not sorted");
            match self.table.routing_table.iter().find(|node_info| node_info.name() == name) {
                Some(node) => Some(node.public_id.clone()),
                None => None,
            }
        }

    }

    fn initialise_buckets(name: &::NameType) -> Vec<Bucket> {
        let arr = [255u8; 64];
        let mut arr_res = [0u8; 64];
        for i in 0..64 {
            arr_res[i] = arr[i] ^ name.0[i];
        }

        let farthest_from_tables_own_name = ::NameType::new(arr_res);

        let mut buckets = Vec::new();
        for i in 0..100 {
            buckets.push(Bucket::new(farthest_from_tables_own_name.clone(), i));
        }

        buckets
    }

    fn create_random_node_info() -> super::NodeInfo {
        let full_id = ::id::FullId::new();
        super::NodeInfo {
            public_id: full_id.public_id().clone(),
            connections: Vec::new(),
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<super::RoutingTable> {
        use rand;
        let mut vector: Vec<super::RoutingTable> = Vec::with_capacity(num_of_tables);
        for _ in 0..num_of_tables {
            vector.push(super::RoutingTable {
                routing_table: Vec::new(),
                our_name: rand::random(),
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
                node_info.public_id.set_name(tables[j].our_name.clone());

                if tables[i].want_to_add(node_info.name()) {
                    let removed_node = tables[i].add_node(node_info);
                    assert!(removed_node.0);
                }
            }
        }
    }

    #[test]
    fn routing_table_test() {
        use rand;
        let mut table = super::RoutingTable {
            routing_table: Vec::new(),
            our_name: rand::random(),
        };

        for _ in 0..::types::GROUP_SIZE {
            let name = rand::random();
            assert!(table.want_to_add(&name));
        }

        assert_eq!(table.len(), 0);

        for _ in 0..::types::GROUP_SIZE {
            let node_info = create_random_node_info();
            assert!(table.add_node(node_info).0);
        }

        assert_eq!(table.len(), ::types::GROUP_SIZE);
    }

    #[test]
    fn add_check_close_group_test() {
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<::NameType> = Vec::with_capacity(num_of_tables);

        for i in 0..num_of_tables {
            addresses.push(tables[i].our_name.clone());
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name.clone());
                let _ = tables[i].add_node(node_info);
            }
        }
        for it in tables.iter() {
            let name = it.our_name.clone();
            addresses.sort_by(|a, b| {
                if ::name_type::closer_to_target(a, b, &name) {
                    ::std::cmp::Ordering::Less
                } else {
                    ::std::cmp::Ordering::Greater
                }
            });
            let mut groups = it.our_close_group();
            assert_eq!(groups.len(), ::types::GROUP_SIZE);

            // TODO(Spandan) vec.dedup does not compile - manually doing it
            if groups.len() > 1 {
                let mut new_end = 1usize;
                for i in 1..groups.len() {
                    if groups[new_end - 1].name() != groups[i].name() {
                        if new_end != i {
                            groups[new_end] = groups[i].clone();
                        }
                        new_end += 1;
                    }
                }
                assert_eq!(new_end, groups.len());
            }

            assert_eq!(groups.len(), ::types::GROUP_SIZE);

            for i in 0..::types::GROUP_SIZE {
                assert!(groups[i].name() == &addresses[i + 1]);
            }
        }
    }

    #[test]
    fn add_node_test() {
        let mut test = RoutingTableUnitTest::new();

        assert_eq!(test.table.len(), 0);

        // try with our name - should fail
        test.node_info.public_id.set_name(test.table.our_name.clone());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(test.table.len(), 0);

        // add first contact
        test.node_info.public_id.set_name(test.buckets[0].far_contact.clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(test.table.len(), 1);

        // try with the same contact - should fail
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(test.table.len(), 1);

        // Add further 'OPTIMAL_TABLE_SIZE' - 1 contacts (should all succeed with no removals).  Set
        // this up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have
        // 0 or 1 contacts.

        // Bucket 0
        test.node_info.public_id.set_name(test.buckets[0].mid_contact.clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(2, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(2, test.table.len());

        test.node_info.public_id.set_name(test.buckets[0].close_contact.clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(3, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(3, test.table.len());

        // Bucket 1
        test.node_info.public_id.set_name(test.buckets[1].far_contact.clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(4, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(4, test.table.len());

        test.node_info.public_id.set_name(test.buckets[1].mid_contact.clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(5, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(5, test.table.len());

        test.node_info.public_id.set_name(test.buckets[1].close_contact.clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(6, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(6, test.table.len());

        // Add remaining contacts
        for i in 2..(super::OPTIMAL_TABLE_SIZE - 4) {
            test.node_info.public_id.set_name(test.buckets[i].mid_contact.clone());
            assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(i + 5, test.table.len());
            assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(i + 5, test.table.len());
        }

        // Check next 4 closer additions return 'buckets_[0].far_contact',
        // 'buckets_[0].mid_contact', 'buckets_[1].far_contact', and 'buckets_[1].mid_contact' as
        // dropped (in that order)
        let mut dropped: Vec<::NameType> = Vec::new();
        let optimal_len = super::OPTIMAL_TABLE_SIZE;
        for i in (optimal_len - 4)..optimal_len {
            test.node_info.public_id.set_name(test.buckets[i].mid_contact.clone());
            let result_of_add = test.table.add_node(test.node_info.clone());
            assert!(result_of_add.0);
            dropped.push(unwrap_option!(result_of_add.1, "").name().clone());
            assert_eq!(super::OPTIMAL_TABLE_SIZE, test.table.len());
            assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(super::OPTIMAL_TABLE_SIZE, test.table.len());
        }
        assert!(test.buckets[0].far_contact == dropped[0]);
        assert!(test.buckets[0].mid_contact == dropped[1]);
        assert!(test.buckets[1].far_contact == dropped[2]);
        assert!(test.buckets[1].mid_contact == dropped[3]);

        // Try to add far contacts again (should fail)
        for far_contact in dropped {
            test.node_info.public_id.set_name(far_contact.clone());
            assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(super::OPTIMAL_TABLE_SIZE, test.table.len());
        }

        // Add final close contact to push len of table_ above OPTIMAL_TABLE_SIZE
        test.node_info.public_id.set_name(test.buckets[super::OPTIMAL_TABLE_SIZE]
                                              .mid_contact
                                              .clone());
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(super::OPTIMAL_TABLE_SIZE + 1, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(super::OPTIMAL_TABLE_SIZE + 1, test.table.len());
    }

    #[test]
    fn drop_node_test() {
        use ::rand::Rng;

        // Check on empty table
        let mut test = RoutingTableUnitTest::new();

        assert_eq!(test.table.len(), 0);

        // Fill the table
        test.partially_fill_table();
        test.complete_filling_table();

        // Try with invalid Address
        test.table.drop_node(&::NameType::new([0u8; 64]));
        assert_eq!(super::OPTIMAL_TABLE_SIZE, test.table.len());

        // Try with our Name
        let drop_name = test.table.our_name.clone();
        test.table.drop_node(&drop_name);
        assert_eq!(super::OPTIMAL_TABLE_SIZE, test.table.len());

        // Try with Address of node not in table
        test.table.drop_node(&test.buckets[0].far_contact);
        assert_eq!(super::OPTIMAL_TABLE_SIZE, test.table.len());

        // Remove all nodes one at a time in random order
        let mut rng = ::rand::thread_rng();
        rng.shuffle(&mut test.added_names[..]);
        let mut len = test.table.len();
        for name in test.added_names {
            len -= 1;
            test.table.drop_node(&name);
            assert_eq!(len, test.table.len());
        }
    }

    #[test]
    fn check_node_test() {
        let mut routing_table_utest = RoutingTableUnitTest::new();

        // Try with our ID
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.table.our_name));

        // Should return true for empty routing table
        assert!(routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0].far_contact));

        // Add the first contact, and check it doesn't allow duplicates
        let mut new_node_0 = create_random_node_info();
        new_node_0.public_id.set_name(routing_table_utest.buckets[0].far_contact.clone());
        assert!(routing_table_utest.table.add_node(new_node_0).0);
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .far_contact));

        // Add further 'OPTIMAL_TABLE_SIZE' - 1 contact (should all succeed with no removals).  Set
        // this up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have
        // 0 or 1 contacts.

        let mut new_node_1 = create_random_node_info();
        new_node_1.public_id.set_name(routing_table_utest.buckets[0].mid_contact.clone());
        assert!(routing_table_utest.table.want_to_add(new_node_1.name()));
        assert!(routing_table_utest.table.add_node(new_node_1).0);
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .mid_contact));

        let mut new_node_2 = create_random_node_info();
        new_node_2.public_id.set_name(routing_table_utest.buckets[0].close_contact.clone());
        assert!(routing_table_utest.table.want_to_add(new_node_2.name()));
        assert!(routing_table_utest.table.add_node(new_node_2).0);
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .close_contact));

        let mut new_node_3 = create_random_node_info();
        new_node_3.public_id.set_name(routing_table_utest.buckets[1].far_contact.clone());
        assert!(routing_table_utest.table.want_to_add(new_node_3.name()));
        assert!(routing_table_utest.table.add_node(new_node_3).0);
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .far_contact));

        let mut new_node_4 = create_random_node_info();
        new_node_4.public_id.set_name(routing_table_utest.buckets[1].mid_contact.clone());
        assert!(routing_table_utest.table.want_to_add(new_node_4.name()));
        assert!(routing_table_utest.table.add_node(new_node_4).0);
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .mid_contact));

        let mut new_node_5 = create_random_node_info();
        new_node_5.public_id.set_name(routing_table_utest.buckets[1].close_contact.clone());
        assert!(routing_table_utest.table.want_to_add(new_node_5.name()));
        assert!(routing_table_utest.table.add_node(new_node_5).0);
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .close_contact));

        for i in 2..(super::OPTIMAL_TABLE_SIZE - 4) {
            let mut new_node = create_random_node_info();
            new_node.public_id.set_name(routing_table_utest.buckets[i].mid_contact.clone());
            assert!(routing_table_utest.table.want_to_add(new_node.name()));
            assert!(routing_table_utest.table.add_node(new_node).0);
            assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[i]
                                                                 .mid_contact));
        }

        assert_eq!(super::OPTIMAL_TABLE_SIZE,
                   routing_table_utest.table.routing_table.len());

        let optimal_len = super::OPTIMAL_TABLE_SIZE;
        for i in (optimal_len - 4)..optimal_len {
            let mut new_node = create_random_node_info();
            new_node.public_id.set_name(routing_table_utest.buckets[i].mid_contact.clone());
            assert!(routing_table_utest.table.want_to_add(new_node.name()));
            assert!(routing_table_utest.table.add_node(new_node).0);
            assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[i]
                                                                 .mid_contact));
            assert_eq!(super::OPTIMAL_TABLE_SIZE,
                       routing_table_utest.table.routing_table.len());
        }

        // Check for contacts again which are now not in the table
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .far_contact));
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[0]
                                                             .mid_contact));
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .far_contact));
        assert!(!routing_table_utest.table.want_to_add(&routing_table_utest.buckets[1]
                                                             .mid_contact));

        // Check final close contact which would push len() of table above OPTIMAL_TABLE_SIZE
        assert!(routing_table_utest.table.want_to_add(
            &routing_table_utest.buckets[super::OPTIMAL_TABLE_SIZE].mid_contact));
    }

    #[test]
    fn churn_test() {
        let network_len = 200usize;
        let nodes_to_remove = 20usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<::NameType> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_name.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name.clone());
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
            let len = if ::types::GROUP_SIZE < tables[i].len() {
                ::types::GROUP_SIZE
            } else {
                tables[i].len()
            };
            let name = tables[i].our_name.clone();
            addresses.sort_by(|a, b| {
                if ::name_type::closer_to_target(a, b, &name) {
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
            addresses.push(tables[i].our_name.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name.clone());
                let _ = tables[i].add_node(node_info);
            }
        }

        for i in 0..tables.len() {
            addresses.sort_by(|a, b| {
                if ::name_type::closer_to_target(a, b, &tables[i].our_name) {
                    ::std::cmp::Ordering::Less
                } else {
                    ::std::cmp::Ordering::Greater
                }
            });
            // if target is in close group return the whole close group excluding target
            for j in 1..(::types::GROUP_SIZE - ::types::QUORUM_SIZE) {
                let target_close_group = tables[i].target_nodes(&addresses[j]);
                assert_eq!(::types::GROUP_SIZE,
                           target_close_group.len());
                // should contain our close group
                for k in 0..target_close_group.len() {
                    assert!(target_close_group[k].name() == &addresses[k + 1]);
                }
            }
        }
    }

    #[test]
    fn our_close_group_and_in_range() {
        // independent double verification of our_close_group()
        // this test verifies that the close group is returned sorted
        let full_id = ::id::FullId::new();
        let name = full_id.public_id().name();
        let mut routing_table = super::RoutingTable::new(name);

        let mut count: usize = 0;
        loop {
            let _ = routing_table.add_node(super::NodeInfo::new(
                ::id::FullId::new().public_id().clone(), vec![]));
            count += 1;
            if routing_table.len() >= super::OPTIMAL_TABLE_SIZE {
                break;
            }
            if count >= 2 * super::OPTIMAL_TABLE_SIZE {
                panic!("Routing table does not fill up.");
            }
        }
        let our_close_group: Vec<super::NodeInfo> = routing_table.our_close_group();
        assert_eq!(our_close_group.len(), ::types::GROUP_SIZE);
        let mut closer_name: ::NameType = name.clone();
        for close_node in &our_close_group {
            assert!(::name_type::closer_to_target(&closer_name, close_node.name(), name));
            assert!(routing_table.is_close(close_node.name()));
            closer_name = close_node.name().clone();
        }
        for node in &routing_table.routing_table {
            if our_close_group.iter()
                              .filter(|close_node| close_node.name() == node.name())
                              .count() > 0 {
                assert!(routing_table.is_close(node.name()));
            } else {
                assert!(!routing_table.is_close(node.name()));
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
                                   .filter(|node| {
                                       *node.name() == table_unit_test.buckets[i].mid_contact
                                   })
                                   .count() > 0);
        }

        table_unit_test.complete_filling_table();
        assert_eq!(::types::GROUP_SIZE,
                   table_unit_test.table.our_close_group().len());

        for close_node in table_unit_test.table.our_close_group().iter() {
            assert!(table_unit_test.added_names
                                   .iter()
                                   .filter(|node| *node == close_node.name())
                                   .count() == 1);
        }
    }

    #[test]
    fn target_nodes_test() {
        use rand;
        let mut routing_table_utest = RoutingTableUnitTest::new();

        // Check on empty table
        let mut target_nodes = routing_table_utest.table.target_nodes(&rand::random());
        assert_eq!(target_nodes.len(), 0);

        // Partially fill the table with < GROUP_SIZE contacts
        routing_table_utest.partially_fill_table();

        // Check we get all contacts returned
        target_nodes = routing_table_utest.table.target_nodes(&rand::random());
        assert_eq!(routing_table_utest.initial_count, target_nodes.len());

        for i in 0..routing_table_utest.initial_count {
            let mut assert_checker = 0;
            for j in 0..target_nodes.len() {
                if *target_nodes[j].name() == routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Complete filling the table up to OPTIMAL_TABLE_SIZE contacts
        routing_table_utest.complete_filling_table();

        // Try with our ID (should return closest to us, i.e. buckets 63 to 32)
        target_nodes = routing_table_utest.table.target_nodes(&routing_table_utest.table.our_name);
        assert_eq!(::types::GROUP_SIZE, target_nodes.len());

        for i in ((super::OPTIMAL_TABLE_SIZE -
                   ::types::GROUP_SIZE)..
                   super::OPTIMAL_TABLE_SIZE - 1).rev() {
            let mut assert_checker = 0;
            for j in 0..target_nodes.len() {
                if *target_nodes[j].name() == routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Try with nodes far from us, first time *not* in table and second time *in* table (should
        // return 'PARALLELISM' contacts closest to target first time and the single actual target
        // the second time)
        let mut target: ::NameType;
        for count in 0..2 {
            for i in 0..(super::OPTIMAL_TABLE_SIZE -
                         ::types::GROUP_SIZE) {
                let (target, expected_len) = if count == 0 {
                    (routing_table_utest.buckets[i].far_contact.clone(), super::PARALLELISM)
                } else {
                    (routing_table_utest.buckets[i].mid_contact.clone(), 1)
                };
                target_nodes = routing_table_utest.table.target_nodes(&target);
                assert_eq!(expected_len, target_nodes.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if ::name_type::closer_to_target(
                            a.name(), b.name(), &routing_table_utest.name) {
                        ::std::cmp::Ordering::Less
                    } else {
                        ::std::cmp::Ordering::Greater
                    });

                for i in 0..target_nodes.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_names.len() {
                        if *target_nodes[i].name() == routing_table_utest.added_names[j] {
                            assert_checker = 1;
                            continue;
                        }
                    }
                    assert!(assert_checker == 1);
                }
            }
        }

        // Try with nodes close to us, first time *not* in table and second time *in* table (should
        // return GROUP_SIZE closest to target)
        for count in 0..2 {
            for i in (super::OPTIMAL_TABLE_SIZE -
                      ::types::GROUP_SIZE)..
                      super::OPTIMAL_TABLE_SIZE {
                target = if count == 0 {
                    routing_table_utest.buckets[i].close_contact.clone()
                } else {
                    routing_table_utest.buckets[i].mid_contact.clone()
                };
                target_nodes = routing_table_utest.table.target_nodes(&target);
                assert_eq!(::types::GROUP_SIZE, target_nodes.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if ::name_type::closer_to_target(
                            a.name(), b.name(), &routing_table_utest.name) {
                        ::std::cmp::Ordering::Less
                    } else {
                        ::std::cmp::Ordering::Greater
                    });

                for i in 0..target_nodes.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_names.len() {
                        if *target_nodes[i].name() == routing_table_utest.added_names[j] {
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
        assert!(table_unit_test.name == table_unit_test.table.our_name);
        assert_eq!(0, table_unit_test.table.routing_table.len());

        // Check on partially filled the table
        table_unit_test.partially_fill_table();
        let test_node = create_random_node_info();
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.public_id(table_unit_test.node_info.name()) {
            Some(_) => {}
            None => panic!("PublicId None"),
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_public_id.public_key(),
        //                                 *table_.GetPublicKey(info_.name())));
        match table_unit_test.public_id(&table_unit_test.buckets[table_unit_test.buckets.len() - 1]
                                             .far_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {}
        }
        assert!(table_unit_test.name == table_unit_test.table.our_name);
        assert_eq!(table_unit_test.initial_count + 1,
                   table_unit_test.table.routing_table.len());

        // Check on fully filled the table
        table_unit_test.table.drop_node(test_node.name());
        table_unit_test.complete_filling_table();
        table_unit_test.table.drop_node(&table_unit_test.buckets[0].mid_contact);
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.public_id(table_unit_test.node_info.name()) {
            Some(_) => {}
            None => panic!("PublicId None"),
        }
        match table_unit_test.public_id(&table_unit_test.buckets[table_unit_test.buckets.len() - 1]
                                             .far_contact) {
            Some(_) => panic!("PublicId Exits"),
            None => {}
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_public_id.public_key(),
        //                                 *table_.GetPublicKey(info_.name())));
        assert!(table_unit_test.name == table_unit_test.table.our_name);
        assert_eq!(super::OPTIMAL_TABLE_SIZE,
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

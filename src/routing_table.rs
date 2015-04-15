// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

use common_bits::*;
use sodiumoxide::crypto;
use std::cmp;
use std::usize;
use types::{DhtId, PublicPmid, RoutingTrait};

static BUCKET_SIZE: usize = 1;
static GROUP_SIZE: usize = 23;
static QUORUM_SIZE: usize = 19;
pub static PARALLELISM: usize = 4;
static OPTIMAL_SIZE: usize = 64;

#[derive(Clone)]
pub struct KeyFob {
    pub id: DhtId,
    keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
    signature: crypto::sign::Signature,
}

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: DhtId, // TODO(Ben 2015-04-10) only mutable for tests!
                   // should be immutable and can be read from
                   // public_pmid.get_name();
    pub fob: PublicPmid,
    pub connected: bool,
}

impl NodeInfo {
  pub fn new(fob: PublicPmid, connected: bool)
         -> NodeInfo {
    NodeInfo {
      id : fob.get_name(),
      fob : fob,
      connected : connected
    }
  }
}

/// The RoutingTable class is used to maintain a list of contacts to which we are connected.
pub struct RoutingTable {
    routing_table: Vec<NodeInfo>,
    our_id: DhtId,
}

impl Clone for RoutingTable {
    fn clone(&self) -> RoutingTable {
        RoutingTable {
            routing_table: self.routing_table.clone(),
            our_id: self.our_id.clone(),
        }
    }
}

impl RoutingTable {
    pub fn new(our_id: DhtId) -> RoutingTable {
        RoutingTable { routing_table: Vec::<NodeInfo>::new(), our_id: our_id }
    }

    pub fn get_bucket_size() -> usize { BUCKET_SIZE }

    pub fn get_parallelism() -> usize { PARALLELISM }

    pub fn get_optimal_size() -> usize { OPTIMAL_SIZE }

    pub fn get_group_size() -> usize { GROUP_SIZE }

    pub fn get_quorum_size() -> usize { QUORUM_SIZE }

    /// Potentially adds a contact to the routing table.  If the contact is added, the first return arg
    /// is true, otherwise false.  If adding the contact caused another contact to be dropped, the
    /// dropped one is returned in the second field, otherwise the optional field is empty.  The
    /// following steps are used to determine whether to add the new contact or not:
    ///
    /// 1 - if the contact is ourself, or doesn't have a valid public key, or is already in the table,
    ///     it will not be added
    /// 2 - if the routing table is not full (size < OptimalSize()), the contact will be added
    /// 3 - if the contact is within our close group, it will be added
    /// 4 - if we can find a candidate for removal (a contact in a bucket with more than 'BucketSize()'
    ///     contacts, which is also not within our close group), and if the new contact will fit in a
    ///     bucket closer to our own bucket, then we add the new contact.
    pub fn add_node(&mut self, their_info: NodeInfo)->(bool, Option<NodeInfo>) {
        assert!(their_info.id.is_valid());

        if self.our_id == their_info.id {
            return (false, None);
        }

        if self.has_node(&their_info.id) {
            return (false, None);
        }

        if self.routing_table.len() < RoutingTable::get_optimal_size() {
            self.push_back_then_sort(their_info);
            return (true, None);
        }

        if RoutingTable::closer_to_target(&their_info.id,
                &self.routing_table[RoutingTable::get_group_size()].id, &self.our_id) {
            self.push_back_then_sort(their_info);
            let removal_node_index = self.find_candidate_for_removal();
            if removal_node_index == usize::MAX {
                return (true, None);
            } else {
                let removal_node = self.routing_table[removal_node_index].clone();
                self.routing_table.remove(removal_node_index);
                return (true, Some(removal_node));
            }
        }

        let removal_node_index = self.find_candidate_for_removal();
        if removal_node_index != usize::MAX &&
                self.new_node_is_better_than_existing(&their_info.id, removal_node_index) {
            let removal_node = self.routing_table[removal_node_index].clone();
            self.routing_table.remove(removal_node_index);
            self.push_back_then_sort(their_info);
            return (true, Some(removal_node));
        }
        (false, None)
    }

    /// This is used to see whether to bother retrieving a contact's public key from the PKI with a
    /// view to adding the contact to our table.  The checking procedure is the same as for
    /// 'AddNode' above, except for the lack of a public key to check in step 1.
    pub fn check_node(&self, their_id: &DhtId)->bool {
        if !self.our_id.is_valid() {
            panic!("Routing Table id is not valid");
        }
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
        let thier_id_clone = their_id.clone();
        if RoutingTable::closer_to_target(&their_id, &self.routing_table[group_size].id,
                                          &self.our_id) {
            return true;
        }
        self.new_node_is_better_than_existing(&their_id, self.find_candidate_for_removal())
    }

    /// This unconditionally removes the contact from the table.
    pub fn drop_node(&mut self, node_to_drop: &DhtId) {
        if node_to_drop.is_valid() {
            let mut index_of_removal = usize::MAX;

            for i in 0..self.routing_table.len() {
                if self.routing_table[i].id == *node_to_drop {
                    index_of_removal = i;
                    break;
                }
            }

            if index_of_removal < self.routing_table.len() {
                self.routing_table.remove(index_of_removal);
            }
        }
    }

    /// This returns a collection of contacts to which a message should be sent onwards.  It will
    /// return all of our close group (comprising 'GroupSize' contacts) if the closest one to the
    /// target is within our close group.  If not, it will return the 'Parallelism()' closest
    /// contacts to the target.
    pub fn target_nodes(&self, target: DhtId)->Vec<NodeInfo> {
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
            |a, b| if RoutingTable::closer_to_target(&a.id, &b.id, &target) {
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

    /// This returns the public key for the given node if the node is in our table.
    pub fn get_public_key(&self, their_id: DhtId)->Option<crypto::asymmetricbox::PublicKey> {
        if !their_id.is_valid() {
            panic!("Id is not valid");
        }
        //std::lock_guard<std::mutex> lock(mutex_);
        if !self.is_nodes_sorted() {
            panic!("Nodes are not sorted");
        }
        let found_node_option = self.routing_table.iter().find(
            |&node_info| {
                node_info.id == their_id
            });
        match found_node_option {
            Some(node) => { Some(node.fob.public_key.get_crypto_public_key()) }
            None => {None}
        }
    }

    pub fn size(&self)->usize {
        //std::lock_guard<std::mutex> lock(mutex_);
        self.routing_table.len()
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
            let bucket_index = self.bucket_index(&self.routing_table[counter].id);

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

    fn bucket_index(&self, id: &DhtId) -> usize {
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

    fn has_node(&self, node_id: &DhtId) -> bool {
        for node_info in &self.routing_table {
            if node_info.id == *node_id {
                return true;
            }
        }
        false
    }

    fn push_back_then_sort(&mut self, node_info: NodeInfo) {
        self.routing_table.push(node_info);
        let our_id = &self.our_id;
        self.routing_table.sort_by(
            |a, b| if RoutingTable::closer_to_target(&a.id,
                                                     &b.id, our_id) {
                cmp::Ordering::Less
            } else {
                cmp::Ordering::Greater
            });
    }

    // lhs is closer to target than rhs
    pub fn closer_to_target(lhs: &DhtId, rhs: &DhtId, target: &DhtId) -> bool {
        for i in 0..lhs.0.len() {
            let res_0 = lhs.0[i] ^ target.0[i];
            let res_1 = rhs.0[i] ^ target.0[i];

            if res_0 != res_1 {
                return res_0 < res_1
            }
        }
        false
    }

    fn is_nodes_sorted(&self) -> bool {
        for i in 1..self.routing_table.len() {
            if RoutingTable::closer_to_target(&self.routing_table[i].id,
                                              &self.routing_table[i - 1].id,
                                              &self.our_id) {
                return false;
            }
        }
        true
    }

    fn new_node_is_better_than_existing (&self, new_node: &DhtId,
                                         removal_node_index: usize) -> bool {
        if removal_node_index >= self.routing_table.len() {
            return false;
        }
        let removal_node = &self.routing_table[removal_node_index];
        self.bucket_index(new_node) > self.bucket_index(&removal_node.id)
    }

    fn is_any_of(vec_close_group: &Vec<NodeInfo>, vec_closest_to_target: &Vec<NodeInfo>) -> bool {
        for iter in vec_close_group.iter() {
            if iter.id == vec_closest_to_target[0].id {
                return true;
            }
        }
        false
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto;
    use std::cmp;
    use std::collections::BitVec;
    use std::net::*;
    use std::fmt;
    use types::{DhtId, PublicPmid, RoutingTrait};
    use types;
    use rand;

    enum ContactType {
        Far,
        Mid,
        Close,
    }

    fn get_contact(farthest_from_tables_own_id: &DhtId, index: usize,
                   contact_type: ContactType) -> DhtId {
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

        DhtId(binary_id.to_bytes())
    }

    struct Bucket {
        index: usize,
        far_contact: DhtId,
        mid_contact: DhtId,
        close_contact: DhtId,
    }

    impl Bucket {
        fn new(farthest_from_tables_own_id: DhtId, index: usize) -> Bucket {
            Bucket {
                index: index,
                far_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Far),
                mid_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Mid),
                close_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Close),
            }
        }
    }

    struct RoutingTableUnitTest {
        our_id: DhtId,
        table: RoutingTable,
        buckets: Vec<Bucket>,
        node_info: NodeInfo,
        initial_count: usize,
        added_ids: Vec<DhtId>,
    }

    impl RoutingTableUnitTest {
        fn new() -> RoutingTableUnitTest {
            let node_info = create_random_node_info();
            let table = RoutingTableUnitTest {
                our_id: node_info.id.clone(),
                table: RoutingTable {
                    our_id: node_info.id.clone(), routing_table: Vec::new(),
                },
                buckets: initialise_buckets(&node_info.id),
                node_info: node_info,
                initial_count: (rand::random::<usize>() % (RoutingTable::get_group_size() - 1)) + 1,
                added_ids: Vec::new(),
            };

            for i in 0..99 {
                // println!("{}\tFar: {}\tMid: {}\tClose: {}", i,
                //     RoutingTableUnitTest::debug_id(&table.buckets[i].far_contact),
                //     RoutingTableUnitTest::debug_id(&table.buckets[i].mid_contact),
                //     RoutingTableUnitTest::debug_id(&table.buckets[i].close_contact));
                assert!(RoutingTable::closer_to_target(&table.buckets[i].mid_contact,
                    &table.buckets[i].far_contact, &table.our_id));
                assert!(RoutingTable::closer_to_target(&table.buckets[i].close_contact,
                    &table.buckets[i].mid_contact, &table.our_id));
                assert!(RoutingTable::closer_to_target(&table.buckets[i + 1].far_contact,
                    &table.buckets[i].close_contact, &table.our_id));
            }

            assert!(RoutingTable::closer_to_target(&table.buckets[99].mid_contact,
                &table.buckets[99].far_contact, &table.our_id));
            assert!(RoutingTable::closer_to_target(&table.buckets[99].close_contact,
                &table.buckets[99].mid_contact, &table.our_id));

            table
        }

        fn partially_fill_table(&mut self) {
            for i in 0..self.initial_count {
                self.node_info.id = self.buckets[i].mid_contact.clone();
                self.added_ids.push(self.node_info.id.clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(self.initial_count, self.table.size());
        }

        fn complete_filling_table(&mut self) {
            for i in self.initial_count..RoutingTable::get_optimal_size() {
                self.node_info.id = self.buckets[i].mid_contact.clone();
                self.added_ids.push(self.node_info.id.clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(RoutingTable::get_optimal_size(), self.table.size());
        }

    }

    fn to_hex(char: u8) -> String {
        let hex = fmt::format(format_args!("{:x}", char));
        if hex.len() == 1 {
            let mut s = String::from_str("0");
            s.push_str(hex.as_str());
            s
        } else {
            hex
        }
    }

    fn debug_id(id: &DhtId) -> String {
        let id_as_bytes = id.0.clone();
        fmt::format(format_args!("{}{}{}..{}{}{}",
            to_hex(id_as_bytes[0]),
            to_hex(id_as_bytes[1]),
            to_hex(id_as_bytes[2]),
            to_hex(id_as_bytes[61]),
            to_hex(id_as_bytes[62]),
            to_hex(id_as_bytes[63])))
    }

    fn initialise_buckets(our_id: &DhtId) -> Vec<Bucket> {
        let arr = [255u8; 64];
        let mut arr_res = [0u8; 64];
        for i in 0..64 {
            arr_res[i] = arr[i] ^ our_id.0[i];
        }

        let farthest_from_tables_own_id = DhtId::new(&arr_res);

        let mut buckets = Vec::new();
        for i in 0..100 {
            buckets.push(Bucket::new(farthest_from_tables_own_id.clone(), i));
        }

        buckets
    }

    fn create_random_socket_address() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(rand::random::<u8>(),
                          rand::random::<u8>(),
                          rand::random::<u8>(),
                          rand::random::<u8>()),
            rand::random::<u16>()))
    }

    fn create_random_arr() -> [u8; 64] {
        let mut arr = [0u8; 64];
        for i in 0..arr.len() {
            arr[i] = rand::random::<u8>();
        }
        arr
    }

    // fn create_random_fob() -> KeyFob {
    //     let id = DhtId::generate_random();
    //     let sig = crypto::sign::Signature(types::vector_as_u8_64_array(id.0.clone()));
    //     KeyFob {
    //         id: id,
    //         keys: (crypto::sign::gen_keypair().0, crypto::asymmetricbox::gen_keypair().0),
    //         signature: sig,
    //     }
    // }

    fn create_random_node_info() -> NodeInfo {
        let public_pmid = types::PublicPmid::new(&types::Pmid::new());
        NodeInfo {
            id : public_pmid.get_name(),
            fob: public_pmid,
            connected: false,
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<RoutingTable> {
        let mut vector: Vec<RoutingTable> = Vec::with_capacity(num_of_tables);
        for i in 0..num_of_tables {
            vector.push(RoutingTable { routing_table: Vec::new(), our_id: DhtId::generate_random() });
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

                if tables[i].check_node(&node_info.id) {
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
            our_id: DhtId::generate_random()
        };

        for i in 0..RoutingTable::get_group_size() {
            let id = DhtId::generate_random();
            assert!(table.check_node(&id));
        }

        assert_eq!(table.size(), 0);

        for i in 0..RoutingTable::get_group_size() {
            let node_info = create_random_node_info();
            assert!(table.add_node(node_info).0);
        }

        assert_eq!(table.size(), RoutingTable::get_group_size());
    }

    #[test]
    fn add_check_close_group_test() {
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<DhtId> = Vec::with_capacity(num_of_tables);

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
                |a, b| if RoutingTable::closer_to_target(&a, &b, &id) {
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
                    if groups[new_end - 1].id != groups[i].id {
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
                assert!(groups[i].id == addresses[i + 1]);
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
        let mut dropped: Vec<DhtId> = Vec::new();
        for i in (RoutingTable::get_optimal_size() - 4)..RoutingTable::get_optimal_size() {
            test.node_info.id = test.buckets[i].mid_contact.clone();
            result_of_add = test.table.add_node(test.node_info.clone());
            assert!(result_of_add.0);
            match result_of_add.1 {
                Some(dropped_info) => { dropped.push(dropped_info.id) },
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
        test.table.drop_node(&DhtId::new(&[0u8;64]));
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

      // Add further 'OptimalSize()' - 1 contacts (should all succeed with no removals).  Set this
      // up so that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have 0 or 1
      // contacts.

      let mut new_node_1 = create_random_node_info();
      new_node_1.id =  routing_table_utest.buckets[0].mid_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_1.id));
      assert!(routing_table_utest.table.add_node(new_node_1).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[0].mid_contact.clone()), false);

      let mut new_node_2 = create_random_node_info();
      new_node_2.id =  routing_table_utest.buckets[0].close_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_2.id));
      assert!(routing_table_utest.table.add_node(new_node_2).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[0].close_contact.clone()), false);

      let mut new_node_3 = create_random_node_info();
      new_node_3.id = routing_table_utest.buckets[1].far_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_3.id));
      assert!(routing_table_utest.table.add_node(new_node_3).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].far_contact.clone()), false);

      let mut new_node_4 = create_random_node_info();
      new_node_4.id =  routing_table_utest.buckets[1].mid_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_4.id));
      assert!(routing_table_utest.table.add_node(new_node_4).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].mid_contact.clone()), false);

      let mut new_node_5 = create_random_node_info();
      new_node_5.id =  routing_table_utest.buckets[1].close_contact.clone();
      assert!(routing_table_utest.table.check_node(&new_node_5.id));
      assert!(routing_table_utest.table.add_node(new_node_5).0);
      assert_eq!(routing_table_utest.table.check_node(
          &routing_table_utest.buckets[1].close_contact.clone()), false);

      for i in 2..(RoutingTable::get_optimal_size() - 4) {
          let mut new_node = create_random_node_info();
          new_node.id =  routing_table_utest.buckets[i].mid_contact.clone();
          assert!(routing_table_utest.table.check_node(&new_node.id));
          assert!(routing_table_utest.table.add_node(new_node).0);
          assert_eq!(routing_table_utest.table.check_node(
              &routing_table_utest.buckets[i].mid_contact.clone()), false);
      }

      assert_eq!(RoutingTable::get_optimal_size(), routing_table_utest.table.routing_table.len());

      for i in (RoutingTable::get_optimal_size() - 4)..RoutingTable::get_optimal_size() {
          let mut new_node = create_random_node_info();
          new_node.id =  routing_table_utest.buckets[i].mid_contact.clone();
          assert!(routing_table_utest.table.check_node(&new_node.id));
          assert!(routing_table_utest.table.add_node(new_node).0);
          assert_eq!(routing_table_utest.table.check_node(
              &routing_table_utest.buckets[i].mid_contact.clone()), false);
          assert_eq!(RoutingTable::get_optimal_size(),
              routing_table_utest.table.routing_table.len());
      }

      // Check far contacts again which are now not in the table
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
        let mut addresses: Vec<DhtId> = Vec::with_capacity(network_size);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_id.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.id = tables[j].our_id.clone();
                tables[i].add_node(node_info);
            }
        }

        // now remove nodes
        let mut drop_vec: Vec<DhtId> = Vec::with_capacity(nodes_to_remove);
        for i in 0..nodes_to_remove {
            drop_vec.push(addresses[i].clone());
        }

        tables = tables.split_off(nodes_to_remove);

        for i in 0..tables.len() {
            for j in 0..drop_vec.len() {
                tables[i].drop_node(&drop_vec[j]);
            }
        }
        // remove ids too
        addresses = addresses.split_off(nodes_to_remove);

        for i in 0..tables.len() {
            let size = if RoutingTable::get_group_size() < tables[i].size() {
                RoutingTable::get_group_size()
            } else {
                tables[i].size()
            };
            let id = tables[i].our_id.clone();
            addresses.sort_by(
                |a, b| if RoutingTable::closer_to_target(&a, &b, &id) {
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
        let mut addresses: Vec<DhtId> = Vec::with_capacity(network_size);

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
                |a, b| if RoutingTable::closer_to_target(&a, &b, &tables[i].our_id) {
                    cmp::Ordering::Less
                } else {
                    cmp::Ordering::Greater
                });
            // if target is in close group return the whole close group excluding target
            for j in 1..(RoutingTable::get_group_size() - RoutingTable::get_quorum_size()) {
                let target_close_group = tables[i].target_nodes(addresses[j].clone());
                assert_eq!(RoutingTable::get_group_size(), target_close_group.len());
                // should contain our close group
                for k in 0..target_close_group.len() {
                    assert!(target_close_group[k].id == addresses[k + 1]);
                }
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
                |&node| { node.id == table_unit_test.buckets[i].mid_contact }).count() > 0);
        }

        table_unit_test.complete_filling_table();
        assert_eq!(RoutingTable::get_group_size(), table_unit_test.table.our_close_group().len());

        table_unit_test.table.our_close_group().sort_by(
            |a, b| if RoutingTable::closer_to_target(&a.id, &b.id,
                                                     &table_unit_test.our_id) {
                cmp::Ordering::Less
            } else {
                cmp::Ordering::Greater
            });

        for close_node in table_unit_test.table.our_close_group().iter() {
            assert!(table_unit_test.added_ids.iter().filter(
                |&node| { node == &close_node.id }).count() > 0);
        }
    }

    #[test]
    fn target_nodes_test() {
        let mut routing_table_utest = RoutingTableUnitTest::new();

        // Check on empty table
        let mut target_nodes_ = routing_table_utest.table.target_nodes(DhtId::generate_random());
        assert_eq!(target_nodes_.len(), 0);

        // Partially fill the table with < GroupSize contacts
        routing_table_utest.partially_fill_table();

        // Check we get all contacts returnedta
        target_nodes_ = routing_table_utest.table.target_nodes(DhtId::generate_random());
        assert_eq!(routing_table_utest.initial_count, target_nodes_.len());

        for i in 0..routing_table_utest.initial_count {
            let mut assert_checker = 0;
            for j in 0..target_nodes_.len() {
                if target_nodes_[j].id == routing_table_utest.buckets[i].mid_contact {
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
            routing_table_utest.table.target_nodes(routing_table_utest.table.our_id.clone());
        assert_eq!(RoutingTable::get_group_size(), target_nodes_.len());

        for i in ((RoutingTable::get_optimal_size() - RoutingTable::get_group_size())..
                   RoutingTable::get_optimal_size() - 1).rev() {
            let mut assert_checker = 0;
            for j in 0..target_nodes_.len() {
                if target_nodes_[j].id == routing_table_utest.buckets[i].mid_contact {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Try with nodes far from us, first time *not* in table and second time *in* table (should
        // return 'RoutingTable::Parallelism()' contacts closest to target)
        let mut target: DhtId;
        for count in 0..2 {
            for i in 0..(RoutingTable::get_optimal_size() - RoutingTable::get_group_size()) {
                target = if count == 0 {
                    routing_table_utest.buckets[i].far_contact.clone()
                } else {
                    routing_table_utest.buckets[i].mid_contact.clone()
                };
                target_nodes_ = routing_table_utest.table.target_nodes(target);
                assert_eq!(RoutingTable::get_parallelism(), target_nodes_.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if RoutingTable::closer_to_target(&a.id, &b.id,
                                                             &routing_table_utest.our_id) {
                        cmp::Ordering::Less
                    } else {
                        cmp::Ordering::Greater
                    });

                for i in 0..target_nodes_.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_ids.len() {
                        if target_nodes_[i].id == routing_table_utest.added_ids[j] {
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
                target_nodes_ = routing_table_utest.table.target_nodes(target);
                assert_eq!(RoutingTable::get_group_size(), target_nodes_.len());
                routing_table_utest.table.our_close_group().sort_by(
                    |a, b| if RoutingTable::closer_to_target(&a.id, &b.id,
                                                             &routing_table_utest.our_id) {
                        cmp::Ordering::Less
                    } else {
                        cmp::Ordering::Greater
                    });

                for i in 0..target_nodes_.len() {
                    let mut assert_checker = 0;
                    for j in 0..routing_table_utest.added_ids.len() {
                        if target_nodes_[i].id == routing_table_utest.added_ids[j] {
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
        match table_unit_test.table.get_public_key(table_unit_test.buckets[0].mid_contact.clone()) {
            Some(crypto::asymmetricbox::PublicKey(p)) => panic!("PublicKey Exits"),
            None => {},
        }
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(0, table_unit_test.table.routing_table.len());

        // Check on partially filled the table
        table_unit_test.partially_fill_table();
        let test_node = create_random_node_info();
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.table.get_public_key(table_unit_test.node_info.id.clone()) {
            Some(crypto::asymmetricbox::PublicKey(p)) => {},
            None => panic!("PublicKey None"),
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_fob.public_key(),
        //                                 *table_.GetPublicKey(info_.id)));
        match table_unit_test.table.get_public_key(
                table_unit_test.buckets[table_unit_test.buckets.len() - 1].far_contact.clone()) {
            Some(crypto::asymmetricbox::PublicKey(p)) => panic!("PublicKey Exits"),
            None => {}
        }
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(table_unit_test.initial_count + 1, table_unit_test.table.routing_table.len());

        // Check on fully filled the table
        table_unit_test.table.drop_node(&test_node.id.clone());
        table_unit_test.complete_filling_table();
        table_unit_test.table.drop_node(&table_unit_test.buckets[0].mid_contact.clone());
        table_unit_test.node_info = test_node.clone();
        assert!(table_unit_test.table.add_node(table_unit_test.node_info.clone()).0);

        match table_unit_test.table.get_public_key(table_unit_test.node_info.id.clone()) {
            Some(crypto::asymmetricbox::PublicKey(p)) => {},
            None => panic!("PublicKey None"),
        }
        match table_unit_test.table.get_public_key(
                table_unit_test.buckets[table_unit_test.buckets.len() - 1].far_contact.clone()) {
            Some(crypto::asymmetricbox::PublicKey(p)) => panic!("PublicKey Exits"),
            None => {}
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_fob.public_key(),
        //                                 *table_.GetPublicKey(info_.id)));
        assert!(table_unit_test.our_id == table_unit_test.table.our_id);
        assert_eq!(RoutingTable::get_optimal_size(), table_unit_test.table.routing_table.len());
    }
}

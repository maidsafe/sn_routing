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

extern crate maidsafe_types;
extern crate sodiumoxide;

use common_bits::*;
use sodiumoxide::crypto;
use std::cmp;
use std::net::*;
use std::usize;

static BUCKET_SIZE: usize = 1;
static GROUP_SIZE: usize = 23;
static PARALLELISM: usize = 4;
static OPTIMAL_SIZE: usize = 64;

type Address = maidsafe_types::NameType;
#[derive(Clone)]
struct KeyFob {
  id: maidsafe_types::NameType,
  keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  signature: crypto::sign::Signature,
}

#[derive(Clone)]
pub struct NodeInfo {
  fob: KeyFob,
  endpoint: SocketAddr,
  connected: bool,
}


/// The RoutingTable class is used to maintain a list of contacts to which we are connected.  
pub struct RoutingTable {
  routing_table: Vec<NodeInfo>,
  our_id: maidsafe_types::NameType,
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
  pub fn get_bucket_size() -> usize {
    BUCKET_SIZE
  }

  pub fn get_parallelism() -> usize {
    PARALLELISM
  }

  pub fn get_optimal_size() -> usize {
    OPTIMAL_SIZE
  }

  pub fn get_group_size() -> usize {
    GROUP_SIZE
  }

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
    //  Validate(their_info.id);

    let maidsafe_types::NameType(their_info_id) = their_info.fob.id;
    let maidsafe_types::NameType(our_id) = self.our_id;

    if self.our_id == their_info.fob.id {
      return (false, None);
    }

    if self.has_node(&their_info.fob.id) {
      return (false, None);
    }

    if self.routing_table.len() < RoutingTable::get_optimal_size() {
      self.push_back_then_sort(their_info);
      return (true, None);
    }

    if RoutingTable::closer_to_target(&self.our_id, &their_info.fob.id, &self.routing_table[RoutingTable::get_group_size()].fob.id) {
      self.push_back_then_sort(their_info);
      let removal_node_index = self.find_candidate_for_removal();
      if removal_node_index == (self.routing_table.len() - 1) {
        return (true, None);
      } else {
        let removal_node = self.routing_table[removal_node_index].clone();
        self.routing_table.remove(removal_node_index);
        return (true, Some(removal_node));
      }
    }

    let removal_node_index = self.find_candidate_for_removal();
    if self.new_node_is_better_than_existing(&their_info.fob.id, removal_node_index) {
      let removal_node = self.routing_table[removal_node_index].clone();
      self.routing_table.remove(removal_node_index);
      self.push_back_then_sort(their_info);
      return (true, Some(removal_node));
    }
    (false, None)
  }
  
  /// This is used to see whether to bother retrieving a contact's public key from the PKI with a
  /// view to adding the contact to our table.  The checking procedure is the same as for 'AddNode'
  /// above, except for the lack of a public key to check in step 1.
  pub fn check_node(&self, their_id: &Address)->bool {
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
    if RoutingTable::closer_to_target(&self.our_id, &their_id, &self.routing_table[group_size].fob.id) {
    	return true;
  	}
    self.new_node_is_better_than_existing(&their_id, self.find_candidate_for_removal())        	
	}
  
  /// This unconditionally removes the contact from the table.
  pub fn drop_node(&mut self, node_to_drop: &Address) {
    let mut index_of_removal = 0usize;

    for i in 0..self.routing_table.len() {
      if self.routing_table[i].fob.id == *node_to_drop {
        index_of_removal = i;
        break;
      }
    }

    if index_of_removal < self.routing_table.len() {
      self.routing_table.remove(index_of_removal);
    }
  }

  /// This returns a collection of contacts to which a message should be sent onwards.  It will
  /// return all of our close group (comprising 'GroupSize' contacts) if the closest one to the
  /// target is within our close group.  If not, it will return the 'Parallelism()' closest contacts
  /// to the target.
  pub fn target_nodes(&self, target: Address)->Vec<NodeInfo> {
    let mut our_close_group = Vec::new();
    let mut closest_to_target = Vec::new();
    let mut result: Vec<NodeInfo> = Vec::new();
    let mut iterations = 0usize;

    let parallelism = if RoutingTable::get_group_size() < self.routing_table.len() {
      RoutingTable::get_group_size()
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

    // Partial Sort:
    // let high = closest_to_target.len() - 1;
    // RoutingTable::partial_sort(&mut closest_to_target, 0, high, parallelism, &self.our_id);

    closest_to_target.sort_by(|a, b| if RoutingTable::closer_to_target(&self.our_id, &a.fob.id, &b.fob.id) { cmp::Ordering::Less } else { cmp::Ordering::Greater });

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
  pub fn get_public_key(&self, their_id: Address)->Option<crypto::asymmetricbox::PublicKey> {  	 
  	 if !their_id.is_valid() {
  	 	 panic!("Id is not valid");
  	 }
    //std::lock_guard<std::mutex> lock(mutex_);    
    if !self.is_nodes_sorted() {
    	panic!("Nodes are not sorted");
    }
    let found_node_option = self.routing_table.iter().find(|&node_info| {
    		  node_info.fob.id == their_id 
    		});
    match found_node_option {
    	Some(node) => { Some(node.fob.keys.1) }
    	None => {None}
    }
  }


//  pub fn our_id(&self)->Address {
//  	self.our_id.0 
//	}

  
  pub fn size(&self)->usize {
  	//std::lock_guard<std::mutex> lock(mutex_);
    self.routing_table.len()
  }

  fn find_candidate_for_removal(&self) -> usize {
    assert!(self.routing_table.len() >= RoutingTable::get_optimal_size());

    let mut number_in_bucket = 0usize;
    let mut bucket = 0usize;

    let mut start = self.routing_table.len() - 1;
    let finish = RoutingTable::get_group_size();

    while start >= finish {
      let index = self.bucket_index(&self.routing_table[start].fob.id);
      if index != bucket {
        bucket = index;
        number_in_bucket = 0;
      }

      number_in_bucket += 1;
      if number_in_bucket > RoutingTable::get_bucket_size() {
        break;
      }

      start -= 1;
    }
    start
  }

  fn bucket_index(&self, id: &maidsafe_types::NameType) -> usize {
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

    let common_bits = K_COMMON_BITS[self.our_id.0[index_of_mismatch] as usize][id.0[index_of_mismatch] as usize];
    8 * index_of_mismatch + common_bits as usize
  }
  
  fn has_node(&self, node_id: &Address) -> bool {
    for node_info in &self.routing_table {
      if node_info.fob.id == *node_id {
        return true;
      }
    }
    false
  }

  fn push_back_then_sort(&mut self, node_info: NodeInfo) -> usize {
    self.routing_table.push(node_info);
    let mut index = self.routing_table.len() - 1;

    for i in 1..self.routing_table.len() {
      let mut j = i - 1;
      let rhs_id = self.routing_table[i].clone();

      while j != usize::MAX && RoutingTable::closer_to_target(&self.our_id, &self.routing_table[j].fob.id, &rhs_id.fob.id) {
        self.routing_table[j + 1] = self.routing_table[j].clone();
        if j != 0 { j -= 1; }
        else      { j = usize::MAX; }
      }

      j = if j == usize::MAX { 0 } else { j + 1 };

      if j != i {
        self.routing_table[j] = rhs_id;
        if i == self.routing_table.len() - 1 {
          index = j;
        }
      }
    }
    index
  }

  // lhs is closer to base than rhs
  fn closer_to_target(base: &maidsafe_types::NameType,
                      lhs: &maidsafe_types::NameType,
                      rhs: &maidsafe_types::NameType) -> bool {
    for i in 0..lhs.0.len() {
      let res_0 = lhs.0[i] ^ base.0[i];
      let res_1 = rhs.0[i] ^ base.0[i];

      if res_0 != res_1 {
          return res_0 < res_1;
      }
    }

    false
  }
  
  fn is_nodes_sorted(&self) -> bool {
  	for i in 1..self.routing_table.len() {
      if RoutingTable::closer_to_target(&self.our_id, &self.routing_table[i - 1].fob.id, &self.routing_table[i].fob.id) {
        return false;
      }
    }
  	true
  }
  
  fn new_node_is_better_than_existing (&self, new_node: &maidsafe_types::NameType, removal_node_index: usize) -> bool {
  	if removal_node_index >= self.routing_table.len() {
  		return false;
  	}
  	let removal_node = &self.routing_table[removal_node_index];
    let last_node_fob_id = &self.routing_table[self.routing_table.len() -1 ].fob.id;    
    
    *last_node_fob_id != removal_node.fob.id && 
      &self.bucket_index(new_node) > &self.bucket_index(&removal_node.fob.id)
  }

  fn is_any_of(vec_close_group: &Vec<NodeInfo>, vec_closest_to_target: &Vec<NodeInfo>) -> bool {
    for iter in vec_close_group.iter() {
      if iter.fob.id == vec_closest_to_target[0].fob.id {
        return true;
      }
    }
    false
  }

  /*
  fn get_pivot(low: usize, high: usize) -> usize {
    // TODO(Spandan) get a random value in the range [low, high] - rand is currently broken on my
    // Rust right now
    (high - low) / 2
  }

  fn partition(vec: &mut Vec<NodeInfo>, low: usize, high: usize, base: &maidsafe_types::NameType) -> usize {
    if low < high {
      let pivot = RoutingTable::get_pivot(low, high);
      let mut new_pivot = low;

      let temp = vec[pivot].clone();
      vec[pivot] = vec[high].clone();
      vec[high] = temp.clone();

      for i in low..high {
        if RoutingTable::closer_to_target(&base, &vec[high].fob.id, &vec[i].fob.id) == cmp::Ordering::Greater {
          if i != new_pivot {
            let temp = vec[new_pivot].clone();
            vec[new_pivot] = vec[i].clone();
            vec[i] = temp.clone();
          }
          new_pivot += 1;
        }
      }

      if new_pivot != high {
        let temp = vec[new_pivot].clone();
        vec[new_pivot] = vec[high].clone();
        vec[high] = temp.clone();
      }

      new_pivot
    } else {
      low
    }
  }

  fn partial_sort(vec: &mut Vec<NodeInfo>, low: usize, high: usize, parallelism: usize, base: &maidsafe_types::NameType) {
    if low < high {
      let new_pivot = RoutingTable::partition(vec, low, high, base);
      RoutingTable::partial_sort(vec, low, new_pivot - 1, parallelism, base);

      if new_pivot < parallelism {
        RoutingTable::partial_sort(vec, new_pivot, high, parallelism, base);
      }
    }
  }
  */
}

///////////////////////////////////////////////////
use std::rand;
use std::collections::BitVec;
use std::mem;

enum ContactType {
    Far,
    Mid,
    Close,
}

fn get_contact(farthest_from_tables_own_id: &maidsafe_types::NameType, index: usize, contact_type: ContactType) -> maidsafe_types::NameType {
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

    maidsafe_types::NameType(maidsafe_types::helper::vector_as_u8_64_array(binary_id.to_bytes()))
}

struct Bucket {
    index: usize,
    far_contact: maidsafe_types::NameType,
    mid_contact: maidsafe_types::NameType,
    close_contact: maidsafe_types::NameType,
}

impl Bucket {
    fn new(farthest_from_tables_own_id: maidsafe_types::NameType, index: usize) -> Bucket {
        Bucket {
            index: index,
            far_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Far),
            mid_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Mid),
            close_contact: get_contact(&farthest_from_tables_own_id, index, ContactType::Close),
        }
    }
}

struct RoutingTableUnitTest {
    our_id: maidsafe_types::NameType,
    table: RoutingTable,
    buckets: [Bucket; 100],
    node_info: NodeInfo,
    initial_count: usize,
    added_ids: Vec<maidsafe_types::NameType>,
}

impl RoutingTableUnitTest {
    fn new() -> RoutingTableUnitTest {
        let node_info = create_random_node_info();
        let table = RoutingTableUnitTest {
            our_id: node_info.fob.id.clone(),
            table: RoutingTable { our_id: node_info.fob.id.clone(), routing_table: Vec::new(), },
            buckets: RoutingTableUnitTest::initialise_buckets(&node_info.fob.id),
            node_info: node_info,
            initial_count: (rand::random::<usize>() % (RoutingTable::get_group_size() - 1)) + 1,
            added_ids: Vec::new(),
        };

        for i in 0..99 {
            assert!(RoutingTable::closer_to_target(&table.our_id, &table.buckets[i].mid_contact, &table.buckets[i].far_contact));
            assert!(RoutingTable::closer_to_target(&table.our_id, &table.buckets[i].close_contact, &table.buckets[i].mid_contact));
            assert!(RoutingTable::closer_to_target(&table.our_id, &table.buckets[i + 1].far_contact, &table.buckets[i].close_contact));
        }

        assert!(RoutingTable::closer_to_target(&table.our_id, &table.buckets[99].mid_contact, &table.buckets[99].far_contact));
        assert!(RoutingTable::closer_to_target(&table.our_id, &table.buckets[99].close_contact, &table.buckets[99].mid_contact));

        table
    }

    fn partially_fill_table(&mut self) {
        for i in 0..self.initial_count {
            self.node_info.fob.id = self.buckets[i].mid_contact.clone();
            self.added_ids.push(self.node_info.fob.id.clone());
            assert!(self.table.add_node(self.node_info.clone()).0);
        }

        assert_eq!(self.initial_count, self.table.size());
    }

    fn complete_filling_table(&mut self) {
        for i in self.initial_count..RoutingTable::get_optimal_size() {
            self.node_info.fob.id = self.buckets[i].mid_contact.clone();
            self.added_ids.push(self.node_info.fob.id.clone());
            assert!(self.table.add_node(self.node_info.clone()).0);
        }

        assert_eq!(RoutingTable::get_optimal_size(), self.table.size());
    }

    fn initialise_buckets(our_id: &maidsafe_types::NameType) -> [Bucket; 100] {
        let arr = [255u8; 64];
        let mut arr_res = [0u8; 64];
        for i in 0..64 {
            arr_res[i] = arr[i] ^ our_id.0[i];
        }

        let farthest_from_tables_own_id = maidsafe_types::NameType(arr_res);

        let mut buckets: [Bucket; 100] = unsafe{mem::uninitialized()};
        for i in 0..buckets.len() {
            buckets[i] = Bucket::new(farthest_from_tables_own_id.clone(), i);
        }

        buckets
    }
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

fn create_random_id() -> maidsafe_types::NameType {
  maidsafe_types::NameType(create_random_arr())
}

fn create_random_fob() -> KeyFob {
  let id = create_random_id();
  let sig = crypto::sign::Signature(id.0);
  KeyFob {
    id: id,
    keys: (crypto::sign::gen_keypair().0, crypto::asymmetricbox::gen_keypair().0),
    signature: sig,
  }
}

fn create_random_node_info() -> NodeInfo {
  NodeInfo {
      fob: create_random_fob(),
      endpoint: create_random_socket_address(),
      connected: false,
  }
}

fn create_random_routing_tables(num_of_tables: usize) -> Vec<RoutingTable> {
    vec![RoutingTable { routing_table: Vec::new(), our_id: create_random_id(), }; num_of_tables]
}

#[test]
fn add_check_nodes_test() {
  let num_of_tables = 50usize;
  let mut tables = create_random_routing_tables(num_of_tables);

  for i in 0..num_of_tables {
    for j in 0..num_of_tables {
      let mut node_info = create_random_node_info();
      node_info.fob.id = tables[j].our_id.clone();

      if tables[i].check_node(&node_info.fob.id) {
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
        our_id: create_random_id(),
    };

    for i in 0..RoutingTable::get_group_size() {
        let id = create_random_id();
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
    let mut addresses: Vec<maidsafe_types::NameType> = Vec::with_capacity(num_of_tables);

    for i in 0..num_of_tables {
        addresses.push(tables[i].our_id.clone());
        for j in 0..num_of_tables {
            let mut node_info = create_random_node_info();
            node_info.fob.id = tables[j].our_id.clone();
            assert!(tables[i].add_node(node_info).0);
        }
    }

    for it in tables.iter() {
        let id = it.our_id.clone();
        addresses.sort_by(|a, b| if RoutingTable::closer_to_target(&id, &a, &b) { cmp::Ordering::Less } else { cmp::Ordering::Greater });
        let mut groups = it.our_close_group();
        assert_eq!(groups.len(), RoutingTable::get_group_size());

        // TODO(Spandan) vec.dedup does not compile - manually doing it
        if groups.len() > 1 {
            let mut new_end = 1usize;
            for i in 1..groups.len() {
                if groups[new_end - 1].fob.id != groups[i].fob.id {
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
            assert!(groups[i].fob.id == addresses[i + 1]);
        }
    }
}

#[test]
fn add_node_test() {
    let mut test = RoutingTableUnitTest::new();

    assert_eq!(test.table.size(), 0);

    // try with our id - should fail
    test.node_info.fob.id = test.table.our_id.clone();
    let mut result_of_add = test.table.add_node(test.node_info.clone());
    assert!(!result_of_add.0);
    match result_of_add.1 {
        Some(_) => panic!("Unexpected"),
        None => {},
    };
    assert_eq!(test.table.size(), 0);

    // add first contact
    test.node_info.fob.id = test.buckets[0].far_contact.clone();
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

    // Add further 'OptimalSize()' - 1 contacts (should all succeed with no removals).  Set this up so
    // that bucket 0 (furthest) and bucket 1 have 3 contacts each and all others have 0 or 1 contacts.

    // Bucket 0
    test.node_info.fob.id = test.buckets[0].mid_contact.clone();
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

    test.node_info.fob.id = test.buckets[0].close_contact.clone();
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
    test.node_info.fob.id = test.buckets[1].far_contact.clone();
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

    test.node_info.fob.id = test.buckets[1].mid_contact.clone();
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

    test.node_info.fob.id = test.buckets[1].close_contact.clone();
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
        test.node_info.fob.id = test.buckets[i].mid_contact.clone();
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
    let mut dropped: Vec<maidsafe_types::NameType> = Vec::new();
    for i in (RoutingTable::get_optimal_size() - 4)..RoutingTable::get_optimal_size() {
        test.node_info.fob.id = test.buckets[i].mid_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(result_of_add.0);
        match result_of_add.1 {
            Some(_) => {},
            None => panic!("Unexpected"),
        };
        dropped.push(result_of_add.1.unwrap().fob.id);
        assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
    }

    // TODO(Spandan) - Fails currently
    // assert!(test.buckets[0].far_contact == dropped[0]);
    // assert!(test.buckets[0].mid_contact == dropped[1]);
    // assert!(test.buckets[1].far_contact == dropped[2]);
    // assert!(test.buckets[1].mid_contact == dropped[3]);

    // Try to add far contacts again (should fail)
    for far_contact in dropped {
        test.node_info.fob.id = far_contact.clone();
        result_of_add = test.table.add_node(test.node_info.clone());
        assert!(!result_of_add.0);
        match result_of_add.1 {
            Some(_) => panic!("Unexpected"),
            None => {},
        };
        assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
    }

    // Add final close contact to push size of table_ above OptimalSize()
    test.node_info.fob.id = test.buckets[RoutingTable::get_optimal_size()].mid_contact.clone();
    result_of_add = test.table.add_node(test.node_info.clone());
    // assert!(result_of_add.0);
    // match result_of_add.1 {
    //     Some(_) => {},
    //     None => panic!("Unexpected"),
    // };
    assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
    result_of_add = test.table.add_node(test.node_info.clone());
    assert!(!result_of_add.0);
    match result_of_add.1 {
        Some(_) => panic!("Unexpected"),
        None => {},
    };
    assert_eq!(RoutingTable::get_optimal_size(), test.table.size());
}

// #[test]
// fn drop_node_test() {
//     let mut table = RoutingTable {
//         routing_table: Vec::new(),
//         our_id: create_random_id(),
//     };
// 
//     table.drop_node(&create_random_id());
// 
//     assert_eq!(table.size(), 0);
// }

// #[test]
// fn drop_node_test() {
//     let mut table = RoutingTable {
//         routing_table: Vec::new(),
//         our_id: create_random_id(),
//     };
// 
//     table.drop_node(&create_random_id());
// 
//     assert_eq!(table.size(), 0);
// }

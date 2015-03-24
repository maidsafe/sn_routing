/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */


extern crate maidsafe_types;
extern crate sodiumoxide;

use common_bits::*;
use sodiumoxide::crypto;
use std::cmp;

static BUCKET_SIZE: u32 = 1;
static PARALELISM: u32 = 4;
static OPTIMAL_SIZE: u32 = 64;

type Address = maidsafe_types::NameType;

struct KeyFob {
  id: maidsafe_types::NameType,
  keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  signature: crypto::sign::Signature,
}


impl Clone for KeyFob {
  fn clone(&self) -> Self {
    KeyFob {
      id: self.id.clone(),
      keys: self.keys.clone(),
      signature: self.signature.clone(),
    }
  }
}

pub struct NodeInfo {
  fob: KeyFob,
  //endpoint: ip::SocketAddress,
  connected: bool,
}

impl Clone for NodeInfo {
  fn clone(&self) -> Self {
    NodeInfo {
      fob: self.fob.clone(),
      //endpoint: self.endpoint
      connected: self.connected,
    }
  }
}

/// The RoutingTable class is used to maintain a list of contacts to which we are connected.  
struct RoutingTable {
  routing_table: Vec<NodeInfo>,
  our_id: maidsafe_types::NameType,
}

impl RoutingTable {
  pub fn get_bucket_size() -> usize {
    1
  }

  pub fn get_parallelism() -> usize {
    4
  }

  pub fn get_optimal_size() -> usize {
    64
  }

  pub fn get_group_size() -> usize {
    23
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
    let mut new_node_index: usize = 0;

    if self.our_id == their_info.fob.id {
      return (false, None);
    }

    if self.has_node(&their_info.fob.id) {
      return (false, None);
    }

    if self.routing_table.len() < RoutingTable::get_optimal_size() {
      new_node_index = self.push_back_then_sort(their_info);
      return (true, None);
    }

    if RoutingTable::closer_to_target(&self.our_id, &their_info.fob.id, &self.routing_table[RoutingTable::get_group_size()].fob.id) {
      new_node_index = self.push_back_then_sort(their_info);
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
      new_node_index = self.push_back_then_sort(their_info);
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
    if self.routing_table.len() < (RoutingTable::get_optimal_size() as usize) {
    	return true;
    }
    let group_size = (RoutingTable::get_group_size() - 1) as usize;
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
    let mut our_close_group: Vec<NodeInfo> = Vec::new();
    let mut closest_to_target: Vec<NodeInfo> = Vec::new();
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

    let high = closest_to_target.len() - 1;
    RoutingTable::partial_sort(&mut closest_to_target, 0, high, parallelism, &self.our_id);

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

      while j != (-1 as usize) && RoutingTable::closer_to_target(&self.our_id, &self.routing_table[j].fob.id, &rhs_id.fob.id) {
        self.routing_table[j + 1] = self.routing_table[j].clone();
        j -= 1;
      }

      if j + 1 != i {
        self.routing_table[j + 1] = rhs_id;
        if i == self.routing_table.len() - 1 {
          index = j + 1;
        }
      }
    }
    index
  }
    
  fn closer_to_target(base: &maidsafe_types::NameType,
                      lhs: &maidsafe_types::NameType,
                      rhs: &maidsafe_types::NameType) -> bool {
    for i in 0..lhs.0.len() {
      let res_0 = lhs.0[i] ^ base.0[i];
      let res_1 = rhs.0[i] ^ base.0[i];

      if res_1 < res_0 {
        return true;
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
        if RoutingTable::closer_to_target(&base, &vec[high].fob.id, &vec[i].fob.id) {
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

}

#[test]
fn it_works() {
}

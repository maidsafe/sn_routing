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
extern crate utp;

use bit_matrix;
use std::net::{TcpStream};
use sodiumoxide::crypto;
use std::default::Default;

static BUCKET_SIZE: u32 = 1;
static PARALELISM: u32 = 4;
static OPTIMAL_SIZE: u32 = 64;

type Address = [u8;64];
struct PublicKey;

struct KeyFob {
  id: maidsafe_types::NameType,
  keys: (crypto::sign::PublicKey, crypto::asymmetricbox::PublicKey),
  signature: crypto::sign::Signature,
}

impl KeyFob {
  pub fn is_valid(&self) -> bool {
   let maidsafe_types::NameType(id) = self.id;
   for it in id.iter() {
    if *it != 0 {
      return true;
    }
   }
   false
  }
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

fn bucket_index(from: Address, to: Address)->u32 {
  let it = from.iter().zip(to.iter());
  /*
  for (i, (x, y)) in it.enumerate {
    if x ^ y  == 1 { return i as u32 }
    }
    */
    0u32
}

fn common_leading_bits(id1: Address, id2: Address) -> u32 {
    let (mut missmatch_first, mut missmatch_second)= (0u8, 0u8);
    let mut index: u32 = 0;
    let identity_size = id1.len() as u32;
    for i in 0..id1.len() {
        if (id1[i] !=  id2[i]) {
          missmatch_first = id1[i];
          missmatch_second = id2[i];
          index  = i as u32;
          break
        }
    }

    if (index == identity_size) {
        return 8u32 * identity_size;
    }

    let bm_result = bit_matrix::bit_matrix(missmatch_first, missmatch_second) as u32;
    (8u32 * index) + bm_result
}

/// The RoutingTable class is used to maintain a list of contacts to which we are connected.  
struct RoutingTable {
  routing_table: Vec<NodeInfo>,
  our_id: maidsafe_types::NameType,
}

impl RoutingTable {
  pub fn get_bucket_size() -> u8 {
    1u8
  }

  pub fn get_parallelism() -> u8 {
    4u8
  }

  pub fn get_optimal_size() -> u8 {
    64u8
  }

  pub fn get_group_size() -> u8 {
    23u8
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
  pub fn add_node(&self, their_info: &NodeInfo)->(bool, Option<NodeInfo>) {
    let ret_val: (bool, Option<NodeInfo>) = (false, None);

    /*
    if their_info.fob.is_valid() &&
       their_info.fob.id != self.our_id {
      if !have_node(their_info.fob.id) {
        if routing_table.len() < get_optimal_size() {
          push_back_then_sort(their_info);
          ret_val = (true, None);
        } else {
          ;
        }
      }
    }
    */

    ret_val
  }

  /// This is used to see whether to bother retrieving a contact's public key from the PKI with a
  /// view to adding the contact to our table.  The checking procedure is the same as for 'AddNode'
  /// above, except for the lack of a public key to check in step 1.
  pub fn check_node(&self, their_id: Address)->bool { false }

  // This unconditionally removes the contact from the table.
  pub fn drop_node(&self, node_to_drop: Address) {  }

  // This returns a collection of contacts to which a message should be sent onwards.  It will
  // return all of our close group (comprising 'GroupSize' contacts) if the closest one to the
  // target is within our close group.  If not, it will return the 'Parallelism()' closest contacts
  // to the target.
  pub fn target_nodes(&self, target: Address)->Vec<NodeInfo> { Vec::new() }

  // This returns our close group, i.e. the 'GroupSize' contacts closest to our ID (or the entire
  // table if we hold less than 'GroupSize' contacts in total).
  pub fn our_close_group()->Vec<NodeInfo>{ Vec::new() }

  // This returns the public key for the given node if the node is in our table.
  pub fn get_public_key(their_id: Address)->Option<PublicKey> { None }

  pub fn our_id(&self)->Address { [0; 64] }

  pub fn size()->usize { 8usize }

  pub fn bucket_index(&self, node_id: Address) -> u32 {
    return common_leading_bits(self.our_id(), node_id);
  }

  // privates
  fn has_node(&self, node_id: &maidsafe_types::NameType) -> bool {
    for node_info in &self.routing_table {
      let maidsafe_types::NameType(lhs) = node_info.fob.id;
      let &maidsafe_types::NameType(rhs) = node_id;

      if maidsafe_types::helper::compare_arr_u8_64(&lhs, &rhs) {
        return true;
      }
    }

    false
  }

  fn push_back_then_sort(&mut self, node_info: NodeInfo) {
    self.routing_table.push(node_info);

    for i in 1..self.routing_table.len() {
      let mut j = i - 1;
      let rhs_id = self.routing_table[i].clone();

      while j >=0 && self.is_rhs_less(&self.routing_table[j].fob.id, &rhs_id.fob.id) {
        self.routing_table[j + 1] = self.routing_table[j].clone();
        j -= 1;
      }

      if j + 1 != i {
        self.routing_table[j + 1] = rhs_id;
      }
    }
  }

  fn is_rhs_less(&self, lhs: &maidsafe_types::NameType, rhs: &maidsafe_types::NameType) -> bool {
    let &maidsafe_types::NameType(lhs_arr) = lhs;
    let &maidsafe_types::NameType(rhs_arr) = lhs;
    let maidsafe_types::NameType(our_arr) = self.our_id;

    for i in 0..lhs_arr.len() {
      let res_0 = lhs_arr[i] ^ our_arr[i];
      let res_1 = rhs_arr[i] ^ our_arr[i];

      if res_1 < res_0 {
        return true;
      }
    }

    false
  }

  fn new_node_is_better_than_existing (&self, new_node: &maidsafe_types::NameType, removal_node: &NodeInfo) -> bool {
    if self.routing_table.is_empty() {
    return true;
    }
    let last_node_fob_id = self.routing_table[self.routing_table.len() -1 ].fob.id.0;
    let removal_node_fob_id = removal_node.fob.id.0;
    let new_node_id = (*new_node).0;

    !maidsafe_types::helper::compare_arr_u8_64(&last_node_fob_id, &removal_node_fob_id) && &self.bucket_index(new_node_id) > &self.bucket_index(removal_node_fob_id)
  }

}

#[test]
fn it_works() {
}

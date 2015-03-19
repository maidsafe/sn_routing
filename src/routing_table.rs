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



static BUCKET_SIZE: u32 = 1;
static PARALELISM: u32 = 4;
static OPTIMAL_SIZE: u32 = 64;

type Address = [u8;64];
struct PublicKey;

struct NodeInfo {
address: Address,
}


fn bucket_index(from: Address, to: Address)->u32 {
  let it = from.iter().zip(to.iter());
  for (i, (x, y)) in it.enumerate {
    if x ^ y  == 1 { return i as u32 }
    }
    0u32
}

/// The RoutingTable class is used to maintain a list of contacts to which we are connected.  
struct RoutingTable {
routing_table: Vec<NodeInfo>,
our_id: Vec<u8>,
}
impl RoutingTable {
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
  pub fn add_node(their_info: NodeInfo)->(bool, Option<NodeInfo>) { (false, None) }

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

  pub fn bucket_index(&self, node_id: Address)->u32 { 8u32 }
 }

#[test]
fn it_works() {
}

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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use routing_table::RoutingTable;
use message_header::MessageHeader;
use NameType;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Authority {
  ClientManager,  // from a node in our range but not routing table
  NaeManager,     // target (name()) is in the group we are in
  NodeManager,    // received from a node in our routing table (handle refresh here)
  ManagedNode,    // in our group and routing table
  ManagedClient,  // in our group
  Client,         // detached
  Unknown
}

impl Encodable for Authority {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let authority = match *self {
      Authority::ClientManager => "ClientManager",
      Authority::NaeManager => "NaeManager",
      Authority::NodeManager => "NodeManager",
      Authority::ManagedNode => "ManagedNode",
      Authority::ManagedClient => "ManagedClient",
      Authority::Client => "Client",
      Authority::Unknown => "Unknown",
    };
    CborTagEncode::new(5483_100, &(&authority)).encode(e)
  }
}

impl Decodable for Authority {
  fn decode<D: Decoder>(d: &mut D)->Result<Authority, D::Error> {
    try!(d.read_u64());
    let authority: String = try!(Decodable::decode(d));
    match &authority[..] {
      "ClientManager" => Ok(Authority::ClientManager),
      "NaeManager" => Ok(Authority::NaeManager),
      "NodeManager" => Ok(Authority::NodeManager),
      "ManagedNode" => Ok(Authority::ManagedNode),
      "ManagedClient" => Ok(Authority::ManagedClient),
      "Client" => Ok(Authority::Client),
      _ => Ok(Authority::Unknown)
    }
  }
}

/// This returns our calculated authority with regards
/// to the element passed in from the message and the message header.
/// Note that the message has first to pass Sentinel as to be verified.
/// a) if the message is not from a group,
///       the originating node is within our close group range
///       and the element is not the destination
///    -> Client Manager
/// b) if the element is within our close group range
///       and the destination is the element
///    -> Network-Addressable-Element Manager
/// c) if the message is from a group,
///       the destination is within our close group,
///       and our id is not the destination
///    -> Node Manager
/// d) if the message is from a group,
///       the group is within our close group range,
///       and the destination is our id
///    -> Managed Node
/// e) otherwise return Unknown Authority
pub fn our_authority(element : &NameType, header : &MessageHeader,
                     routing_table : &RoutingTable) -> Authority {
    if !header.is_from_group()
       && routing_table.address_in_our_close_group_range(&header.from_node())
       && header.destination.dest != *element {
        return Authority::ClientManager; }
    else if routing_table.address_in_our_close_group_range(element)
       && header.destination.dest == *element {
        return Authority::NaeManager; }
    else if header.is_from_group()
       && routing_table.address_in_our_close_group_range(&header.destination.dest)
       && header.destination.dest != routing_table.our_name() {
        return Authority::NodeManager; }
    else if header.from_group()
                  .map(|group| routing_table.address_in_our_close_group_range(&group))
                  .unwrap_or(false)
       && header.destination.dest == routing_table.our_name() {
        return Authority::ManagedNode; }
    return Authority::Unknown;
}


#[cfg(test)]
mod test {
    use routing_table::{RoutingTable, NodeInfo};
    use types;
    use types::{Id, PublicId, MessageId};
    use test_utils::{random_endpoint, random_endpoints, Random, xor};
    use rand::random;
    use name_type::{closer_to_target, NameType};
    use message_header::MessageHeader;
    use authority::{Authority, our_authority};

#[test]
fn our_authority_full_routing_table() {
    let id = types::Id::new();
    let mut routing_table = RoutingTable::new(&id.get_name());
    let mut count : usize = 0;
    loop {
        routing_table.add_node(NodeInfo::new(
                               PublicId::new(&Id::new()), random_endpoints(),
                               Some(random_endpoint())));
        count += 1;
        if count > 100 { break; }
        // if routing_node.routing_table.size() >=
        //     routing_table::RoutingTable::get_optimal_size() { break; }
        // if count >= 2 * routing_table::RoutingTable::get_optimal_size() {
        //     panic!("Routing table does not fill up."); }
    }
    let a_message_id : MessageId = random::<u32>();
    let our_name = id.get_name();
    let our_close_group : Vec<NodeInfo> = routing_table.our_close_group();
    let furthest_node_close_group : NodeInfo
        = our_close_group.last().unwrap().clone();
    let closest_node_in_our_close_group = our_close_group.first().unwrap().clone();
    let second_closest_node_in_our_close_group : NodeInfo = our_close_group[1].clone();

    let nae_or_client_in_our_close_group : NameType
        = xor(&xor(&closest_node_in_our_close_group.id, &our_name),
              &second_closest_node_in_our_close_group.id);
    // assert nae is indeed within close group
    assert!(closer_to_target(&nae_or_client_in_our_close_group,
                             &furthest_node_close_group.id,
                             &our_name));
    for close_node in our_close_group {
        // assert that nae does not collide with close node
        assert!(close_node.id != nae_or_client_in_our_close_group);
    }
    // invert to get a far away address outside of the close group
    let name_outside_close_group : NameType
        = xor(&furthest_node_close_group.id, &NameType::new([255u8; 64]));
    // note: if the close group spans close to the whole address space,
    // this construction actually inverts the address into the close group range;
    // for group_size 32; 64 node in the network this intermittently fails at 41%
    // for group_size 32; 80 nodes in the network this intermittently fails at 2%
    // for group_size 32; 100 nodes in the network this intermittently fails
    //     less than 1/8413 times, but should be exponentially less still.
    assert!(closer_to_target(&furthest_node_close_group.id,
                             &name_outside_close_group,
                             &our_name));

    // assert to get a client_manager Authority
    let client_manager_header : MessageHeader = MessageHeader {
        message_id : a_message_id.clone(),
        destination : types::DestinationAddress {
            dest : Random::generate_random(),
            reply_to : None },
        source : types::SourceAddress {
            from_node : nae_or_client_in_our_close_group.clone(),
            from_group : None,
            reply_to : None },
        authority : Authority::Client
    };
    assert_eq!(our_authority(&name_outside_close_group,
                             &client_manager_header,
                             &routing_table),
               Authority::ClientManager);

    // assert to get a nae_manager Authority
    let nae_manager_header : MessageHeader = MessageHeader {
        message_id : a_message_id.clone(),
        destination : types::DestinationAddress {
            dest : nae_or_client_in_our_close_group.clone(),
            reply_to : None },
        source : types::SourceAddress {
            from_node : Random::generate_random(),
            from_group : Some(name_outside_close_group.clone()),
            reply_to : None },
        authority : Authority::ClientManager
    };
    assert_eq!(our_authority(&nae_or_client_in_our_close_group,
                             &nae_manager_header, &routing_table),
               Authority::NaeManager);

    // assert to get a node_manager Authority
    let node_manager_header : MessageHeader = MessageHeader {
        message_id : a_message_id.clone(),
        destination : types::DestinationAddress {
            dest : second_closest_node_in_our_close_group.id.clone(),
            reply_to : None },
        source : types::SourceAddress {
            from_node : Random::generate_random(),
            from_group : Some(name_outside_close_group.clone()),
            reply_to : None },
        authority : Authority::NaeManager
    };
    assert_eq!(our_authority(&name_outside_close_group,
                             &node_manager_header,
                             &routing_table),
               Authority::NodeManager);

    // assert to get a managed_node Authority
    let managed_node_header : MessageHeader = MessageHeader {
        message_id : a_message_id.clone(),
        destination : types::DestinationAddress {
            dest : our_name.clone(),
            reply_to : None },
        source : types::SourceAddress {
            from_node : Random::generate_random(),
            from_group : Some(second_closest_node_in_our_close_group.id.clone()),
            reply_to : None },
        authority : Authority::NodeManager
    };
    assert_eq!(our_authority(&name_outside_close_group,
                             &managed_node_header,
                             &routing_table),
               Authority::ManagedNode);
}

}

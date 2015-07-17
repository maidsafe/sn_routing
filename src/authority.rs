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

use rustc_serialize::{Decoder, Encodable, Encoder};
use routing_table::RoutingTable;
use NameType;
use sodiumoxide::crypto;
use messages::{RoutingMessage, MessageType};

#[derive(RustcEncodable, RustcDecodable, PartialEq, PartialOrd, Eq, Ord, Debug, Clone)]
pub enum Authority {
  ClientManager(NameType),  // signed by a client and corresponding ClientName is in our range
  NaeManager(NameType),     // we are responsible for this element
                            // and the destination is the element
  NodeManager(NameType),    // the destination is not the element, and we are responsible for it
  ManagedNode,              // our name is the destination
                            // and the message came from within our range
  ManagedClient(crypto::sign::PublicKey),  // in our group
  Client(crypto::sign::PublicKey),         // detached
  Unknown,
}


/// This returns our calculated authority with regards
/// to the element passed in from the message and the message header.
/// Note that the message has first to pass Sentinel as to be verified.
/// a) if the message is from and signed by a client,
///       the originating node is within our close group range
///       and the element is not the destination
///    -> Client Manager
/// b) if the element is within our close group range
///       and the destination is the element
///       and the element is not our name (to exclude false)
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

// extract the element from RoutingMessage,
// then pass on to determine_authority
pub fn our_authority(message       : &RoutingMessage,
                     routing_table : &RoutingTable) -> Authority {

    // Purposely listing all the cases and not using wild cards so
    // that if a new message is added to the MessageType enum, compiler
    // will warn us that we need to add it here.
    let element = match message.message_type {
        MessageType::ConnectRequest(_)      => None,
        MessageType::ConnectResponse(_)     => None,
        MessageType::FindGroup(_)           => None,
        MessageType::FindGroupResponse(_)   => None,
        MessageType::GetData(_)             => Some(message.non_relayed_destination()),
        MessageType::GetDataResponse(_)     => None,
        MessageType::DeleteData(_)          => None,
        MessageType::DeleteDataResponse(_)  => None,
        MessageType::GetKey                 => None,
        MessageType::GetKeyResponse(_,_)    => None,
        MessageType::GetGroupKey            => None,
        MessageType::GetGroupKeyResponse(_) => None,
        MessageType::Post(_)                => None,
        MessageType::PostResponse(_)        => None,
        MessageType::PutData(ref data)      => Some(data.name()),
        MessageType::PutDataResponse(_)     => None,
        MessageType::PutKey                 => None,
        MessageType::PutPublicId(ref public_id) => Some(public_id.name()),
        MessageType::PutPublicIdResponse(_) => None,
        //MessageType::Refresh(_, _)        => Some(message.from_group()),
        MessageType::Refresh(_,_)           => None,
        MessageType::Unknown                => None,
    };

    let element = match element {
        Some(e) => e,
        None    => { return Authority::Unknown; }
    };

    return determine_authority(message, routing_table, element);
}

// determine_authority is split off to allow unit tests to test it
// separate from the content of the RoutingMessage;
// in particular element needs to be controllably inside
// or outside the close group of routing table.
fn determine_authority(message       : &RoutingMessage,
                       routing_table : &RoutingTable,
                       element       : NameType) -> Authority {

    // if signed by a client in our range and destination is not the element
    // this explicitly excludes GetData from ever being passed to ClientManager
    match message.client_key_as_name() {
        Some(client_name) => {
            if routing_table.address_in_our_close_group_range(&client_name)
                && message.non_relayed_destination() != element {
                return Authority::ClientManager(client_name); }
        },
        None => { }
    };
    if routing_table.address_in_our_close_group_range(&element)
        && message.non_relayed_destination() == element
        && element != routing_table.our_name() {
        return Authority::NaeManager(element); }
    else if message.from_group().is_some()
        && routing_table.address_in_our_close_group_range(&message.non_relayed_destination())
        && message.non_relayed_destination() != routing_table.our_name() {
        return Authority::NodeManager(message.non_relayed_destination()); }
    else if message.from_group()
                   .map(|group| routing_table.address_in_our_close_group_range(&group))
                   .unwrap_or(false)
        && message.non_relayed_destination() == routing_table.our_name() {
        return Authority::ManagedNode; }
    return Authority::Unknown;
}


#[cfg(test)]
mod test {
    use routing_table::{RoutingTable, NodeInfo};
    use types;
    use types::{MessageId, DestinationAddress, SourceAddress};
    use public_id::PublicId;
    use messages::{RoutingMessage, MessageType};
    use id::Id;
    use test_utils::{Random, xor, messages_util};
    use rand::random;
    use name_type::{closer_to_target, NameType};
    use message_header::MessageHeader;
    use authority::{Authority, our_authority};
    use sodiumoxide::crypto;
    use data::{Data};
    use immutable_data::{ImmutableDataType};

#[test]
fn our_authority_full_routing_table() {
    let id = Id::new();
    let mut routing_table = RoutingTable::new(&id.get_name());
    let mut count : usize = 0;
    loop {
        routing_table.add_node(NodeInfo::new(
                               PublicId::new(&Id::new()),
                               messages_util::test::random_endpoints(),
                               Some(messages_util::test::random_endpoint())));
        count += 1;
        if count > 100 { break; }
        // if routing_node.routing_table.size() >=
        //     routing_table::RoutingTable::get_optimal_size() { break; }
        // if count >= 2 * routing_table::RoutingTable::get_optimal_size() {
        //     panic!("Routing table does not fill up."); }
    }
    let a_message_id : MessageId = random::<u32>();
    let our_name = id.get_name();
    let (client_public_key, _) = crypto::sign::gen_keypair();
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
    // let client_manager_message : RoutingMessage = RoutingMessage {
    //     message_id : a_message_id.clone(),
    //     destination : types::DestinationAddress {dest : , relay_to : None },
    //     source : types::SourceAddress {
    //         from_node : nae_or_client_in_our_close_group.clone(),
    //         from_group : None, reply_to : None, relayed_for : None },
    //     authority : Authority::Client(crypto::sign::PublicKey([0u8; crypto::sign::PUBLICKEYBYTES]))
    // };
    let client_manager_message = RoutingMessage {
        destination : DestinationAddress::Direct(name_outside_close_group.clone()),
        // note: the CM NameType needs to equal SHA512 of the crypto::sign::PublicKey
        // but then it is cryptohard to find a matching set; so ignored for this unit test
        source      : SourceAddress::RelayedForClient(nae_or_client_in_our_close_group.clone(),
                          client_public_key.clone()),
        orig_message: None,
        message_type: MessageType::PutData(Data::ImmutableData::new(
                          ImmutableDataType::Normal, vec![213u8; 20u8])),
        message_id  : a_message_id.clone(),
        authority   : Authority::Client(client_public_key.clone()),
    };
    assert_eq!(super::determine_authority(&client_manager_message,
        &routing_table,
        name_outside_close_group.clone()),
        Authority::ClientManager(name_outside_close_group.clone()));

    // assert to get a nae_manager Authority
    let nae_manager_message = RoutingMessage {
        destination : DestinationAddress::Direct(nae_or_client_in_our_close_group.clone()),
        source      : SourceAddress::Direct(Random::generate_random()),
        orig_message: None,
        message_type: MessageType::PutData(Data::ImmutableData::new(
                          ImmutableDataType::Normal, vec![213u8; 20u8])),
        message_id  : a_message_id.clone(),
        authority   : Authority::ClientManager(Random::generate_random()),
    };
    assert_eq!(super::determine_authority(&nae_manager_message, &routing_table,
        nae_or_client_in_our_close_group),
        Authority::NaeManager(nae_or_client_in_our_close_group));

    // assert to get a node_manager Authority
    let node_manager_message = RoutingMessage {
        destination : DestinationAddress::Direct(second_closest_node_in_our_close_group.clone()),
        source      : SourceAddress::Direct(Random::generate_random()),
        orig_message: None,
        message_type: MessageType::PutData(Data::ImmutableData::new(
                          ImmutableDataType::Normal, vec![213u8; 20u8])),
        message_id  : a_message_id.clone(),
        authority   : Authority::NaeManager(Random::generate_random()),
    };
    assert_eq!(super::determine_authority(&node_manager_message,
        &routing_table, name_outside_close_group),
        Authority::NodeManager(name_outside_close_group));

    // assert to get a managed_node Authority
    let managed_node_message = RoutingMessage {
        destination : DestinationAddress::Direct(our_name.clone()),
        source      : SourceAddress::Direct(second_closest_node_in_our_close_group.id.clone()),
        orig_message: None,
        message_type: MessageType::PutData(Data::ImmutableData::new(
                          ImmutableDataType::Normal, vec![213u8; 20u8])),
        message_id  : a_message_id.clone(),
        authority   : Authority::NodeManager(our_name.clone()),
    };
    assert_eq!(super::determine_authority(&managed_node_message, &routing_table,
        name_outside_close_group),
        Authority::ManagedNode);
}

}

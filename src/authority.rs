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
use std::fmt::{Debug, Formatter, Error};

use messages::{RoutingMessage, Content, ExternalRequest, InternalRequest};
use types::Address;

#[derive(RustcEncodable, RustcDecodable, PartialEq, PartialOrd, Eq, Ord, Clone, Hash)]
/// Authority.
pub enum Authority {
    /// Signed by a client and corresponding ClientName is in our range.
    ClientManager(NameType),
    /// We are responsible for this element and the destination is the element.
    NaeManager(NameType),
    /// The destination is not the element, and we are responsible for it.
    NodeManager(NameType),
    /// Our name is the destination and the message came from within our range.
    ManagedNode(NameType),
    /// Client can specify a location where a relay will be found.
    Client(NameType, crypto::sign::PublicKey),
}

impl Authority {

    /// Return true if group authority, otherwise false.
    pub fn is_group(&self) -> bool {
        match self {
            &Authority::ClientManager(_) => true,
            &Authority::NaeManager(_) => true,
            &Authority::NodeManager(_) => true,
            &Authority::ManagedNode(_) => false,
            &Authority::Client(_, _) => false,
        }
    }

    /// Return the named part of an authority.
    pub fn get_location(&self) -> &NameType {
        match self {
            &Authority::ClientManager(ref loc) => loc,
            &Authority::NaeManager(ref loc) => loc,
            &Authority::NodeManager(ref loc) => loc,
            &Authority::ManagedNode(ref loc) => loc,
            &Authority::Client(ref loc, _) => loc,
        }
    }

    /// Return the address of none group nodes.
    pub fn get_address(&self) -> Option<Address> {
        match self {
            &Authority::ClientManager(_) => None,
            &Authority::NaeManager(_) => None,
            &Authority::NodeManager(_) => None,
            &Authority::ManagedNode(ref name) => Some(Address::Node(name.clone())),
            &Authority::Client(_, ref public_key) => Some(Address::Client(public_key.clone())),
        }
    }
}

impl Debug for Authority {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        match self {
            &Authority::ClientManager(ref name) => {
                formatter.write_str(&format!("ClientManager(name:{:?})", name))
            }
            &Authority::NaeManager(ref name) => {
                formatter.write_str(&format!("NaeManager(name:{:?})", name))
            }
            &Authority::NodeManager(ref name) => {
                formatter.write_str(&format!("NodeManager(name:{:?})", name))
            }
            &Authority::ManagedNode(ref name) => {
                formatter.write_str(&format!("ManagedNode(name:{:?})", name))
            }
            &Authority::Client(ref relay, ref public_key) => {
                formatter.write_str(&format!("Client(relay:{:?}, public_key:{:?})",
                relay, NameType::new(crypto::hash::sha512::hash(&public_key[..]).0)))
            }
        }
    }
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
///       and the element is not our name (to exclude false positive for ManagedNode)
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
pub fn our_authority(message: &RoutingMessage, routing_table: &RoutingTable) -> Option<Authority> {

    // Purposely listing all the cases and not using wild cards so
    // that if a new message is added to the MessageType enum, compiler
    // will warn us that we need to add it here.
    let element = match message.content {
        Content::ExternalRequest(ref request) => {
            match *request {
                ExternalRequest::Get(ref data_request, _) => Some(data_request.name().clone()),
                ExternalRequest::Put(ref data) => Some(data.name()),
                ExternalRequest::Post(ref data) => Some(data.name()),
                ExternalRequest::Delete(ref data) => Some(data.name()),
            }
        }
        Content::InternalRequest(ref request) => {
            match *request {
                InternalRequest::Connect(_) => None,
                InternalRequest::RequestNetworkName(ref public_id) => Some(public_id.name()),
                InternalRequest::CacheNetworkName(ref public_id, _) => Some(public_id.name()),
                InternalRequest::Refresh(_, _, _)                      => {
                    let destination = message.destination();
                    if destination != message.source() { return None; };
                    if destination.is_group()
                        && routing_table.address_in_our_close_group_range(
                            destination.get_location()) {
                        return Some(destination);
                    };
                    None
                },
            }
        }
        Content::ExternalResponse(_) => None,
        Content::InternalResponse(_) => None,
    };

    let element = match element {
        Some(e) => e,
        None => {
            return None;
        }
    };

    determine_authority(message, routing_table, element)
}

// determine_authority is a static method to allow unit tests to test it
// separate from the content of the RoutingMessage;
// in particular element needs to be controllably inside
// or outside the close group of routing table.
fn determine_authority(message: &RoutingMessage,
                       routing_table: &RoutingTable,
                       element: NameType)
                       -> Option<Authority> {

    // if signed by a client in our range and destination is not the element
    // this explicitly excludes GetData from ever being passed to ClientManager

    match message.client_key_as_name() {
        Some(client_name) => {
            if routing_table.address_in_our_close_group_range(&client_name) &&
               *message.destination().get_location() != element {
                return Some(Authority::ClientManager(client_name));
            }
        }
        None => {
        }
    };
    if routing_table.address_in_our_close_group_range(&element) &&
       *message.destination().get_location() == element &&
       element != routing_table.our_name() {
        return Some(Authority::NaeManager(element));
    } else if message.from_group().is_some() &&
       routing_table.address_in_our_close_group_range(message.destination().get_location()) &&
       *message.destination().get_location() != routing_table.our_name() {
        return Some(Authority::NodeManager(message.destination().get_location().clone()));
    } else if message.from_group()
                   .map(|group| routing_table.address_in_our_close_group_range(&group))
                   .unwrap_or(false) &&
       *message.destination().get_location() == routing_table.our_name() {
        return Some(Authority::ManagedNode(routing_table.our_name()));
    }
    return None;
}


#[cfg(test)]
mod test {
    use routing_table::{RoutingTable, NodeInfo};
    use public_id::PublicId;
    use messages::{RoutingMessage, Content, ExternalRequest};
    use id::Id;
    use test_utils::{xor, test};
    use utils::public_key_to_client_name;
    use name_type::{closer_to_target, NameType};
    use authority::Authority;
    use sodiumoxide::crypto;
    use data::Data;
    use immutable_data::{ImmutableData, ImmutableDataType};
    use rand;

    #[test]
    fn our_authority_full_routing_table() {
        let id = Id::new();
        let mut routing_table = RoutingTable::new(&id.name());
        let mut count : usize = 0;
        loop {
            let _ = routing_table.add_node(NodeInfo::new(
                PublicId::new(&Id::new()),
                test::random_endpoints(&mut rand::thread_rng()),
                Some(test::random_connection())));
            count += 1;
            if count > 100 {
                break;
            }
        // if routing_node.routing_table.size() >=
        //     routing_table::RoutingTable::get_optimal_size() { break; }
        // if count >= 2 * routing_table::RoutingTable::get_optimal_size() {
        //     panic!("Routing table does not fill up."); }
        }
        let our_name = id.name();
        let (mut client_public_key, _) = crypto::sign::gen_keypair();
        count = 0;
        loop {
            let client_name = public_key_to_client_name(&client_public_key);
            if routing_table.address_in_our_close_group_range(&client_name) {
                break;
            } else {
                let (new_client_public_key, _) = crypto::sign::gen_keypair();
                client_public_key = new_client_public_key;
                count += 1;
            }
        // tends to take 0 - 50 attempts to find a ClientName in our range.
            if count > 1000 {
                panic!("Failed to find a ClientName in our range.")
            };
        }
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

        let some_data : Data = Data::ImmutableData(ImmutableData::new(
            ImmutableDataType::Normal, ::types::generate_random_vec_u8(20usize)));

        // --- test determine_authority specific ----------------------------------------------------------------
        let client_manager_message = RoutingMessage {
            from_authority : Authority::Client(rand::random(), client_public_key.clone()),
            to_authority   : Authority::ClientManager(public_key_to_client_name(&client_public_key)),
            content : Content::ExternalRequest(ExternalRequest::Put(some_data.clone())),
        };
        assert_eq!(super::determine_authority(&client_manager_message,
            &routing_table,
            some_data.name()).unwrap(),
            Authority::ClientManager(public_key_to_client_name(&client_public_key)));

        // assert to get a nae_manager Authority
        let nae_manager_message = RoutingMessage {
            from_authority : Authority::ClientManager(public_key_to_client_name(&client_public_key)),
            to_authority   : Authority::NaeManager(nae_or_client_in_our_close_group.clone()),
            content        : Content::ExternalRequest(ExternalRequest::Put(some_data.clone())),
        };
        assert_eq!(super::determine_authority(&nae_manager_message, &routing_table,
            nae_or_client_in_our_close_group).unwrap(),
            Authority::NaeManager(nae_or_client_in_our_close_group));

        // assert to get a node_manager Authority
        let node_manager_message = RoutingMessage {
            from_authority : Authority::NaeManager(rand::random()),
            to_authority   : Authority::NodeManager(second_closest_node_in_our_close_group.id.clone()),
            content        : Content::ExternalRequest(ExternalRequest::Put(some_data.clone())),
        };
        assert_eq!(super::determine_authority(&node_manager_message,
            &routing_table, some_data.name()).unwrap(),
            Authority::NodeManager(second_closest_node_in_our_close_group.id.clone()));

        // assert to get a managed_node Authority
        let managed_node_message = RoutingMessage {
            from_authority : Authority::NodeManager(our_name.clone()),
            to_authority   : Authority::ManagedNode(our_name.clone()),
            content        : Content::ExternalRequest(ExternalRequest::Put(some_data.clone())),
        };
        assert_eq!(super::determine_authority(&managed_node_message, &routing_table,
            some_data.name()).unwrap(),
            Authority::ManagedNode(our_name.clone()));

        // --- test our_authority specific ----------------------------------------------------------------------
        let some_bytes = ::types::generate_random_vec_u8(20usize);
        // assert to get Refresh Authorities
        let refresh_message = RoutingMessage {
            from_authority : Authority::NaeManager(nae_or_client_in_our_close_group.clone()),
            to_authority   : Authority::NaeManager(nae_or_client_in_our_close_group.clone()),
            content        : Content::InternalRequest(::messages::InternalRequest::Refresh(0u64,
                some_bytes.clone(), rand::random())),
        };
        assert_eq!(super::our_authority(&refresh_message, &routing_table),
            Some(Authority::NaeManager(nae_or_client_in_our_close_group.clone())));

        // assert that this is not a valid Refresh Authority
        let refresh_message = RoutingMessage {
            from_authority : Authority::ClientManager(nae_or_client_in_our_close_group.clone()),
            to_authority   : Authority::NaeManager(nae_or_client_in_our_close_group.clone()),
            content        : Content::InternalRequest(::messages::InternalRequest::Refresh(0u64,
                some_bytes.clone(), rand::random())),
        };
        assert!(super::our_authority(&refresh_message, &routing_table).is_none());
        // assert that this is not a valid Refresh Authority
        let refresh_message = RoutingMessage {
            from_authority : Authority::NaeManager(closest_node_in_our_close_group.id.clone()),
            to_authority   : Authority::NaeManager(nae_or_client_in_our_close_group.clone()),
            content        : Content::InternalRequest(::messages::InternalRequest::Refresh(0u64,
                some_bytes.clone(), rand::random())),
        };
        assert!(super::our_authority(&refresh_message, &routing_table).is_none());
    }
}

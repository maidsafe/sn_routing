// Copyright 2015 MaidSafe.net limited.
//
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

use std::sync::mpsc::Sender;

use crust;

use routing_table::{RoutingTable, NodeInfo};
use relay::RelayMap;
use types::Address;
use authority;
use authority::Authority;
use id::Id;
use public_id::PublicId;
use NameType;
use peer::Peer;
use action::Action;
use event::Event;
use messages::RoutingMessage;

/// ConnectionName labels the counterparty on a connection in relation to us
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum ConnectionName {
    Relay(Address),
    Routing(NameType),
    Bootstrap(NameType),
    Unidentified(crust::Endpoint, bool),
   //                            ~|~~
   //                             | set true when connected as a bootstrap connection
}

/// RoutingCore provides the fundamental routing of messages, exposing both the routing
/// table and the relay map.  Routing core
pub struct RoutingCore {
    id: Id,
    network_name: Option<NameType>,
    routing_table: Option<RoutingTable>,
    relay_map: RelayMap,
    // sender for signaling events and action
    event_sender: Sender<Event>,
    action_sender: Sender<Action>,
}

#[allow(unused)]
impl RoutingCore {
    /// Start a RoutingCore with a new Id and the disabled RoutingTable
    pub fn new(event_sender: Sender<Event>,
               action_sender: Sender<Action>,
               keys: Option<Id>)
               -> RoutingCore {
        let id = match keys {
            Some(id) => id,
            None => Id::new(),
        };
        // nodes are not persistant, and a client has no network allocated name
        if id.is_relocated() {
            error!("Core terminates routing as initialised with relocated id {:?}",
                PublicId::new(&id));
            let _ = action_sender.send(Action::Terminate);
        };

        RoutingCore {
            id: id,
            network_name: None,
            routing_table: None,
            relay_map: RelayMap::new(),
            event_sender: event_sender,
            action_sender: action_sender,
        }
    }

    /// Borrow RoutingNode id.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Returns Address::Node(network_given_name) or Address::Client(PublicKey) when no network name
    /// is given.
    pub fn our_address(&self) -> Address {
        match self.network_name {
            Some(name) => Address::Node(name.clone()),
            None => Address::Client(self.id.signing_public_key()),
        }
    }

    /// Returns true if Client(public_key) matches our public signing key, even if we are a full
    /// node; or returns true if Node(name) is our current name.  Note that there is a difference to
    /// using core::our_address, as that would fail to assert an (old) Client identification after
    /// we were assigned a network name.
    pub fn is_us(&self, address: &Address) -> bool {
        match *address {
            Address::Client(public_key) => public_key == self.id.signing_public_key(),
            Address::Node(name) => name == self.id().name(),
        }
    }

    /// Assigning a network received name to the core.  If a name is already assigned, the function
    /// returns false and no action is taken.  After a name is assigned, Routing connections can be
    /// accepted.
    pub fn assign_network_name(&mut self, network_name: &NameType) -> bool {
        // if routing_table is constructed, reject name assignment
        match self.routing_table {
            Some(_) => return false,
            None => {}
        };
        if !self.id.assign_relocated_name(network_name.clone()) {
            return false
        };
        self.routing_table = Some(RoutingTable::new(&network_name));
        self.network_name = Some(network_name.clone());
        // TODO (ben 11/08/2015) assigning a network name changes our address from
        // client to node; minimally we need to send a new hello on unidentified
        // connections, we currently freeze our bootstrap connections
        // ie send nothing new.
        true
    }

    /// Currently wraps around RoutingCore::assign_network_name
    pub fn assign_name(&mut self, name: &NameType) -> bool {
        // wrap to assign_network_name
        self.assign_network_name(name)
    }

    /// Look up an endpoint in the routing table and the relay map and return the ConnectionName
    pub fn lookup_endpoint(&self, endpoint: &crust::Endpoint) -> Option<ConnectionName> {
        let routing_name = match self.routing_table {
            Some(ref routing_table) => {
                match routing_table.lookup_endpoint(&endpoint) {
                    Some(name) => Some(ConnectionName::Routing(name)),
                    None => None,
                }
            }
            None => None,
        };

        match routing_name {
            Some(name) => Some(name),
            None => match self.relay_map.lookup_endpoint(&endpoint) {
                Some(peer) => Some(peer.identity().clone()),
                None => None,
            },
        }
    }

    /// Returns the ConnectionName if either a Routing(name) is found in RoutingTable, or
    /// Relay(Address::Node(name)) or Bootstrap(name) is found in the RelayMap.
    pub fn lookup_name(&self, name: &NameType) -> Option<ConnectionName> {
        let routing_name = match self.routing_table {
            Some(ref routing_table) => {
                if routing_table.has_node(name) {
                    Some(ConnectionName::Routing(name.clone()))
                } else {
                    None
                }
            }
            None => None,
        };

        match routing_name {
            Some(found_name) => Some(found_name),
            None => match self.relay_map.lookup_name(name) {
                Some(relay_name) => Some(relay_name),
                None => None,
            },
        }
    }

    /// Returns a copy of the peer information if found in the relay_map.  The routing table does
    /// not support retrieval of peer information, and this does not pose a problem, as connections,
    /// once a Routing connection, do not need to be moved; they can only be dropped.
    pub fn get_relay_peer(&self, connection_name: &ConnectionName) -> Option<Peer> {
        match *connection_name {
            ConnectionName::Routing(name) => None,
            _ => match self.relay_map.lookup_connection_name(connection_name) {
                Some(peer) => Some(peer.clone()),
                None => None,
            },
        }
    }

    /// Returns the peer if successfully dropped from the relay_map.  If dropped from the routing
    /// table a churn event is triggered for the user if the dropped peer changed our close group.
    pub fn drop_peer(&mut self, connection_name: &ConnectionName) -> Option<Peer> {
        match *connection_name {
            ConnectionName::Routing(name) => {
                match self.routing_table {
                    Some(ref mut routing_table) => {
                        let trigger_churn = routing_table
                            .address_in_our_close_group_range(&name);
                        let routing_table_count_prior = routing_table.size();
                        routing_table.drop_node(&name);
                        if routing_table_count_prior == 1usize {
                            error!("Routing Node has disconnected.");
                            let _ = self.event_sender.send(Event::Disconnected);
                        };
                        info!("RT({:?}) dropped node {:?}", routing_table.size(), name);
                        if trigger_churn {
                            let our_close_group = routing_table.our_close_group();
                            let mut close_group : Vec<NameType> = our_close_group.iter()
                                    .map(|node_info| node_info.public_id.name())
                                    .collect::<Vec<::NameType>>();
                            close_group.insert(0, self.id.name());
                            let target_endpoints : Vec<::crust::Endpoint> = our_close_group.iter()
                                .filter_map(|node_info| node_info.connected_endpoint)
                                .collect::<Vec<::crust::Endpoint>>();
                            let _ = self.action_sender.send(Action::Churn(
                                ::direct_messages::Churn{ close_group: close_group },
                                target_endpoints, name ));
                        };
                        None
                    }
                    None => None,
                }
            }
            _ => {
                let bootstrapped_prior = self.relay_map.has_bootstrap_connections();
                let dropped_peer = self.relay_map.drop_connection_name(connection_name);
                let bootstrapped_posterior = self.relay_map.has_bootstrap_connections();
                if !bootstrapped_posterior && bootstrapped_prior && !self.is_node() {
                    error!("Routing Client has disconnected.");
                    let _ = self.event_sender.send(Event::Disconnected);
                };
                dropped_peer
            }
        }
    }

    /// To be documented
    pub fn add_peer(&mut self,
                    identity: ConnectionName,
                    endpoint: crust::Endpoint,
                    public_id: Option<PublicId>)
                    -> bool {
        match identity {
            ConnectionName::Routing(routing_name) => {
                match self.routing_table {
                    Some(ref mut routing_table) => {
                        match public_id {
                            None => return false,
                            Some(given_public_id) => {
                                if given_public_id.name() != routing_name {
                                    return false;
                                }
                                let trigger_churn = routing_table
                                    .address_in_our_close_group_range(&routing_name);
                                let node_info = NodeInfo::new(given_public_id,
                                                              vec![endpoint.clone()],
                                                              Some(endpoint));
                                let routing_table_count_prior = routing_table.size();
                                // TODO (ben 10/08/2015) drop connection of dropped node
                                let (added, _) = routing_table.add_node(node_info);
                                if added {
                                    // if we transition from zero to one routing connection
                                    if routing_table_count_prior == ::types::GROUP_SIZE - 1usize {
                                        info!("Routing Node has connected.");
                                        let _ = self.event_sender.send(Event::Connected);
                                    };
                                    info!("RT({:?}) added {:?}", routing_table.size(),
                                        routing_name);                                };
                                if added && trigger_churn {
                                    let our_close_group = routing_table.our_close_group();
                                    let mut close_group : Vec<NameType> = our_close_group.iter()
                                            .map(|node_info| node_info.public_id.name())
                                            .collect::<Vec<::NameType>>();
                                    close_group.insert(0, self.id.name());
                                    let target_endpoints : Vec<::crust::Endpoint> = our_close_group
                                        .iter()
                                        .filter_map(|node_info| node_info.connected_endpoint)
                                        .collect::<Vec<::crust::Endpoint>>();
                                    let _ = self.action_sender.send(Action::Churn(
                                        ::direct_messages::Churn{ close_group: close_group },
                                        target_endpoints, routing_name ));
                                };
                                added
                            }
                        }
                    }
                    None => false,
                }
            }
            _ => {
                let bootstrapped_prior = self.relay_map.has_bootstrap_connections();
                let is_bootstrap_connection = match identity {
                    ConnectionName::Bootstrap(_) => true,
                    _ => false,
                };
                let added = self.relay_map.add_peer(identity, endpoint, public_id);
                if !bootstrapped_prior && added && is_bootstrap_connection &&
                   self.routing_table.is_none() {
                    info!("Routing Client bootstrapped.");
                    let _ = self.event_sender.send(Event::Bootstrapped);
                };
                added
            }
        }
    }

    /// Check whether a certain identity is of interest to the core.
    /// For a Routing(NameType), the routing table will be consulted;
    /// for completeness we quote the documentation of RoutingTable::check_node below.
    /// Connections currently don't support multiple endpoints per peer,
    /// so if relay map (or routing table) already has the peer, then check_node returns false.
    /// For Relay connections it suffices that the relay map is not full to return true.
    /// For Bootstrap connections the relay map cannot be full and no routing table should exist;
    /// this logic is still under consideration [Ben 6/08/2015]
    /// For unidentified connections check_node always return true.
    /// Routing: "This is used to check whether it is worth while retrieving
    ///           a contact's public key from the PKI with a view to adding
    ///           the contact to our routing table.  The checking procedure is the
    ///           same as for 'AddNode' above, except for the lack of a public key
    ///           to check in step 1.
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
    ///     a bucket closer to our own bucket, then we add the new contact."
    pub fn check_node(&self, identity: &ConnectionName) -> bool {
        // currently don't support double endpoints per peer,
        // so if relay map (all but routing table peer) already has the peer,
        // then check_node returns false.
        match self.relay_map.lookup_connection_name(identity) {
            None => {}
            Some(_) => return false,
        };

        match *identity {
            ConnectionName::Routing(name) => {
                match self.routing_table {
                    Some(ref routing_table) => routing_table.check_node(&name),
                    None => return false,
                }
            }
            ConnectionName::Relay(_) => !self.relay_map.is_full(),
            // TODO (ben 6/08/2015) up for debate, don't show interest for bootstrap connections,
            // after we have established a routing table.
            ConnectionName::Bootstrap(_) => {
                !self.relay_map.is_full() && self.routing_table.is_none()
            }
            ConnectionName::Unidentified(_, _) => true,
        }
    }

    /// Get the endpoints to send on as a node.  This will exclude the bootstrap connections we
    /// might have.  Endpoints returned here will expect us to send the message, as anything but a
    /// Client.  If to_authority is Client(_, public_key) and this client is connected, then we only
    /// return this endpoint.
    /// If the above condition is not satisfied, the routing table will either provide a set of
    /// endpoints to send parallel to or our full close group (ourselves excluded) when the
    /// destination is in range.  If resulting vector is empty there are no routing connections.
    pub fn target_endpoints(&self, to_authority: &Authority) -> Vec<crust::Endpoint> {
        let mut target_endpoints : Vec<crust::Endpoint> = Vec::new();
        // if we can relay to the client, return that client connection
        match *to_authority {
            Authority::Client(_, ref client_public_key) => {
                match self.relay_map.lookup_connection_name(
                    &ConnectionName::Relay(Address::Client(client_public_key.clone()))) {
                    Some(ref client_peer) => {
                        target_endpoints.push(client_peer.endpoint().clone());
                        return target_endpoints;
                    }
                    None => {}
                }
            }
            _ => {}
        };
        let destination = to_authority.get_location();
        // query routing table to send it out parallel or to our close group (ourselves excluded)
        match self.routing_table {
            Some(ref routing_table) => {
                for node_info in routing_table.target_nodes(destination) {
                    match node_info.connected_endpoint {
                        Some(endpoint) => target_endpoints.push(endpoint.clone()),
                        None => {}
                    }
                };
            }
            None => {}
        };
        target_endpoints
    }

    /// Returns the available Boostrap connections as Peers. If we are a connected node, then access
    /// to the bootstrap connections will be blocked, and an empty vector is returned.
    pub fn bootstrap_endpoints(&self) -> Option<Vec<Peer>> {
        // block explicitly if we are a connected node
        if self.is_connected_node() {
            return None
        };
        Some(self.relay_map.bootstrap_connections())
    }

    /// Returns true if bootstrap connections are available. If we are a connected node, then access
    /// to the bootstrap connections will be blocked, and false is returned.  We might still receive
    /// messages from our bootstrap connections, but active usage is blocked once we are a node.
    pub fn has_bootstrap_endpoints(&self) -> bool {
        // block explicitly if routing table is available
        !self.is_connected_node() && self.relay_map.has_bootstrap_connections()
    }

    /// Returns true if the core is a full routing node, but not necessarily connected
    pub fn is_node(&self) -> bool {
        self.routing_table.is_some()
    }

    /// Returns true if the core is a full routing node and has connections
    pub fn is_connected_node(&self) -> bool {
        match self.routing_table {
            Some(ref routing_table) => routing_table.size() > 0,
            None => false,
        }
    }

    /// Returns true if the relay map contains bootstrap connections
    pub fn has_bootstrap_connections(&self) -> bool {
        self.relay_map.has_bootstrap_connections()
    }

    /// Returns true if a name is in range for our close group.
    /// If the core is not a full node, this always returns false.
    pub fn name_in_range(&self, name: &NameType) -> bool {
        match self.routing_table {
            Some(ref routing_table) => routing_table.address_in_our_close_group_range(name),
            None => false,
        }
    }

    /// Our authority is defined by the routing message, if we are a full node;  if we are a client,
    /// this always returns Client authority (where the relay name is taken from the routing message
    /// destination)
    pub fn our_authority(&self, message: &RoutingMessage) -> Option<Authority> {
        match self.routing_table {
            Some(ref routing_table) => {
                authority::our_authority(message, routing_table)
            }
            // if the message reached us as a client, then destination.get_location()
            // was our relay name
            None => Some(Authority::Client(message.destination().get_location().clone(),
                                       self.id.signing_public_key())),
        }
    }

    /// Returns our close group as a vector of NameTypes, sorted from our own name;  Our own name is
    /// always included, and the first member of the result.  If we are not a full node None is
    /// returned.
    pub fn our_close_group(&self) -> Option<Vec<NameType>> {
        match self.routing_table {
            Some(ref routing_table) => {
                let mut close_group : Vec<NameType> = routing_table
                        .our_close_group().iter()
                        .map(|node_info| node_info.public_id.name())
                        .collect::<Vec<NameType>>();
                close_group.insert(0, self.id.name());
                Some(close_group)
            }
            None => None,
        }
    }

    /// Returns our close group as a vector of PublicIds, sorted from our own name; Our own PublicId
    /// is always included, and the first member of the result.  If we are not a full node None is
    /// returned.
    pub fn our_close_group_with_public_ids(&self) -> Option<Vec<PublicId>> {
        match self.routing_table {
            Some(ref routing_table) => {
                let mut close_group : Vec<PublicId> = routing_table
                        .our_close_group().iter()
                        .map(|node_info| node_info.public_id.clone())
                        .collect::<Vec<PublicId>>();
                close_group.insert(0, PublicId::new(&self.id));
                Some(close_group)
            }
            None => None,
        }
    }

    /// Returns the number of connected peers in routing table.
    pub fn routing_table_size(&self) -> usize {
        if let Some(ref rt) = self.routing_table {
            rt.size()
        } else {
            0
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn add_peers_as_client() {
        let (event_sender, event_receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let (action_sender, action_receiver) = ::std::sync::mpsc::channel::<::action::Action>();
        let id = ::id::Id::new();
        let mut routing_core = super::RoutingCore::new(event_sender, action_sender, Some(id));

        // routing core is not yet a full node, so it should not accept routing connections
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let routing_peer = super::ConnectionName::Routing(public_id.name());
        assert!(!routing_core.add_peer(routing_peer,
            ::test_utils::messages_util::test::random_endpoint(),
            Some(public_id)));
        assert!(event_receiver.try_recv().is_err());
        assert!(action_receiver.try_recv().is_err());

        // a Bootstrap connection should be accepted though
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let bootstrap_peer = super::ConnectionName::Bootstrap(public_id.name());
        assert!(routing_core.add_peer(bootstrap_peer,
            ::test_utils::messages_util::test::random_endpoint(),
            Some(public_id)));
        assert_eq!(event_receiver.try_recv(), Ok(::event::Event::Bootstrapped));
        assert!(action_receiver.try_recv().is_err());
    }

    #[test]
    fn add_peers_as_full_node() {
        use ::test_utils::random_trait::Random;

        let (event_sender, event_receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let (action_sender, action_receiver) = ::std::sync::mpsc::channel::<::action::Action>();
        let id = ::id::Id::new();
        let mut routing_core = super::RoutingCore::new(event_sender, action_sender, Some(id));

        let our_name = ::NameType::generate_random();
        assert!(routing_core.assign_network_name(&our_name));

        // routing core is a full node, so it will accept routing connections and generate churn
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let name = public_id.name();
        let endpoint = ::test_utils::messages_util::test::random_endpoint();
        let routing_peer = super::ConnectionName::Routing(public_id.name());
        assert!(routing_core.add_peer(routing_peer, endpoint.clone(), Some(public_id)));
        assert!(event_receiver.try_recv().is_err());
        match action_receiver.try_recv() {
            Ok(::action::Action::Churn(direct_churn, targets, churn)) => {
                assert_eq!(direct_churn, ::direct_messages::Churn {
                    close_group: vec![our_name.clone(), name.clone()] } );
                assert_eq!(targets, vec![endpoint]);
                assert_eq!(churn, name);
            },
            _ => panic!("Should have caused a churn action."),
        };
        // assert that was the only action and the queue is now empty.
        assert!(action_receiver.try_recv().is_err());

        // a Bootstrap connection will still be accepted as a full node
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let bootstrap_peer = super::ConnectionName::Bootstrap(public_id.name());
        assert!(routing_core.add_peer(bootstrap_peer,
            ::test_utils::messages_util::test::random_endpoint(),
            Some(public_id)));
        assert!(event_receiver.try_recv().is_err());
        assert!(action_receiver.try_recv().is_err());

        // now add connections until we reach group size -1 + ourselves
        for i in 1..::types::GROUP_SIZE - 1 {
            let public_id = ::public_id::PublicId::new(&::id::Id::new());
            let name = public_id.name();
            let endpoint = ::test_utils::messages_util::test::random_endpoint();
            let routing_peer = super::ConnectionName::Routing(public_id.name());
            assert!(routing_core.add_peer(routing_peer, endpoint.clone(), Some(public_id)));
            assert!(event_receiver.try_recv().is_err());
            match action_receiver.try_recv() {
                Ok(::action::Action::Churn(direct_churn, targets, churn)) => {
                    assert_eq!(direct_churn.close_group.len(), i + 2usize);
                    assert_eq!(targets.len(), i + 1usize);
                    assert_eq!(churn, name);
                },
                _ => panic!("Should have caused a churn action."),
            };
            // assert that was the only action and the queue is now empty.
            assert!(action_receiver.try_recv().is_err());
        }

        // on reaching group size plus ourselves, core needs to signal we are connected
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let name = public_id.name();
        let endpoint = ::test_utils::messages_util::test::random_endpoint();
        let routing_peer = super::ConnectionName::Routing(public_id.name());
        assert!(routing_core.add_peer(routing_peer, endpoint.clone(), Some(public_id)));
        assert_eq!(event_receiver.try_recv(), Ok(::event::Event::Connected));
        assert!(event_receiver.try_recv().is_err());
        match action_receiver.try_recv() {
            Ok(::action::Action::Churn(direct_churn, targets, churn)) => {
                assert_eq!(direct_churn.close_group.len(), ::types::GROUP_SIZE + 1usize);
                assert_eq!(targets.len(), ::types::GROUP_SIZE);
                assert_eq!(churn, name);
            },
            _ => panic!("Should have caused a churn action."),
        };
        // assert that was the only action and the queue is now empty.
        assert!(action_receiver.try_recv().is_err());
    }
}

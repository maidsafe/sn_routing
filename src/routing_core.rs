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
use types::Address;
use authority;
use authority::Authority;
use id::Id;
use public_id::PublicId;
use NameType;
use action::Action;
use event::Event;
use messages::RoutingMessage;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Relay {
    pub public_key: ::sodiumoxide::crypto::sign::PublicKey,
}

impl ::utilities::Identifiable for Relay {
    fn valid_public_id(&self, public_id: &::public_id::PublicId) -> bool {
        self.public_key == public_id.signing_public_key()
    }
}

/// ConnectionName labels the counterparty on a connection in relation to us
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
#[allow(unused)]
pub enum ConnectionName {
    Relay(Address),
    Routing(NameType),
    Bootstrap(NameType),
    Unidentified(crust::Connection, bool),
   //                               ~|~~
   //                                | set true when connected as a bootstrap connection
}


/// State determines the current state of RoutingCore based on the established connections.
/// State will start at Disconnected and for a full node under expected behaviour cycle from
/// Disconnected to Bootstrapped.  Once Bootstrapped it requires a relocated name provided by
/// the network.  Once the name has been acquired, the state is Relocated and a routing table
/// is initialised with this name.  Once routing connections with the network are established,
/// the state is Connected.  Once more than ::types::GROUP_SIZE connections have been established,
/// the state is marked as GroupConnected. If the routing connections are lost, the state returns
/// to Disconnected and the routing table is destroyed.  If the node accepts an incoming connection
/// while itself disconnected it can jump from Disconnected to Relocated (assigning itself a name).
/// For a client the cycle is reduced to Disconnected and Bootstrapped.
/// When the user calls ::stop(), the state is set to Terminated.
#[allow(unused)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum State {
    /// There are no connections.
    Disconnected,
    /// There are only bootstrap connections, and we do not yet have a name.
    Bootstrapped,
    /// There are only bootstrap connections, and we have received a name.
    Relocated,
    /// There are 0 < n < GROUP_SIZE routing connections, and we have a name.
    Connected,
    /// There are n >= GROUP_SIZE routing connections, and we have a name.
    GroupConnected,
    /// ::stop() has been called.
    Terminated,
}

/// ExpectedConnection.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
#[allow(unused)]
pub enum ExpectedConnection {
    /// ConnectRequest sent by peer.
    Request(::messages::ConnectRequest),
    /// ConnectResponse in response to a ConnectRequest sent by peer.
    Response(::messages::ConnectResponse),
}

/// RoutingCore provides the fundamental routing of messages, exposing both the routing
/// table and the relay map.  Routing core
#[allow(unused)]
pub struct RoutingCore {
    id: Id,
    state: State,
    network_name: Option<NameType>,
    routing_table: Option<RoutingTable>,
    bootstrap_map: Option<::utilities::ConnectionMap<::NameType>>,
    relay_map: Option<::utilities::ConnectionMap<Relay>>,
    expected_connections: ::utilities::ExpirationMap<ExpectedConnection,
        Option<::crust::Connection>>,
    unknown_connections: ::utilities::ExpirationMap<::crust::Connection,
        Option<::direct_messages::Hello>>,
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
            state: State::Disconnected,
            network_name: None,
            routing_table: None,
            bootstrap_map: Some(::utilities::ConnectionMap::new()),
            relay_map: None,
            expected_connections: ::utilities::ExpirationMap::with_expiry_duration(
                ::time::Duration::minutes(5)),
            unknown_connections: ::utilities::ExpirationMap::with_expiry_duration(
                ::time::Duration::minutes(5)),
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

    /// Returns a borrow of the current state
    pub fn state(&self) -> &::routing_core::State {
        &self.state
    }

    /// Resets the full routing core to a disconnected state and will return a full list of all
    /// open connections to drop, if any should linger.  Resetting with persistant identity will
    /// preserve the Id, only if it has not been relocated.
    pub fn reset(&mut self, persistant: bool) -> Vec<::crust::Connection> {
        if self.id.is_relocated() || !persistant {
            self.id = ::id::Id::new(); };
        self.state = State::Disconnected;
        let mut open_connections = Vec::new();
        let bootstrap_connections = match self.bootstrap_map {
            Some(ref bootstrap_map) => bootstrap_map.connections(),
            None => vec![],
        };
        for connection in bootstrap_connections {
            open_connections.push(connection.clone()); };
        let relay_connections = match self.relay_map {
            Some(ref relay_map) => relay_map.connections(),
            None => vec![],
        };
        for connection in relay_connections {
            open_connections.push(connection.clone()); };
        // routing table should be empty in all sensible use-cases of reset() already.
        // this is merely a redundancy measure.
        let routing_connections = match self.routing_table {
            Some(ref rt) => rt.all_connections(),
            None => vec![],
        };
        for connection in routing_connections {
            open_connections.push(connection.clone()); };
        self.routing_table = None;
        self.network_name = None;
        self.relay_map = None;
        self.bootstrap_map = Some(::utilities::ConnectionMap::new());
        open_connections
    }

    /// Assigning a network received name to the core.  If a name is already assigned, the function
    /// returns false and no action is taken.  After a name is assigned, Routing connections can be
    /// accepted.
    pub fn assign_network_name(&mut self, network_name: &NameType) -> bool {
        match self.state {
            State::Disconnected => {
                debug!("Assigning name {:?} while disconnected.", network_name);
            },
            State::Bootstrapped => {},
            State::Relocated => return false,
            State::Connected => return false,
            State::GroupConnected => return false,
            State::Terminated => return false,
        };
        // if routing_table is constructed, reject name assignment
        match self.routing_table {
            Some(_) => {
                error!("Attempt to assign name {:?} while status is {:?}",
                    network_name, self.state);
                return false;
            },
            None => {}
        };
        if !self.id.assign_relocated_name(network_name.clone()) {
            return false
        };
        self.routing_table = Some(RoutingTable::new(&network_name));
        self.network_name = Some(network_name.clone());
        self.state = State::Relocated;
        true
    }

    /// Currently wraps around RoutingCore::assign_network_name
    pub fn assign_name(&mut self, name: &NameType) -> bool {
        // wrap to assign_network_name
        self.assign_network_name(name)
    }

    /// Look up a connection in the routing table and the relay map and return the ConnectionName
    pub fn lookup_connection(&self, connection: &crust::Connection) -> Option<ConnectionName> {
        match self.state {
            State::Connected | State::GroupConnected => {
                match self.routing_table {
                    Some(ref routing_table) => {
                        match routing_table.lookup_endpoint(&connection.peer_endpoint()) {
                            Some(name) => return Some(ConnectionName::Routing(name)),
                            None => {},
                        };
                    },
                    None => {},
                };

                match self.relay_map {
                    Some(ref relay_map) => {
                        match relay_map.lookup_connection(&connection) {
                            Some(public_id) => Some(ConnectionName::Relay(::types::Address::Client(
                                public_id.signing_public_key().clone()))),
                            None => None,
                        }
                    },
                    None => None,
                }
            },
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => {
                        match bootstrap_map.lookup_connection(&connection) {
                            Some(public_id) => Some(ConnectionName::Bootstrap(public_id.name())),
                            None => None,
                        }
                    },
                    None => None,
                }
            },
            State::Disconnected | State::Terminated => None,
        }
    }

    /// Drops the associated name from the relevant connection map or from routing table.
    /// If dropped from the routing table a churn event is triggered for the user
    /// if the dropped peer changed our close group and churn is generated in routing.
    /// If dropped from a connection map and multiple connections are active on the same identity
    /// all connections will be dropped asynchronously.  Removing a node from the routing table
    /// does not ensure the connection is dropped.
    pub fn drop_peer(&mut self, connection_name: &ConnectionName) {
        match *connection_name {
            ConnectionName::Routing(name) => {
                match self.routing_table {
                    Some(ref mut routing_table) => {
                        let trigger_churn = routing_table
                            .address_in_our_close_group_range(&name);
                        let routing_table_count_prior = routing_table.size();
                        routing_table.drop_node(&name);
                        match routing_table_count_prior {
                            1usize => {
                                error!("Routing Node has disconnected.");
                                self.state = State::Disconnected;
                                let _ = self.event_sender.send(Event::Disconnected);
                            },
                            ::types::GROUP_SIZE => {
                                self.state = State::Connected;
                            },
                            _ => {},
                        };
                        info!("RT({:?}) dropped node {:?}", routing_table.size(), name);
                        if trigger_churn {
                            let our_close_group = routing_table.our_close_group();

                            let mut close_group = our_close_group.iter()
                                    .map(|node_info| node_info.public_id.name())
                                    .collect::<Vec<::NameType>>();

                            close_group.insert(0, self.id.name());

                            let target_connections = our_close_group.iter()
                                .filter_map(|node_info| node_info.connection)
                                .collect::<Vec<::crust::Connection>>();

                            let _ = self.action_sender.send(Action::Churn(
                                ::direct_messages::Churn{ close_group: close_group },
                                target_connections, name ));
                        };
                    },
                    None => {},
                };
            },
            ConnectionName::Bootstrap(name) => {
                match self.bootstrap_map {
                    Some(ref mut bootstrap_map) => {
                        let bootstrapped_prior = bootstrap_map.identities_len() > 0usize;
                        let (dropped_public_id, connections_to_drop)
                            = bootstrap_map.drop_identity(&name);
                        if !connections_to_drop.is_empty() {
                            match self.action_sender.send(
                                Action::DropConnections(connections_to_drop)) {
                                Ok(()) => {},
                                Err(_) => {
                                    error!("Action receiver in RoutingNode disconnected. \
                                        Terminating from core.");
                                    self.state = State::Terminated;
                                },
                            };
                        };
                        match self.state {
                            State::Bootstrapped | State::Relocated => {
                                if bootstrap_map.identities_len() == 0usize
                                    && bootstrapped_prior {
                                    error!("Routing Client has disconnected.");
                                    self.state = State::Disconnected;
                                    let _ = self.event_sender.send(Event::Disconnected);
                                };
                            },
                            _ => {},
                        };
                    },
                    None => {},
                };
            },
            ConnectionName::Relay(::types::Address::Client(public_key)) => {
                match self.relay_map {
                    Some(ref mut relay_map) => {
                        let (_dropped_public_id, connections_to_drop)
                            = relay_map.drop_identity(&Relay{public_key: public_key});
                        if !connections_to_drop.is_empty() {
                            match self.action_sender.send(
                                Action::DropConnections(connections_to_drop)) {
                                Ok(()) => {},
                                Err(_) => {
                                    error!("Action receiver in RoutingNode disconnected. \
                                        Terminating from core.");
                                    self.state = State::Terminated;
                                },
                            };
                        };
                    },
                    None => {},
                };
            },
            _ => {

            }
        };

        match self.state {
            State::Disconnected => {
                self.routing_table = None;
                match self.action_sender.send(::action::Action::Rebootstrap) {
                    Ok(()) => {},
                    Err(_) => {
                        error!("Action receiver in RoutingNode disconnected. \
                            Terminating from core.");
                        self.state = State::Terminated;
                    }
                };
            },
            _ => {},
        };
    }

    /// To be documented
    pub fn add_peer(&mut self,
                    identity: ConnectionName,
                    connection: crust::Connection,
                    public_id: PublicId)
                    -> bool {
        let endpoint = connection.peer_endpoint();

        match identity {
            ConnectionName::Routing(routing_name) => {
                match self.routing_table {
                    Some(ref mut routing_table) => {
                        if public_id.name() != routing_name { return false; };
                        let trigger_churn = routing_table
                            .address_in_our_close_group_range(&routing_name);
                        let node_info = NodeInfo::new(public_id,
                                                      vec![endpoint.clone()],
                                                      Some(connection));
                        let routing_table_count_prior = routing_table.size();
                        let (added, removal_node) = routing_table.add_node(node_info);

                        match removal_node {
                            Some(node) => {
                                match node.connection {
                                    Some(connection) => {
                                        let _ = self.action_sender.send(
                                            Action::DropConnections(vec![connection]));
                                    },
                                    None => ()
                                }
                            },
                            None => ()
                        }

                        if added {
                            if routing_table_count_prior == 0usize {
                                // if we transition from zero to one routing connection
                                info!("Routing Node has connected.");
                                self.state = State::Connected;
                            } else if routing_table_count_prior
                                == ::types::GROUP_SIZE - 1usize {
                                info!("Routing Node has connected to {:?} nodes.",
                                    routing_table.size());
                                self.state = State::GroupConnected;
                                let _ = self.event_sender.send(Event::Connected);
                            };
                            info!("RT({:?}) added {:?}", routing_table.size(),
                                routing_name); };
                        if added && trigger_churn {
                            let our_close_group = routing_table.our_close_group();
                            let mut close_group : Vec<NameType> = our_close_group.iter()
                                    .map(|node_info| node_info.public_id.name())
                                    .collect::<Vec<::NameType>>();
                            close_group.insert(0, self.id.name());
                            let targets = our_close_group
                                .iter()
                                .filter_map(|node_info| node_info.connection)
                                .collect::<Vec<::crust::Connection>>();
                            let _ = self.action_sender.send(Action::Churn(
                                ::direct_messages::Churn{ close_group: close_group },
                                targets, routing_name ));
                        };
                        added
                    }
                    None => false,
                }
            },
            ConnectionName::Bootstrap(bootstrap_name) => {
                match self.bootstrap_map {
                    Some(ref mut bootstrap_map) => {
                        let bootstrapped_prior = bootstrap_map.identities_len() > 0usize;
                        let added = bootstrap_map.add_peer(connection, bootstrap_name, public_id);
                        if !bootstrapped_prior && added && self.routing_table.is_none() {
                            info!("Routing Client bootstrapped.");
                            self.state = State::Bootstrapped;
                            let _ = self.event_sender.send(Event::Bootstrapped);
                        };
                        added
                    },
                    None => false
                }
            },
            ConnectionName::Relay(::types::Address::Client(public_key)) => {
                match self.relay_map {
                    Some(ref mut relay_map) => {
                        relay_map.add_peer(connection, Relay{public_key: public_key}, public_id)
                    },
                    None => false,
                }
            },
            _ => false,
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
        match *identity {
            ConnectionName::Routing(name) => {
                match self.state {
                    State::Disconnected => return false,
                    _ => {},
                };
                match self.routing_table {
                    Some(ref routing_table) => routing_table.check_node(&name),
                    None => return false,
                }
            },
            ConnectionName::Relay(_) => {
                match self.state {
                    State::Disconnected => return false,
                    _ => {},
                };
                match self.relay_map {
                    Some(ref relay_map) => !relay_map.is_full(),
                    None => return false,
                }
            },
            // TODO (ben 6/08/2015) up for debate, don't show interest for bootstrap connections,
            // after we have established a single bootstrap connection.
            ConnectionName::Bootstrap(_) => {
                match self.state {
                    State::Disconnected => {},
                    _ => return false,
                };
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => !bootstrap_map.is_full(),
                    None => return false,
                }
            },
            ConnectionName::Unidentified(_, _) => true,
        }
    }

    /// Get the endpoints to send on as a node.  This will exclude the bootstrap connections
    /// we might have.  Endpoints returned here will expect us to send the message,
    /// as anything but a Client.  If to_authority is Client(_, public_key) and this client is
    /// connected, then we only return this endpoint.
    /// If the above condition is not satisfied, the routing table will either provide
    /// a set of endpoints to send parallel to or our full close group (ourselves excluded)
    /// when the destination is in range.
    /// If resulting vector is empty there are no routing connections.
    pub fn target_connections(&self, to_authority: &Authority) -> Vec<crust::Connection> {
        // if we can relay to the client, return that client connection
        match self.relay_map {
            Some(ref relay_map) => {
                match *to_authority {
                    Authority::Client(_, ref client_public_key) => {
                        let (_, connections) = relay_map.lookup_identity(
                            &Relay{public_key: client_public_key.clone()});
                        return connections;
                    }
                    _ => {}
                };
            },
            None => {},
        }

        let mut target_connections : Vec<crust::Connection> = Vec::new();
        let destination = to_authority.get_location();
        // query routing table to send it out parallel or to our close group (ourselves excluded)
        match self.routing_table {
            Some(ref routing_table) => {
                for node_info in routing_table.target_nodes(destination) {
                    match node_info.connection {
                        Some(c) => target_connections.push(c.clone()),
                        None => {}
                    }
                };
            }
            None => {}
        };
        target_connections
    }

    /// Returns the available Boostrap connections as connections. If we are a connected node,
    /// then access to the bootstrap connections will be blocked, and None is returned.
    pub fn bootstrap_connections(&self) -> Option<Vec<::crust::Connection>> {
        // block explicitly if we are a connected node
        match self.state {
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => Some(bootstrap_map.connections()),
                    None => None,
                }
            },
            _ => None,
        }
    }

    /// Returns the available Boostrap connections as names. If we are a connected node,
    /// then access to the bootstrap names will be blocked, and None is returned.
    pub fn bootstrap_names(&self) -> Option<Vec<::NameType>> {
        // block explicitly if we are a connected node
        match self.state {
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => Some(bootstrap_map.identities()),
                    None => None,
                }
            },
            _ => None,
        }
    }

    /// Returns true if bootstrap connections are available. If we are a connected node, then access
    /// to the bootstrap connections will be blocked, and false is returned.  We might still receive
    /// messages from our bootstrap connections, but active usage is blocked once we are a node.
    pub fn has_bootstrap_endpoints(&self) -> bool {
        // block explicitly if routing table is available
        match self.state {
            State::Bootstrapped | State::Relocated => {
                match self.bootstrap_map {
                    Some(ref bootstrap_map) => bootstrap_map.identities_len() > 0usize,
                    None => false,
                }
            },
            _ => false,
        }
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
        match self.bootstrap_map {
            Some(ref bootstrap_map) => bootstrap_map.identities_len() > 0usize,
            None => false,
        }
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

    /// Check whether the connection has been sent in a ConnectRequest/ConnectResponse.
    pub fn match_expected_connection(&mut self, connection: &::crust::Connection) -> bool {
        let endpoint = connection.peer_endpoint();
        let keys = self.expected_connections.keys().filter(|&k| match k {
            &ExpectedConnection::Request(ref connect_request) => {
                connect_request.external_endpoints.iter().filter(|&e| *e == endpoint)
                .collect::<Vec<_>>().len() > 0usize
            },
            &ExpectedConnection::Response(ref connect_response) => {
                connect_response.external_endpoints.iter().filter(|&e| *e == endpoint)
                .collect::<Vec<_>>().len() > 0usize
            },
        }).cloned().collect::<Vec<_>>();

        debug_assert!(keys.len() <= 1usize);
        let unconnected_key = match keys.first() {
            Some(key) => {
                match self.expected_connections.get(&key) {
                    Some(_existing_connection) => {
                        // If we already have a matched connection drop the new one.
                        let _ = self.action_sender.send(::action::Action::DropConnections(
                            vec![connection.clone()]));
                        None
                    },
                    None => Some(key.clone()),
                }
            },
            None => None,
        };

        match unconnected_key {
            Some(key) => {
                let _ = self.expected_connections.insert(key.clone(), Some(connection.clone()));
                // self.action_sender.send(::action::Action::MatchConnection(
                //     Some(key.clone(), Some(connection.clone())), None));
                true
            },
            None => false,
        }
    }

    /// Check whether the connection has been made.
    pub fn match_unknown_connection(&mut self, connection: &::crust::Connection,
            hello: &::direct_messages::Hello) -> bool {
        if self.unknown_connections.contains_key(connection) {
            let _ = self.unknown_connections.insert(connection.clone(), Some(hello.clone()));
            true
        }
        else {
            false
        }
    }

    /// Add a bootstrap connection.
    pub fn add_bootstrap_connection(&mut self, _connection: ::crust::Connection) {
        unimplemented!();
    }

    /// Add an expected connection.
    pub fn add_expected_connection(&mut self, expected_connection: ExpectedConnection)
            -> Option<Option<::crust::Connection>> {
        self.expected_connections.insert(expected_connection, None)
    }

    /// Add an unknown connection.
    pub fn add_unknown_connection(&mut self, unknown_connection: ::crust::Connection)
            -> Option<Option<::direct_messages::Hello>> {
        self.unknown_connections.insert(unknown_connection, None)
    }
}

#[cfg(test)]
mod test {
    use test_utils::test;

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
            test::random_connection(), public_id));
        assert!(event_receiver.try_recv().is_err());
        assert!(action_receiver.try_recv().is_err());

        // a Bootstrap connection should be accepted though
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let bootstrap_peer = super::ConnectionName::Bootstrap(public_id.name());
        assert!(routing_core.add_peer(bootstrap_peer,
            test::random_connection(), public_id));
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
        let connection = test::random_connection();
        let routing_peer = super::ConnectionName::Routing(public_id.name());
        assert!(routing_core.add_peer(routing_peer, connection.clone(), public_id));
        assert!(event_receiver.try_recv().is_err());
        match action_receiver.try_recv() {
            Ok(::action::Action::Churn(direct_churn, targets, churn)) => {
                assert_eq!(direct_churn, ::direct_messages::Churn {
                    close_group: vec![our_name.clone(), name.clone()] } );
                assert_eq!(targets, vec![connection]);
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
            test::random_connection(), public_id));
        assert!(event_receiver.try_recv().is_err());
        assert!(action_receiver.try_recv().is_err());

        // now add connections until we reach group size -1 + ourselves
        for i in 1..::types::GROUP_SIZE - 1 {
            let public_id = ::public_id::PublicId::new(&::id::Id::new());
            let name = public_id.name();
            let connection = test::random_connection();
            let routing_peer = super::ConnectionName::Routing(public_id.name());
            assert!(routing_core.add_peer(routing_peer, connection.clone(), public_id));
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
        let connection = test::random_connection();
        let routing_peer = super::ConnectionName::Routing(public_id.name());
        assert!(routing_core.add_peer(routing_peer, connection.clone(), public_id));
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

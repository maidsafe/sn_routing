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

use crust;

use routing_table::RoutingTable;
use relay::RelayMap;
use types::Address;
use authority::Authority;
use id::Id;
use NameType;

/// ConnectionName labels the counterparty on a connection in relation to us
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ConnectionName {
   Relay(Address),
   Routing(NameType),
   Bootstrap(NameType),
   Unidentified(crust::Endpoint),
}

/// RoutingCore provides the fundamental routing of messages, exposing both the routing
/// table and the relay map.  Routing core
pub struct RoutingCore {
    id            : Id,
    network_name  : Option<NameType>,
    routing_table : Option<RoutingTable>,
    relay_map     : RelayMap,
}

impl RoutingCore {
    /// Start a RoutingCore with a new Id and the disabled RoutingTable
    pub fn new() -> RoutingCore {
        let id = Id::new();
        RoutingCore {
            id            : id,
            network_name  : None,
            routing_table : None,
            relay_map     : RelayMap::new(),
        }
    }

    /// Get the
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Assigning a network received name to the core.
    /// If a name is already assigned, the function returns false and no action is taken.
    /// After a name is assigned, Routing connections can be accepted.
    pub fn assign_network_name(&mut self, network_name: &NameType) -> bool {
        // if routing_table is constructed, reject name assignment
        match self.routing_table {
            Some(_) => return false,
            None => {},
        };
        if !self.id.assign_relocated_name(network_name.clone()) {
            return false };
        self.routing_table = Some(RoutingTable::new(&network_name));
        true
    }

    /// Look up an endpoint in the routing table and the relay map and return the ConnectionName
    pub fn lookup_endpoint(&self, endpoint: &crust::Endpoint) -> Option<ConnectionName> {
        let routing_name = match self.routing_table {
            Some(ref routing_table) => {
                match routing_table.lookup_endpoint(&endpoint) {
                    Some(name) => Some(ConnectionName::Routing(name)),
                    None => None,
                }
            },
            None => None,
        };

        match routing_name {
            Some(name) => Some(name),
            None => match self.relay_map.lookup_endpoint(&endpoint) {
                Some(peer) => Some(peer.identity().clone()),
                None => None,
            }
        }
    }

    /// Returns the ConnectionName if either a Routing(name) is found in RoutingTable,
    /// or Relay(Address::Node(name)) or Bootstrap(name) is found in the RelayMap.
    pub fn lookup_name(&self, name : &NameType) -> Option<ConnectionName> {
        let routing_name = match self.routing_table {
            Some(ref routing_table) => {
                if routing_table.has_node(name) {
                    Some(ConnectionName::Routing(name.clone()))
                } else { None } },
            None => None,
        };

        match routing_name {
            Some(found_name) => Some(found_name),
            None => match self.relay_map.lookup_name(name) {
                Some(relay_name) => Some(relay_name),
                None => None,
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
    pub fn check_node(&self, identity : &ConnectionName) -> bool {
        // currently don't support double endpoints per peer,
        // so if relay map (all but routing table peer) already has the peer,
        // then check_node returns false.
        match self.relay_map.lookup_connection_name(identity) {
            None => {},
            Some(_) => return false,
        };

        match *identity {
            ConnectionName::Routing(name) => {
                match self.routing_table {
                    Some(ref routing_table) => routing_table.check_node(&name),
                    None => return false,
                }
            },
            ConnectionName::Relay(_) => !self.relay_map.is_full(),
            // TODO (ben 6/08/2015) up for debate, don't show interest for bootstrap connections,
            // after we have established a routing table.
            ConnectionName::Bootstrap(_) => {
                !self.relay_map.is_full() &&
                self.routing_table.is_none() },
            ConnectionName::Unidentified(_) => true,
        }
    }

    pub fn target_endpoints(&self, to_authority : &Authority) -> Vec<crust::Endpoint> {
        unimplemented!()
    }
}

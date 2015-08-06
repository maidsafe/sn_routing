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
use id::Id;
use NameType;

/// ConnectionName labels the counterparty on a connection in relation to us
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ConnectionName {
   Relay(Address),
   Routing(NameType),
   Bootstrap(NameType),
   UnidentifiedConnection(crust::Endpoint),
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

    ///
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
}

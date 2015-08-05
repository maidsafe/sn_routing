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

use routing_table::RoutingTable;
use relay::RelayMap;
use types::Address;
use id::Id;
use NameType;

pub enum ConnectionName {
   Relay(Address),
   Routing(NameType),
   Bootstrap(NameType),
   UnidentifiedConnection,
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
    pub fn new(id : Id) -> RoutingCore {

        RoutingCore {
            id            : id,
            network_name  : None,
            routing_table : None,
            relay_map     : RelayMap::new(),
        }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }
}

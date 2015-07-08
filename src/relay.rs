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

//! This module handle all connections that are not managed by the routing table.
//!
//! As such the relay module handles messages that need to flow in or out of the SAFE network.
//! These messages include bootstrap actions by starting nodes or relay messages for clients.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use time::{SteadyTime};
use crust::Endpoint;
use types::{Id, PublicId};
use NameType;

const MAX_RELAY : usize = 100;

/// The relay map is used to maintain a list of contacts for whom
/// we are relaying messages, when we are ourselves connected to the network.
pub struct RelayMap {
    relay_map: BTreeMap<NameType, (PublicId, BTreeSet<Endpoint>)>,
    lookup_map: HashMap<Endpoint, NameType>,
    // FIXME : we don't want to store a value; but LRUcache can clear itself out
    // however, we want the explicit timestamp stored and clear it at routing,
    // to drop the connection on clearing; for now CM will just keep all these connections
    unknown_connections: HashMap<Endpoint, SteadyTime>,
    our_name: NameType,
    self_relocated: bool
}

impl RelayMap {
    /// This creates a new RelayMap.
    pub fn new(our_id: &Id) -> RelayMap {
        RelayMap {
            relay_map: BTreeMap::new(),
            lookup_map: HashMap::new(),
            unknown_connections: HashMap::new(),
            our_name: our_id.get_name(),
            self_relocated: our_id.is_self_relocated()
        }
    }

    /// Adds an IP Node info to the relay map if the relay map has open
    /// slots.  This returns true if Info was addded.
    /// Returns true is the endpoint is newly added, or was already present.
    /// Returns false if the threshold was reached or name is our name.
    /// Returns false if the endpoint is already assigned to a different name.
    pub fn add_ip_node(&mut self, relay_info: PublicId, relay_endpoint: Endpoint) -> bool {
        // always reject our own id
        if self.our_name == relay_info.name() {
            return false;
        }
        // impose limit on number of relay nodes active
        if !self.relay_map.contains_key(&relay_info.name())
            && self.relay_map.len() >= MAX_RELAY {
            return false;
        }
        if self.lookup_map.contains_key(&relay_endpoint) {
          return false; }
        self.lookup_map.entry(relay_endpoint.clone())
                       .or_insert(relay_info.name());
        let new_set = || { (relay_info.clone(), BTreeSet::<Endpoint>::new()) };
        self.relay_map.entry(relay_info.name()).or_insert_with(new_set).1
                      .insert(relay_endpoint);
        true
    }

    /// This removes the provided endpoint and returns a NameType if this endpoint
    /// was the last endpoint assocoiated with this Name; otherwise returns None.
    pub fn drop_endpoint(&mut self, endpoint_to_drop: &Endpoint) -> Option<NameType> {
        let mut old_entry = match self.lookup_map.remove(endpoint_to_drop) {
            Some(name) => {
                match self.relay_map.remove(&name) {
                    Some(entry) => Some((name, entry)),
                    None => None
                }
            },
            None => None
        };
        let new_entry = match old_entry {
            Some((ref name, (ref public_id, ref mut endpoints))) => {
                endpoints.remove(endpoint_to_drop);
                Some((name, (public_id, endpoints)))
            },
            None => None
        };
        match new_entry {
            Some((name, (public_id, endpoints))) => {
                if endpoints.is_empty() {
                    println!("Connection {:?} lost for relayed node {:?}", endpoint_to_drop, name);
                    Some(name.clone())
                } else {
                    self.relay_map.insert(name.clone(), (public_id.clone(), endpoints.clone()));
                    None
                }
            },
            None => None
        }
    }

    /// Returns true if we keep relay endpoints for given name.
    pub fn contains_relay_for(&self, relay_name: &NameType) -> bool {
        self.relay_map.contains_key(relay_name)
    }

    /// Returns true if we already have a name associated with this endpoint.
    pub fn contains_endpoint(&self, relay_endpoint: &Endpoint) -> bool {
        self.lookup_map.contains_key(relay_endpoint)
    }

    /// Returns Option<NameType> if an endpoint is found
    pub fn lookup_endpoint(&self, relay_endpoint: &Endpoint) -> Option<NameType> {
        match self.lookup_map.get(relay_endpoint) {
            Some(name) => Some(name.clone()),
            None => None
        }
    }

    /// This returns a pair of the stored PublicId and a BTreeSet of the stored Endpoints.
    pub fn get_endpoints(&self, relay_name: &NameType) -> Option<&(PublicId, BTreeSet<Endpoint>)> {
        self.relay_map.get(relay_name)
    }


    /// On unknown NewConnection, register the endpoint we are connected to.
    pub fn register_unknown_connection(&mut self, endpoint: Endpoint) {
        // TODO: later prune and drop old unknown connections
        self.unknown_connections.insert(endpoint, SteadyTime::now());
    }

    /// When we receive an "I am" message on this connection, drop it
    pub fn remove_unknown_connection(&mut self, endpoint: &Endpoint) -> Option<Endpoint> {
        match self.unknown_connections.remove(endpoint) {
            Some(_) => Some(endpoint.clone()), // return the endpoint
            None => None
        }
    }

    /// Returns true if the endpoint has been registered as an unknown NewConnection
    pub fn lookup_unknown_connection(&self, endpoint: &Endpoint) -> bool {
        self.unknown_connections.contains_key(endpoint)
    }

    /// Returns true if the relay map was instantiated with a self_relocated id.
    /// A self_relocated id should only be used by the first node to start a network.
    pub fn zero_node(&self) -> bool {
        self.self_relocated
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crust::Endpoint;
    use types::{Id, PublicId};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use rand::random;
    use NameType;

    fn generate_random_endpoint() -> Endpoint {
        Endpoint::Tcp(SocketAddr::from_str(&format!("127.0.0.1:{}", random::<u16>())).unwrap())
    }

    fn drop_ip_node(relay_map: &mut RelayMap, ip_node_to_drop: &NameType) {
        match relay_map.relay_map.get(&ip_node_to_drop) {
            Some(relay_entry) => {
                for endpoint in relay_entry.1.iter() {
                    relay_map.lookup_map.remove(endpoint);
                }
            },
            None => return
        };
        relay_map.relay_map.remove(ip_node_to_drop);
    }

    #[test]
    fn add() {
        let our_id : Id = Id::new();
        let our_public_id = PublicId::new(&our_id);
        let mut relay_map = RelayMap::new(&our_id);
        assert_eq!(false, relay_map.add_ip_node(our_public_id.clone(), generate_random_endpoint()));
        assert_eq!(0, relay_map.relay_map.len());
        assert_eq!(0, relay_map.lookup_map.len());
        while relay_map.relay_map.len() < super::MAX_RELAY {
            let new_endpoint = generate_random_endpoint();
            if !relay_map.contains_endpoint(&new_endpoint) {
                assert_eq!(true, relay_map.add_ip_node(PublicId::new(&Id::new()),
                    new_endpoint)); };
        }
        assert_eq!(false, relay_map.add_ip_node(PublicId::new(&Id::new()),
                          generate_random_endpoint()));
    }

    #[test]
    fn drop() {
        let our_id : Id = Id::new();
        let mut relay_map = RelayMap::new(&our_id);
        let test_public_id = PublicId::new(&Id::new());
        let test_endpoint = generate_random_endpoint();
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint.clone()));
        assert_eq!(true, relay_map.contains_relay_for(&test_public_id.name()));
        assert_eq!(true, relay_map.contains_endpoint(&test_endpoint));
        drop_ip_node(&mut relay_map, &test_public_id.name());
        assert_eq!(false, relay_map.contains_relay_for(&test_public_id.name()));
        assert_eq!(false, relay_map.contains_endpoint(&test_endpoint));
        assert_eq!(None, relay_map.get_endpoints(&test_public_id.name()));
    }

    #[test]
    fn add_conflicting_endpoints() {
        let our_id : Id = Id::new();
        let mut relay_map = RelayMap::new(&our_id);
        let test_public_id = PublicId::new(&Id::new());
        let test_endpoint = generate_random_endpoint();
        let test_conflicting_public_id = PublicId::new(&Id::new());
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint.clone()));
        assert_eq!(true, relay_map.contains_relay_for(&test_public_id.name()));
        assert_eq!(true, relay_map.contains_endpoint(&test_endpoint));
        assert_eq!(false, relay_map.add_ip_node(test_conflicting_public_id.clone(),
                                                test_endpoint.clone()));
        assert_eq!(false, relay_map.contains_relay_for(&test_conflicting_public_id.name()))
    }

    #[test]
    fn add_multiple_endpoints() {
        let our_id : Id = Id::new();
        let mut relay_map = RelayMap::new(&our_id);
        assert!(super::MAX_RELAY - 1 > 0);
        // ensure relay_map is all but full, so multiple endpoints are not counted as different
        // relays.
        while relay_map.relay_map.len() < super::MAX_RELAY - 1 {
            let new_endpoint = generate_random_endpoint();
            if !relay_map.contains_endpoint(&new_endpoint) {
                assert_eq!(true, relay_map.add_ip_node(PublicId::new(&Id::new()),
                    new_endpoint)); };
        }
        let test_public_id = PublicId::new(&Id::new());

        let mut test_endpoint_1 = generate_random_endpoint();
        let mut test_endpoint_2 = generate_random_endpoint();
        loop {
            if !relay_map.contains_endpoint(&test_endpoint_1) { break; }
            test_endpoint_1 = generate_random_endpoint(); };
        loop {
            if !relay_map.contains_endpoint(&test_endpoint_2) { break; }
            test_endpoint_2 = generate_random_endpoint(); };
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint_1.clone()));
        assert_eq!(true, relay_map.contains_relay_for(&test_public_id.name()));
        assert_eq!(true, relay_map.contains_endpoint(&test_endpoint_1));
        assert_eq!(false, relay_map.add_ip_node(test_public_id.clone(),
                                                test_endpoint_1.clone()));
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint_2.clone()));
        assert!(relay_map.get_endpoints(&test_public_id.name()).unwrap().1
                         .contains(&test_endpoint_1));
        assert!(relay_map.get_endpoints(&test_public_id.name()).unwrap().1
                         .contains(&test_endpoint_2));
    }

    // TODO: add test for drop_endpoint

    // TODO: add tests for unknown_connections
}

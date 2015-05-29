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
use crust::Endpoint;
use types::PublicId;
use NameType;

const MAX_RELAY : usize = 5;

/// The relay map is used to maintain a list of contacts for whom
/// we are relaying messages, when we are ourselves connected to the network.
pub struct RelayMap {
    relay_map: BTreeMap<NameType, (PublicId, BTreeSet<Endpoint>)>,
    lookup_map: HashMap<Endpoint, NameType>,
    our_name: NameType
}

impl RelayMap {
    /// This creates a new RelayMap.
    pub fn new(our_name: &NameType) -> RelayMap {
        RelayMap {
            relay_map: BTreeMap::new(),
            lookup_map: HashMap::new(),
            our_name: our_name.clone()
        }
    }

    /// Adds an IP Node info to the relay map if the relay map has open
    /// slots.  This returns true if Info was addded.
    /// Returns true is the endpoint is newly added, or was already present.
    /// Returns false if the threshold was reached or name is our name.
    /// Returns false if the endpoint is already assigned to a different name.
    pub fn add_ip_node(&mut self, relay_info: PublicId, relay_endpoint: Endpoint) -> bool {
        // always reject our own id
        if self.our_name == relay_info.name {
            return false;
        }
        // impose limit on number of relay nodes active
        if !self.relay_map.contains_key(&relay_info.name)
            && self.relay_map.len() >= MAX_RELAY {
            return false;
        }
        if self.lookup_map.contains_key(&relay_endpoint) {
          return false; }
        self.lookup_map.entry(relay_endpoint.clone())
                       .or_insert(relay_info.name.clone());
        let new_set = || { (relay_info.clone(), BTreeSet::<Endpoint>::new()) };
        self.relay_map.entry(relay_info.name.clone()).or_insert_with(new_set).1
                      .insert(relay_endpoint);
        true
    }

    /// This removes the ip_node from the relay map.
    pub fn drop_ip_node(&mut self, ip_node_to_drop: &NameType) {
        match self.relay_map.get(&ip_node_to_drop) {
            Some(relay_entry) => {
                for endpoint in relay_entry.1.iter() {
                    self.lookup_map.remove(endpoint);
                }
            },
            None => return
        };
        self.relay_map.remove(ip_node_to_drop);
    }

    /// Returns true if we keep relay endpoints for given name.
    pub fn contains_relay_for(&self, relay_name: &NameType) -> bool {
        self.relay_map.contains_key(relay_name)
    }

    /// Returns true if we already have a name associated with this endpoint.
    pub fn contains_endpoint(&self, relay_endpoint: &Endpoint) -> bool {
        self.lookup_map.contains_key(relay_endpoint)
    }

    /// This returns a pair of the stored PublicId and a BTreeSet of the stored Endpoints.
    pub fn get_endpoints(&self, relay_name: &NameType) -> Option<&(PublicId, BTreeSet<Endpoint>)> {
        self.relay_map.get(relay_name)
    }

    /// This changes our name and drops any endpoint that would be stored under that name.
    /// The motivation for this behaviour is that our claim for a name will overrule any unverified
    /// other node claiming this name.
    pub fn change_our_name(&mut self, new_name: &NameType) {
        if self.relay_map.contains_key(new_name) {
            self.drop_ip_node(new_name);
        }

        self.our_name = new_name.clone();
    }
}

/// Bootstrap endpoints are used to connect to the network before
/// routing table connections are established.
pub struct BootstrapEndpoints {
    bootstrap_endpoints: Vec<Endpoint>,
}


#[cfg(test)]
mod test {
    use super::*;
    use NameType;
    use crust::Endpoint;
    use types::{Id, PublicId};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use test_utils::Random;
    use rand::random;

    fn generate_random_endpoint() -> Endpoint {
        Endpoint::Tcp(SocketAddr::from_str(&format!("127.0.0.1:{}", random::<u16>())).unwrap())
    }

    #[test]
    fn add() {
        let our_id : Id = Id::new();
        let our_public_id = PublicId::new(&our_id);
        let our_name = our_id.get_name();
        let mut relay_map = RelayMap::new(&our_name);
        assert_eq!(false, relay_map.add_ip_node(our_public_id.clone(), generate_random_endpoint()));
        assert_eq!(0, relay_map.relay_map.len());
        assert_eq!(0, relay_map.lookup_map.len());
        for _ in 0..super::MAX_RELAY {
            assert_eq!(true, relay_map.add_ip_node(PublicId::new(&Id::new()),
                             generate_random_endpoint()));
        }
        assert_eq!(false, relay_map.add_ip_node(PublicId::new(&Id::new()),
                          generate_random_endpoint()));
    }

    #[test]
    fn drop() {
        let our_name : NameType = Random::generate_random();
        let mut relay_map = RelayMap::new(&our_name);
        let test_public_id = PublicId::new(&Id::new());
        let test_endpoint = generate_random_endpoint();
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint.clone()));
        assert_eq!(true, relay_map.contains_relay_for(&test_public_id.name));
        assert_eq!(true, relay_map.contains_endpoint(&test_endpoint));
        relay_map.drop_ip_node(&test_public_id.name);
        assert_eq!(false, relay_map.contains_relay_for(&test_public_id.name));
        assert_eq!(false, relay_map.contains_endpoint(&test_endpoint));
        assert_eq!(None, relay_map.get_endpoints(&test_public_id.name));
    }

    #[test]
    fn add_conflicting_endpoints() {
        let our_name : NameType = Random::generate_random();
        let mut relay_map = RelayMap::new(&our_name);
        let test_public_id = PublicId::new(&Id::new());
        let test_endpoint = generate_random_endpoint();
        let test_conflicting_public_id = PublicId::new(&Id::new());
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint.clone()));
        assert_eq!(true, relay_map.contains_relay_for(&test_public_id.name));
        assert_eq!(true, relay_map.contains_endpoint(&test_endpoint));
        assert_eq!(false, relay_map.add_ip_node(test_conflicting_public_id.clone(),
                                                test_endpoint.clone()));
        assert_eq!(false, relay_map.contains_relay_for(&test_conflicting_public_id.name))
    }

    #[test]
    fn add_multiple_endpoints() {
        let our_name : NameType = Random::generate_random();
        let mut relay_map = RelayMap::new(&our_name);
        assert!(super::MAX_RELAY - 1 > 0);
        // ensure relay_map is all but full, so multiple endpoints are not counted as different
        // relays.
        for _ in 0..super::MAX_RELAY - 1 {
            assert_eq!(true, relay_map.add_ip_node(PublicId::new(&Id::new()),
                             generate_random_endpoint()));
        }
        let test_public_id = PublicId::new(&Id::new());
        let test_endpoint_1 = generate_random_endpoint();
        let test_endpoint_2 = generate_random_endpoint();
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint_1.clone()));
        assert_eq!(true, relay_map.contains_relay_for(&test_public_id.name));
        assert_eq!(true, relay_map.contains_endpoint(&test_endpoint_1));
        assert_eq!(false, relay_map.add_ip_node(test_public_id.clone(),
                                                test_endpoint_1.clone()));
        assert_eq!(true, relay_map.add_ip_node(test_public_id.clone(),
                                               test_endpoint_2.clone()));
        assert!(relay_map.get_endpoints(&test_public_id.name).unwrap().1
                         .contains(&test_endpoint_1));
        assert!(relay_map.get_endpoints(&test_public_id.name).unwrap().1
                         .contains(&test_endpoint_2));
    }
}

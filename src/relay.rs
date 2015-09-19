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

const MAX_RELAY : usize = 100;

/// The relay map is used to maintain a list of contacts for whom
/// we are relaying messages, when we are ourselves connected to the network.
/// These have to identify as Client(sign::PublicKey)
pub struct RelayMap {
    relay_map: ::std::collections::BTreeMap<::routing_core::ConnectionName, ::peer::Peer>,
    lookup_map: ::std::collections::HashMap<::crust::Endpoint, ::routing_core::ConnectionName>,
}

#[allow(unused)]
impl RelayMap {
    /// This creates a new RelayMap.
    pub fn new() -> RelayMap {
        RelayMap {
            relay_map: ::std::collections::BTreeMap::new(),
            lookup_map: ::std::collections::HashMap::new()
        }
    }

    /// Adds a Peer to the relay map if the relay map has open slots, and the Peer is not marked for
    /// RoutingTable.
    /// Returns true if the Peer was addded.
    /// Returns true if the endpoint is newly added, or was already present.
    /// Returns false if the threshold was reached or identity already exists.
    /// Returns false if the endpoint is already assigned (to a different name).
    pub fn add_peer(&mut self,
                    identity: ::routing_core::ConnectionName,
                    endpoint: ::crust::Endpoint,
                    public_id: Option<::public_id::PublicId>)
                    -> bool {
        // reject Routing peers from relay_map
        match identity {
            ::routing_core::ConnectionName::Routing(_) => return false,
            _ => {}
        };
        // impose limit on number of relay nodes active
        if !self.relay_map.contains_key(&identity) && self.relay_map.len() >= MAX_RELAY {
            error!("REJECTED because of MAX_RELAY");
            return false;
        }
        // check if endpoint already exists
        if self.lookup_map.contains_key(&endpoint) {
            return false;
        }
        // for now don't allow multiple endpoints on a Peer
        if self.relay_map.contains_key(&identity) {
            return false;
        }
        let _ = self.lookup_map.entry(endpoint.clone()).or_insert(identity.clone());
        let new_peer = || ::peer::Peer::new(identity.clone(), endpoint, public_id);
        let _ = self.relay_map.entry(identity.clone()).or_insert_with(new_peer);
        true
    }

    /// This removes the provided endpoint and returns the Peer this endpoint was registered to,
    /// otherwise returns None.
    //  TODO (ben 6/08/2015) drop_endpoint has been simplified for a single endpoint per Peer
    //  find the archived version on 628febf879a9d3684f69967e00b5a45dc880c6e3 for reference
    pub fn drop_endpoint(&mut self, endpoint_to_drop: &::crust::Endpoint) -> Option<::peer::Peer> {
        match self.lookup_map.remove(endpoint_to_drop) {
            Some(identity) => self.relay_map.remove(&identity),
            None => None,
        }
    }

    /// Removes the given ConnectionName from the relay map if it exists, returning the Peer removed
    /// from the lookup_map.
    pub fn drop_connection_name(&mut self, connection_name: &::routing_core::ConnectionName)
            -> Option<::peer::Peer> {
        match self.relay_map.remove(connection_name) {
            Some(peer) => {
                let _ = self.lookup_map.remove(peer.endpoint());
                Some(peer)
            }
            None => None,
        }
    }

    /// Returns true if we keep relay endpoints for given name.
    // FIXME(ben) this needs to be used 16/07/2015
    #[allow(dead_code)]
    pub fn contains_identity(&self, identity: &::routing_core::ConnectionName) -> bool {
        self.relay_map.contains_key(identity)
    }

    /// Returns true if we already have a name associated with this endpoint.
    #[allow(dead_code)]
    pub fn contains_endpoint(&self, endpoint: &::crust::Endpoint) -> bool {
        self.lookup_map.contains_key(endpoint)
    }

    /// Returns Option<&Peer> if an endpoint is found
    pub fn lookup_endpoint(&self, endpoint: &::crust::Endpoint) -> Option<&::peer::Peer> {
        match self.lookup_map.get(endpoint) {
            Some(identity) => self.relay_map.get(&identity),
            None => None,
        }
    }

    /// Returns the ConnectionName if either a Relay(Address::Node(name)) or Bootstrap(name) is
    /// found in the relay map.
    pub fn lookup_name(&self, name: &::NameType) -> Option<::routing_core::ConnectionName> {
        let relay_name = match self.relay_map.get(
                &::routing_core::ConnectionName::Relay(::types::Address::Node(name.clone()))) {
            Some(peer) => Some(peer.identity().clone()),
            None => None,
        };
        match relay_name {
            None => match self.relay_map.get(
                    &::routing_core::ConnectionName::Bootstrap(name.clone())) {
                Some(peer) => Some(peer.identity().clone()),
                None => None,
            },
            Some(found_name) => Some(found_name),
        }
    }

    /// Returns the Peer associated to ConnectionName.
    pub fn lookup_connection_name(&self, identity: &::routing_core::ConnectionName)
            -> Option<&::peer::Peer> {
        self.relay_map.get(identity)
    }

    /// Returns true if the length of the relay map is bigger or equal to the maximum allowed
    /// connections.
    pub fn is_full(&self) -> bool {
        self.relay_map.len() >= MAX_RELAY
    }

    /// Returns a vector of all bootstrap connections listed. If none found, returns empty.
    pub fn bootstrap_connections(&self) -> Vec<::peer::Peer> {
        let mut bootstrap_connections : Vec<::peer::Peer> = Vec::new();
        for (_, peer) in self.relay_map.iter()
            .filter(|ref entry| match *entry.1.identity() {
                ::routing_core::ConnectionName::Bootstrap(_) => true, _ => false }) {
            bootstrap_connections.push(peer.clone());
        }
        bootstrap_connections
    }

    /// Returns true if bootstrap connections are listed.
    pub fn has_bootstrap_connections(&self) -> bool {
        for _ in self.relay_map.iter()
            .filter(|ref entry| match *entry.1.identity() {
                ::routing_core::ConnectionName::Bootstrap(_) => true, _ => false }) {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod test {

    fn generate_random_endpoint() -> ::crust::Endpoint {
        ::crust::Endpoint::Tcp(::std::net::SocketAddr::V4(::std::net::SocketAddrV4::new(
            ::std::net::Ipv4Addr::new(::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>()),
            ::rand::random::<u16>())))
    }

    #[test]
    fn add_max_peers() {
        let mut relay_map = super::RelayMap::new();

        for i in 0..super::MAX_RELAY {
            let id = ::id::Id::new();
            let public_id = ::public_id::PublicId::new(&id);
            let identity = ::routing_core::ConnectionName::Relay(
                    ::types::Address::Client(public_id.signing_public_key()));
            let endpoint = generate_random_endpoint();

            assert!(relay_map.add_peer(identity.clone(), endpoint.clone(),
                    Some(public_id.clone())));
            assert!(relay_map.contains_identity(&identity));
            assert!(relay_map.contains_endpoint(&endpoint));
            assert!(relay_map.lookup_connection_name(&identity).is_some());
            assert!(relay_map.lookup_endpoint(&endpoint).is_some());

            let peer = ::peer::Peer::new(identity.clone(), endpoint.clone(), Some(public_id));
            let relay_peer = relay_map.lookup_connection_name(&identity).unwrap();

            assert_eq!(peer.identity(), relay_peer.identity());
            assert_eq!(peer.endpoint(), relay_peer.endpoint());
            assert_eq!(peer.public_id(), relay_peer.public_id());

            let relay_peer = relay_map.lookup_endpoint(&endpoint).unwrap();

            assert_eq!(peer.identity(), relay_peer.identity());
            assert_eq!(peer.endpoint(), relay_peer.endpoint());
            assert_eq!(peer.public_id(), relay_peer.public_id());
            assert!(!relay_map.has_bootstrap_connections());

            if i != super::MAX_RELAY-1 {
                assert!(!relay_map.is_full());
            } else {
                assert!(relay_map.is_full());
            }
        }

        let id = ::id::Id::new();
        let public_id = ::public_id::PublicId::new(&id);
        let identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Client(public_id.signing_public_key()));
        let endpoint = generate_random_endpoint();

        assert!(!relay_map.add_peer(identity.clone(), endpoint.clone(), Some(public_id)));
        assert!(!relay_map.contains_identity(&identity));
        assert!(!relay_map.contains_endpoint(&endpoint));
        assert!(relay_map.lookup_connection_name(&identity).is_none());
        assert!(relay_map.lookup_endpoint(&endpoint).is_none());
        assert!(!relay_map.has_bootstrap_connections());
        assert!(relay_map.is_full());
    }

    #[test]
    fn drop_endpoint() {
        let mut relay_map = super::RelayMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Client(public_id.signing_public_key()));
        let endpoint = generate_random_endpoint();

        assert!(relay_map.add_peer(identity.clone(), endpoint.clone(), Some(public_id)));
        assert!(relay_map.contains_identity(&identity));
        assert!(relay_map.contains_endpoint(&endpoint));

        let _ = relay_map.drop_endpoint(&endpoint);

        assert!(!relay_map.contains_identity(&identity));
        assert!(!relay_map.contains_endpoint(&endpoint));
    }

    #[test]
    fn drop_connection_name() {
        let mut relay_map = super::RelayMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Client(public_id.signing_public_key()));
        let endpoint = generate_random_endpoint();

        assert!(relay_map.add_peer(identity.clone(), endpoint.clone(), Some(public_id)));
        assert!(relay_map.contains_identity(&identity));
        assert!(relay_map.contains_endpoint(&endpoint));

        let _ = relay_map.drop_connection_name(&identity);

        assert!(!relay_map.contains_identity(&identity));
        assert!(!relay_map.contains_endpoint(&endpoint));
    }

    #[test]
    fn add_conflicting_identity() {
        let mut relay_map = super::RelayMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Client(public_id.signing_public_key()));
        let endpoint = generate_random_endpoint();
        let conflicting_public_id = ::public_id::PublicId::new(&::id::Id::new());
        let conflicting_identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Client(conflicting_public_id.signing_public_key()));

        assert!(relay_map.add_peer(identity.clone(), endpoint.clone(), Some(public_id)));
        assert!(relay_map.contains_identity(&identity));
        assert!(relay_map.contains_endpoint(&endpoint));
        assert!(!relay_map.add_peer(
                conflicting_identity.clone(), endpoint.clone(), Some(conflicting_public_id)));
        assert!(!relay_map.contains_identity(&conflicting_identity));
        assert!(relay_map.contains_endpoint(&endpoint));
    }

    #[test]
    fn check_bootstrap_connections() {
        let mut relay_map = super::RelayMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Client(public_id.signing_public_key()));
        let endpoint = generate_random_endpoint();

        assert!(relay_map.add_peer(identity.clone(), endpoint.clone(), Some(public_id)));
        assert!(relay_map.contains_identity(&identity));
        assert!(relay_map.contains_endpoint(&endpoint));

        let name: ::NameType = ::test_utils::Random::generate_random();
        let bootstrap_identity = ::routing_core::ConnectionName::Bootstrap(name.clone());
        let bootstrap_endpoint = generate_random_endpoint();

        assert!(relay_map.add_peer(bootstrap_identity.clone(), bootstrap_endpoint.clone(), None));
        assert!(relay_map.contains_identity(&bootstrap_identity));
        assert!(relay_map.contains_endpoint(&bootstrap_endpoint));

        let endpoint = generate_random_endpoint();
        let identity = ::routing_core::ConnectionName::Unidentified(endpoint.clone(), false);

        assert!(relay_map.add_peer(identity.clone(), endpoint.clone(), None));
        assert!(relay_map.contains_identity(&identity));
        assert!(relay_map.contains_endpoint(&endpoint));
        assert!(relay_map.lookup_name(&name).is_some());

        let identity = relay_map.lookup_name(&name).unwrap();

        assert_eq!(identity, ::routing_core::ConnectionName::Bootstrap(name.clone()));
        assert!(relay_map.has_bootstrap_connections());

        let bootstrap_connections = relay_map.bootstrap_connections();

        assert_eq!(1, bootstrap_connections.len());
        assert_eq!(bootstrap_connections[0].identity(), &bootstrap_identity);
        assert_eq!(bootstrap_connections[0].endpoint(), &bootstrap_endpoint);
        assert_eq!(bootstrap_connections[0].public_id(), &None);
    }

    #[test]
    fn add_routing_peer() {
        let mut relay_map = super::RelayMap::new();
        let name: ::NameType = ::test_utils::Random::generate_random();
        let identity = ::routing_core::ConnectionName::Routing(name.clone());
        let endpoint = generate_random_endpoint();

        assert!(!relay_map.add_peer(identity.clone(), endpoint.clone(), None));
        assert!(!relay_map.contains_identity(&identity));
        assert!(!relay_map.contains_endpoint(&endpoint));
    }

    #[test]
    fn lookup_relay_node() {
        let mut relay_map = super::RelayMap::new();
        let name: ::NameType = ::test_utils::Random::generate_random();
        let identity = ::routing_core::ConnectionName::Relay(
                ::types::Address::Node(name.clone()));
        let endpoint = generate_random_endpoint();

        assert!(relay_map.add_peer(identity.clone(), endpoint.clone(), None));
        assert!(relay_map.contains_identity(&identity));
        assert!(relay_map.contains_endpoint(&endpoint));
        assert!(relay_map.lookup_name(&name).is_some());

        let relay_identity = relay_map.lookup_name(&name).unwrap();

        assert_eq!(identity, relay_identity);
    }

    // TODO (ben 6/08/2015) multiple endpoints are not supported by RelayMap
    // until ::peer::Peer supports it.
    // #[test]
    // fn add_multiple_endpoints() {
    //     let our_id : ::id::Id = ::id::Id::new();
    //     let mut relay_map = RelayMap::new(&our_id);
    //     assert!(super::MAX_RELAY - 1 > 0);
    //     // ensure relay_map is all but full, so multiple endpoints are not counted as different
    //     // relays.
    //     while relay_map.relay_map.len() < super::MAX_RELAY - 1 {
    //         let new_endpoint = generate_random_endpoint();
    //         if !relay_map.contains_endpoint(&new_endpoint) {
    //             assert_eq!(true, relay_map.add_client(::public_id::PublicId::new(&::id::Id::new()),
    //                 new_endpoint)); };
    //     }
    //     let test_public_id = ::public_id::PublicId::new(&::id::Id::new());
    //     let test_id = ::types::Address::Client(test_public_id.signing_public_key());
    //
    //     let mut test_endpoint_1 = generate_random_endpoint();
    //     let mut test_endpoint_2 = generate_random_endpoint();
    //     loop {
    //         if !relay_map.contains_endpoint(&test_endpoint_1) { break; }
    //         test_endpoint_1 = generate_random_endpoint(); };
    //     loop {
    //         if !relay_map.contains_endpoint(&test_endpoint_2) { break; }
    //         test_endpoint_2 = generate_random_endpoint(); };
    //     assert_eq!(true, relay_map.add_client(test_public_id.clone(),
    //                                            test_endpoint_1.clone()));
    //     assert_eq!(true, relay_map.contains_relay_for(&test_id));
    //     assert_eq!(true, relay_map.contains_endpoint(&test_endpoint_1));
    //     assert_eq!(false, relay_map.add_client(test_public_id.clone(),
    //                                             test_endpoint_1.clone()));
    //     assert_eq!(true, relay_map.add_client(test_public_id.clone(),
    //                                            test_endpoint_2.clone()));
    //     assert!(relay_map.get_endpoints(&test_id).unwrap().1
    //                      .contains(&test_endpoint_1));
    //     assert!(relay_map.get_endpoints(&test_id).unwrap().1
    //                      .contains(&test_endpoint_2));
    // }
}

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

/// Peer enables multiple endpoints per peer in the network.
/// It currently wraps around crust::endpoint, and will be extended to enable multiple
/// endpoints, merging, comparing and other functionality.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Peer {
    identity: ::routing_core::ConnectionName,
    //                    ~~|~~~~~~~~~~~
    //                      | identifies the peer in relation to us
    endpoint: ::crust::Endpoint,
    //                    ~~|~~~~~~~~~~~~
    //                      | initially only support a single endpoint
    public_id: Option<::public_id::PublicId>,
    //                    ~~|~~~~~~~~~~~~~
    //                      | store public_id once obtained
    connected_timestamp: ::time::SteadyTime,
    //                    ~~|~~~~~~~
    //                      | the recorded time when the connection was established,
    //                      | this allows unidentified connections to time-out
}

#[allow(unused)]
impl Peer {
    pub fn new(identity: ::routing_core::ConnectionName,
               endpoint: ::crust::Endpoint,
               public_id: Option<::public_id::PublicId>)
               -> Peer {
        Peer {
            identity: identity,
            endpoint: endpoint,
            public_id: public_id,
            connected_timestamp: ::time::SteadyTime::now(),
        }
    }

    pub fn identity(&self) -> &::routing_core::ConnectionName {
        &self.identity
    }

    pub fn endpoint(&self) -> &::crust::Endpoint {
        &self.endpoint
    }

    pub fn public_id(&self) -> &Option<::public_id::PublicId> {
        &self.public_id
    }

    pub fn connected_timestamp(&self) -> &::time::SteadyTime {
        &self.connected_timestamp
    }

    pub fn set_public_id(&mut self, public_id: ::public_id::PublicId) {
        self.public_id = Some(public_id);
    }

    /// Returns a new Peer with the changed identity.  No checks are performed on the consistency of
    /// the new identity with the previous information.
    pub fn change_identity(&mut self, identity: ::routing_core::ConnectionName) -> Peer {
        Peer {
            identity: identity,
            endpoint: self.endpoint.clone(),
            public_id: self.public_id.clone(),
            connected_timestamp: self.connected_timestamp.clone(),
        }
    }
}

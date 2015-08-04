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

use types::Address;

/// Peer enables multiple endpoints per peer in the network.
/// It currently wraps around crust::endpoint, and will be extended to enable multiple
/// endpoints, merging, comparing and other functionality.
pub struct Peer {
    identity : Address,
    //         ~~|~~~~
    //           | address can be either a Node(NameType) or a Client(PublicKey)
    endpoint : crust::Endpoint,
    //         ~~|~~~~~~~~~~~~
    //           | initially only support a single endpoint
}

impl Peer {
    pub fn new(identity : Address, endpoint : crust::Endpoint) -> Peer {
        Peer {
            identity : Address,
            endpoint : endpoint,
        }
    }

    pub fn identity(&self) -> &Address {
        &self.identity
    }

    pub fn endpoint(&self) -> &endpoint {
        &self.endpoint
    }
}

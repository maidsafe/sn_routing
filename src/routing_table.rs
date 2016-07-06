// Copyright 2015 MaidSafe.net limited.
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

use crust::PeerId;
use kademlia_routing_table::ContactInfo;

use id::PublicId;
use xor_name::XorName;

/// The group size for the routing table. This is the maximum that can be used for consensus.
pub const GROUP_SIZE: usize = 8;
/// The quorum for group consensus.
pub const QUORUM_SIZE: usize = 5;

/// `RoutingTable` managing `NodeInfo`s.
pub type RoutingTable = ::kademlia_routing_table::RoutingTable<NodeInfo>;

/// Info about nodes in the routing table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodeInfo {
    pub public_id: PublicId,
    pub peer_id: PeerId,
}

impl NodeInfo {
    pub fn new(public_id: PublicId, peer_id: PeerId) -> Self {
        NodeInfo {
            public_id: public_id,
            peer_id: peer_id,
        }
    }
}

impl ContactInfo for NodeInfo {
    type Name = XorName;

    fn name(&self) -> &XorName {
        self.public_id.name()
    }
}

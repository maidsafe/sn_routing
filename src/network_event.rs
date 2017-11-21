// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use peer_id::PeerId;
use routing_table::Prefix;

pub type Age = u8;
pub type Version = u64;

/// This is the events on the network,
/// After alpha3 this may include daa related events
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum NetworkEvent {
    InfantNew(PeerId), // Age 1
    PeerRelocate(PeerId, Prefix),
    PeerAccept(PeerId),   // Accept relocation from another section
    AdultPromote(PeerId), // Promote to Elder, will be sent to siblings
    PeerRejoin(PeerId),   // immediately Relocate, not to be part of close group
    ElderLost(PeerId),    // Immediate Add a new close group member after this
    PeerLost(PeerId),
    ElderKill(PeerId), // Immediate Add a new close group member after this
    PeerKill(PeerId),
    MergeTo(Prefix),
    MergePeer(PeerId, Prefix), // each peer fom a merge is like adding a peer
    Split(Prefix, Prefix),     // split to both these prefixes
    SplitPeer(PeerId, Prefix),
}

impl NetworkEvent {
    pub fn is_after(&self, other: NetworkEvent) -> bool {
        match other {
            NetworkEvent::InfantNew(_) |
            NetworkEvent::PeerRelocate(_, _) |
            NetworkEvent::PeerAccept(_) |
            NetworkEvent::PeerRejoin(_) |
            NetworkEvent::PeerLost(_) |
            NetworkEvent::PeerKill(_) => true,
            _ => false,
        }
    }

    pub fn can_rejoin(&self) -> bool {
        match *self {
            NetworkEvent::PeerLost(_) | NetworkEvent::ElderLost(_) => true,
            _ => false,
        }
    }

    pub fn is_live(&self) -> bool {
        match *self {
            NetworkEvent::InfantNew(_) | NetworkEvent::PeerAccept(_) => true,
            _ => false,
        }
    }

    pub fn is_dead(&self) -> bool {
        match *self {
            NetworkEvent::PeerRejoin(_) |
            NetworkEvent::ElderKill(_) |
            NetworkEvent::PeerKill(_) => true,
            _ => false,
        }
    }

    fn before_peer_new(&self, _other: NetworkEvent) -> bool {
        true
    }

    fn after_peer_new(&self, _other: NetworkEvent) -> bool {
        true
    }




    pub fn is_before(&self, _other: NetworkEvent) -> bool {
        true
    }
}

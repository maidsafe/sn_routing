// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This,
// along with the
// Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations
// relating to use of the SAFE Network Software.

use routing_table::Prefix;
use rust_sodium::crypto::sign::PublicKey;

pub type Age = u64;
pub type Version = u64;

/// This is the events on the network,
/// After alpha3 this may include daa related events
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum NetworkEvent {
    PeerNew(PublicKey), // Age 1
    PeerRelocate(PublicKey, u64, Prefix<u64>),
    PeerAccept(PublicKey, Age), // Accept relocation from another section
    PeerRejoin(PublicKey), // immediately Relocate, not to be part of close group
    PeerLost(PublicKey), // Immediate Add a new close group member after this
    PeerKill(PublicKey), // Immediate Add a new close group member after this
    PeerPenalise(PublicKey, Age), // may move the peer out of close group
    MergeTo(Prefix<u64>, Version),
    MergePeer(PublicKey, Prefix<u64>, Version), // each peer fom a merge is like adding a peer
    Split((Prefix<u64>, Version), (Prefix<u64>, Version)), // split to both these prefixes
    SplitPeer(PublicKey, Prefix<u64>, Version),
}

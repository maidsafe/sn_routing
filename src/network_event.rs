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
pub type NMessage = u64;

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum Elders {
    // All INTERAL group votes
    ElderRelocate(PeerId, Prefix), // GROUP_SIZE = 8 : Followed by PeerPromote
    // Do not relocate if it makes group < 8, elder self votes
    ElderAccept(PeerId), // GROUP_SIZE = 8 (this peer will be an Elder but not until consensus) :
    //may be followed by ElderDemote new peer votes here so group is still oldest 8 members
    AdultPromote(PeerId), // Take an Adult ofmr ValidPeers and use it here if we lose an Elder
    ElderDemote(PeerId), // GROUP_SIZE = 8 or less if group not complete
    ElderLost(PeerId), // GROUP_SIZE-- (7 or less) an Elder will not vote for its own loss
    ElderKill(PeerId), // GROUP_SIZE-- (7 or less) we may kill more than one Elder at once ???
    Merge(Prefix), // GROUP_SIZE = 8 or less
    Split(Prefix, Prefix), // GROUP_SIZE = 8
}

// TODO - could be a simple state machine !!
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum AdultsAndInfants {
    // All INTERNAL group votes
    PeerAccept(PeerId), // this one is live
    PeerRelocate(PeerId, Prefix), // then remove
    PeerRejoin(PeerId), // then relocate
    PeerLost(PeerId), // on reconnect remove this
    PeerKill(PeerId), // just remove
}

/// Trea this just like ValidPeers - i..e Eveny new Elder must give us its `Vote` for all of theese to be accepted.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum DataIdentifier {
    Temp,
}

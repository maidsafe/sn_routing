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


/// Will create `Block`s we keep in a chain, transitions happens in pairs (i.e. Lost -> Live) (Live -> gone) (Live -> kill) etc.
/// merge and split (prefix change) sparks pairs of (Live Gone) pairs (possibly none, but inlikely). Lost is out of the blue but
/// pairs with Live or possibly Prefixchange as can Live create PrefixChange and then more pairs.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum Elders {
    Live(PeerId),         // accepted but not yet lost, may have come back from a merge
    Killed(PeerId),       // Cannot ever become live again.
    Lost(PeerId), // Lost and can restart (to us) to be relocated ONLY UNFORSEABLE STATE, can happen out of order, but forces next state
    Gone(PeerId), // Gone to another section or become an Adult (Demoted), can again become `Live`
    Relocated(PeerId), // Similar to killed as this cannot become Live ever again
    PrefixChange(Prefix), // We merged or split here, can possibly be used as checkpoints later in network.
}

// TODO - could be a simple state machine !!
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum AdultsAndInfants {
    // All INTERNAL group votes
    PeerAccept(PeerId),           // this one is live
    PeerRelocate(PeerId, Prefix), // then remove
    PeerRejoin(PeerId),           // then relocate
    PeerLost(PeerId),             // on reconnect remove this
    PeerKill(PeerId),             // just remove
}

/// Trea this just like ValidPeers - i..e Eveny new Elder must give us its `Vote` for all of theese to be accepted.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum DataIdentifier {
    Temp,
}
